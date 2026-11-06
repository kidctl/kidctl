//! Policy evaluation. The Kotlin agent implements the same rules
//! (`agent/.../Evaluator.kt`); both are checked against `spec/vectors.json`.
//!
//! Order of rules for one package:
//! 1. `blocked`                       -> blocked ("blocked")
//! 2. `always_allowed`                -> allowed
//! 3. approval on, user-installed app not named in the policy -> blocked ("unapproved")
//! 4. active unlock override          -> allowed
//! 5. active lock override            -> blocked ("lock")
//! 6. inside a downtime window        -> blocked ("downtime")
//! 7. any matching limit exhausted    -> blocked ("limit:<name>")
//! 8. otherwise                       -> allowed
//!
//! Screen lock (device-wide, [`screen_locked`]), checked in this order:
//! 1. active unlock override                      -> not locked
//! 2. active lock override with `screen: true`    -> locked
//! 3. inside a downtime window with `lock_screen` -> locked
//! 4. otherwise                                   -> not locked
//!
//! Usage counts are seconds of foreground time since local midnight, per
//! package, as reported by the device (system/exempt packages excluded).
//!
//! Notifications ([`notify_step`], only when the policy has `notify`), a pure
//! transition from the previous [`NotifyState`] (kept by the phone):
//! - Quota: for each limit with `notify_at`, the level is the highest
//!   threshold t with `used * 100 >= t * budget` (budget including active
//!   extra time; budget 0 -> level 0). A notice is due when the level rises
//!   above the level already notified for that limit today; each limit
//!   notifies on its own (a sub-limit and `general` each count the same app),
//!   except within one evaluation: a due notice is dropped (its threshold
//!   still counts as notified) when another limit due at the same time has
//!   less time remaining (tie: the one earlier in the policy) and both count
//!   an app used today (usage > 0). Limits sharing no used app both notify.
//!   No notice while the level jumped straight to an exhausted limit
//!   (`used >= budget`: the app is paused, Android says so), nor while an
//!   unlock, a lock or a downtime window is active (limits decide nothing
//!   then; the notice comes once it is over, if still due). When the budget
//!   grows (extra time), the thresholds above the new percentage are armed
//!   again: crossed later, they notify again; those still below do not.
//!   The notified levels reset at local midnight.
//! - Downtime: one notice per start, `before_downtime_secs` (or less) before
//!   downtime starts pausing apps ("pause"), and/or a `lock_screen` window
//!   starts locking the screen ("lock"; inside an earlier window: lock only).
//!   A start covered by an unlock override gives no notice; the end of an
//!   unlock inside a downtime window counts as a start.

use crate::policy::{Compiled, Downtime, Limit, Override};
use chrono::{Datelike, TimeZone, Timelike};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Decision {
    Allowed,
    Blocked(String),
}

impl Decision {
    pub fn label(&self) -> String {
        match self {
            Decision::Allowed => "allowed".into(),
            Decision::Blocked(r) => format!("blocked:{r}"),
        }
    }
}

/// Local (day-of-week Monday=0, minute-of-day) of an epoch second in `tz`.
pub fn local(tz: Tz, now: i64) -> (usize, u32) {
    let t = tz.timestamp_opt(now, 0).single().expect("valid epoch");
    (
        t.weekday().num_days_from_monday() as usize,
        t.hour() * 60 + t.minute(),
    )
}

fn window_active(w: &Downtime, dow: usize, minute: u32) -> bool {
    let prev = (dow + 6) % 7;
    if w.start_min < w.end_min {
        w.days[dow] && w.start_min <= minute && minute < w.end_min
    } else {
        (w.days[dow] && minute >= w.start_min) || (w.days[prev] && minute < w.end_min)
    }
}

pub fn in_downtime(c: &Compiled, dow: usize, minute: u32) -> bool {
    c.downtime.iter().any(|w| window_active(w, dow, minute))
}

/// Whether the screen itself must be locked now (see the module docs).
pub fn screen_locked(c: &Compiled, now: i64) -> bool {
    let active = |f: fn(&Override) -> bool| c.overrides.iter().any(|o| o.active_at(now) && f(o));
    if active(|o| matches!(o, Override::Unlock { .. })) {
        return false;
    }
    if active(|o| matches!(o, Override::Lock { screen: true, .. })) {
        return true;
    }
    let tz: Tz = c.timezone.parse().expect("validated timezone");
    let (dow, minute) = local(tz, now);
    c.downtime
        .iter()
        .any(|w| w.lock_screen && window_active(w, dow, minute))
}

fn limit_matches(c: &Compiled, l: &Limit, pkg: &str) -> bool {
    if c.always_allowed.iter().any(|a| a == pkg) || l.exclude.iter().any(|a| a == pkg) {
        return false;
    }
    l.wildcard || l.apps.iter().any(|a| a == pkg)
}

/// Seconds used today by all packages counted against `l`.
pub fn limit_used(c: &Compiled, l: &Limit, usage: &BTreeMap<String, u64>) -> u64 {
    usage
        .iter()
        .filter(|(p, _)| limit_matches(c, l, p))
        .map(|(_, s)| s)
        .sum()
}

/// Today's budget for `l` including active extra-time overrides.
pub fn limit_budget(c: &Compiled, l: &Limit, dow: usize, now: i64) -> u64 {
    let extra: u64 = c
        .overrides
        .iter()
        .filter(|o| o.active_at(now))
        .filter_map(|o| match o {
            Override::Extra { limit, secs, .. } if limit.as_deref().is_none_or(|n| n == l.name) => {
                Some(*secs)
            }
            _ => None,
        })
        .sum();
    l.daily_secs[dow] + extra
}

fn named_in_policy(c: &Compiled, pkg: &str) -> bool {
    c.approved
        .iter()
        .chain(&c.always_allowed)
        .chain(&c.blocked)
        .any(|a| a == pkg)
        || c.limits.iter().any(|l| l.apps.iter().any(|a| a == pkg))
}

/// Decide for one package. `user_installed`: the app is not part of the
/// system image (only those are subject to approval).
pub fn decide(
    c: &Compiled,
    now: i64,
    usage: &BTreeMap<String, u64>,
    pkg: &str,
    user_installed: bool,
) -> Decision {
    let tz: Tz = c.timezone.parse().expect("validated timezone");
    if c.blocked.iter().any(|a| a == pkg) {
        return Decision::Blocked("blocked".into());
    }
    if c.always_allowed.iter().any(|a| a == pkg) {
        return Decision::Allowed;
    }
    if c.approval && user_installed && !named_in_policy(c, pkg) {
        return Decision::Blocked("unapproved".into());
    }
    let active = |f: fn(&Override) -> bool| c.overrides.iter().any(|o| o.active_at(now) && f(o));
    if active(|o| matches!(o, Override::Unlock { .. })) {
        return Decision::Allowed;
    }
    if active(|o| matches!(o, Override::Lock { .. })) {
        return Decision::Blocked("lock".into());
    }
    let (dow, minute) = local(tz, now);
    if in_downtime(c, dow, minute) {
        return Decision::Blocked("downtime".into());
    }
    for l in &c.limits {
        if limit_matches(c, l, pkg) && limit_used(c, l, usage) >= limit_budget(c, l, dow, now) {
            return Decision::Blocked(format!("limit:{}", l.name));
        }
    }
    Decision::Allowed
}

/// Highest threshold of `l.notify_at` reached by `used` out of `budget` (0: none).
pub fn quota_level(l: &Limit, used: u64, budget: u64) -> u8 {
    if budget == 0 {
        return 0;
    }
    l.notify_at
        .iter()
        .copied()
        .filter(|&t| used * 100 >= u64::from(t) * budget)
        .max()
        .unwrap_or(0)
}

/// What was already notified for one limit on [`NotifyState::date`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mark {
    /// Budget (with extra time) when last evaluated.
    pub budget: u64,
    /// Highest threshold notified (or passed silently).
    pub level: u8,
}

/// Notification bookkeeping carried from one evaluation to the next (on the
/// phone: persisted). Start with `NotifyState::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyState {
    /// Local date (YYYY-MM-DD) the marks belong to.
    pub date: String,
    pub limits: BTreeMap<String, Mark>,
    /// Start (epoch) of the last downtime window noticed.
    pub downtime_start: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Notice {
    Quota {
        limit: String,
        level: u8,
        used_secs: u64,
        budget_secs: u64,
        remaining_secs: u64,
    },
    /// `local_start`: HH:MM in the child's timezone; `in_secs`: until it
    /// starts; `pause`: apps get paused then; `lock_screen`: the screen gets locked.
    Downtime {
        start: i64,
        local_start: String,
        in_secs: i64,
        pause: bool,
        lock_screen: bool,
    },
}

impl Notice {
    /// "quota:<limit>:<level>:<remaining secs>" or
    /// "downtime:<HH:MM>:<in secs>:<pause|pause+lock|lock>" (shared vectors).
    pub fn label(&self) -> String {
        match self {
            Notice::Quota {
                limit,
                level,
                remaining_secs,
                ..
            } => format!("quota:{limit}:{level}:{remaining_secs}"),
            Notice::Downtime {
                local_start,
                in_secs,
                pause,
                lock_screen,
                ..
            } => {
                let what = match (pause, lock_screen) {
                    (true, true) => "pause+lock",
                    (true, false) => "pause",
                    _ => "lock",
                };
                format!("downtime:{local_start}:{in_secs}:{what}")
            }
        }
    }
}

fn unlock_at(c: &Compiled, t: i64) -> bool {
    c.overrides
        .iter()
        .any(|o| matches!(o, Override::Unlock { .. }) && o.active_at(t))
}

/// What downtime does at `t`: (apps paused, screen locked by a `lock_screen`
/// window); nothing while an unlock override is active.
fn downtime_effect(c: &Compiled, tz: Tz, t: i64) -> (bool, bool) {
    if unlock_at(c, t) {
        return (false, false);
    }
    let (dow, minute) = local(tz, t);
    (
        in_downtime(c, dow, minute),
        c.downtime
            .iter()
            .any(|w| w.lock_screen && window_active(w, dow, minute)),
    )
}

/// The first instant `s` in `(now, now + within]` at which downtime starts
/// pausing apps and/or locking the screen (see [`downtime_effect`]), as
/// `(s, pause starts, screen lock starts)`. Candidates: minute boundaries and
/// the end of unlock overrides.
pub fn upcoming_downtime(c: &Compiled, now: i64, within: u64) -> Option<(i64, bool, bool)> {
    let tz: Tz = c.timezone.parse().expect("validated timezone");
    let end = now + within as i64;
    let mut candidates: Vec<i64> = ((now.div_euclid(60) + 1) * 60..=end).step_by(60).collect();
    for o in &c.overrides {
        let (_, until) = o.window();
        if matches!(o, Override::Unlock { .. }) && now < until && until <= end {
            candidates.push(until);
        }
    }
    candidates.sort_unstable();
    candidates.into_iter().find_map(|s| {
        let ((pause, lock), (was_paused, was_locked)) =
            (downtime_effect(c, tz, s), downtime_effect(c, tz, s - 1));
        let (pause, lock) = (pause && !was_paused, lock && !was_locked);
        (pause || lock).then_some((s, pause, lock))
    })
}

/// One evaluation of the notification rules (see the module docs): the
/// notices to post now and the state to keep for the next call.
pub fn notify_step(
    c: &Compiled,
    now: i64,
    usage: &BTreeMap<String, u64>,
    prev: &NotifyState,
) -> (Vec<Notice>, NotifyState) {
    let Some(n) = &c.notify else {
        return (Vec::new(), prev.clone());
    };
    let tz: Tz = c.timezone.parse().expect("validated timezone");
    let t = tz.timestamp_opt(now, 0).single().expect("valid epoch");
    let date = t.format("%Y-%m-%d").to_string();
    let mut st = prev.clone();
    if st.date != date {
        st.date = date;
        st.limits.clear();
    }
    let mut out = Vec::new();
    let (dow, minute) = local(tz, now);
    let active = |f: fn(&Override) -> bool| c.overrides.iter().any(|o| o.active_at(now) && f(o));
    let quiet = active(|o| matches!(o, Override::Unlock { .. }))
        || active(|o| matches!(o, Override::Lock { .. }))
        || in_downtime(c, dow, minute);
    if !quiet {
        // Quota notices due now, in policy order, with their limit.
        let mut due: Vec<(&Limit, u8, u64, u64)> = Vec::new();
        for l in c.limits.iter().filter(|l| !l.notify_at.is_empty()) {
            let used = limit_used(c, l, usage);
            let budget = limit_budget(c, l, dow, now);
            let level = quota_level(l, used, budget);
            let mark = st
                .limits
                .entry(l.name.clone())
                .or_insert(Mark { budget, level: 0 });
            if budget > mark.budget {
                mark.level = mark.level.min(level);
            }
            mark.budget = budget;
            if level > mark.level {
                if used < budget {
                    due.push((l, level, used, budget));
                }
                mark.level = level;
            }
        }
        // Same tick, same app: only the most constraining limit speaks.
        let shared = |a: &Limit, b: &Limit| {
            usage
                .iter()
                .any(|(p, &s)| s > 0 && limit_matches(c, a, p) && limit_matches(c, b, p))
        };
        for (i, &(l, level, used, budget)) in due.iter().enumerate() {
            let remaining = budget - used;
            let dominated = due.iter().enumerate().any(|(j, &(la, _, ua, ba))| {
                j != i && (ba - ua < remaining || (ba - ua == remaining && j < i)) && shared(la, l)
            });
            if !dominated {
                out.push(Notice::Quota {
                    limit: l.name.clone(),
                    level,
                    used_secs: used,
                    budget_secs: budget,
                    remaining_secs: remaining,
                });
            }
        }
    }
    if n.before_downtime_secs > 0
        && let Some((start, pause, lock_screen)) = upcoming_downtime(c, now, n.before_downtime_secs)
        && st.downtime_start != Some(start)
    {
        let local_start = tz
            .timestamp_opt(start, 0)
            .single()
            .expect("valid")
            .format("%H:%M")
            .to_string();
        out.push(Notice::Downtime {
            start,
            local_start,
            in_secs: start - now,
            pause,
            lock_screen,
        });
        st.downtime_start = Some(start);
    }
    (out, st)
}

#[derive(Debug, Serialize)]
pub struct LimitStatus {
    pub name: String,
    pub used_secs: u64,
    pub budget_secs: u64,
    pub remaining_secs: u64,
    /// Notification thresholds (percent of the budget); empty = none.
    pub notify_at: Vec<u8>,
    /// Thresholds reached now (used/budget, extra time included).
    pub reached: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub child: String,
    pub local_time: String,
    pub in_downtime: bool,
    pub lock_active: bool,
    pub unlock_active: bool,
    pub screen_locked: bool,
    pub limits: Vec<LimitStatus>,
    pub active_overrides: Vec<Override>,
}

pub fn status(c: &Compiled, now: i64, usage: &BTreeMap<String, u64>) -> Status {
    let tz: Tz = c.timezone.parse().expect("validated timezone");
    let (dow, minute) = local(tz, now);
    let limits = c
        .limits
        .iter()
        .map(|l| {
            let used = limit_used(c, l, usage);
            let budget = limit_budget(c, l, dow, now);
            let level = quota_level(l, used, budget);
            LimitStatus {
                name: l.name.clone(),
                used_secs: used,
                budget_secs: budget,
                remaining_secs: budget.saturating_sub(used),
                notify_at: l.notify_at.clone(),
                reached: l
                    .notify_at
                    .iter()
                    .copied()
                    .filter(|&t| t <= level)
                    .collect(),
            }
        })
        .collect();
    let active: Vec<Override> = c
        .overrides
        .iter()
        .filter(|o| o.active_at(now))
        .cloned()
        .collect();
    Status {
        child: c.child.clone(),
        local_time: tz
            .timestamp_opt(now, 0)
            .single()
            .expect("valid")
            .format("%a %Y-%m-%d %H:%M %Z")
            .to_string(),
        in_downtime: in_downtime(c, dow, minute),
        lock_active: active.iter().any(|o| matches!(o, Override::Lock { .. })),
        unlock_active: active.iter().any(|o| matches!(o, Override::Unlock { .. })),
        screen_locked: screen_locked(c, now),
        limits,
        active_overrides: active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        now: i64,
        usage: BTreeMap<String, u64>,
        #[serde(default)]
        user_installed: Vec<String>,
        expect: BTreeMap<String, String>,
        /// Expected [`screen_locked`] (device-wide).
        screen_locked: bool,
    }
    #[derive(Deserialize)]
    struct NotifyStep {
        now: i64,
        usage: BTreeMap<String, u64>,
        /// [`Notice::label`]s due at this step, in order.
        expect: Vec<String>,
    }
    #[derive(Deserialize)]
    struct NotifyCase {
        name: String,
        /// Run in order from `NotifyState::default()`.
        steps: Vec<NotifyStep>,
    }
    #[derive(Deserialize)]
    struct Vectors {
        policy: Compiled,
        cases: Vec<Vector>,
        notify_cases: Vec<NotifyCase>,
    }

    /// The shared vectors file is also run by the Kotlin agent's unit tests.
    #[test]
    fn shared_vectors() {
        let v: Vectors = serde_json::from_str(include_str!("../spec/vectors.json")).unwrap();
        let mut failures = Vec::new();
        for case in &v.cases {
            for (pkg, want) in &case.expect {
                let ui = case.user_installed.iter().any(|p| p == pkg);
                let got = decide(&v.policy, case.now, &case.usage, pkg, ui).label();
                if &got != want {
                    failures.push(format!("{}: {pkg}: want {want}, got {got}", case.name));
                }
            }
            let got = screen_locked(&v.policy, case.now);
            if got != case.screen_locked {
                failures.push(format!(
                    "{}: screen_locked: want {}, got {got}",
                    case.name, case.screen_locked
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn shared_notify_vectors() {
        let v: Vectors = serde_json::from_str(include_str!("../spec/vectors.json")).unwrap();
        assert!(!v.notify_cases.is_empty());
        let mut failures = Vec::new();
        for case in &v.notify_cases {
            let mut st = NotifyState::default();
            for (i, s) in case.steps.iter().enumerate() {
                let (notices, next) = notify_step(&v.policy, s.now, &s.usage, &st);
                let got: Vec<String> = notices.iter().map(Notice::label).collect();
                if got != s.expect {
                    failures.push(format!(
                        "{} step {i}: want {:?}, got {got:?}",
                        case.name, s.expect
                    ));
                }
                st = next;
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn notify_off_without_policy_notify() {
        let mut c: Compiled = serde_json::from_str::<Vectors>(include_str!("../spec/vectors.json"))
            .unwrap()
            .policy;
        c.notify = None;
        let usage = BTreeMap::from([("com.instagram.android".to_string(), 1500)]);
        let prev = NotifyState::default();
        // Mon 21:55: social at 83 % and downtime in 5 min, but notifications are off.
        let (n, st) = notify_step(&c, 1792439700, &usage, &prev);
        assert!(n.is_empty());
        assert_eq!(st, prev);
    }

    #[test]
    fn status_reports_thresholds_reached() {
        let v: Vectors = serde_json::from_str(include_str!("../spec/vectors.json")).unwrap();
        // Mon 16:00, social 1500 s of 1800 s (83 %), video budget 0.
        let usage = BTreeMap::from([("com.instagram.android".to_string(), 1500)]);
        let s = status(&v.policy, 1792418400, &usage);
        let social = s.limits.iter().find(|l| l.name == "social").unwrap();
        assert_eq!(
            (social.notify_at.clone(), social.reached.clone()),
            (vec![50, 80, 95], vec![50, 80])
        );
        let video = s.limits.iter().find(|l| l.name == "video").unwrap();
        assert_eq!(
            (video.notify_at.clone(), video.reached.clone()),
            (vec![90], vec![])
        );
        let audio = s.limits.iter().find(|l| l.name == "audio").unwrap();
        assert!(audio.notify_at.is_empty() && audio.reached.is_empty());
    }

    #[test]
    fn vectors_policy_matches_example_yaml() {
        // spec/vectors.json embeds the compiled form of spec/vectors-policy.yaml;
        // keep them in sync (regenerate with `kidctl compile`).
        let y = include_str!("../spec/vectors-policy.yaml");
        let o = include_str!("../spec/vectors-overrides.yaml");
        let c = crate::policy::compile(y, Some(o), 0).unwrap();
        let v: Vectors = serde_json::from_str(include_str!("../spec/vectors.json")).unwrap();
        assert_eq!(c, v.policy);
    }
}
