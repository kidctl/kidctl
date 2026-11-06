//! MCP write tools: every rule of a child can be changed by talking to
//! Claude, and every change is a git commit pushed to the infra repo (see
//! [`crate::gitops`]): never an edit of the server's config directory,
//! SQLite, or the phones.
//!
//! The structured tools (`approve_app`, `block_app`, `add_override`...) are
//! planned here as [`yamledit::Edit`]s on the current file text and applied
//! with comments and layout preserved ([`yamledit::apply_verified`]);
//! `write_policy` replaces a whole file (with an optimistic-concurrency
//! revision check) and covers anything else, including fields added later.
//! Every write tool has `dry_run` (diff + validation, nothing committed).
//!
//! Offered only on the OAuth endpoint (`/mcp`, owner password typed), and
//! only when GitOps is configured (`KIDCTL_GITOPS_REMOTE`).

use crate::config::now_epoch;
use crate::gitops::{self, Change, EditFn, Edited, FileKind, Files, Outcome};
use crate::mcp::{Requester, Server};
use crate::policy::{self, OverridesFile, PolicyFile};
use crate::yamledit::{self, Edit, Seg, key};
use chrono::TimeZone;
use rmcp::{handler::server::wrapper::Parameters, model::Extensions, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value as Y};
use std::collections::BTreeMap;

// ------------------------------------------------------------ arguments

#[derive(Deserialize, JsonSchema)]
pub struct SourceArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// "policy" (<child>.yaml, the rules) or "overrides" (<child>.overrides.yaml, temporary exceptions).
    pub file: FileKind,
}

#[derive(Deserialize, JsonSchema, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum OverrideKind {
    /// Extra time on one limit (`limit`) or on every limit.
    Extra,
    /// Block every app except always_allowed (homework, dinner...); `screen: true` also keeps the screen locked.
    Lock,
    /// Lift downtime and limits (blocked and unapproved apps stay blocked).
    Unlock,
}

#[derive(Deserialize, JsonSchema)]
pub struct AddOverrideArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// extra | lock | unlock.
    pub kind: OverrideKind,
    /// kind=extra: the extra time, e.g. "30m", "1h15m".
    pub extra: Option<String>,
    /// kind=extra: the limit name it applies to (see `policy`); omit for every limit.
    pub limit: Option<String>,
    /// kind=lock: also keep the screen itself locked (emergency calls stay possible).
    pub screen: Option<bool>,
    /// Optional start; default now. Local time in the child's timezone ("2026-10-31T18:00"), RFC 3339, or relative to now ("+2h").
    pub from: Option<String>,
    /// Required end, same formats as `from` (e.g. "2026-10-24T23:00" or "+30m"). Must be in the future.
    pub until: String,
    /// Optional note (why), kept in the file.
    pub note: Option<String>,
    /// Preview only: return the diff and the validation result, commit nothing.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RemoveOverrideArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// 0-based position in the `overrides` list (as shown by policy_source).
    pub index: Option<usize>,
    /// Or: text that identifies exactly one entry (case-insensitive substring of the entry, e.g. its note or "lock").
    #[serde(rename = "match")]
    pub matching: Option<String>,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ChildDryRun {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ApproveArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Android package name (MCP `apps` lists the installed ones), e.g. "com.duolingo".
    pub package: String,
    /// Where the app goes (it is first taken out of blocked, approved, always_allowed, every limit's apps and every "*" limit's exclude):
    /// "approved" (allowed, counts in "*" limits, not in downtime);
    /// "always_allowed" (never limited, usable even in downtime and during a lock);
    /// "limit:<name>" (counted in that limit's budget, e.g. "limit:social"; a "*" limit approves it);
    /// "unlimited_outside_downtime" (approved and excluded from every "*" limit: no budget, but downtime applies).
    pub mode: String,
    /// With "limit:<name>": also exclude the app from the "*" limits, so only that limit counts it.
    pub exclude_from_wildcard: Option<bool>,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PackageArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Android package name, e.g. "com.zhiliaoapp.musically".
    pub package: String,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetLimitArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Limit name. Existing: only the given fields change. New: `apps` and `daily` are required.
    pub name: String,
    /// Packages counted in this limit (the full list), or ["*"] for every app not always_allowed/excluded.
    pub apps: Option<Vec<String>>,
    /// With apps ["*"]: packages not counted (the full list; [] removes it).
    pub exclude: Option<Vec<String>>,
    /// Daily budgets (the full map): keys mon..sun, weekdays, weekend, default (most specific wins; every day must get a value);
    /// values are durations as strings: "1h30m", "45m", "90s", "0" (0 = blocked that day). E.g. {"weekdays": "1h", "weekend": "1h30m"}.
    pub daily: Option<BTreeMap<String, String>>,
    /// Notification thresholds for this limit, in % of its budget (integers 1..99, ascending), e.g. [80, 95]; [] = no notification
    /// for this limit; null = remove, back to the policy's notify.quota_at. Needs `notify:` in the policy (turn it on with write_policy).
    #[serde(default, deserialize_with = "present")]
    pub notify_at: Option<Option<Vec<i64>>>,
    /// Preview only.
    pub dry_run: Option<bool>,
}

/// A field that may be absent (outer None), null (Some(None)) or set.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Deserialize, JsonSchema, Clone)]
pub struct Window {
    /// "HH:MM", local time.
    pub start: String,
    /// "HH:MM"; may be before start (crosses midnight).
    pub end: String,
    /// Days the window STARTS on (mon..sun); omit for every day.
    pub days: Option<Vec<String>>,
    /// Also keep the screen itself locked during the window.
    pub lock_screen: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetDowntimeArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// The complete list of downtime windows (replaces the current list; [] = no downtime). Only always_allowed apps work during downtime.
    pub windows: Vec<Window>,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetDeviceArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// A `device:` field (docs/POLICY.md): restrictions, uninstall_blocked, user_control_disabled, hidden, camera_disabled, screen_capture_disabled,
    /// auto_system_updates, location_always_on, permitted_accessibility_services, permitted_input_methods, always_on_vpn,
    /// private_dns, lock_screen_info, support_message, organization_name, wifi_ssids, default_apps, app_config.
    pub field: String,
    /// New value as JSON, e.g. true, "Famille", ["no_factory_reset", "no_safe_boot"], {"mode": "host", "host": "dns.example.net"},
    /// {"allow": ["HomeNet"]}, {"launcher": "com.google.android.apps.nexuslauncher"},
    /// {"com.tailscale.ipn": {"ForceEnabled": true, "Hostname": "phone"}} (app_config: every package with all its keys).
    /// Lists and mappings replace the whole value. null removes the field (Android's default comes back).
    pub value: serde_json::Value,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct WritePolicyArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// "policy" or "overrides".
    pub file: FileKind,
    /// The complete new file content (YAML). Keep the existing comments.
    pub yaml: String,
    /// The `revision` policy_source returned for this file: refused if the file changed since (read it again).
    pub base_revision: String,
    /// Preview only.
    pub dry_run: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ValidatePolicyArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// "policy" or "overrides".
    pub file: FileKind,
    /// The complete candidate file content (YAML).
    pub yaml: String,
}

// ------------------------------------------------------------- planners

fn parse_policy(text: &str) -> Result<PolicyFile, String> {
    serde_yaml_ng::from_str(text).map_err(|e| {
        format!("the current policy file does not parse ({e}); fix it with write_policy")
    })
}

fn parse_overrides(text: &str) -> Result<Option<OverridesFile>, String> {
    serde_yaml_ng::from_str(text).map_err(|e| {
        format!("the current overrides file does not parse ({e}); fix it with write_policy")
    })
}

fn apply_policy(text: &str, edits: &[Edit]) -> Result<String, String> {
    if edits.is_empty() {
        return Ok(text.to_string());
    }
    yamledit::apply_verified::<PolicyFile>(text, edits).map_err(|e| e.to_string())
}

fn apply_overrides(text: &str, edits: &[Edit]) -> Result<String, String> {
    if edits.is_empty() {
        return Ok(text.to_string());
    }
    yamledit::apply_verified::<Option<OverridesFile>>(text, edits).map_err(|e| e.to_string())
}

fn ylist(v: &[String]) -> Y {
    Y::Sequence(v.iter().map(|s| Y::String(s.clone())).collect())
}

fn path(parts: &[Seg]) -> Vec<Seg> {
    parts.to_vec()
}

fn check_package(pkg: &str) -> Result<(), String> {
    if pkg != "*" && policy::valid_package(pkg) {
        Ok(())
    } else {
        Err(format!(
            "{pkg:?} is not an Android package name (e.g. com.duolingo); MCP `apps` lists the installed ones"
        ))
    }
}

#[derive(Debug, PartialEq)]
enum Mode {
    Approved,
    AlwaysAllowed,
    Unlimited,
    Limit(String),
}

fn parse_mode(m: &str) -> Result<Mode, String> {
    match m.trim() {
        "approved" => Ok(Mode::Approved),
        "always_allowed" => Ok(Mode::AlwaysAllowed),
        "unlimited_outside_downtime" => Ok(Mode::Unlimited),
        s => match s.strip_prefix("limit:") {
            Some(n) if !n.trim().is_empty() => Ok(Mode::Limit(n.trim().to_string())),
            _ => Err(format!(
                "mode {m:?}: use approved, always_allowed, limit:<name> or unlimited_outside_downtime"
            )),
        },
    }
}

fn is_wild(l: &policy::LimitIn) -> bool {
    l.apps.iter().any(|a| a == "*")
}

/// `approve_app`: put `pkg` in exactly one place (see [`ApproveArgs::mode`]).
pub fn plan_approve(
    text: &str,
    pkg: &str,
    mode: &str,
    exclude_from_wildcard: bool,
) -> Result<Edited, String> {
    check_package(pkg)?;
    let mode = parse_mode(mode)?;
    let p = parse_policy(text)?;
    let without = |l: &[String]| l.iter().filter(|x| *x != pkg).cloned().collect::<Vec<_>>();
    let blocked = without(&p.blocked);
    let mut approved = without(&p.approved);
    let mut always = without(&p.always_allowed);
    let mut apps: Vec<Vec<String>> = p
        .limits
        .iter()
        .map(|l| {
            if is_wild(l) {
                l.apps.clone()
            } else {
                without(&l.apps)
            }
        })
        .collect();
    let mut excl: Vec<Vec<String>> = p.limits.iter().map(|l| without(&l.exclude)).collect();
    let wild: Vec<usize> = (0..p.limits.len())
        .filter(|&j| is_wild(&p.limits[j]))
        .collect();
    let summary = match &mode {
        Mode::Approved => {
            approved.push(pkg.into());
            format!("approve {pkg}")
        }
        Mode::AlwaysAllowed => {
            always.push(pkg.into());
            format!("always allow {pkg}")
        }
        Mode::Unlimited => {
            approved.push(pkg.into());
            for &j in &wild {
                excl[j].push(pkg.into());
            }
            format!("approve {pkg}, unlimited outside downtime")
        }
        Mode::Limit(name) => {
            let j = p
                .limits
                .iter()
                .position(|l| &l.name == name)
                .ok_or_else(|| {
                    format!(
                        "no limit named {name:?}; limits: {:?}",
                        p.limits.iter().map(|l| &l.name).collect::<Vec<_>>()
                    )
                })?;
            if is_wild(&p.limits[j]) {
                approved.push(pkg.into());
            } else {
                apps[j].push(pkg.into());
            }
            if exclude_from_wildcard {
                for &k in wild.iter().filter(|&&k| k != j) {
                    excl[k].push(pkg.into());
                }
            }
            format!(
                "approve {pkg} in limit {name}{}",
                if exclude_from_wildcard { " only" } else { "" }
            )
        }
    };
    let mut edits = Vec::new();
    for (k, old, new) in [
        ("blocked", &p.blocked, &blocked),
        ("approved", &p.approved, &approved),
        ("always_allowed", &p.always_allowed, &always),
    ] {
        if old != new {
            edits.push(Edit::Set(vec![key(k)], ylist(new)));
        }
    }
    for (j, l) in p.limits.iter().enumerate() {
        if l.apps != apps[j] {
            edits.push(Edit::Set(
                path(&[key("limits"), Seg::Index(j), key("apps")]),
                ylist(&apps[j]),
            ));
        }
        if l.exclude != excl[j] {
            let v = if excl[j].is_empty() {
                Y::Null
            } else {
                ylist(&excl[j])
            };
            edits.push(Edit::Set(
                path(&[key("limits"), Seg::Index(j), key("exclude")]),
                v,
            ));
        }
    }
    Ok(Edited {
        text: apply_policy(text, &edits)?,
        summary,
    })
}

/// `block_app`: add to `blocked` (and out of `always_allowed`, which
/// conflicts); the app's other placements stay, so `unblock_app` restores
/// exactly what was there before.
pub fn plan_block(text: &str, pkg: &str) -> Result<Edited, String> {
    check_package(pkg)?;
    let p = parse_policy(text)?;
    let mut edits = Vec::new();
    if !p.blocked.iter().any(|x| x == pkg) {
        let mut b = p.blocked.clone();
        b.push(pkg.into());
        edits.push(Edit::Set(vec![key("blocked")], ylist(&b)));
    }
    if p.always_allowed.iter().any(|x| x == pkg) {
        let a: Vec<String> = p
            .always_allowed
            .iter()
            .filter(|x| *x != pkg)
            .cloned()
            .collect();
        edits.push(Edit::Set(vec![key("always_allowed")], ylist(&a)));
    }
    Ok(Edited {
        text: apply_policy(text, &edits)?,
        summary: format!("block {pkg}"),
    })
}

pub fn plan_unblock(text: &str, pkg: &str) -> Result<Edited, String> {
    check_package(pkg)?;
    let p = parse_policy(text)?;
    if !p.blocked.iter().any(|x| x == pkg) {
        return Err(format!(
            "{pkg} is not in blocked (blocked: {:?})",
            p.blocked
        ));
    }
    let b: Vec<String> = p.blocked.iter().filter(|x| *x != pkg).cloned().collect();
    let text = apply_policy(text, &[Edit::Set(vec![key("blocked")], ylist(&b))])?;
    let note = if p.approval && !named_elsewhere(&p, pkg) {
        " (approval is on and it is named nowhere else: a user-installed app stays suspended until approved)"
    } else {
        ""
    };
    Ok(Edited {
        text,
        summary: format!("unblock {pkg}{note}"),
    })
}

fn named_elsewhere(p: &PolicyFile, pkg: &str) -> bool {
    let s = pkg.to_string();
    p.approved.contains(&s)
        || p.always_allowed.contains(&s)
        || p.limits
            .iter()
            .any(|l| l.apps.contains(&s) || l.exclude.contains(&s))
}

const DAY_ORDER: [&str; 10] = [
    "mon", "tue", "wed", "thu", "fri", "sat", "sun", "weekdays", "weekend", "default",
];

fn daily_value(daily: &BTreeMap<String, String>) -> Y {
    let mut m = Mapping::new();
    let rank = |k: &str| {
        DAY_ORDER
            .iter()
            .position(|d| *d == k)
            .unwrap_or(DAY_ORDER.len())
    };
    let mut keys: Vec<&String> = daily.keys().collect();
    keys.sort_by_key(|k| (rank(k), (*k).clone()));
    for k in keys {
        m.insert(Y::String(k.clone()), Y::String(daily[k].trim().to_string()));
    }
    Y::Mapping(m)
}

pub fn plan_set_limit(
    text: &str,
    name: &str,
    apps: Option<&[String]>,
    exclude: Option<&[String]>,
    daily: Option<&BTreeMap<String, String>>,
    notify_at: Option<Option<&[i64]>>,
) -> Result<Edited, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("limit name is empty".into());
    }
    let p = parse_policy(text)?;
    let mut edits = Vec::new();
    let summary;
    if let Some(j) = p.limits.iter().position(|l| l.name == name) {
        let at = |f: &str| path(&[key("limits"), Seg::Index(j), key(f)]);
        if apps.is_none() && exclude.is_none() && daily.is_none() && notify_at.is_none() {
            return Err("give apps, exclude, daily and/or notify_at".into());
        }
        if let Some(a) = apps {
            edits.push(Edit::Set(at("apps"), ylist(a)));
        }
        if let Some(e) = exclude {
            edits.push(Edit::Set(
                at("exclude"),
                if e.is_empty() { Y::Null } else { ylist(e) },
            ));
        }
        if let Some(d) = daily {
            edits.push(Edit::Set(at("daily"), daily_value(d)));
        }
        if let Some(n) = notify_at {
            // Replace, not Set: the thresholds' order matters (ascending).
            edits.push(Edit::Replace(
                at("notify_at"),
                n.map_or(Y::Null, thresholds_value),
            ));
        }
        summary = describe_limit("set limit", name, apps, exclude, daily, notify_at);
    } else {
        let (Some(a), Some(d)) = (apps, daily) else {
            return Err(format!(
                "no limit named {name:?} (limits: {:?}); a new limit needs apps and daily",
                p.limits.iter().map(|l| &l.name).collect::<Vec<_>>()
            ));
        };
        let mut m = Mapping::new();
        m.insert(Y::String("name".into()), Y::String(name.into()));
        m.insert(Y::String("apps".into()), ylist(a));
        if let Some(e) = exclude.filter(|e| !e.is_empty()) {
            m.insert(Y::String("exclude".into()), ylist(e));
        }
        m.insert(Y::String("daily".into()), daily_value(d));
        if let Some(Some(n)) = notify_at {
            m.insert(Y::String("notify_at".into()), thresholds_value(n));
        }
        edits.push(Edit::Push(vec![key("limits")], Y::Mapping(m)));
        summary = describe_limit("new limit", name, apps, exclude, daily, notify_at);
    }
    Ok(Edited {
        text: apply_policy(text, &edits)?,
        summary,
    })
}

fn thresholds_value(v: &[i64]) -> Y {
    Y::Sequence(v.iter().map(|&t| Y::Number(t.into())).collect())
}

fn describe_limit(
    what: &str,
    name: &str,
    apps: Option<&[String]>,
    exclude: Option<&[String]>,
    daily: Option<&BTreeMap<String, String>>,
    notify_at: Option<Option<&[i64]>>,
) -> String {
    let mut s = format!("{what} {name}");
    if let Some(d) = daily {
        s.push_str(&format!(" daily {}", yamledit::flow(&daily_value(d))));
    }
    if let Some(a) = apps {
        s.push_str(&format!(" apps {}", yamledit::flow(&ylist(a))));
    }
    if let Some(e) = exclude {
        s.push_str(&format!(" exclude {}", yamledit::flow(&ylist(e))));
    }
    match notify_at {
        Some(Some(n)) => s.push_str(&format!(
            " notify_at {}",
            yamledit::flow(&thresholds_value(n))
        )),
        Some(None) => s.push_str(" notify_at default"),
        None => {}
    }
    s
}

pub fn plan_set_downtime(text: &str, windows: &[Window]) -> Result<Edited, String> {
    let p = parse_policy(text)?;
    let list: Vec<Y> = windows
        .iter()
        .map(|w| {
            let mut m = Mapping::new();
            m.insert(Y::String("start".into()), Y::String(w.start.trim().into()));
            m.insert(Y::String("end".into()), Y::String(w.end.trim().into()));
            if let Some(d) = &w.days {
                m.insert(Y::String("days".into()), ylist(d));
            }
            if w.lock_screen == Some(true) {
                m.insert(Y::String("lock_screen".into()), Y::Bool(true));
            }
            Y::Mapping(m)
        })
        .collect();
    let edits = if list.is_empty() && p.downtime.is_empty() {
        vec![]
    } else {
        vec![Edit::Set(vec![key("downtime")], Y::Sequence(list.clone()))]
    };
    let summary = if list.is_empty() {
        "no downtime".to_string()
    } else {
        format!("downtime {}", yamledit::flow(&Y::Sequence(list)))
    };
    Ok(Edited {
        text: apply_policy(text, &edits)?,
        summary,
    })
}

pub fn plan_set_device(
    text: &str,
    field: &str,
    value: &serde_json::Value,
) -> Result<Edited, String> {
    if field.is_empty() || !field.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
        return Err(format!(
            "field {field:?}: a device: key such as camera_disabled or wifi_ssids"
        ));
    }
    parse_policy(text)?;
    let mut v: Y = serde_yaml_ng::to_value(value).map_err(|e| e.to_string())?;
    // JSON objects arrive with sorted keys: write them in the documented order.
    let order: &[&str] = match field {
        "private_dns" => &["mode", "host"],
        "always_on_vpn" => &["package", "lockdown"],
        "wifi_ssids" => &["allow", "deny"],
        "default_apps" => &["launcher", "browser"],
        _ => &[],
    };
    if let Y::Mapping(m) = &mut v {
        let mut sorted = Mapping::new();
        for k in order {
            if let Some(x) = m.shift_remove(*k) {
                sorted.insert(Y::String((*k).into()), x);
            }
        }
        for (k, x) in std::mem::take(m) {
            sorted.insert(k, x);
        }
        *m = sorted;
    }
    let summary = if v.is_null() {
        format!("remove device.{field}")
    } else {
        format!("device.{field} = {}", yamledit::flow(&v))
    };
    Ok(Edited {
        text: apply_policy(text, &[Edit::Set(vec![key("device"), key(field)], v)])?,
        summary,
    })
}

/// "+30m" (relative to now, rounded up to the minute) -> local
/// "YYYY-MM-DDTHH:MM" in `tz`; anything else unchanged.
fn resolve_instant(s: &str, tz: chrono_tz::Tz, now: i64) -> Result<String, String> {
    let s = s.trim();
    let Some(d) = s.strip_prefix('+') else {
        return Ok(s.to_string());
    };
    let secs = policy::parse_duration(d)? as i64;
    let t = (now + secs + 59) / 60 * 60;
    let local = tz.timestamp_opt(t, 0).single().ok_or("time out of range")?;
    Ok(local.format("%Y-%m-%dT%H:%M").to_string())
}

fn local(tz: chrono_tz::Tz, t: i64) -> String {
    tz.timestamp_opt(t, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

pub struct OverrideSpec<'a> {
    pub kind: OverrideKind,
    pub extra: Option<&'a str>,
    pub limit: Option<&'a str>,
    pub screen: bool,
    pub from: Option<&'a str>,
    pub until: &'a str,
    pub note: Option<&'a str>,
}

pub fn plan_add_override(
    policy_text: &str,
    overrides_text: &str,
    o: &OverrideSpec,
    now: i64,
) -> Result<Edited, String> {
    let p = parse_policy(policy_text)?;
    parse_overrides(overrides_text)?;
    let tz: chrono_tz::Tz = p
        .timezone
        .parse()
        .map_err(|_| format!("policy timezone {:?} is invalid", p.timezone))?;
    let until = resolve_instant(o.until, tz, now)?;
    let until_t = policy::parse_instant(&until, tz)?;
    if until_t <= now {
        return Err(format!(
            "until {until} is already past (now {} in {tz})",
            local(tz, now)
        ));
    }
    let from = o.from.map(|f| resolve_instant(f, tz, now)).transpose()?;
    let mut m = Mapping::new();
    let mut put = |k: &str, v: Y| {
        m.insert(Y::String(k.into()), v);
    };
    match o.kind {
        OverrideKind::Extra => {
            let e = o.extra.ok_or("kind extra needs `extra` (e.g. \"30m\")")?;
            policy::parse_duration(e)?;
            if o.screen {
                return Err("screen only applies to kind lock".into());
            }
            put("extra", Y::String(e.trim().into()));
            if let Some(l) = o.limit {
                put("limit", Y::String(l.trim().into()));
            }
        }
        OverrideKind::Lock | OverrideKind::Unlock => {
            if o.extra.is_some() || o.limit.is_some() {
                return Err("extra and limit only apply to kind extra".into());
            }
            if o.kind == OverrideKind::Unlock && o.screen {
                return Err("screen only applies to kind lock".into());
            }
            put(
                if o.kind == OverrideKind::Lock {
                    "lock"
                } else {
                    "unlock"
                },
                Y::Bool(true),
            );
            if o.screen {
                put("screen", Y::Bool(true));
            }
        }
    }
    if let Some(f) = &from {
        put("from", Y::String(f.clone()));
    }
    put("until", Y::String(until.clone()));
    if let Some(n) = o.note.map(str::trim).filter(|n| !n.is_empty()) {
        put("note", Y::String(n.into()));
    }
    let entry = Y::Mapping(m);
    let summary = format!("add override {}", yamledit::flow(&entry));
    Ok(Edited {
        text: apply_overrides(overrides_text, &[Edit::Push(vec![key("overrides")], entry)])?,
        summary,
    })
}

fn override_entries(overrides_text: &str) -> Result<Vec<Y>, String> {
    parse_overrides(overrides_text)?;
    let v = yamledit::parse(overrides_text)?;
    Ok(match v.get("overrides") {
        Some(Y::Sequence(q)) => q.clone(),
        _ => vec![],
    })
}

pub fn plan_remove_override(
    overrides_text: &str,
    index: Option<usize>,
    matching: Option<&str>,
) -> Result<Edited, String> {
    let entries = override_entries(overrides_text)?;
    let listing = || {
        entries
            .iter()
            .enumerate()
            .map(|(i, e)| format!("[{i}] {}", yamledit::flow(e)))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let i = match (index, matching.map(str::trim).filter(|m| !m.is_empty())) {
        (Some(i), None) => {
            if i >= entries.len() {
                return Err(format!(
                    "no override at index {i}; overrides: {}",
                    if entries.is_empty() {
                        "none".into()
                    } else {
                        listing()
                    }
                ));
            }
            i
        }
        (None, Some(m)) => {
            let m = m.to_lowercase();
            let hits: Vec<usize> = (0..entries.len())
                .filter(|&i| yamledit::flow(&entries[i]).to_lowercase().contains(&m))
                .collect();
            match hits.as_slice() {
                [i] => *i,
                [] => {
                    return Err(format!(
                        "no override matches {m:?}; overrides: {}",
                        if entries.is_empty() {
                            "none".into()
                        } else {
                            listing()
                        }
                    ));
                }
                _ => {
                    return Err(format!(
                        "{} overrides match {m:?}, give the index: {}",
                        hits.len(),
                        listing()
                    ));
                }
            }
        }
        _ => return Err("give exactly one of index or match".into()),
    };
    let summary = format!("remove override {}", yamledit::flow(&entries[i]));
    Ok(Edited {
        text: apply_overrides(
            overrides_text,
            &[Edit::Remove(vec![key("overrides"), Seg::Index(i)])],
        )?,
        summary,
    })
}

pub fn plan_prune(policy_text: &str, overrides_text: &str, now: i64) -> Result<Edited, String> {
    let p = parse_policy(policy_text)?;
    let tz: chrono_tz::Tz = p
        .timezone
        .parse()
        .map_err(|_| format!("policy timezone {:?} is invalid", p.timezone))?;
    let entries = override_entries(overrides_text)?;
    let expired: Vec<usize> = (0..entries.len())
        .filter(|&i| {
            entries[i]
                .get("until")
                .and_then(Y::as_str)
                .and_then(|u| policy::parse_instant(u, tz).ok())
                .is_some_and(|u| u <= now)
        })
        .collect();
    let edits: Vec<Edit> = expired
        .iter()
        .rev()
        .map(|&i| Edit::Remove(vec![key("overrides"), Seg::Index(i)]))
        .collect();
    let summary = if expired.is_empty() {
        "prune expired overrides (none)".to_string()
    } else {
        format!(
            "prune {} expired override(s): {}",
            expired.len(),
            expired
                .iter()
                .map(|&i| yamledit::flow(&entries[i]))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Ok(Edited {
        text: apply_overrides(overrides_text, &edits)?,
        summary,
    })
}

// ---------------------------------------------------------------- tools

fn requester(ext: &Extensions) -> String {
    ext.get::<axum::http::request::Parts>()
        .and_then(|p| p.extensions.get::<Requester>())
        .map(Requester::describe)
        .unwrap_or_else(|| "unknown MCP client".into())
}

fn text_of(f: &Files, which: FileKind) -> Result<&str, String> {
    f.get(which)
        .text
        .as_deref()
        .ok_or_else(|| format!("{} does not exist", which.file_name(&f.child)))
}

const DEPLOY_NOTE: &str = "Phones apply it within about 2-3 minutes (ArgoCD polls git every 60 s, ConfigMap refresh, server reload, then the phones' 1-minute sync).";

impl Server {
    fn report(&self, child: &str, o: &Outcome, dry_run: bool) -> String {
        let served = self
            .st
            .store
            .get()
            .compiled(child, now_epoch())
            .and_then(Result::ok)
            .map(|c| policy::version(&c))
            .unwrap_or_else(|| "none".into());
        let branch = self
            .gitops
            .as_ref()
            .map(|g| g.config().branch.clone())
            .unwrap_or_default();
        let mut out = match (&o.commit, dry_run) {
            (_, true) if o.diff.is_empty() => {
                format!("dry run: nothing to change ({}).\n", o.summary)
            }
            (_, true) => format!(
                "dry run, valid, nothing committed: {}\npolicy version it would produce: {} (served now: {served})\n",
                o.summary, o.version
            ),
            (None, false) => format!(
                "nothing to change ({}): the file already says that. Served version: {served}.\n",
                o.summary
            ),
            (Some(c), false) => format!(
                "committed {} on {branch}{}: {}\npolicy version it will produce: {} (served now: {served}). {DEPLOY_NOTE} \
                 Check with `policy` that version {} is served.\n",
                &c[..12.min(c.len())],
                if o.retried {
                    " (re-applied after a concurrent push)"
                } else {
                    ""
                },
                o.summary,
                o.version,
                o.version
            ),
        };
        if !o.diff.is_empty() {
            out.push('\n');
            out.push_str(&o.diff);
        }
        out
    }

    async fn write(
        &self,
        ext: &Extensions,
        tool: &str,
        child: &str,
        file: FileKind,
        dry_run: Option<bool>,
        edit: Box<EditFn>,
    ) -> Result<String, String> {
        let g = self
            .gitops
            .as_ref()
            .ok_or("GitOps writes are not configured on this server")?;
        let who = requester(ext);
        let dry = dry_run.unwrap_or(false);
        let c = Change {
            tool: tool.into(),
            child: child.into(),
            file,
            requested_by: who.clone(),
            dry_run: dry,
            edit,
        };
        let o = g.change(c).await?;
        if o.commit.is_some() {
            eprintln!(
                "mcp write: {tool} {child} by {}",
                gitops::one_line(&who, 120)
            );
        }
        Ok(self.report(child, &o, dry))
    }
}

#[tool_router(router = write_router, vis = "pub(crate)")]
impl Server {
    #[tool(
        description = "Read a child's policy file (<child>.yaml) or overrides file (<child>.overrides.yaml) exactly as it is in the GitOps repo now (with comments), with its revision (needed by write_policy) and the repo commit."
    )]
    async fn policy_source(&self, Parameters(a): Parameters<SourceArgs>) -> Result<String, String> {
        let g = self.gitops.as_ref().ok_or("GitOps is not configured")?;
        let f = g.read(&a.child).await?;
        let s = f.get(a.file);
        let name = a.file.file_name(&a.child);
        Ok(match &s.text {
            Some(t) => format!(
                "file: {name}\nrevision: {}\ncommit: {}\n---\n{t}",
                s.revision, f.commit
            ),
            None => format!(
                "file: {name}\nrevision: {}\ncommit: {}\n(the file does not exist)",
                s.revision, f.commit
            ),
        })
    }

    #[tool(
        description = "Add a temporary exception for a child (committed to the GitOps repo): kind=extra (extra time on one limit or all, e.g. \"30 more minutes tonight\"), kind=lock (only always_allowed apps until `until`; screen=true also keeps the screen locked), kind=unlock (no downtime/limits until `until`). Times: local \"2026-10-24T23:00\", RFC 3339, or \"+30m\" from now."
    )]
    async fn add_override(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<AddOverrideArgs>,
    ) -> Result<String, String> {
        let now = now_epoch();
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| {
            let spec = OverrideSpec {
                kind: a.kind,
                extra: a.extra.as_deref(),
                limit: a.limit.as_deref(),
                screen: a.screen.unwrap_or(false),
                from: a.from.as_deref(),
                until: &a.until,
                note: a.note.as_deref(),
            };
            plan_add_override(
                text_of(f, FileKind::Policy)?,
                text_of(f, FileKind::Overrides)?,
                &spec,
                now,
            )
        };
        self.write(
            &ext,
            "add_override",
            &child,
            FileKind::Overrides,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Remove one temporary exception of a child, by index (0-based, see policy_source) or by `match` (text identifying exactly one entry, e.g. its note)."
    )]
    async fn remove_override(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<RemoveOverrideArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| {
            plan_remove_override(
                text_of(f, FileKind::Overrides)?,
                a.index,
                a.matching.as_deref(),
            )
        };
        self.write(
            &ext,
            "remove_override",
            &child,
            FileKind::Overrides,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Delete a child's expired temporary exceptions (until in the past) from the overrides file."
    )]
    async fn prune_overrides(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<ChildDryRun>,
    ) -> Result<String, String> {
        let now = now_epoch();
        let edit = move |f: &Files| {
            plan_prune(
                text_of(f, FileKind::Policy)?,
                text_of(f, FileKind::Overrides)?,
                now,
            )
        };
        self.write(
            &ext,
            "prune_overrides",
            &a.child,
            FileKind::Overrides,
            a.dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Allow an app for a child (committed to the GitOps repo). mode: approved | always_allowed | limit:<name> | unlimited_outside_downtime. The app is first taken out of blocked, approved, always_allowed and every limit, so it ends up in exactly that place. Use `apps` to find the package name."
    )]
    async fn approve_app(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<ApproveArgs>,
    ) -> Result<String, String> {
        let excl = a.exclude_from_wildcard.unwrap_or(false);
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit =
            move |f: &Files| plan_approve(text_of(f, FileKind::Policy)?, &a.package, &a.mode, excl);
        self.write(
            &ext,
            "approve_app",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Block an app for a child (never usable; committed to the GitOps repo). Its other settings stay, so unblock_app restores them."
    )]
    async fn block_app(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<PackageArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| plan_block(text_of(f, FileKind::Policy)?, &a.package);
        self.write(
            &ext,
            "block_app",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Remove an app from a child's blocked list (committed to the GitOps repo)."
    )]
    async fn unblock_app(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<PackageArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| plan_unblock(text_of(f, FileKind::Policy)?, &a.package);
        self.write(
            &ext,
            "unblock_app",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Create or change a daily time limit of a child (committed to the GitOps repo): apps (full list, or [\"*\"]), exclude (with \"*\"), daily budgets per day (e.g. {\"weekdays\": \"1h\", \"weekend\": \"1h30m\"}), notification thresholds notify_at (e.g. [80, 95]; needs notify: in the policy). Only the fields given change. An app must have budget left in every limit that matches it."
    )]
    async fn set_limit(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<SetLimitArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| {
            let notify_at = a.notify_at.as_ref().map(|n| n.as_deref());
            plan_set_limit(
                text_of(f, FileKind::Policy)?,
                &a.name,
                a.apps.as_deref(),
                a.exclude.as_deref(),
                a.daily.as_ref(),
                notify_at,
            )
        };
        self.write(
            &ext,
            "set_limit",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Set a child's downtime windows (the complete list; committed to the GitOps repo). During downtime only always_allowed apps work; lock_screen=true also keeps the screen locked."
    )]
    async fn set_downtime(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<SetDowntimeArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit = move |f: &Files| plan_set_downtime(text_of(f, FileKind::Policy)?, &a.windows);
        self.write(
            &ext,
            "set_downtime",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Set one device setting of a child (device.<field> in the policy; committed to the GitOps repo): restrictions, hidden apps, uninstall_blocked, user_control_disabled (no force stop / clear storage), camera_disabled, wifi_ssids, default_apps, organization_name, lock_screen_info, private_dns, always_on_vpn... value null removes it. See docs/POLICY.md for each field."
    )]
    async fn set_device(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<SetDeviceArgs>,
    ) -> Result<String, String> {
        let (child, dry_run) = (a.child.clone(), a.dry_run);
        let edit =
            move |f: &Files| plan_set_device(text_of(f, FileKind::Policy)?, &a.field, &a.value);
        self.write(
            &ext,
            "set_device",
            &child,
            FileKind::Policy,
            dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Replace a child's whole policy or overrides file (committed to the GitOps repo): the catch-all for any change the other tools do not cover (e.g. the notify: block, which turns screen-time notifications on: notify: {quota_at: [50, 80, 95], before_downtime: 5m, locale: fr}). Read it first with policy_source and pass its revision as base_revision (refused if the file changed since); keep the comments. Validated like `kidctl validate` before committing."
    )]
    async fn write_policy(
        &self,
        ext: Extensions,
        Parameters(a): Parameters<WritePolicyArgs>,
    ) -> Result<String, String> {
        let mut yaml = a.yaml.clone();
        if !yaml.ends_with('\n') {
            yaml.push('\n');
        }
        let (file, base) = (a.file, a.base_revision.trim().to_string());
        let edit = move |f: &Files| {
            let cur = &f.get(file).revision;
            if *cur != base {
                return Err(format!(
                    "{} changed since revision {base} (now {cur}): read it again with policy_source and redo the change",
                    file.file_name(&f.child)
                ));
            }
            Ok(Edited {
                text: yaml.clone(),
                summary: format!("replace {}", file.file_name(&f.child)),
            })
        };
        self.write(
            &ext,
            "write_policy",
            &a.child,
            a.file,
            a.dry_run,
            Box::new(edit),
        )
        .await
    }

    #[tool(
        description = "Check a candidate policy or overrides file against the whole GitOps policies directory, exactly like `kidctl validate`, without committing: returns the errors, or the diff and the policy version it would produce."
    )]
    async fn validate_policy(
        &self,
        Parameters(a): Parameters<ValidatePolicyArgs>,
    ) -> Result<String, String> {
        let g = self.gitops.as_ref().ok_or("GitOps is not configured")?;
        let o = g.validate(&a.child, a.file, &a.yaml).await?;
        Ok(self.report(&a.child, &o, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yamledit::tests::COMMENTED;

    fn compiles(t: &str) {
        policy::compile(t, None, 0).unwrap_or_else(|e| panic!("{e:?}\n{t}"));
    }

    fn p(t: &str) -> PolicyFile {
        parse_policy(t).unwrap()
    }

    #[test]
    fn approve_modes() {
        // approved: out of the general exclude and blocked, into approved.
        let e = plan_approve(COMMENTED, "com.zhiliaoapp.musically", "approved", false).unwrap();
        compiles(&e.text);
        let x = p(&e.text);
        assert!(
            x.blocked.is_empty() && x.approved.contains(&"com.zhiliaoapp.musically".to_string())
        );
        assert!(
            e.text.contains("# Never usable.\nblocked: []\n"),
            "{}",
            e.text
        );
        assert!(e.text.contains("  - com.duolingo                          # Duolingo\n  - com.zhiliaoapp.musically\n"), "{}", e.text);
        // always_allowed: taken out of approved and of the "*" exclude.
        let e = plan_approve(COMMENTED, "com.duolingo", "always_allowed", false).unwrap();
        compiles(&e.text);
        let x = p(&e.text);
        assert!(
            x.always_allowed.contains(&"com.duolingo".into())
                && !x.approved.contains(&"com.duolingo".into())
        );
        assert!(!x.limits[2].exclude.contains(&"com.duolingo".into()));
        assert!(
            e.text.contains(
                "# unlimited outside downtime (see approved):\n              com.example.flow]\n"
            ),
            "{}",
            e.text
        );
        // limit:social: into that limit's apps (counts in general too).
        let e = plan_approve(COMMENTED, "com.example.new", "limit:social", false).unwrap();
        compiles(&e.text);
        assert!(
            p(&e.text).limits[0]
                .apps
                .contains(&"com.example.new".into())
        );
        assert!(
            !p(&e.text).limits[2]
                .exclude
                .contains(&"com.example.new".into())
        );
        let e = plan_approve(COMMENTED, "com.example.new", "limit:video", true).unwrap();
        compiles(&e.text);
        let x = p(&e.text);
        assert!(
            x.limits[1].apps.contains(&"com.example.new".into())
                && x.limits[2].exclude.contains(&"com.example.new".into())
        );
        // limit:general ("*"): approved.
        let e = plan_approve(COMMENTED, "com.example.new", "limit:general", false).unwrap();
        assert!(p(&e.text).approved.contains(&"com.example.new".into()));
        // unlimited outside downtime: approved + excluded from every "*" limit.
        let e = plan_approve(
            COMMENTED,
            "com.netflix.mediaclient",
            "unlimited_outside_downtime",
            false,
        )
        .unwrap();
        compiles(&e.text);
        let x = p(&e.text);
        assert!(x.approved.contains(&"com.netflix.mediaclient".into()));
        assert!(!x.limits[1].apps.contains(&"com.netflix.mediaclient".into()));
        assert!(
            x.limits[2]
                .exclude
                .contains(&"com.netflix.mediaclient".into())
        );
        // Errors.
        assert!(
            plan_approve(COMMENTED, "com.x.y", "limit:nope", false)
                .unwrap_err()
                .contains("no limit named \"nope\"")
        );
        assert!(
            plan_approve(COMMENTED, "com.x.y", "maybe", false)
                .unwrap_err()
                .contains("mode \"maybe\"")
        );
        assert!(
            plan_approve(COMMENTED, "../etc", "approved", false)
                .unwrap_err()
                .contains("not an Android package")
        );
        // Already exactly there: unchanged text.
        assert_eq!(
            plan_approve(
                COMMENTED,
                "com.duolingo",
                "unlimited_outside_downtime",
                false
            )
            .unwrap()
            .text,
            COMMENTED
        );
    }

    #[test]
    fn block_and_unblock_round_trip() {
        let e = plan_block(COMMENTED, "com.example.piano").unwrap();
        compiles(&e.text);
        let x = p(&e.text);
        assert!(
            x.blocked.contains(&"com.example.piano".into())
                && !x.always_allowed.contains(&"com.example.piano".into())
        );
        let e2 = plan_block(COMMENTED, "com.android.chrome").unwrap();
        let back = plan_unblock(&e2.text, "com.android.chrome").unwrap();
        assert_eq!(
            back.text, COMMENTED,
            "block then unblock restores the file byte for byte"
        );
        assert!(back.summary.contains("approval is on"), "{}", back.summary);
        assert!(
            plan_unblock(COMMENTED, "com.android.chrome")
                .unwrap_err()
                .contains("not in blocked")
        );
        assert_eq!(
            plan_block(COMMENTED, "com.zhiliaoapp.musically")
                .unwrap()
                .text,
            COMMENTED
        );
    }

    #[test]
    fn limits_downtime_device() {
        let d: BTreeMap<String, String> = [
            ("weekend".into(), "2h".into()),
            ("weekdays".into(), "1h".into()),
        ]
        .into();
        let e = plan_set_limit(COMMENTED, "social", None, None, Some(&d), None).unwrap();
        compiles(&e.text);
        assert!(
            e.text.contains("    daily: {weekdays: 1h, weekend: 2h}\n"),
            "{}",
            e.text
        );
        assert_eq!(
            e.summary,
            "set limit social daily {weekdays: 1h, weekend: 2h}"
        );
        let e = plan_set_limit(
            COMMENTED,
            "games",
            Some(&["com.mojang.minecraftpe".into()]),
            None,
            Some(&d),
            None,
        )
        .unwrap();
        compiles(&e.text);
        assert!(e.text.contains("  - name: games\n    apps: [com.mojang.minecraftpe]\n    daily: {weekdays: 1h, weekend: 2h}\n"), "{}", e.text);
        assert!(
            plan_set_limit(COMMENTED, "games", None, None, Some(&d), None)
                .unwrap_err()
                .contains("needs apps and daily")
        );
        let e = plan_set_limit(COMMENTED, "general", None, Some(&[]), None, None).unwrap();
        assert!(!e.text.contains("exclude:"), "{}", e.text);
        // notify_at: needs notify: in the policy; replaced as a whole (order matters), [] = none, null = back to quota_at.
        let on = format!("notify: {{}}\n{COMMENTED}");
        let e = plan_set_limit(&on, "video", None, None, None, Some(Some(&[50, 80]))).unwrap();
        compiles(&e.text);
        assert!(
            e.text.contains(
                "    daily: {fri: 2h30m, sat: 2h30m, default: 0}\n    notify_at: [50, 80]\n"
            ),
            "{}",
            e.text
        );
        assert_eq!(e.summary, "set limit video notify_at [50, 80]");
        let e2 = plan_set_limit(
            &e.text,
            "video",
            None,
            None,
            None,
            Some(Some(&[30, 50, 80])),
        )
        .unwrap();
        compiles(&e2.text);
        assert!(
            e2.text.contains("    notify_at: [30, 50, 80]\n"),
            "{}",
            e2.text
        );
        let c = policy::compile(&e2.text, None, 0).unwrap();
        assert_eq!(
            c.limits
                .iter()
                .find(|l| l.name == "video")
                .unwrap()
                .notify_at,
            vec![30, 50, 80]
        );
        let none = plan_set_limit(&e2.text, "video", None, None, None, Some(Some(&[]))).unwrap();
        let c = policy::compile(&none.text, None, 0).unwrap();
        assert!(
            c.limits
                .iter()
                .find(|l| l.name == "video")
                .unwrap()
                .notify_at
                .is_empty()
        );
        let back = plan_set_limit(&e2.text, "video", None, None, None, Some(None)).unwrap();
        assert_eq!(back.text, on);
        assert_eq!(back.summary, "set limit video notify_at default");
        let c = policy::compile(&back.text, None, 0).unwrap();
        assert_eq!(
            c.limits
                .iter()
                .find(|l| l.name == "video")
                .unwrap()
                .notify_at,
            policy::DEFAULT_QUOTA_AT.to_vec()
        );
        let e = plan_set_limit(
            &on,
            "games",
            Some(&["com.mojang.minecraftpe".into()]),
            None,
            Some(&d),
            Some(Some(&[90])),
        )
        .unwrap();
        compiles(&e.text);
        assert!(e.text.contains("  - name: games\n    apps: [com.mojang.minecraftpe]\n    daily: {weekdays: 1h, weekend: 2h}\n    notify_at: [90]\n"), "{}", e.text);
        // Without notify: the edit applies, the validation (compile) refuses it.
        let e = plan_set_limit(COMMENTED, "video", None, None, None, Some(Some(&[80]))).unwrap();
        assert!(policy::compile(&e.text, None, 0).is_err());
        let w = [Window {
            start: "13:00".into(),
            end: "14:00".into(),
            days: Some(vec!["sat".into()]),
            lock_screen: Some(true),
        }];
        let e = plan_set_downtime(COMMENTED, &w).unwrap();
        compiles(&e.text);
        assert!(e.text.contains("downtime:\n  - {start: \"13:00\", end: \"14:00\", days: [sat], lock_screen: true}\n\n"), "{}", e.text);
        let e = plan_set_downtime(COMMENTED, &[]).unwrap();
        assert!(e.text.contains("\ndowntime: []\n"), "{}", e.text);
        let e = plan_set_device(
            COMMENTED,
            "private_dns",
            &serde_json::json!({"mode": "host", "host": "dns.google"}),
        )
        .unwrap();
        compiles(&e.text);
        assert!(e.text.ends_with("  uninstall_blocked: []\n  private_dns: {mode: host, host: dns.google}\n  # always_on_vpn: {package: com.tailscale.ipn, lockdown: true}\n"), "{}", e.text);
        let e = plan_set_device(
            COMMENTED,
            "restrictions",
            &serde_json::json!(["no_factory_reset", "no_safe_boot", "no_add_user"]),
        )
        .unwrap();
        assert!(
            e.text
                .contains("    - no_safe_boot\n    - no_add_user\n    # Enable once"),
            "{}",
            e.text
        );
        let e = plan_set_device(COMMENTED, "lock_screen_info", &serde_json::Value::Null).unwrap();
        assert!(!e.text.contains("lock_screen_info"), "{}", e.text);
        assert!(
            plan_set_device(COMMENTED, "nope", &serde_json::json!(1))
                .unwrap_err()
                .contains("unknown field")
        );
        assert!(plan_set_device(COMMENTED, "a.b", &serde_json::json!(1)).is_err());
        // user_control_disabled: a list, replaced as a whole; null removes it.
        let e = plan_set_device(
            COMMENTED,
            "user_control_disabled",
            &serde_json::json!(["com.tailscale.ipn"]),
        )
        .unwrap();
        compiles(&e.text);
        assert_eq!(
            policy::compile(&e.text, None, 0)
                .unwrap()
                .device
                .user_control_disabled,
            vec!["com.tailscale.ipn".to_string()]
        );
        assert_eq!(
            e.summary,
            "device.user_control_disabled = [com.tailscale.ipn]"
        );
        let gone =
            plan_set_device(&e.text, "user_control_disabled", &serde_json::Value::Null).unwrap();
        assert!(
            !gone.text.contains("user_control_disabled"),
            "{}",
            gone.text
        );
        let bad = plan_set_device(
            COMMENTED,
            "user_control_disabled",
            &serde_json::json!(["tailscale"]),
        )
        .unwrap();
        assert!(
            policy::compile(&bad.text, None, 0)
                .unwrap_err()
                .join("\n")
                .contains(
                    "device.user_control_disabled: \"tailscale\" is not an Android package name"
                )
        );
        // app_config: a whole mapping per package, every value type.
        let cfg = serde_json::json!({"com.tailscale.ipn": {"ForceEnabled": true, "UseTailscaleDNSSettings": "always", "MaxRetries": 3, "Pickers": ["a", "b"]}});
        let e = plan_set_device(COMMENTED, "app_config", &cfg).unwrap();
        compiles(&e.text);
        let c = policy::compile(&e.text, None, 0).unwrap();
        assert_eq!(serde_json::to_value(&c.device.app_config).unwrap(), cfg);
        assert!(
            e.summary
                .starts_with("device.app_config = {com.tailscale.ipn: {"),
            "{}",
            e.summary
        );
        assert!(
            e.text
                .contains("# always_on_vpn: {package: com.tailscale.ipn, lockdown: true}\n"),
            "comments kept: {}",
            e.text
        );
        let gone = plan_set_device(&e.text, "app_config", &serde_json::Value::Null).unwrap();
        assert!(!gone.text.contains("app_config"), "{}", gone.text);
        assert!(
            policy::compile(&gone.text, None, 0)
                .unwrap()
                .device
                .app_config
                .is_empty()
        );
        // Validated like a hand edit: a float is refused at compile time.
        let bad = plan_set_device(
            COMMENTED,
            "app_config",
            &serde_json::json!({"com.x.y": {"A": 1.5}}),
        )
        .unwrap();
        assert!(
            policy::compile(&bad.text, None, 0)
                .unwrap_err()
                .join("\n")
                .contains("1.5 is not an integer")
        );
    }

    #[test]
    fn set_limit_notify_at_absent_null_or_list() {
        let a: SetLimitArgs =
            serde_json::from_str(r#"{"child": "alex", "name": "video"}"#).unwrap();
        assert_eq!(a.notify_at, None);
        let a: SetLimitArgs =
            serde_json::from_str(r#"{"child": "alex", "name": "video", "notify_at": null}"#)
                .unwrap();
        assert_eq!(a.notify_at, Some(None));
        let a: SetLimitArgs =
            serde_json::from_str(r#"{"child": "alex", "name": "video", "notify_at": []}"#).unwrap();
        assert_eq!(a.notify_at, Some(Some(vec![])));
        let a: SetLimitArgs =
            serde_json::from_str(r#"{"child": "alex", "name": "video", "notify_at": [80, 95]}"#)
                .unwrap();
        assert_eq!(a.notify_at, Some(Some(vec![80, 95])));
        let schema = serde_json::to_value(schemars::schema_for!(SetLimitArgs)).unwrap();
        let n = &schema["properties"]["notify_at"];
        assert_eq!(n["type"], serde_json::json!(["array", "null"]), "{schema}");
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("notify_at")),
            "{schema}"
        );
    }

    #[test]
    fn overrides_add_remove_prune() {
        let tz: chrono_tz::Tz = "Europe/Brussels".parse().unwrap();
        let now = policy::parse_instant("2026-10-20T18:00", tz).unwrap();
        let o = "# Exceptions.\noverrides: []\n";
        let lock = OverrideSpec {
            kind: OverrideKind::Lock,
            extra: None,
            limit: None,
            screen: true,
            from: None,
            until: "+1h30m",
            note: Some("devoirs"),
        };
        let e = plan_add_override(COMMENTED, o, &lock, now).unwrap();
        assert_eq!(
            e.text,
            "# Exceptions.\noverrides:\n  - {lock: true, screen: true, until: \"2026-10-20T19:30\", note: devoirs}\n"
        );
        let extra = OverrideSpec {
            kind: OverrideKind::Extra,
            extra: Some("30m"),
            limit: Some("video"),
            screen: false,
            from: Some("2026-10-20T20:00"),
            until: "2026-10-20T23:00",
            note: None,
        };
        let e2 = plan_add_override(COMMENTED, &e.text, &extra, now).unwrap();
        let c = policy::compile(COMMENTED, Some(&e2.text), now).unwrap();
        assert_eq!(c.overrides.len(), 2);
        let past = OverrideSpec {
            until: "2026-10-20T17:00",
            ..extra
        };
        assert!(
            plan_add_override(COMMENTED, o, &past, now)
                .unwrap_err()
                .contains("already past")
        );
        let bad = OverrideSpec {
            kind: OverrideKind::Unlock,
            extra: None,
            limit: None,
            screen: true,
            from: None,
            until: "+1h",
            note: None,
        };
        assert!(
            plan_add_override(COMMENTED, o, &bad, now)
                .unwrap_err()
                .contains("screen only applies")
        );
        // Remove by match / index.
        let r = plan_remove_override(&e2.text, None, Some("DEVOIRS")).unwrap();
        assert!(
            !r.text.contains("devoirs") && r.text.contains("extra: 30m"),
            "{}",
            r.text
        );
        assert!(
            plan_remove_override(&e2.text, None, Some("2026"))
                .unwrap_err()
                .contains("2 overrides match")
        );
        assert!(
            plan_remove_override(&e2.text, Some(5), None)
                .unwrap_err()
                .contains("no override at index 5")
        );
        assert!(
            plan_remove_override(&e2.text, Some(0), Some("x"))
                .unwrap_err()
                .contains("exactly one")
        );
        let r = plan_remove_override(&e2.text, Some(1), None).unwrap();
        assert!(
            r.text.contains("devoirs") && !r.text.contains("extra"),
            "{}",
            r.text
        );
        // Prune: at 19:45 the lock (until 19:30) is expired, the extra (until 23:00) is not.
        let later = policy::parse_instant("2026-10-20T19:45", tz).unwrap();
        let pr = plan_prune(COMMENTED, &e2.text, later).unwrap();
        assert!(
            !pr.text.contains("devoirs") && pr.text.contains("extra: 30m"),
            "{}",
            pr.text
        );
        assert!(pr.text.starts_with("# Exceptions.\n"));
        assert_eq!(plan_prune(COMMENTED, &e2.text, now).unwrap().text, e2.text);
    }

    fn full_line_comments(t: &str) -> Vec<String> {
        let mut v: Vec<String> = t
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with('#'))
            .map(String::from)
            .collect();
        v.sort();
        v
    }

    /// Every planner on a real policy file, without putting it in the repo:
    /// `KIDCTL_REAL_POLICY=<dir with child.yaml + child.overrides.yaml> KIDCTL_REAL_CHILD=<child>
    /// cargo test real_policy -- --ignored --nocapture`. Checks that each change compiles, keeps
    /// every full-line comment, and touches only a few lines (printed).
    #[test]
    #[ignore]
    fn real_policy_every_tool() {
        let dir = std::path::PathBuf::from(
            std::env::var("KIDCTL_REAL_POLICY").expect("KIDCTL_REAL_POLICY"),
        );
        let child = std::env::var("KIDCTL_REAL_CHILD").expect("KIDCTL_REAL_CHILD");
        let pol = std::fs::read_to_string(dir.join(format!("{child}.yaml"))).unwrap();
        let ovr = std::fs::read_to_string(dir.join(format!("{child}.overrides.yaml"))).unwrap();
        let x = p(&pol);
        let some_approved = x
            .approved
            .first()
            .cloned()
            .unwrap_or_else(|| "com.example.app".into());
        let some_always = x.always_allowed.last().cloned().unwrap();
        let wild = x
            .limits
            .iter()
            .find(|l| is_wild(l))
            .map(|l| l.name.clone())
            .unwrap();
        let capped = x
            .limits
            .iter()
            .find(|l| !is_wild(l))
            .map(|l| l.name.clone())
            .unwrap();
        let d: BTreeMap<String, String> = [
            ("weekdays".into(), "1h15m".into()),
            ("weekend".into(), "2h".into()),
        ]
        .into();
        let j = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        let mut cases: Vec<(String, Result<Edited, String>)> = vec![
            (
                "approve new approved".into(),
                plan_approve(&pol, "com.example.newapp", "approved", false),
            ),
            (
                "approve new always_allowed".into(),
                plan_approve(&pol, "com.example.newapp", "always_allowed", false),
            ),
            (
                format!("approve new limit:{capped}"),
                plan_approve(
                    &pol,
                    "com.example.newapp",
                    &format!("limit:{capped}"),
                    false,
                ),
            ),
            (
                format!("approve new limit:{capped} only"),
                plan_approve(&pol, "com.example.newapp", &format!("limit:{capped}"), true),
            ),
            (
                "approve new unlimited".into(),
                plan_approve(
                    &pol,
                    "com.example.newapp",
                    "unlimited_outside_downtime",
                    false,
                ),
            ),
            (
                format!("approve {some_approved} approved"),
                plan_approve(&pol, &some_approved, "approved", false),
            ),
            (
                format!("approve {some_always} limit:{wild}"),
                plan_approve(&pol, &some_always, &format!("limit:{wild}"), false),
            ),
            (
                "block chrome".into(),
                plan_block(&pol, "com.android.chrome"),
            ),
            (
                format!("block {some_always}"),
                plan_block(&pol, &some_always),
            ),
            (
                format!("limit {wild} daily"),
                plan_set_limit(&pol, &wild, None, None, Some(&d), None),
            ),
            (
                "new limit".into(),
                plan_set_limit(
                    &pol,
                    "games",
                    Some(&["com.mojang.minecraftpe".into()]),
                    None,
                    Some(&d),
                    None,
                ),
            ),
            (
                "downtime".into(),
                plan_set_downtime(
                    &pol,
                    &[
                        Window {
                            start: "22:00".into(),
                            end: "07:00".into(),
                            days: None,
                            lock_screen: None,
                        },
                        Window {
                            start: "13:00".into(),
                            end: "14:00".into(),
                            days: Some(vec!["sat".into()]),
                            lock_screen: Some(true),
                        },
                    ],
                ),
            ),
            ("no downtime".into(), plan_set_downtime(&pol, &[])),
        ];
        let mut restr = x.device.restrictions.clone();
        restr.push("no_modify_accounts".into());
        for (f, v) in [
            ("restrictions", serde_json::to_value(&restr).unwrap()),
            (
                "restrictions",
                serde_json::to_value(&x.device.restrictions[1..]).unwrap(),
            ),
            ("hidden", j(r#"["com.android.chrome"]"#)),
            ("camera_disabled", j("true")),
            ("wifi_ssids", j(r#"{"deny": ["Hotspot"]}"#)),
            (
                "default_apps",
                j(
                    r#"{"browser": "org.mozilla.firefox", "launcher": "com.google.android.apps.nexuslauncher"}"#,
                ),
            ),
            ("organization_name", j(r#""Famille""#)),
            ("lock_screen_info", j(r#""Lost? Call home""#)),
            ("lock_screen_info", serde_json::Value::Null),
            (
                "private_dns",
                j(r#"{"mode": "host", "host": "dns.google"}"#),
            ),
            (
                "always_on_vpn",
                j(r#"{"package": "com.tailscale.ipn", "lockdown": true}"#),
            ),
            ("uninstall_blocked", j(r#"["com.tailscale.ipn"]"#)),
        ] {
            cases.push((format!("device.{f} = {v}"), plan_set_device(&pol, f, &v)));
        }
        let mut failures = Vec::new();
        for (name, r) in cases {
            let e = match r {
                Ok(e) => e,
                Err(e) => {
                    failures.push(format!("{name}: {e}"));
                    continue;
                }
            };
            let (gone, new) = (
                pol.lines()
                    .filter(|l| !e.text.lines().any(|m| m == *l))
                    .collect::<Vec<_>>(),
                e.text
                    .lines()
                    .filter(|l| !pol.lines().any(|m| m == *l))
                    .collect::<Vec<_>>(),
            );
            println!(
                "== {name}\n{}",
                gone.iter()
                    .map(|l| format!("- {l}"))
                    .chain(new.iter().map(|l| format!("+ {l}")))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            if let Err(err) = policy::compile(&e.text, Some(&ovr), 0) {
                failures.push(format!("{name}: does not compile: {err:?}"));
            }
            let (before, after) = (full_line_comments(&pol), full_line_comments(&e.text));
            for c in &before {
                if before.iter().filter(|x| *x == c).count()
                    > after.iter().filter(|x| *x == c).count()
                {
                    failures.push(format!("{name}: lost comment {c:?}"));
                }
            }
            if gone.len() > 3 || new.len() > 3 {
                failures.push(format!(
                    "{name}: {} lines removed, {} added",
                    gone.len(),
                    new.len()
                ));
            }
        }
        // Overrides: add two, remove one, prune.
        let now = config_now();
        let lock = OverrideSpec {
            kind: OverrideKind::Lock,
            extra: None,
            limit: None,
            screen: true,
            from: None,
            until: "+1h",
            note: Some("devoirs"),
        };
        let a = plan_add_override(&pol, &ovr, &lock, now).unwrap();
        let extra = OverrideSpec {
            kind: OverrideKind::Extra,
            extra: Some("30m"),
            limit: Some(&wild),
            screen: false,
            from: None,
            until: "+3h",
            note: None,
        };
        let b = plan_add_override(&pol, &a.text, &extra, now).unwrap();
        let c = plan_remove_override(&b.text, None, Some("devoirs")).unwrap();
        let pr = plan_prune(&pol, &b.text, now + 2 * 3600).unwrap();
        println!(
            "== overrides after add+add\n{}\n== after remove\n{}\n== after prune (+2h)\n{}",
            b.text, c.text, pr.text
        );
        for (n, t) in [("add", &b.text), ("remove", &c.text), ("prune", &pr.text)] {
            if full_line_comments(&ovr) != full_line_comments(t) {
                failures.push(format!("overrides {n}: comments changed"));
            }
            if let Err(e) = policy::compile(&pol, Some(t), now) {
                failures.push(format!("overrides {n}: {e:?}"));
            }
        }
        assert!(
            !pr.text.contains("devoirs") && pr.text.contains("extra: 30m"),
            "{}",
            pr.text
        );
        assert!(failures.is_empty(), "{failures:#?}");
    }

    fn config_now() -> i64 {
        crate::config::now_epoch()
    }
}
