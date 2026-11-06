//! Policy model: the YAML written by humans (one file per child, plus an
//! optional overrides file) and the normalized JSON sent to devices.
//!
//! The normalized form ([`Compiled`]) is what both evaluators (Rust here, Kotlin
//! in the agent) consume, so it is deliberately flat: minutes-of-day, seconds,
//! 7-element arrays indexed Monday=0 .. Sunday=6, epoch seconds.

use chrono::{DateTime, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// Android user restrictions accepted in `device.restrictions` (string values of
/// `android.os.UserManager` constants, API 37.2).
pub const KNOWN_RESTRICTIONS: &[&str] = &[
    "allow_parent_profile_app_linking",
    "no_add_managed_profile",
    "no_add_private_profile",
    "no_add_user",
    "no_add_wifi_config",
    "no_adjust_volume",
    "no_airplane_mode",
    "no_ambient_display",
    "no_control_apps",
    "no_assist_content",
    "no_autofill",
    "no_bluetooth",
    "no_bluetooth_sharing",
    "disallow_camera_toggle",
    "no_change_near_field_communication_radio",
    "no_change_wifi_state",
    "no_config_bluetooth",
    "no_config_brightness",
    "no_config_cell_broadcasts",
    "no_config_credentials",
    "no_config_date_time",
    "disallow_config_default_apps",
    "no_config_locale",
    "no_config_location",
    "no_config_mobile_networks",
    "disallow_config_private_dns",
    "no_config_screen_timeout",
    "no_config_tethering",
    "no_config_vpn",
    "no_config_wifi",
    "no_content_capture",
    "no_content_suggestions",
    "no_create_windows",
    "no_cross_profile_copy_paste",
    "no_data_roaming",
    "no_debugging_features",
    "no_factory_reset",
    "no_fun",
    "no_grant_admin",
    "no_install_apps",
    "no_install_unknown_sources",
    "no_install_unknown_sources_globally",
    "no_install_unknown_sources_including_registered_app_stores",
    "disallow_microphone_toggle",
    "no_modify_accounts",
    "no_physical_media",
    "no_near_field_communication_radio",
    "no_network_reset",
    "no_outgoing_beam",
    "no_outgoing_calls",
    "no_printing",
    "no_remove_managed_profile",
    "no_remove_user",
    "no_safe_boot",
    "no_set_user_icon",
    "no_set_wallpaper",
    "no_sharing_into_profile",
    "no_share_location",
    "no_sharing_admin_configured_wifi",
    "no_sim_globally",
    "no_sms",
    "no_system_error_dialogs",
    "no_task_continuity_handoff",
    "no_thread_network",
    "no_ultra_wideband_radio",
    "no_unified_password",
    "no_uninstall_apps",
    "no_unmute_microphone",
    "no_usb_file_transfer",
    "no_user_switch",
    "no_wifi_direct",
    "no_wifi_tethering",
    "ensure_verify_apps",
];

// ---------------------------------------------------------------- YAML input

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub child: String,
    pub timezone: String,
    #[serde(default)]
    pub downtime: Vec<DowntimeIn>,
    #[serde(default)]
    pub always_allowed: Vec<String>,
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(default)]
    pub limits: Vec<LimitIn>,
    /// When true, user-installed apps not named anywhere in this policy are
    /// suspended until listed in `approved` (or another list).
    #[serde(default)]
    pub approval: bool,
    #[serde(default)]
    pub approved: Vec<String>,
    #[serde(default)]
    pub device: DeviceIn,
    /// Notifications on the child's phone (quota thresholds, downtime notice).
    /// Absent: no notifications at all.
    #[serde(default)]
    pub notify: Option<NotifyIn>,
}

/// `notify:` at the top of `<child>.yaml`. Every field is optional: `notify: {}`
/// turns notifications on with the defaults.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotifyIn {
    /// Percentages of each limit's budget (1..99, ascending); default [50, 80, 95].
    #[serde(default)]
    pub quota_at: Option<Vec<i64>>,
    /// Notice this long before a downtime window starts (0..60m, 0 = none); default 5m.
    #[serde(default)]
    pub before_downtime: Option<String>,
    /// Language of the notifications: fr or en; default fr.
    #[serde(default)]
    pub locale: Option<String>,
}

/// Defaults of `notify:`.
pub const DEFAULT_QUOTA_AT: [u8; 3] = [50, 80, 95];
pub const DEFAULT_BEFORE_DOWNTIME_SECS: u64 = 5 * 60;
pub const MAX_BEFORE_DOWNTIME_SECS: u64 = 60 * 60;
pub const LOCALES: [&str; 2] = ["fr", "en"];

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DowntimeIn {
    pub start: String,
    pub end: String,
    /// Days on which the window *starts*; default: every day.
    #[serde(default)]
    pub days: Option<Vec<String>>,
    /// Also keep the screen locked (DevicePolicyManager.lockNow) during the window.
    #[serde(default)]
    pub lock_screen: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitIn {
    pub name: String,
    pub apps: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Keys: mon..sun, weekdays, weekend, default. Values: durations ("1h30m", "45m", "0").
    pub daily: BTreeMap<String, String>,
    /// Thresholds for this limit instead of `notify.quota_at` (`[]`: none).
    #[serde(default)]
    pub notify_at: Option<Vec<i64>>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceIn {
    #[serde(default)]
    pub restrictions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on_vpn: Option<AlwaysOnVpn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_dns: Option<PrivateDns>,
    #[serde(default)]
    pub uninstall_blocked: Vec<String>,
    /// Apps the child cannot force-stop or clear (storage, cache) from
    /// Settings (`setUserControlDisabledPackages`), e.g. the always-on VPN
    /// app: a force-stopped VPN app is not restarted by always-on VPN. The
    /// agent always protects itself this way too. Absent from the compiled
    /// JSON when empty (versions of policies without it are unchanged).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_control_disabled: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_screen_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_message: Option<String>,
    /// Shown by Android as "This device belongs to <name>" (Settings, lock
    /// screen, Quick Settings); absent = Android's generic "your organization".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    /// Apps made invisible (gone from the launcher, cannot run).
    #[serde(default)]
    pub hidden: Vec<String>,
    #[serde(default)]
    pub camera_disabled: bool,
    #[serde(default)]
    pub screen_capture_disabled: bool,
    /// Install OS updates automatically (no postponing).
    #[serde(default)]
    pub auto_system_updates: bool,
    /// Keep location services on (find the phone); pair with no_config_location.
    #[serde(default)]
    pub location_always_on: bool,
    /// Only these accessibility services may be enabled (system ones always
    /// allowed). None = any. Accessibility apps can be abused to bypass limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permitted_accessibility_services: Option<Vec<String>>,
    /// Only these keyboards (system ones always allowed). None = any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permitted_input_methods: Option<Vec<String>>,
    /// Wi-Fi networks the phone may join (exactly one of allow/deny). None =
    /// no restriction (the agent clears any previous SSID policy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi_ssids: Option<WifiSsids>,
    /// Default apps locked by the device owner (persistent preferred activities).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_apps: Option<DefaultApps>,
    /// Managed configurations (Android app restrictions,
    /// `setApplicationRestrictions`): package -> key -> value (boolean,
    /// 32-bit integer, string, or list of strings). The agent checks each key
    /// against the restrictions the app declares and converts the value to
    /// the declared type. Absent from the compiled JSON when empty (versions
    /// of policies without it are unchanged).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub app_config: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WifiSsids {
    /// Only these SSIDs may be joined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    /// These SSIDs may not be joined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DefaultApps {
    /// Handles http/https links (VIEW + BROWSABLE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// Home screen (MAIN + HOME).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AlwaysOnVpn {
    pub package: String,
    #[serde(default = "yes")]
    pub lockdown: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateDns {
    /// "host" (needs `host`), "opportunistic".
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OverridesFile {
    #[serde(default)]
    pub overrides: Vec<OverrideIn>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OverrideIn {
    /// Extra time ("30m"), added to `limit` (or every limit if omitted).
    #[serde(default)]
    pub extra: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
    /// Block everything except always_allowed.
    #[serde(default)]
    pub lock: bool,
    /// With `lock: true`: also keep the screen locked (lockNow) until expiry.
    #[serde(default)]
    pub screen: bool,
    /// Lift downtime and limits (blocked/unapproved apps stay blocked).
    #[serde(default)]
    pub unlock: bool,
    /// Optional start; default: active immediately. Local time in the child's
    /// timezone ("2026-10-17T20:00") or RFC 3339.
    #[serde(default)]
    pub from: Option<String>,
    /// Expiry, same formats as `from`. Required.
    pub until: String,
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------- normalized output

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Compiled {
    pub child: String,
    pub timezone: String,
    pub downtime: Vec<Downtime>,
    pub always_allowed: Vec<String>,
    pub blocked: Vec<String>,
    pub limits: Vec<Limit>,
    pub approval: bool,
    pub approved: Vec<String>,
    pub overrides: Vec<Override>,
    pub device: DeviceIn,
    /// Notifications on the phone; absent (None) = off. Additive wire field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<Notify>,
}

/// Compiled `notify:` (the quota thresholds are resolved per limit, `Limit::notify_at`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Notify {
    /// Notice before a downtime window starts, in seconds; 0 = none.
    pub before_downtime_secs: u64,
    /// "fr" or "en".
    pub locale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Downtime {
    /// Minutes since local midnight.
    pub start_min: u32,
    pub end_min: u32,
    /// Monday=0..Sunday=6: the window starts on these days.
    pub days: [bool; 7],
    /// The screen must stay locked during the window.
    #[serde(default, skip_serializing_if = "is_false")]
    pub lock_screen: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Limit {
    pub name: String,
    pub apps: Vec<String>,
    /// `apps` contained "*": matches every app not always-allowed / excluded.
    pub wildcard: bool,
    pub exclude: Vec<String>,
    /// Budget in seconds, Monday=0..Sunday=6.
    pub daily_secs: [u64; 7],
    /// Percentages of the budget at which the phone notifies (ascending,
    /// 1..99); empty = none (always empty when `notify` is off). Additive wire field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notify_at: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Override {
    Extra {
        limit: Option<String>,
        secs: u64,
        from: i64,
        until: i64,
    },
    Lock {
        from: i64,
        until: i64,
        /// Also keep the screen locked.
        #[serde(default, skip_serializing_if = "is_false")]
        screen: bool,
    },
    Unlock {
        from: i64,
        until: i64,
    },
}

impl Override {
    pub fn window(&self) -> (i64, i64) {
        match *self {
            Override::Extra { from, until, .. }
            | Override::Lock { from, until, .. }
            | Override::Unlock { from, until } => (from, until),
        }
    }
    pub fn active_at(&self, now: i64) -> bool {
        let (f, u) = self.window();
        f <= now && now < u
    }
}

// ------------------------------------------------------------------ parsing

/// "1h30m", "45m", "2h", "90s", "0" -> seconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t == "0" {
        return Ok(0);
    }
    let mut total = 0u64;
    let mut num = String::new();
    let mut any = false;
    for c in t.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
        num.clear();
        total += n * match c {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return Err(format!("bad duration {s:?}: unit {c:?} (use h, m, s)")),
        };
        any = true;
    }
    if !num.is_empty() || !any {
        return Err(format!("bad duration {s:?}: expected e.g. 1h30m, 45m, 0"));
    }
    Ok(total)
}

/// "HH:MM" -> minutes since midnight (00:00..23:59, plus "24:00" as end).
pub fn parse_hhmm(s: &str) -> Result<u32, String> {
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| format!("bad time {s:?}: expected HH:MM"))?;
    let h: u32 = h.parse().map_err(|_| format!("bad time {s:?}"))?;
    let m: u32 = m.parse().map_err(|_| format!("bad time {s:?}"))?;
    if m > 59 || h > 24 || (h == 24 && m != 0) {
        return Err(format!("bad time {s:?}"));
    }
    Ok(h * 60 + m)
}

fn day_index(d: &str) -> Result<usize, String> {
    DAYS.iter()
        .position(|x| *x == d)
        .ok_or_else(|| format!("bad day {d:?}: use mon..sun"))
}

/// Local naive time in `tz`, or RFC 3339 -> epoch seconds.
pub fn parse_instant(s: &str, tz: Tz) -> Result<i64, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp());
    }
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M"))
        .map_err(|_| format!("bad instant {s:?}: expected 2026-10-17T22:00 (local) or RFC 3339"))?;
    tz.from_local_datetime(&naive)
        .earliest()
        .map(|d| d.timestamp())
        .ok_or_else(|| format!("instant {s:?} does not exist in {tz} (DST gap)"))
}

/// `device.organization_name` length limit, in characters: it is displayed
/// inside one sentence ("This device belongs to <name>").
pub const MAX_ORGANIZATION_NAME: usize = 64;

pub fn valid_package(p: &str) -> bool {
    let parts: Vec<&str> = p.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|s| {
            !s.is_empty()
                && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Notification thresholds: integers 1..99, strictly ascending (so unique).
fn thresholds(list: &[i64], what: &str, errs: &mut Vec<String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, &t) in list.iter().enumerate() {
        if !(1..=99).contains(&t) {
            errs.push(format!("{what}: {t} is not a percentage between 1 and 99"));
        } else if i > 0 && t <= list[i - 1] {
            errs.push(format!(
                "{what}: {t} after {}: use ascending values, each once",
                list[i - 1]
            ));
        } else {
            out.push(t as u8);
        }
    }
    out
}

fn daily_budget(daily: &BTreeMap<String, String>, limit: &str) -> Result<[u64; 7], String> {
    let mut out: [Option<u64>; 7] = [None; 7];
    let mut default = None;
    let mut weekdays = None;
    let mut weekend = None;
    for (k, v) in daily {
        let secs = parse_duration(v).map_err(|e| format!("limit {limit:?}: {e}"))?;
        match k.as_str() {
            "default" => default = Some(secs),
            "weekdays" => weekdays = Some(secs),
            "weekend" => weekend = Some(secs),
            d => out[day_index(d).map_err(|e| format!("limit {limit:?}: {e}"))?] = Some(secs),
        }
    }
    let mut res = [0u64; 7];
    for (i, slot) in res.iter_mut().enumerate() {
        let group = if i < 5 { weekdays } else { weekend };
        *slot = out[i].or(group).or(default).ok_or_else(|| {
            format!(
                "limit {limit:?}: no budget for {} (add it, or weekdays/weekend/default)",
                DAYS[i]
            )
        })?;
    }
    Ok(res)
}

/// Validate and normalize one child's policy (+ overrides). `now` is used only
/// to drop overrides that already expired.
pub fn compile(
    policy_yaml: &str,
    overrides_yaml: Option<&str>,
    now: i64,
) -> Result<Compiled, Vec<String>> {
    let mut errs = Vec::new();
    let p: PolicyFile = match serde_yaml_ng::from_str(policy_yaml) {
        Ok(p) => p,
        Err(e) => return Err(vec![format!("policy: {e}")]),
    };
    let tz: Option<Tz> = match p.timezone.parse() {
        Ok(t) => Some(t),
        Err(_) => {
            errs.push(format!(
                "timezone {:?} is not an IANA zone (e.g. Europe/Brussels)",
                p.timezone
            ));
            None
        }
    };
    if p.child.is_empty()
        || !p
            .child
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        errs.push(format!(
            "child {:?}: use lowercase letters, digits, '-'",
            p.child
        ));
    }

    let mut downtime = Vec::new();
    for (i, d) in p.downtime.iter().enumerate() {
        let (s, e) = (parse_hhmm(&d.start), parse_hhmm(&d.end));
        let mut days = [true; 7];
        if let Some(list) = &d.days {
            days = [false; 7];
            for x in list {
                match day_index(x) {
                    Ok(j) => days[j] = true,
                    Err(e) => errs.push(format!("downtime[{i}]: {e}")),
                }
            }
        }
        match (s, e) {
            (Ok(s), Ok(e)) if s == e => errs.push(format!("downtime[{i}]: start == end")),
            (Ok(s), Ok(_)) if s >= 24 * 60 => {
                errs.push(format!("downtime[{i}]: start must be < 24:00 (got {s})"))
            }
            (Ok(start_min), Ok(end_min)) => downtime.push(Downtime {
                start_min,
                end_min,
                days,
                lock_screen: d.lock_screen,
            }),
            (s, e) => errs.extend(
                [s.err(), e.err()]
                    .into_iter()
                    .flatten()
                    .map(|m| format!("downtime[{i}]: {m}")),
            ),
        }
    }

    let seen_pkgs = |list: &[String], what: &str, errs: &mut Vec<String>| {
        let mut set = BTreeSet::new();
        for a in list {
            if !valid_package(a) {
                errs.push(format!("{what}: {a:?} is not an Android package name"));
            } else if !set.insert(a.clone()) {
                errs.push(format!("{what}: {a:?} listed twice"));
            }
        }
    };
    seen_pkgs(&p.always_allowed, "always_allowed", &mut errs);
    seen_pkgs(&p.blocked, "blocked", &mut errs);
    seen_pkgs(&p.approved, "approved", &mut errs);
    for a in &p.blocked {
        if p.always_allowed.contains(a) {
            errs.push(format!("{a:?} is both blocked and always_allowed"));
        }
    }

    let notify = p.notify.as_ref().map(|n| {
        let quota_at = match &n.quota_at {
            Some(v) => thresholds(v, "notify.quota_at", &mut errs),
            None => DEFAULT_QUOTA_AT.to_vec(),
        };
        let before_downtime_secs = match &n.before_downtime {
            None => DEFAULT_BEFORE_DOWNTIME_SECS,
            Some(d) => match parse_duration(d) {
                Ok(s) if s <= MAX_BEFORE_DOWNTIME_SECS => s,
                Ok(_) => {
                    errs.push(format!("notify.before_downtime: {d:?} is more than 60m"));
                    0
                }
                Err(e) => {
                    errs.push(format!("notify.before_downtime: {e}"));
                    0
                }
            },
        };
        let locale = n.locale.clone().unwrap_or_else(|| "fr".into());
        if !LOCALES.contains(&locale.as_str()) {
            errs.push(format!("notify.locale {locale:?}: use fr or en"));
        }
        (
            quota_at,
            Notify {
                before_downtime_secs,
                locale,
            },
        )
    });

    let mut limits = Vec::new();
    let mut names = BTreeSet::new();
    for l in &p.limits {
        if !names.insert(l.name.clone()) {
            errs.push(format!("limit name {:?} used twice", l.name));
        }
        let wildcard = l.apps.iter().any(|a| a == "*");
        let apps: Vec<String> = l.apps.iter().filter(|a| *a != "*").cloned().collect();
        if apps.is_empty() && !wildcard {
            errs.push(format!("limit {:?}: no apps", l.name));
        }
        seen_pkgs(&apps, &format!("limit {:?} apps", l.name), &mut errs);
        seen_pkgs(
            &l.exclude,
            &format!("limit {:?} exclude", l.name),
            &mut errs,
        );
        if !wildcard && !l.exclude.is_empty() {
            errs.push(format!(
                "limit {:?}: exclude only makes sense with \"*\"",
                l.name
            ));
        }
        for a in &apps {
            if p.always_allowed.contains(a) {
                errs.push(format!(
                    "limit {:?}: {a:?} is always_allowed, the limit would never apply",
                    l.name
                ));
            }
        }
        let notify_at = match (&l.notify_at, &notify) {
            (Some(v), Some(_)) => {
                thresholds(v, &format!("limit {:?} notify_at", l.name), &mut errs)
            }
            (Some(_), None) => {
                errs.push(format!(
                    "limit {:?}: notify_at needs notify: at the top of the policy",
                    l.name
                ));
                Vec::new()
            }
            (None, Some((quota_at, _))) => quota_at.clone(),
            (None, None) => Vec::new(),
        };
        match daily_budget(&l.daily, &l.name) {
            Ok(daily_secs) => limits.push(Limit {
                name: l.name.clone(),
                apps,
                wildcard,
                exclude: l.exclude.clone(),
                daily_secs,
                notify_at,
            }),
            Err(e) => errs.push(e),
        }
    }

    for r in &p.device.restrictions {
        if !KNOWN_RESTRICTIONS.contains(&r.as_str()) {
            errs.push(format!(
                "device.restrictions: unknown {r:?} (see docs/CONTROLS.md)"
            ));
        }
    }
    seen_pkgs(
        &p.device.uninstall_blocked,
        "device.uninstall_blocked",
        &mut errs,
    );
    seen_pkgs(
        &p.device.user_control_disabled,
        "device.user_control_disabled",
        &mut errs,
    );
    seen_pkgs(&p.device.hidden, "device.hidden", &mut errs);
    for a in &p.device.hidden {
        if p.always_allowed.contains(a) {
            errs.push(format!("device.hidden: {a:?} is always_allowed"));
        }
    }
    if let Some(v) = &p.device.permitted_accessibility_services {
        seen_pkgs(v, "device.permitted_accessibility_services", &mut errs);
    }
    if let Some(v) = &p.device.permitted_input_methods {
        seen_pkgs(v, "device.permitted_input_methods", &mut errs);
    }
    if let Some(v) = &p.device.always_on_vpn
        && !valid_package(&v.package)
    {
        errs.push(format!(
            "device.always_on_vpn.package {:?} is not a package name",
            v.package
        ));
    }
    if let Some(w) = &p.device.wifi_ssids {
        validate_wifi_ssids(w, &mut errs);
    }
    if let Some(n) = &p.device.organization_name {
        let chars = n.chars().count();
        if n.trim().is_empty() {
            errs.push("device.organization_name: empty (omit it for Android's default)".into());
        } else if chars > MAX_ORGANIZATION_NAME {
            errs.push(format!(
                "device.organization_name: {chars} characters (max {MAX_ORGANIZATION_NAME})"
            ));
        }
        if n.chars().any(char::is_control) {
            errs.push(
                "device.organization_name: control characters (e.g. a newline) not allowed".into(),
            );
        }
    }
    if let Some(d) = &p.device.default_apps {
        for (role, pkg) in [("browser", &d.browser), ("launcher", &d.launcher)] {
            let Some(pkg) = pkg else { continue };
            if !valid_package(pkg) {
                errs.push(format!(
                    "device.default_apps.{role}: {pkg:?} is not an Android package name"
                ));
            }
            if p.blocked.contains(pkg) {
                errs.push(format!("device.default_apps.{role}: {pkg:?} is in blocked"));
            }
            if p.device.hidden.contains(pkg) {
                errs.push(format!(
                    "device.default_apps.{role}: {pkg:?} is in device.hidden"
                ));
            }
        }
    }
    validate_app_config(&p.device.app_config, &mut errs);
    if let Some(d) = &p.device.private_dns {
        match (d.mode.as_str(), &d.host) {
            ("host", Some(h)) if !h.is_empty() && !h.contains('/') => {}
            ("host", _) => {
                errs.push("device.private_dns: mode host needs host: (a hostname)".into())
            }
            ("opportunistic", None) => {}
            ("opportunistic", Some(_)) => {
                errs.push("device.private_dns: opportunistic takes no host".into())
            }
            (m, _) => errs.push(format!(
                "device.private_dns.mode {m:?}: use host or opportunistic"
            )),
        }
    }

    let mut overrides = Vec::new();
    if let (Some(y), Some(tz)) = (overrides_yaml, tz) {
        match serde_yaml_ng::from_str::<Option<OverridesFile>>(y) {
            Err(e) => errs.push(format!("overrides: {e}")),
            Ok(None) => {}
            Ok(Some(f)) => {
                for (i, o) in f.overrides.iter().enumerate() {
                    match compile_override(o, tz, &names) {
                        Ok(c) => {
                            if c.window().1 > now {
                                overrides.push(c)
                            }
                        }
                        Err(e) => errs.push(format!("overrides[{i}]: {e}")),
                    }
                }
            }
        }
    }

    if !errs.is_empty() {
        return Err(errs);
    }
    let sorted = |v: &[String]| {
        let mut v = v.to_vec();
        v.sort();
        v
    };
    Ok(Compiled {
        child: p.child,
        timezone: p.timezone,
        downtime,
        always_allowed: sorted(&p.always_allowed),
        blocked: sorted(&p.blocked),
        limits,
        approval: p.approval,
        approved: sorted(&p.approved),
        overrides,
        device: p.device,
        notify: notify.map(|(_, n)| n),
    })
}

/// `device.app_config`: valid package names, non-empty keys without control
/// characters, values the agent can put in a restrictions Bundle (boolean,
/// 32-bit integer, string, list of strings).
fn validate_app_config(
    m: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    errs: &mut Vec<String>,
) {
    use serde_json::Value as V;
    for (pkg, cfg) in m {
        let at = format!("device.app_config.{pkg}");
        if !valid_package(pkg) {
            errs.push(format!(
                "device.app_config: {pkg:?} is not an Android package name"
            ));
        }
        if cfg.is_empty() {
            errs.push(format!(
                "{at}: no keys (remove the package to clear its configuration)"
            ));
        }
        for (k, v) in cfg {
            if k.trim().is_empty() || k.chars().any(char::is_control) {
                errs.push(format!("{at}: key {k:?}: empty or with control characters"));
                continue;
            }
            let bad = match v {
                V::Bool(_) | V::String(_) => None,
                V::Number(n) => match n.as_i64() {
                    Some(i) if i32::try_from(i).is_ok() => None,
                    Some(_) => Some("integer out of the 32-bit range".to_string()),
                    None => Some(format!("{n} is not an integer (no decimals)")),
                },
                V::Array(a) if a.iter().all(V::is_string) => None,
                V::Array(_) => Some("a list may only hold strings".into()),
                V::Null => Some("no value (remove the key to leave it unset)".into()),
                V::Object(_) => Some("nested mappings (bundles) are not supported".into()),
            };
            if let Some(why) = bad {
                errs.push(format!(
                    "{at}.{k}: {why}; use a boolean, an integer, a string or a list of strings"
                ));
            }
        }
    }
}

/// Android limits an SSID to 32 bytes (`WifiSsid.fromBytes`); the agent sends
/// the UTF-8 bytes of each entry.
fn validate_wifi_ssids(w: &WifiSsids, errs: &mut Vec<String>) {
    let (what, list) = match (&w.allow, &w.deny) {
        (Some(l), None) => ("allow", l),
        (None, Some(l)) => ("deny", l),
        _ => {
            errs.push("device.wifi_ssids: exactly one of allow: or deny:".into());
            return;
        }
    };
    if list.is_empty() {
        errs.push(format!(
            "device.wifi_ssids.{what}: empty list (omit wifi_ssids to allow every network)"
        ));
    }
    let mut seen = BTreeSet::new();
    for s in list {
        if s.is_empty() {
            errs.push(format!("device.wifi_ssids.{what}: empty SSID"));
        } else if s.len() > 32 {
            errs.push(format!(
                "device.wifi_ssids.{what}: {s:?} is {} bytes in UTF-8 (max 32)",
                s.len()
            ));
        }
        if !seen.insert(s) {
            errs.push(format!("device.wifi_ssids.{what}: {s:?} listed twice"));
        }
    }
}

fn compile_override(
    o: &OverrideIn,
    tz: Tz,
    limit_names: &BTreeSet<String>,
) -> Result<Override, String> {
    let until = parse_instant(&o.until, tz)?;
    let from = match &o.from {
        Some(f) => parse_instant(f, tz)?,
        None => i64::MIN / 2,
    };
    if from >= until {
        return Err("from must be before until".into());
    }
    let kinds = [o.extra.is_some(), o.lock, o.unlock]
        .iter()
        .filter(|b| **b)
        .count();
    if kinds != 1 {
        return Err("exactly one of extra:, lock: true, unlock: true".into());
    }
    if o.screen && !o.lock {
        return Err("screen: only applies to lock: true".into());
    }
    if let Some(l) = &o.limit {
        if o.extra.is_none() {
            return Err("limit: only applies to extra:".into());
        }
        if !limit_names.contains(l) {
            return Err(format!("unknown limit {l:?}"));
        }
    }
    Ok(match &o.extra {
        Some(e) => Override::Extra {
            limit: o.limit.clone(),
            secs: parse_duration(e)?,
            from,
            until,
        },
        None if o.lock => Override::Lock {
            from,
            until,
            screen: o.screen,
        },
        None => Override::Unlock { from, until },
    })
}

/// Stable version string of a compiled policy (devices skip unchanged ones).
pub fn version(c: &Compiled) -> String {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_vec(c).expect("serializable");
    hex::encode(&Sha256::digest(&json)[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h30m").unwrap(), 5400);
        assert_eq!(parse_duration("45m").unwrap(), 2700);
        assert_eq!(parse_duration("0").unwrap(), 0);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert!(parse_duration("90").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn times() {
        assert_eq!(parse_hhmm("22:00").unwrap(), 1320);
        assert_eq!(parse_hhmm("07:30").unwrap(), 450);
        assert!(parse_hhmm("25:00").is_err());
        assert!(parse_hhmm("7h").is_err());
    }

    #[test]
    fn budget_precedence() {
        let mut d = BTreeMap::new();
        d.insert("default".into(), "0".into());
        d.insert("weekend".into(), "1h".into());
        d.insert("fri".into(), "2h30m".into());
        assert_eq!(
            daily_budget(&d, "x").unwrap(),
            [0, 0, 0, 0, 9000, 3600, 3600]
        );
        let mut d = BTreeMap::new();
        d.insert("weekdays".into(), "1h".into());
        assert!(daily_budget(&d, "x").is_err(), "weekend missing");
    }

    #[test]
    fn rejects_bad_policy() {
        let y = r#"
child: Alex
timezone: Mars/Base
downtime: [{start: "22:00", end: "22:00"}]
always_allowed: [com.a.b, notapkg]
blocked: [com.a.b]
limits:
  - {name: x, apps: [com.c.d], exclude: [com.e.f], daily: {weekdays: 1h}}
device: {restrictions: [no_such_thing], private_dns: {mode: host}}
"#;
        let errs = compile(y, None, 0).unwrap_err();
        let all = errs.join("\n");
        for needle in [
            "child",
            "timezone",
            "start == end",
            "notapkg",
            "both blocked",
            "exclude only",
            "no budget for sat",
            "no_such_thing",
            "private_dns",
        ] {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn overrides_compile_and_expire() {
        let y = "child: alex\ntimezone: Europe/Brussels\nlimits: [{name: video, apps: [com.netflix.mediaclient], daily: {default: 0}}]\n";
        let o = r#"
overrides:
  - {extra: 30m, limit: video, until: "2026-10-17T23:00"}
  - {lock: true, until: "2026-10-01T10:00"}
"#;
        let now = parse_instant("2026-10-17T20:00", "Europe/Brussels".parse().unwrap()).unwrap();
        let c = compile(y, Some(o), now).unwrap();
        assert_eq!(c.overrides.len(), 1, "expired lock dropped");
        assert!(matches!(c.overrides[0], Override::Extra { secs: 1800, .. }));
        let bad = "overrides: [{extra: 30m, limit: nope, until: \"2026-10-17T23:00\"}]";
        assert!(compile(y, Some(bad), now).is_err());
        let both = "overrides: [{lock: true, unlock: true, until: \"2026-10-17T23:00\"}]";
        assert!(compile(y, Some(both), now).is_err());
    }

    #[test]
    fn screen_lock_fields() {
        let y = r#"
child: alex
timezone: Europe/Brussels
downtime:
  - {start: "22:00", end: "07:00"}
  - {start: "23:00", end: "06:00", days: [fri], lock_screen: true}
"#;
        let o = r#"
overrides:
  - {lock: true, screen: true, until: "2026-10-17T23:00"}
  - {lock: true, until: "2026-10-17T23:00"}
"#;
        let c = compile(y, Some(o), 0).unwrap();
        assert!(!c.downtime[0].lock_screen && c.downtime[1].lock_screen);
        assert!(matches!(
            c.overrides[0],
            Override::Lock { screen: true, .. }
        ));
        assert!(matches!(
            c.overrides[1],
            Override::Lock { screen: false, .. }
        ));
        // Wire format is additive: defaults are omitted, so older agents and
        // policies that do not use the feature see exactly the previous JSON.
        let j = serde_json::to_value(&c).unwrap();
        assert!(j["downtime"][0].get("lock_screen").is_none());
        assert_eq!(j["downtime"][1]["lock_screen"], true);
        assert_eq!(j["overrides"][0]["screen"], true);
        assert!(j["overrides"][1].get("screen").is_none());
        assert!(
            j["device"].get("wifi_ssids").is_none() && j["device"].get("default_apps").is_none()
        );
        let back: Compiled = serde_json::from_value(j).unwrap();
        assert_eq!(back, c);
        for bad in [
            "overrides: [{unlock: true, screen: true, until: \"2026-10-17T23:00\"}]",
            "overrides: [{extra: 30m, screen: true, until: \"2026-10-17T23:00\"}]",
        ] {
            let e = compile(y, Some(bad), 0).unwrap_err().join("\n");
            assert!(e.contains("screen: only applies to lock"), "{e}");
        }
        let e = compile(
            "child: alex\ntimezone: UTC\ndowntime: [{start: \"22:00\", end: \"07:00\", lock_screen: yes}]\n",
            None,
            0,
        );
        assert!(e.is_err(), "lock_screen must be a bool");
    }

    #[test]
    fn wifi_ssids() {
        let base = "child: alex\ntimezone: Europe/Brussels\n";
        let ok = |dev: &str| compile(&format!("{base}device: {{wifi_ssids: {dev}}}\n"), None, 0);
        let c = ok(r#"{allow: [HomeNet, "École du Centre"]}"#).unwrap();
        assert_eq!(
            c.device.wifi_ssids,
            Some(WifiSsids {
                allow: Some(vec!["HomeNet".into(), "École du Centre".into()]),
                deny: None
            })
        );
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(
            j["device"]["wifi_ssids"],
            serde_json::json!({"allow": ["HomeNet", "École du Centre"]})
        );
        assert!(ok("{deny: [PublicHotspot]}").is_ok());
        // 32 bytes is the limit: 16 x "é" = 32 bytes OK, 17 x "é" = 34 bytes (only 17 chars).
        assert!(ok(&format!("{{allow: [\"{}\"]}}", "é".repeat(16))).is_ok());
        for (dev, needle) in [
            ("{allow: [a], deny: [b]}", "exactly one of allow: or deny:"),
            ("{}", "exactly one of allow: or deny:"),
            ("{allow: []}", "empty list"),
            ("{allow: [\"\"]}", "empty SSID"),
            ("{deny: [a, b, a]}", "\"a\" listed twice"),
            (
                &format!("{{allow: [\"{}\"]}}", "é".repeat(17)),
                "34 bytes in UTF-8 (max 32)",
            ),
            (
                &format!("{{allow: [{}]}}", "x".repeat(33)),
                "33 bytes in UTF-8 (max 32)",
            ),
            ("{allowlist: [a]}", "unknown field"),
        ] {
            let e = ok(dev).unwrap_err().join("\n");
            assert!(e.contains(needle), "{dev}: missing {needle:?} in {e}");
        }
    }

    #[test]
    fn default_apps() {
        let pol = |dev: &str| {
            compile(
                &format!(
                    "child: alex\ntimezone: Europe/Brussels\nblocked: [com.blocked.browser]\n\
                     device: {{hidden: [com.hidden.launcher], default_apps: {dev}}}\n"
                ),
                None,
                0,
            )
        };
        let c =
            pol("{browser: org.mozilla.firefox, launcher: com.google.android.apps.nexuslauncher}")
                .unwrap();
        assert_eq!(
            c.device.default_apps,
            Some(DefaultApps {
                browser: Some("org.mozilla.firefox".into()),
                launcher: Some("com.google.android.apps.nexuslauncher".into())
            })
        );
        let c = pol("{launcher: com.google.android.apps.nexuslauncher}").unwrap();
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(
            j["device"]["default_apps"],
            serde_json::json!({"launcher": "com.google.android.apps.nexuslauncher"})
        );
        for (dev, needle) in [
            (
                "{browser: firefox}",
                "default_apps.browser: \"firefox\" is not an Android package name",
            ),
            (
                "{launcher: com..x}",
                "default_apps.launcher: \"com..x\" is not an Android package name",
            ),
            (
                "{browser: com.blocked.browser}",
                "default_apps.browser: \"com.blocked.browser\" is in blocked",
            ),
            (
                "{launcher: com.hidden.launcher}",
                "default_apps.launcher: \"com.hidden.launcher\" is in device.hidden",
            ),
            ("{dialer: com.a.b}", "unknown field"),
        ] {
            let e = pol(dev).unwrap_err().join("\n");
            assert!(e.contains(needle), "{dev}: missing {needle:?} in {e}");
        }
    }

    #[test]
    fn notify() {
        let pol = |notify: &str, social_extra: &str| {
            compile(
                &format!(
                    "child: alex\ntimezone: Europe/Brussels\nlimits:\n  \
                     - {{name: social, apps: [com.instagram.android], daily: {{default: 30m}}{social_extra}}}\n  \
                     - {{name: general, apps: [\"*\"], daily: {{default: 1h}}}}\n{notify}"
                ),
                None,
                0,
            )
        };
        // Absent: off, and the wire JSON (hence the version) is exactly as before.
        let off = pol("", "").unwrap();
        assert!(off.notify.is_none() && off.limits.iter().all(|l| l.notify_at.is_empty()));
        let j = serde_json::to_value(&off).unwrap();
        assert!(j.get("notify").is_none() && j["limits"][0].get("notify_at").is_none());
        // `notify: {}`: defaults for every limit.
        let on = pol("notify: {}\n", "").unwrap();
        assert_eq!(
            on.notify,
            Some(Notify {
                before_downtime_secs: 300,
                locale: "fr".into()
            })
        );
        assert!(on.limits.iter().all(|l| l.notify_at == vec![50, 80, 95]));
        let j = serde_json::to_value(&on).unwrap();
        assert_eq!(
            j["notify"],
            serde_json::json!({"before_downtime_secs": 300, "locale": "fr"})
        );
        assert_eq!(j["limits"][1]["notify_at"], serde_json::json!([50, 80, 95]));
        assert_eq!(serde_json::from_value::<Compiled>(j).unwrap(), on);
        // Explicit values, per-limit override, [] = none for that limit.
        let c = pol(
            "notify: {quota_at: [75], before_downtime: 10m, locale: en}\n",
            ", notify_at: [10, 90]",
        )
        .unwrap();
        assert_eq!(
            c.notify,
            Some(Notify {
                before_downtime_secs: 600,
                locale: "en".into()
            })
        );
        assert_eq!(
            (c.limits[0].notify_at.clone(), c.limits[1].notify_at.clone()),
            (vec![10, 90], vec![75])
        );
        let c = pol("notify: {before_downtime: 0}\n", ", notify_at: []").unwrap();
        assert_eq!(c.notify.as_ref().unwrap().before_downtime_secs, 0);
        assert!(c.limits[0].notify_at.is_empty() && c.limits[1].notify_at == vec![50, 80, 95]);
        assert!(
            serde_json::to_value(&c).unwrap()["limits"][0]
                .get("notify_at")
                .is_none()
        );
        assert!(pol("notify: {before_downtime: 60m, quota_at: [1, 99]}\n", "").is_ok());
        for (notify, extra, needle) in [
            (
                "notify: {quota_at: [0]}\n",
                "",
                "notify.quota_at: 0 is not a percentage between 1 and 99",
            ),
            (
                "notify: {quota_at: [100]}\n",
                "",
                "notify.quota_at: 100 is not a percentage",
            ),
            (
                "notify: {quota_at: [-5]}\n",
                "",
                "notify.quota_at: -5 is not a percentage",
            ),
            (
                "notify: {quota_at: [80, 50]}\n",
                "",
                "notify.quota_at: 50 after 80: use ascending values, each once",
            ),
            (
                "notify: {quota_at: [50, 50]}\n",
                "",
                "notify.quota_at: 50 after 50",
            ),
            ("notify: {quota_at: [50.5]}\n", "", "notify"),
            (
                "notify: {}\n",
                ", notify_at: [95, 90]",
                "limit \"social\" notify_at: 90 after 95",
            ),
            (
                "notify: {}\n",
                ", notify_at: [120]",
                "limit \"social\" notify_at: 120 is not a percentage",
            ),
            (
                "",
                ", notify_at: [50]",
                "limit \"social\": notify_at needs notify: at the top of the policy",
            ),
            (
                "notify: {before_downtime: 61m}\n",
                "",
                "notify.before_downtime: \"61m\" is more than 60m",
            ),
            ("notify: {before_downtime: 2h}\n", "", "is more than 60m"),
            (
                "notify: {before_downtime: soon}\n",
                "",
                "notify.before_downtime: bad duration",
            ),
            (
                "notify: {locale: de}\n",
                "",
                "notify.locale \"de\": use fr or en",
            ),
            ("notify: {quota: [50]}\n", "", "unknown field `quota`"),
            ("notify: true\n", "", "notify"),
        ] {
            let e = pol(notify, extra).unwrap_err().join("\n");
            assert!(
                e.contains(needle),
                "{notify} {extra}: missing {needle:?} in {e}"
            );
        }
    }

    #[test]
    fn app_config() {
        let pol = |dev: &str| {
            compile(
                &format!("child: kid\ntimezone: Europe/Brussels\ndevice:\n{dev}"),
                None,
                0,
            )
        };
        let tailscale = "  app_config:\n    com.tailscale.ipn:\n      ForceEnabled: true\n      UseTailscaleDNSSettings: always\n      \
                         LoginURL: https://hs.example.net\n      Hostname: kid-phone\n      MaxRetries: 3\n      \
                         ManagedByOrganizationName: Papa et Maman\n      Features: [a, b]\n";
        let c = pol(tailscale).unwrap();
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(
            j["device"]["app_config"],
            serde_json::json!({"com.tailscale.ipn": {
                "ForceEnabled": true, "UseTailscaleDNSSettings": "always", "LoginURL": "https://hs.example.net",
                "Hostname": "kid-phone", "MaxRetries": 3, "ManagedByOrganizationName": "Papa et Maman", "Features": ["a", "b"]
            }})
        );
        // Additive wire field: absent from the JSON (and the version) when unset.
        let none = pol("  restrictions: []\n").unwrap();
        assert!(
            serde_json::to_value(&none).unwrap()["device"]
                .get("app_config")
                .is_none()
        );
        assert_eq!(
            version(&none),
            version(&compile("child: kid\ntimezone: Europe/Brussels\n", None, 0).unwrap())
        );
        assert_eq!(version(&pol("  app_config: {}\n").unwrap()), version(&none));
        assert!(pol("  app_config: {com.x.y: {Max: 2147483647, Min: -2147483648, Empty: \"\", None: []}}\n").is_ok());
        for (dev, needle) in [
            (
                "  app_config: {tailscale: {A: true}}\n",
                "device.app_config: \"tailscale\" is not an Android package name",
            ),
            (
                "  app_config: {com.x.y: {}}\n",
                "device.app_config.com.x.y: no keys",
            ),
            ("  app_config: {com.x.y: {\"\": 1}}\n", "key \"\": empty"),
            (
                "  app_config: {com.x.y: {\"a\\tb\": 1}}\n",
                "control characters",
            ),
            (
                "  app_config: {com.x.y: {A: 1.5}}\n",
                "device.app_config.com.x.y.A: 1.5 is not an integer",
            ),
            (
                "  app_config: {com.x.y: {A: 2147483648}}\n",
                "A: integer out of the 32-bit range",
            ),
            ("  app_config: {com.x.y: {A: ~}}\n", "A: no value"),
            (
                "  app_config: {com.x.y: {A: {b: 1}}}\n",
                "A: nested mappings (bundles) are not supported",
            ),
            (
                "  app_config: {com.x.y: {A: [1, b]}}\n",
                "A: a list may only hold strings",
            ),
            ("  app_config: {com.x.y: true}\n", "app_config"),
            ("  app_config: [com.x.y]\n", "app_config"),
        ] {
            let e = pol(dev).unwrap_err().join("\n");
            assert!(e.contains(needle), "{dev}: missing {needle:?} in {e}");
        }
    }

    #[test]
    fn user_control_disabled() {
        let pol = |dev: &str| {
            compile(
                &format!("child: kid\ntimezone: Europe/Brussels\ndevice:\n{dev}"),
                None,
                0,
            )
        };
        let c = pol("  user_control_disabled: [com.tailscale.ipn, com.example.app]\n").unwrap();
        assert_eq!(
            serde_json::to_value(&c).unwrap()["device"]["user_control_disabled"],
            serde_json::json!(["com.tailscale.ipn", "com.example.app"])
        );
        // Additive wire field: absent from the JSON (and the version) when unset or empty.
        let none = compile("child: kid\ntimezone: Europe/Brussels\n", None, 0).unwrap();
        assert!(
            serde_json::to_value(&none).unwrap()["device"]
                .get("user_control_disabled")
                .is_none()
        );
        assert_eq!(
            version(&pol("  user_control_disabled: []\n").unwrap()),
            version(&none)
        );
        assert_ne!(version(&c), version(&none));
        for (dev, needle) in [
            (
                "  user_control_disabled: [tailscale]\n",
                "device.user_control_disabled: \"tailscale\" is not an Android package name",
            ),
            (
                "  user_control_disabled: [com.a.b, com.a.b]\n",
                "device.user_control_disabled: \"com.a.b\" listed twice",
            ),
            (
                "  user_control_disabled: com.a.b\n",
                "user_control_disabled",
            ),
        ] {
            let e = pol(dev).unwrap_err().join("\n");
            assert!(e.contains(needle), "{dev}: missing {needle:?} in {e}");
        }
    }

    #[test]
    fn organization_name() {
        let pol = |dev: &str| {
            compile(
                &format!("child: alex\ntimezone: Europe/Brussels\ndevice: {dev}\n"),
                None,
                0,
            )
        };
        let c = pol("{organization_name: kidctl}").unwrap();
        assert_eq!(c.device.organization_name.as_deref(), Some("kidctl"));
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["device"]["organization_name"], "kidctl");
        // Additive wire field: absent from the JSON (and the version) when unset.
        let none = pol("{}").unwrap();
        assert!(
            serde_json::to_value(&none).unwrap()["device"]
                .get("organization_name")
                .is_none()
        );
        assert_eq!(
            version(&none),
            version(&compile("child: alex\ntimezone: Europe/Brussels\n", None, 0).unwrap())
        );
        // 64 characters is the limit, counted in characters, not bytes.
        assert!(pol(&format!("{{organization_name: \"{}\"}}", "é".repeat(64))).is_ok());
        for (dev, needle) in [
            (
                format!("{{organization_name: \"{}\"}}", "é".repeat(65)),
                "65 characters (max 64)",
            ),
            (
                format!("{{organization_name: {}}}", "x".repeat(100)),
                "100 characters (max 64)",
            ),
            (
                "{organization_name: \"\"}".to_string(),
                "device.organization_name: empty",
            ),
            (
                "{organization_name: \"  \"}".to_string(),
                "device.organization_name: empty",
            ),
            (
                "{organization_name: \"a\\nb\"}".to_string(),
                "control characters",
            ),
            ("{organization_name: [a]}".to_string(), "organization_name"),
        ] {
            let e = pol(&dev).unwrap_err().join("\n");
            assert!(e.contains(needle), "{dev}: missing {needle:?} in {e}");
        }
    }
}
