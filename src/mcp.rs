//! MCP: lets Claude see status, usage and installed apps (read tools, here)
//! and, when GitOps writes are configured, change every rule (write tools,
//! `mcp_write`): each change is a git commit pushed to the infra repo, the
//! same path as a manual edit (ArgoCD syncs, the server reloads, phones
//! sync). The MCP never edits SQLite, the config directory or the phones.
//! Write tools are offered on the OAuth endpoint only (the owner typed the
//! password), never on the legacy URL token.

use crate::api::AppState;
use crate::config::now_epoch;
use crate::eval;
use crate::policy;
use chrono::TimeZone;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Deserialize, JsonSchema)]
pub struct ChildArgs {
    /// Child name as in the policy file name (e.g. "alex").
    pub child: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct UsageArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Local date YYYY-MM-DD in the child's timezone (default: today).
    pub date: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct EventsArgs {
    /// Child name (e.g. "alex").
    pub child: String,
    /// Look back this many hours (default 24).
    pub hours: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ValidateArgs {
    /// Full text of a policy file (<child>.yaml).
    pub policy_yaml: String,
    /// Optional full text of <child>.overrides.yaml.
    pub overrides_yaml: Option<String>,
}

#[derive(Clone)]
pub struct Server {
    pub(crate) st: AppState,
    /// Set when write tools are offered on this endpoint.
    pub(crate) gitops: Option<std::sync::Arc<crate::gitops::Gitops>>,
    tool_router: ToolRouter<Self>,
}

/// Who calls the MCP (request extension set by the OAuth route in
/// `serve`), for the `Requested-By:` trailer of commits.
#[derive(Clone, Debug)]
pub struct Requester {
    pub client_id: String,
    /// The OAuth state's `oauth-clients.json` (client names of dynamically
    /// registered clients).
    pub clients_file: Option<std::path::PathBuf>,
}

impl Requester {
    /// "Claude Code (OAuth client 3f2a...)", or the client metadata URL of a
    /// CIMD client.
    pub fn describe(&self) -> String {
        if self.client_id.starts_with("https://") {
            return format!("OAuth client {}", self.client_id);
        }
        let name = self
            .clients_file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| {
                v["clients"]
                    .as_array()?
                    .iter()
                    .find(|c| c["client_id"] == self.client_id.as_str())?
                    .get("client_name")?
                    .as_str()
                    .map(String::from)
            });
        match name {
            Some(n) => format!(
                "{} (OAuth client {})",
                crate::gitops::one_line(&n, 60),
                self.client_id
            ),
            None => format!("OAuth client {}", self.client_id),
        }
    }
}

fn hm(secs: u64) -> String {
    format!(
        "{}h{:02}m{:02}s",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

impl Server {
    fn child_ctx(
        &self,
        child: &str,
    ) -> Result<(policy::Compiled, Vec<String>, chrono_tz::Tz), String> {
        let cfg = self.st.store.get();
        let c = cfg
            .compiled(child, now_epoch())
            .ok_or_else(|| {
                format!(
                    "unknown child {child:?}; known: {:?}",
                    cfg.children.keys().collect::<Vec<_>>()
                )
            })?
            .map_err(|e| e.join("; "))?;
        let devices = cfg
            .devices
            .iter()
            .filter(|d| d.child == child)
            .map(|d| d.id.clone())
            .collect();
        let tz = c.timezone.parse().map_err(|_| "bad tz".to_string())?;
        Ok((c, devices, tz))
    }

    fn today(tz: chrono_tz::Tz) -> String {
        tz.timestamp_opt(now_epoch(), 0)
            .single()
            .expect("valid")
            .format("%Y-%m-%d")
            .to_string()
    }

    /// "agent 0.1.0 (code 7)" as reported by the device, or "agent 0.1.0 (code ?)" for old agents.
    fn agent(s: &crate::db::DeviceSeen) -> String {
        format!(
            "agent {} (code {})",
            s.agent_version,
            s.agent_version_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into())
        )
    }

    /// Whether the device enforces the policy served now: "policy up to date
    /// (<version>)" or "policy behind: has X, served Y (...)". The device
    /// reports the version it holds when it syncs, so a version sent in the
    /// answer to its last sync is only confirmed at its next one.
    fn policy_state(s: &crate::db::DeviceSeen, served: Result<&str, &str>) -> String {
        let has = if s.policy_version.is_empty() {
            "none"
        } else {
            s.policy_version.as_str()
        };
        match served {
            Err(e) => format!("policy has {has}, none served ({e})"),
            Ok(v) if v == s.policy_version => format!("policy up to date ({v})"),
            Ok(v) if s.policy_served.as_deref() == Some(v) => {
                format!(
                    "policy behind: has {has}, served {v} (sent at the last sync, confirmed at the next)"
                )
            }
            Ok(v) => format!(
                "policy behind: has {has}, served {v} (changed since the last sync, sent at the next)"
            ),
        }
    }

    /// The version served to `child`'s devices now, or why there is none.
    fn served_version(
        cfg: &crate::config::Config,
        child: &str,
        now: i64,
    ) -> Result<String, String> {
        match cfg.compiled(child, now) {
            Some(Ok(c)) => Ok(policy::version(&c)),
            Some(Err(e)) => Err(format!("policy invalid: {}", e.join("; "))),
            None => Err("no policy".into()),
        }
    }

    fn release_line(&self) -> String {
        match self.st.agent.get() {
            Some(r) => format!(
                "agent release offered: code {} ({}), sha256 {}\n",
                r.meta.version_code, r.meta.version_name, r.meta.sha256
            ),
            None => "agent release offered: none\n".into(),
        }
    }

    fn labels(&self, devices: &[String]) -> BTreeMap<String, String> {
        devices
            .iter()
            .flat_map(|d| self.st.db.apps(d).unwrap_or_default())
            .map(|a| (a.package, a.label))
            .collect()
    }
}

#[tool_router]
impl Server {
    /// `writes`: offer the write tools (only if GitOps is configured).
    pub fn new(st: AppState, writes: bool) -> Self {
        let gitops = if writes { st.gitops.clone() } else { None };
        let mut tool_router = Self::tool_router();
        if gitops.is_some() {
            tool_router += Self::write_router();
        }
        Self {
            st,
            gitops,
            tool_router,
        }
    }

    #[tool(
        description = "List children with their devices: last sync, agent version and versionCode, device owner, whether the device has the policy version served now (\"policy up to date\" or \"policy behind: has X, served Y\"), last error; and the agent release offered for self-update."
    )]
    async fn list_children(&self) -> Result<String, String> {
        let cfg = self.st.store.get();
        let now = now_epoch();
        let mut out = self.release_line();
        for child in cfg.children.keys() {
            let _ = writeln!(out, "{child}");
            let served = Self::served_version(&cfg, child, now);
            for d in cfg.devices.iter().filter(|d| &d.child == child) {
                match self.st.db.device(&d.id).map_err(|e| e.to_string())? {
                    Some(s) => {
                        let _ = writeln!(
                            out,
                            "  {}: last sync {} min ago, {}, sdk {}, device_owner={}, {}{}",
                            d.id,
                            (now - s.last_seen) / 60,
                            Self::agent(&s),
                            s.android_sdk,
                            s.device_owner,
                            Self::policy_state(&s, served.as_deref().map_err(String::as_str)),
                            s.last_error
                                .as_ref()
                                .map(|e| format!(", last error: {e}"))
                                .unwrap_or_default()
                        );
                    }
                    None => {
                        let _ = writeln!(out, "  {}: never synced", d.id);
                    }
                }
            }
        }
        Ok(out)
    }

    #[tool(
        description = "Current state for a child: local time, downtime, active overrides, per-limit used/budget/remaining today (usage summed over all the child's devices) with the notification thresholds and those reached today, notification settings, the policy version served, and each device's agent version/versionCode, last sync, whether it has the served policy (\"policy up to date\" or \"policy behind: has X, served Y\") and its last error."
    )]
    async fn status(&self, Parameters(a): Parameters<ChildArgs>) -> Result<String, String> {
        let (c, devices, tz) = self.child_ctx(&a.child)?;
        let usage = self
            .st
            .db
            .usage(&devices, &Self::today(tz))
            .map_err(|e| e.to_string())?;
        let s = eval::status(&c, now_epoch(), &usage);
        let mut out = format!(
            "{} — {}\ndowntime now: {}\nlock: {}  unlock: {}  screen locked: {}\n",
            s.child, s.local_time, s.in_downtime, s.lock_active, s.unlock_active, s.screen_locked
        );
        match &c.notify {
            None => out.push_str("notifications: off\n"),
            Some(n) => {
                let _ = writeln!(
                    out,
                    "notifications: on ({}), downtime notice: {}",
                    n.locale,
                    if n.before_downtime_secs == 0 {
                        "none".to_string()
                    } else {
                        format!("{} before", hm(n.before_downtime_secs))
                    }
                );
            }
        }
        for l in &s.limits {
            let _ = write!(
                out,
                "limit {:<10} used {} / {}  remaining {}",
                l.name,
                hm(l.used_secs),
                hm(l.budget_secs),
                hm(l.remaining_secs)
            );
            if c.notify.is_some() {
                let list = |v: &[u8]| {
                    v.iter()
                        .map(|t| format!("{t}%"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                if l.notify_at.is_empty() {
                    out.push_str("  notify: none");
                } else {
                    let reached = if l.reached.is_empty() {
                        "none".to_string()
                    } else {
                        list(&l.reached)
                    };
                    let _ = write!(
                        out,
                        "  notify at {}, reached today: {reached}",
                        list(&l.notify_at)
                    );
                }
            }
            out.push('\n');
        }
        for o in &s.active_overrides {
            let _ = writeln!(
                out,
                "override: {}",
                serde_json::to_string(o).unwrap_or_default()
            );
        }
        let now = now_epoch();
        let served = policy::version(&c);
        let _ = writeln!(out, "policy served: version {served}");
        for d in &devices {
            match self.st.db.device(d).map_err(|e| e.to_string())? {
                Some(seen) => {
                    let _ = writeln!(
                        out,
                        "device {d}: {}, device_owner={}, last sync {} min ago, {}{}",
                        Self::agent(&seen),
                        seen.device_owner,
                        (now - seen.last_seen) / 60,
                        Self::policy_state(&seen, Ok(&served)),
                        seen.last_error
                            .as_ref()
                            .map(|e| format!(", last error: {e}"))
                            .unwrap_or_default()
                    );
                }
                None => {
                    let _ = writeln!(out, "device {d}: never synced");
                }
            }
        }
        out.push_str(&self.release_line());
        Ok(out)
    }

    #[tool(
        description = "Foreground time per app for a child on a given local date (default today), summed over devices, with app labels when known."
    )]
    async fn usage(&self, Parameters(a): Parameters<UsageArgs>) -> Result<String, String> {
        let (_, devices, tz) = self.child_ctx(&a.child)?;
        let date = a.date.unwrap_or_else(|| Self::today(tz));
        let usage = self
            .st
            .db
            .usage(&devices, &date)
            .map_err(|e| e.to_string())?;
        let labels = self.labels(&devices);
        let mut rows: Vec<_> = usage.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        let total: u64 = rows.iter().map(|r| r.1).sum();
        let mut out = format!("{} on {date}: total {}\n", a.child, hm(total));
        for (p, s) in rows {
            let _ = writeln!(
                out,
                "{:>6}  {}  ({p})",
                hm(s),
                labels.get(&p).map(String::as_str).unwrap_or("?")
            );
        }
        Ok(out)
    }

    #[tool(
        description = "Installed apps on the child's devices (label, package, user-installed, suspended now) and what the policy decides for each right now. Use it to find package names when editing the policy."
    )]
    async fn apps(&self, Parameters(a): Parameters<ChildArgs>) -> Result<String, String> {
        let (c, devices, tz) = self.child_ctx(&a.child)?;
        let usage = self
            .st
            .db
            .usage(&devices, &Self::today(tz))
            .map_err(|e| e.to_string())?;
        let now = now_epoch();
        let mut out = String::new();
        for d in &devices {
            let _ = writeln!(out, "== {d}");
            for app in self.st.db.apps(d).map_err(|e| e.to_string())? {
                let dec = eval::decide(&c, now, &usage, &app.package, app.user_installed).label();
                let _ = writeln!(
                    out,
                    "{:<28} {:<45} {}{} -> {dec}",
                    app.label,
                    app.package,
                    if app.user_installed { "user" } else { "system" },
                    if app.suspended { " [suspended]" } else { "" }
                );
            }
        }
        Ok(out)
    }

    #[tool(
        description = "The compiled policy currently served for a child (JSON, as devices receive it), with its version."
    )]
    async fn policy(&self, Parameters(a): Parameters<ChildArgs>) -> Result<String, String> {
        let (c, _, _) = self.child_ctx(&a.child)?;
        Ok(format!(
            "version {}\n{}",
            policy::version(&c),
            serde_json::to_string_pretty(&c).map_err(|e| e.to_string())?
        ))
    }

    #[tool(
        description = "Device events (boots, admin warnings, enforcement errors) for a child's devices."
    )]
    async fn events(&self, Parameters(a): Parameters<EventsArgs>) -> Result<String, String> {
        let (_, devices, tz) = self.child_ctx(&a.child)?;
        let since = now_epoch() - i64::from(a.hours.unwrap_or(24)) * 3600;
        let mut out = String::new();
        for d in &devices {
            for e in self.st.db.events(d, since).map_err(|e| e.to_string())? {
                let t = tz
                    .timestamp_opt(e.ts, 0)
                    .single()
                    .map(|t| t.format("%m-%d %H:%M").to_string())
                    .unwrap_or_default();
                let _ = writeln!(out, "{t} {d} {} {}", e.kind, e.detail);
            }
        }
        Ok(if out.is_empty() {
            "no events".into()
        } else {
            out
        })
    }

    #[tool(
        description = "Validate a policy (and optional overrides) YAML text before committing it. Returns the compiled JSON or the list of errors. Does not change anything."
    )]
    async fn validate(&self, Parameters(a): Parameters<ValidateArgs>) -> Result<String, String> {
        match policy::compile(&a.policy_yaml, a.overrides_yaml.as_deref(), now_epoch()) {
            Ok(c) => Ok(format!(
                "valid, version {}\n{}",
                policy::version(&c),
                serde_json::to_string_pretty(&c).unwrap_or_default()
            )),
            Err(e) => Err(format!("invalid:\n- {}", e.join("\n- "))),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        let instructions = if self.gitops.is_some() {
            "kidctl parental control. Read: list_children, status, usage, apps (package names), policy (served \
             version), events, policy_source (the YAML with comments). Change rules with the write tools: \
             add_override / remove_override / prune_overrides (temporary exceptions: extra time, lock, unlock), \
             approve_app, block_app, unblock_app, set_limit, set_downtime, set_device, and write_policy (whole \
             file, for anything else; pass the revision from policy_source). Each change is validated, committed \
             and pushed to the GitOps repo; phones apply it within about 2-3 minutes (check with `policy` that \
             the announced version is served). Use dry_run to preview a change."
        } else {
            "kidctl parental control (read-only). To change rules, edit <child>.yaml or \
             <child>.overrides.yaml in the gitops repo and push; use `validate` first."
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(instructions)
    }
}

#[cfg(test)]
mod tests {
    use super::{Requester, Server};

    #[test]
    fn policy_state_says_up_to_date_or_behind_and_why() {
        let seen = |has: &str, sent: Option<&str>| crate::db::DeviceSeen {
            id: "p".into(),
            last_seen: 0,
            agent_version: "0.3.0".into(),
            android_sdk: 37,
            device_owner: true,
            policy_version: has.into(),
            last_error: None,
            agent_version_code: Some(3),
            policy_served: sent.map(String::from),
        };
        assert_eq!(
            Server::policy_state(&seen("v2", Some("v2")), Ok("v2")),
            "policy up to date (v2)"
        );
        assert_eq!(
            Server::policy_state(&seen("v2", None), Ok("v2")),
            "policy up to date (v2)"
        );
        assert_eq!(
            Server::policy_state(&seen("v1", Some("v2")), Ok("v2")),
            "policy behind: has v1, served v2 (sent at the last sync, confirmed at the next)"
        );
        assert_eq!(
            Server::policy_state(&seen("", Some("v2")), Ok("v2")),
            "policy behind: has none, served v2 (sent at the last sync, confirmed at the next)"
        );
        for sent in [Some("v1"), None] {
            assert_eq!(
                Server::policy_state(&seen("v1", sent), Ok("v3")),
                "policy behind: has v1, served v3 (changed since the last sync, sent at the next)"
            );
        }
        assert_eq!(
            Server::policy_state(&seen("v1", None), Err("no policy")),
            "policy has v1, none served (no policy)"
        );
    }

    #[test]
    fn requester_names_the_client() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("oauth-clients.json");
        std::fs::write(
            &f,
            r#"{"clients":[{"client_id":"abc","client_name":"Claude\nCode\u0007 x"},{"client_id":"noname"}]}"#,
        )
        .unwrap();
        let r = |id: &str, file: Option<&std::path::Path>| {
            Requester {
                client_id: id.into(),
                clients_file: file.map(|p| p.to_path_buf()),
            }
            .describe()
        };
        // Control characters from a client-chosen name never reach a commit message.
        assert_eq!(r("abc", Some(&f)), "Claude Code x (OAuth client abc)");
        assert_eq!(r("noname", Some(&f)), "OAuth client noname");
        assert_eq!(r("abc", None), "OAuth client abc");
        assert_eq!(
            r("abc", Some(&dir.path().join("missing.json"))),
            "OAuth client abc"
        );
        assert_eq!(
            r(
                "https://claude.ai/oauth/claude-code-client-metadata",
                Some(&f)
            ),
            "OAuth client https://claude.ai/oauth/claude-code-client-metadata"
        );
        std::fs::write(&f, "not json").unwrap();
        assert_eq!(r("abc", Some(&f)), "OAuth client abc");
    }
}
