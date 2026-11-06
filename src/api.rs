//! Device sync API.
//!
//! `POST /api/v1/sync` with `Authorization: Bearer <device token>`. The device
//! reports today's usage (and its app list / events when they changed); the
//! server answers with the compiled policy (omitted when the device already has
//! that version) plus the usage of the child's *other* devices, so a budget is
//! shared across devices.
//!
//! Agent self-update: when a release is published (see `release`), the sync
//! response carries `agent: {version_code, version_name, sha256, size, url}`;
//! an older agent downloads `GET <url>` (same bearer token, plus
//! `X-Device-Id`), checks the SHA-256 and installs it as device owner.

use crate::config::{Config, Device, Store, now_epoch};
use crate::db::{App, Db, DeviceSeen, Event};
use crate::policy::{self, Compiled};
use crate::release::ReleaseStore;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::TimeZone;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

pub const SYNC_INTERVAL_SECS: u64 = 60;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub db: Db,
    pub guard: crate::guard::Guard,
    /// Agent release offered for self-update (none when not published).
    pub agent: ReleaseStore,
    /// GitOps writes for the MCP write tools (None: read-only MCP).
    pub gitops: Option<std::sync::Arc<crate::gitops::Gitops>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SyncRequest {
    pub device_id: String,
    pub agent_version: String,
    pub android_sdk: i64,
    pub device_owner: bool,
    /// Version the device currently enforces ("" if none).
    #[serde(default)]
    pub policy_version: String,
    /// Local date (policy timezone) the usage refers to, YYYY-MM-DD.
    pub date: String,
    #[serde(default)]
    pub usage: BTreeMap<String, u64>,
    /// Present only when the installed-app list changed since the last sync.
    #[serde(default)]
    pub apps: Option<Vec<AppReport>>,
    #[serde(default)]
    pub events: Vec<EventReport>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Android versionCode of the running agent (absent from agents older
    /// than self-update).
    #[serde(default)]
    pub agent_version_code: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AppReport {
    pub package: String,
    pub label: String,
    pub user_installed: bool,
    pub suspended: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventReport {
    pub ts: i64,
    pub kind: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub server_time: i64,
    pub policy_version: String,
    /// Null when `policy_version` equals the one the device sent.
    pub policy: Option<Compiled>,
    /// Today's usage on the child's other devices (added to local usage).
    pub other_usage: BTreeMap<String, u64>,
    pub sync_interval_secs: u64,
    /// Current agent release; absent when none is published. Agents older
    /// than self-update ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentOffer>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentOffer {
    pub version_code: i64,
    pub version_name: String,
    /// Lowercase hex SHA-256 the downloaded APK must have.
    pub sha256: String,
    pub size: u64,
    /// Download path, relative to the server URL the device is configured with.
    pub url: String,
}

pub const AGENT_PATH: &str = "/api/v1/agent";

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

pub fn router(st: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/v1/sync", post(sync))
        .route("/api/v1/agent/{version_code}", get(agent_apk))
        .with_state(st)
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}

/// The one device-authentication path (sync and agent download): device id +
/// bearer token whose SHA-256 is in devices.yaml. A failure is reported to the
/// guard (ban after repeated failures).
fn auth_device<'a>(
    st: &AppState,
    cfg: &'a Config,
    headers: &HeaderMap,
    device_id: &str,
) -> Option<&'a Device> {
    let got: [u8; 32] = Sha256::digest(bearer(headers).as_bytes()).into();
    let dev = cfg.devices.iter().find(|d| {
        d.id == device_id
            && hex::decode(&d.token_sha256)
                .is_ok_and(|want| bool::from(want.as_slice().ct_eq(&got)))
    });
    if dev.is_none() {
        st.guard.auth_failed(
            &crate::guard::client_ip(headers),
            "device token",
            std::time::Instant::now(),
        );
    }
    dev
}

/// `GET /api/v1/agent/<version_code>` (bearer token + `X-Device-Id`): the APK
/// of the current release. 404 when nothing or another version is published,
/// so a device never installs something it was not offered. Like sync, an
/// authenticated download is served even if the client IP is banned (the home
/// NAT); a bad token counts as an authentication failure.
async fn agent_apk(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(version_code): Path<String>,
) -> Response {
    let cfg = st.store.get();
    let device_id = headers
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(dev) = auth_device(&st, &cfg, &headers, device_id) else {
        return err(StatusCode::UNAUTHORIZED, "unknown device or bad token");
    };
    // Authenticated from here on.
    crate::guard::authenticated(agent_download(&st, dev, &version_code))
}

/// The download proper, for an authenticated device.
fn agent_download(st: &AppState, dev: &Device, version_code: &str) -> Response {
    let Some(rel) = st
        .agent
        .get()
        .filter(|r| version_code == r.meta.version_code.to_string())
    else {
        return err(StatusCode::NOT_FOUND, "no such agent release");
    };
    let ev = Event {
        ts: now_epoch(),
        kind: "agent_download".into(),
        detail: format!("version_code {}", rel.meta.version_code),
    };
    if let Err(e) = st.db.add_event(&dev.id, &ev) {
        eprintln!("db: agent download event: {e}");
    }
    eprintln!(
        "agent download: version_code {} by {}",
        rel.meta.version_code, dev.id
    );
    (
        [
            (
                header::CONTENT_TYPE,
                "application/vnd.android.package-archive".to_string(),
            ),
            (
                header::HeaderName::from_static("x-sha256"),
                rel.meta.sha256.clone(),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        // Bytes is reference counted: no copy per download.
        rel.bytes.clone(),
    )
        .into_response()
}

async fn sync(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SyncRequest>,
) -> Response {
    let cfg = st.store.get();
    let Some(dev) = auth_device(&st, &cfg, &headers, &req.device_id) else {
        return err(StatusCode::UNAUTHORIZED, "unknown device or bad token");
    };
    // Authenticated from here on: served even if the client IP is banned.
    crate::guard::authenticated(synced(&st, &cfg, dev, &req))
}

/// The sync proper, for an authenticated device.
fn synced(st: &AppState, cfg: &Config, dev: &Device, req: &SyncRequest) -> Response {
    let now = now_epoch();
    let compiled = match cfg.compiled(&dev.child, now) {
        Some(Ok(c)) => c,
        Some(Err(e)) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("policy invalid: {}", e.join("; ")),
            );
        }
        None => return err(StatusCode::INTERNAL_SERVER_ERROR, "no policy for child"),
    };
    if chrono::NaiveDate::parse_from_str(&req.date, "%Y-%m-%d").is_err() {
        return err(StatusCode::BAD_REQUEST, "date must be YYYY-MM-DD");
    }
    let version = policy::version(&compiled);
    let seen = DeviceSeen {
        id: dev.id.clone(),
        last_seen: now,
        agent_version: req.agent_version.clone(),
        android_sdk: req.android_sdk,
        device_owner: req.device_owner,
        policy_version: req.policy_version.clone(),
        last_error: req.last_error.clone(),
        agent_version_code: req.agent_version_code,
        policy_served: Some(version.clone()),
    };
    let apps: Option<Vec<App>> = req.apps.as_ref().map(|v| {
        v.iter()
            .map(|a| App {
                package: a.package.clone(),
                label: a.label.clone(),
                user_installed: a.user_installed,
                suspended: a.suspended,
            })
            .collect()
    });
    let events: Vec<Event> = req
        .events
        .iter()
        .map(|e| Event {
            ts: e.ts,
            kind: e.kind.clone(),
            detail: e.detail.clone(),
        })
        .collect();
    if let Err(e) = st
        .db
        .record_sync(&seen, &req.date, &req.usage, apps.as_deref(), &events)
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db: {e}"));
    }
    // Usage of the child's other devices, for the server's notion of "today".
    let tz: chrono_tz::Tz = compiled.timezone.parse().expect("validated");
    let today = tz
        .timestamp_opt(now, 0)
        .single()
        .expect("valid")
        .format("%Y-%m-%d")
        .to_string();
    let others: Vec<String> = cfg
        .devices
        .iter()
        .filter(|d| d.child == dev.child && d.id != dev.id)
        .map(|d| d.id.clone())
        .collect();
    let other_usage = if req.date == today {
        st.db.usage(&others, &today).unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let policy = (req.policy_version != version).then_some(compiled);
    let agent = st.agent.get().map(|r| AgentOffer {
        version_code: r.meta.version_code,
        version_name: r.meta.version_name.clone(),
        sha256: r.meta.sha256.clone(),
        size: r.bytes.len() as u64,
        url: format!("{AGENT_PATH}/{}", r.meta.version_code),
    });
    Json(SyncResponse {
        server_time: now,
        policy_version: version,
        policy,
        other_usage,
        sync_interval_secs: SYNC_INTERVAL_SECS,
        agent,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn setup() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("alex.yaml"),
            include_str!("../spec/vectors-policy.yaml"),
        )
        .unwrap();
        let sha = hex::encode(Sha256::digest(b"secret-token"));
        std::fs::write(
            dir.path().join("devices.yaml"),
            format!("devices:\n  - {{id: alex-phone, child: alex, token_sha256: {sha}}}\n  - {{id: alex-tablet, child: alex, token_sha256: {sha}}}\n"),
        )
        .unwrap();
        let store = Store::open(dir.path().to_path_buf()).unwrap();
        let agent = ReleaseStore::open(dir.path().join("agent"));
        (
            dir,
            AppState {
                store,
                db: Db::memory().unwrap(),
                guard: crate::guard::Guard::new(crate::guard::limits()),
                agent,
                gitops: None,
            },
        )
    }

    async fn call(
        st: &AppState,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::post("/api/v1/sync")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router(st.clone()).oneshot(req).await.unwrap();
        let code = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            code,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn today() -> String {
        chrono_tz::Europe::Brussels
            .timestamp_opt(now_epoch(), 0)
            .single()
            .unwrap()
            .format("%Y-%m-%d")
            .to_string()
    }

    #[tokio::test]
    async fn rejects_bad_token_and_unknown_device() {
        let (_d, st) = setup();
        let body = serde_json::json!({"device_id":"alex-phone","agent_version":"t","android_sdk":37,"device_owner":true,"date":today()});
        assert_eq!(
            call(&st, "wrong", body.clone()).await.0,
            StatusCode::UNAUTHORIZED
        );
        let mut other = body.clone();
        other["device_id"] = "nope".into();
        assert_eq!(
            call(&st, "secret-token", other).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn sync_returns_policy_then_omits_it_and_shares_usage() {
        let (_d, st) = setup();
        let t = today();
        let (code, r) = call(
            &st,
            "secret-token",
            serde_json::json!({"device_id":"alex-phone","agent_version":"t","android_sdk":37,"device_owner":true,
                "date":t,"usage":{"com.android.chrome":600},
                "apps":[{"package":"com.android.chrome","label":"Chrome","user_installed":false,"suspended":false}],
                "events":[{"ts":1,"kind":"boot"}]}),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "{r}");
        assert_eq!(r["policy"]["child"], "alex");
        let v = r["policy_version"].as_str().unwrap().to_string();
        // Same version -> no policy body; the other device sees pixel's usage.
        let (code, r2) = call(
            &st,
            "secret-token",
            serde_json::json!({"device_id":"alex-tablet","agent_version":"t","android_sdk":37,"device_owner":true,
                "policy_version":v,"date":t,"usage":{}}),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(r2["policy"].is_null());
        assert_eq!(r2["other_usage"]["com.android.chrome"], 600);
        assert_eq!(st.db.apps("alex-phone").unwrap().len(), 1);
        assert_eq!(st.db.events("alex-phone", 0).unwrap().len(), 1);
        assert!(st.db.device("alex-tablet").unwrap().is_some());
    }

    async fn download(
        st: &AppState,
        path: &str,
        token: &str,
        device: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut req =
            axum::http::Request::get(path).header("authorization", format!("Bearer {token}"));
        if let Some(d) = device {
            req = req.header("x-device-id", d);
        }
        let resp = router(st.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (code, h) = (resp.status(), resp.headers().clone());
        (
            code,
            h,
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    fn sync_body() -> serde_json::Value {
        serde_json::json!({"device_id":"alex-phone","agent_version":"0.1.0","agent_version_code":3,
            "android_sdk":37,"device_owner":true,"date":today()})
    }

    #[tokio::test]
    async fn no_release_no_agent_field_and_no_download() {
        let (_d, st) = setup();
        let (code, r) = call(&st, "secret-token", sync_body()).await;
        assert_eq!(code, StatusCode::OK);
        assert!(
            r.get("agent").is_none(),
            "agent must be absent without a release: {r}"
        );
        assert_eq!(
            st.db
                .device("alex-phone")
                .unwrap()
                .unwrap()
                .agent_version_code,
            Some(3)
        );
        let (code, _, _) =
            download(&st, "/api/v1/agent/4", "secret-token", Some("alex-phone")).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn release_is_offered_and_downloadable_by_authenticated_devices_only() {
        let (d, st) = setup();
        std::fs::create_dir(d.path().join("agent")).unwrap();
        let sha = crate::release::tests::publish(&d.path().join("agent"), 4, b"new agent");
        st.agent.reload();
        let (code, r) = call(&st, "secret-token", sync_body()).await;
        assert_eq!(code, StatusCode::OK);
        let offer: AgentOffer = serde_json::from_value(r["agent"].clone()).unwrap();
        assert_eq!(
            offer,
            AgentOffer {
                version_code: 4,
                version_name: "0.1.0".into(),
                sha256: sha.clone(),
                size: 13,
                url: "/api/v1/agent/4".into()
            }
        );
        let (code, h, body) = download(&st, &offer.url, "secret-token", Some("alex-phone")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, b"PK\x03\x04new agent");
        assert_eq!(hex::encode(Sha256::digest(&body)), sha);
        assert_eq!(h["x-sha256"], sha.as_str());
        assert_eq!(h["content-type"], "application/vnd.android.package-archive");
        assert_eq!(h["content-length"], "13");
        let ev = st.db.events("alex-phone", 0).unwrap();
        assert!(
            ev.iter()
                .any(|e| e.kind == "agent_download" && e.detail == "version_code 4"),
            "{ev:?}"
        );
        // Wrong token, unknown device, no device header: 401; other version: 404.
        assert_eq!(
            download(&st, &offer.url, "wrong", Some("alex-phone"))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            download(&st, &offer.url, "secret-token", Some("nope"))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            download(&st, &offer.url, "secret-token", None).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            download(&st, "/api/v1/agent/3", "secret-token", Some("alex-phone"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            download(&st, "/api/v1/agent/04", "secret-token", Some("alex-phone"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn old_agents_parse_new_responses_and_old_requests_still_accepted() {
        // A request without agent_version_code (agent older than self-update).
        let r: SyncRequest = serde_json::from_value(
            serde_json::json!({"device_id":"x","agent_version":"0.1.0","android_sdk":37,"device_owner":true,"date":"2026-10-18"}),
        )
        .unwrap();
        assert_eq!(r.agent_version_code, None);
    }
}
