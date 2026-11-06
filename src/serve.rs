//! One HTTP listener: device API (`/api/v1/sync`, `/api/v1/agent/<code>`),
//! `/healthz`, and the read-only MCP, reachable two independent ways:
//!
//! - OAuth 2.1 at `/mcp` (bearer token; the mcp-oauth crate makes this server
//!   its own authorization server: `/.well-known/oauth-protected-resource`,
//!   `/.well-known/oauth-authorization-server`, `/oauth/{register,authorize,
//!   token,revoke}`). For claude.ai custom connectors, Claude Code, ChatGPT.
//!   No or bad token -> 401 with `WWW-Authenticate: Bearer resource_metadata=..`.
//! - Legacy URL token at `/mcp/t/<token>` (token known only by its SHA-256;
//!   wrong token -> 404), for clients configured before OAuth.
//!
//! The whole app is wrapped once in [`guard::protect`] (rate limit, ban, body
//! cap, timeout, concurrency cap; unknown paths counted except harmless
//! probes) with the `AppState` guard, so OAuth failures, device-token failures,
//! legacy-token failures and scanner paths all count towards the same per-IP
//! ban. Authenticated responses carry `guard::Authenticated` (device API and
//! legacy MCP here, OAuth bearer and token responses in the crate) so that a
//! banned IP (the home NAT) keeps being served when it presents valid
//! credentials; anything else to a banned IP becomes 429.

use crate::api::{self, AppState};
use crate::guard;
use crate::mcp::{Requester, Server};
use axum::{
    Router,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Path of the OAuth-protected MCP endpoint (the protected resource is
/// `issuer + MCP_PATH`).
pub const MCP_PATH: &str = "/mcp";

/// How the MCP endpoints are authenticated. Neither set: MCP disabled (the
/// sync API runs anyway).
#[derive(Default)]
pub struct McpAuth {
    /// Legacy `/mcp/t/<token>`: SHA-256 of the URL token (`KIDCTL_MCP_TOKEN_SHA256`).
    pub legacy_token_sha256: Option<[u8; 32]>,
    /// OAuth 2.1 bearer tokens on `mcp_path` plus the metadata and `/oauth/*` endpoints.
    pub oauth: Option<mcp_oauth::Config>,
}

impl McpAuth {
    fn enabled(&self) -> bool {
        self.legacy_token_sha256.is_some() || self.oauth.is_some()
    }
}

type Svc = StreamableHttpService<Server, LocalSessionManager>;

struct McpState {
    /// OAuth endpoint: read tools, plus the write tools when GitOps is configured.
    svc: Svc,
    /// Legacy URL token: read tools only (a URL token is weaker than the
    /// owner's password; changing rules needs OAuth).
    legacy_svc: Svc,
    token_sha256: [u8; 32],
    guard: guard::Guard,
    /// `oauth-clients.json` in the OAuth state dir (client names for commits).
    clients_file: Option<std::path::PathBuf>,
}

/// Legacy URL token: a wrong token is an authentication failure (404); the
/// right one is marked authenticated (served even to a banned IP).
async fn mcp_legacy(
    State(st): State<Arc<McpState>>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    let got: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !bool::from(got.ct_eq(&st.token_sha256)) {
        st.guard.auth_failed(
            &guard::client_ip(req.headers()),
            "mcp token",
            std::time::Instant::now(),
        );
        return StatusCode::NOT_FOUND.into_response();
    }
    guard::authenticated(st.legacy_svc.handle(req).await.map(axum::body::Body::new))
}

/// Reached only through the OAuth bearer layer (which counts bad tokens,
/// marks the response of a valid one and puts its `Grant` in the request).
async fn mcp_bearer(State(st): State<Arc<McpState>>, mut req: Request) -> Response {
    if let Some(g) = req.extensions().get::<mcp_oauth::Grant>().cloned() {
        req.extensions_mut().insert(Requester {
            client_id: g.client_id,
            clients_file: st.clients_file.clone(),
        });
    }
    st.svc.handle(req).await.map(axum::body::Body::new)
}

/// The whole HTTP app. Fails only on an invalid OAuth config (issuer, password
/// hash, redirect patterns, unreadable state directory).
pub fn app(st: AppState, auth: McpAuth, allowed_hosts: Vec<String>) -> Result<Router, String> {
    let guard = st.guard.clone();
    let mut r = api::router(st.clone());
    if auth.enabled() {
        let mut cfg = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true);
        cfg = if allowed_hosts.is_empty() {
            cfg.disable_allowed_hosts()
        } else {
            cfg.with_allowed_hosts(allowed_hosts)
        };
        let st2 = st.clone();
        let svc = StreamableHttpService::new(
            move || Ok(Server::new(st.clone(), true)),
            Arc::new(LocalSessionManager::default()),
            cfg.clone(),
        );
        let legacy_svc = StreamableHttpService::new(
            move || Ok(Server::new(st2.clone(), false)),
            Arc::new(LocalSessionManager::default()),
            cfg,
        );
        let mcp_st = Arc::new(McpState {
            svc,
            legacy_svc,
            token_sha256: auth.legacy_token_sha256.unwrap_or_default(),
            guard: guard.clone(),
            clients_file: auth
                .oauth
                .as_ref()
                .map(|o| o.state_dir.join("oauth-clients.json")),
        });
        let mut m = Router::new();
        if auth.legacy_token_sha256.is_some() {
            m = m.route("/mcp/t/{token}", any(mcp_legacy));
        }
        let mut oauth_router = None;
        if let Some(oc) = auth.oauth {
            let path = oc.mcp_path.clone();
            let o = mcp_oauth::OAuth::new(oc)?;
            eprintln!(
                "oauth: protecting {} (metadata {})",
                o.resource(),
                o.resource_metadata_url()
            );
            m = m.route(&path, any(mcp_bearer).layer(o.bearer_layer()));
            oauth_router = Some(o.router());
        }
        r = r.merge(m.with_state(mcp_st));
        if let Some(o) = oauth_router {
            r = r.merge(o);
        }
    }
    // Rate limit + ban (all routes, OAuth included; shared-IP mode), body cap,
    // timeout, concurrency cap; unknown paths 404, counted unless harmless.
    Ok(guard::protect(r, guard))
}

pub async fn run(
    st: AppState,
    addr: &str,
    auth: McpAuth,
    allowed_hosts: Vec<String>,
) -> Result<(), String> {
    let mut endpoints = Vec::new();
    if let Some(o) = &auth.oauth {
        endpoints.push(format!(
            "MCP at {} (OAuth, issuer {})",
            o.mcp_path, o.issuer
        ));
    }
    if auth.legacy_token_sha256.is_some() {
        endpoints.push("MCP at /mcp/t/<token>".to_string());
    }
    if endpoints.is_empty() {
        endpoints.push(
            "MCP disabled: neither KIDCTL_OWNER_PASSWORD_HASH nor KIDCTL_MCP_TOKEN_SHA256"
                .to_string(),
        );
    }
    let app = app(st, auth, allowed_hosts)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("{addr}: {e}"))?;
    eprintln!(
        "kidctl listening on http://{} (sync API; {})",
        listener.local_addr().map_err(|e| e.to_string())?,
        endpoints.join("; ")
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        })
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Store,
        db::Db,
        guard::{Guard, Limits},
    };
    use axum::{
        body::Body,
        http::{HeaderMap, header},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use std::sync::OnceLock;
    use tower::ServiceExt;

    const PW: &str = "correct horse battery staple";
    const ISSUER: &str = "https://kidctl.test";
    const CB: &str = "http://localhost:33418/callback"; // Claude Code loopback
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const IP: &str = "198.51.100.7";
    const DEVICE_TOKEN: &str = "device-token";

    /// argon2id is deliberately slow: hash once for all tests.
    fn pw_hash() -> &'static str {
        static H: OnceLock<String> = OnceLock::new();
        H.get_or_init(|| mcp_oauth::hash_password(PW).unwrap())
    }

    fn oauth_config(state_dir: &std::path::Path) -> mcp_oauth::Config {
        mcp_oauth::Config {
            issuer: ISSUER.into(),
            mcp_path: MCP_PATH.into(),
            owner_password_hash: pw_hash().into(),
            state_dir: state_dir.to_path_buf(),
            redirect_patterns: mcp_oauth::DEFAULT_REDIRECT_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            resource_name: "kidctl".into(),
            cimd_allowlist: None,
        }
    }

    /// Config dir (policy `alex`, device `alex-phone` with [`DEVICE_TOKEN`],
    /// agent release dir), OAuth state dir, and the app built on them.
    struct T {
        config: tempfile::TempDir,
        state: tempfile::TempDir,
        limits: Limits,
        app: Router,
        /// The app's guard (shared state).
        guard: Guard,
        legacy: String,
    }

    fn state(dir: &std::path::Path, limits: Limits) -> AppState {
        AppState {
            store: Store::open(dir.to_path_buf()).unwrap(),
            db: Db::memory().unwrap(),
            guard: Guard::new(limits),
            agent: crate::release::ReleaseStore::open(dir.join("agent")),
            gitops: None,
        }
    }

    /// `publish`: agent releases (version code, payload) published before the
    /// app is built (the release store loads at open).
    fn setup_with(
        limits: Limits,
        legacy: bool,
        oauth: bool,
        publish: &[(i64, &[u8])],
    ) -> (T, Vec<String>) {
        let config = tempfile::tempdir().unwrap();
        std::fs::write(
            config.path().join("alex.yaml"),
            include_str!("../spec/vectors-policy.yaml"),
        )
        .unwrap();
        let dev_sha = hex::encode(Sha256::digest(DEVICE_TOKEN.as_bytes()));
        std::fs::write(
            config.path().join("devices.yaml"),
            format!("devices:\n  - {{id: alex-phone, child: alex, token_sha256: {dev_sha}}}\n"),
        )
        .unwrap();
        std::fs::create_dir(config.path().join("agent")).unwrap();
        let shas = publish
            .iter()
            .map(|(code, p)| crate::release::tests::publish(&config.path().join("agent"), *code, p))
            .collect();
        let state_dir = tempfile::tempdir().unwrap();
        let token = "good-token".to_string();
        let auth = McpAuth {
            legacy_token_sha256: legacy.then(|| Sha256::digest(token.as_bytes()).into()),
            oauth: oauth.then(|| oauth_config(state_dir.path())),
        };
        let st = state(config.path(), limits.clone());
        let guard = st.guard.clone();
        let app = app(st, auth, vec![]).unwrap();
        (
            T {
                config,
                state: state_dir,
                limits,
                app,
                guard,
                legacy: token,
            },
            shas,
        )
    }

    fn setup(limits: Limits, legacy: bool, oauth: bool) -> T {
        setup_with(limits, legacy, oauth, &[]).0
    }

    impl T {
        /// Same config and OAuth state directory, fresh process state (restart).
        fn restart(&self) -> Router {
            let auth = McpAuth {
                legacy_token_sha256: None,
                oauth: Some(oauth_config(self.state.path())),
            };
            app(state(self.config.path(), self.limits.clone()), auth, vec![]).unwrap()
        }
    }

    /// kidctl's production limits (shared-IP mode, unknown paths counted).
    fn lim() -> Limits {
        guard::limits()
    }

    struct Resp {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    async fn send(app: &Router, req: axum::http::Request<Body>) -> Resp {
        let r = app.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let headers = r.headers().clone();
        let body = axum::body::to_bytes(r.into_body(), 64 << 20).await.unwrap();
        Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    fn get(path: &str, ip: &str) -> axum::http::Request<Body> {
        axum::http::Request::get(path)
            .header("cf-connecting-ip", ip)
            .body(Body::empty())
            .unwrap()
    }

    fn req(method: &str, path: &str, ip: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("cf-connecting-ip", ip)
            .body(Body::empty())
            .unwrap()
    }

    async fn status(app: &Router, r: axum::http::Request<Body>) -> StatusCode {
        app.clone().oneshot(r).await.unwrap().status()
    }

    fn form(path: &str, ip: &str, pairs: &[(&str, &str)]) -> axum::http::Request<Body> {
        axum::http::Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("cf-connecting-ip", ip)
            .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
            .unwrap()
    }

    fn json_post(path: &str, ip: &str, body: String) -> axum::http::Request<Body> {
        axum::http::Request::post(path)
            .header(header::HOST, "kidctl.test")
            .header("cf-connecting-ip", ip)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(Body::from(body))
            .unwrap()
    }

    fn mcp_req(
        path: &str,
        ip: &str,
        bearer: Option<&str>,
        body: String,
    ) -> axum::http::Request<Body> {
        let mut r = json_post(path, ip, body);
        if let Some(t) = bearer {
            r.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {t}").parse().unwrap(),
            );
        }
        r
    }

    async fn post(app: &Router, path: &str, ip: &str, body: String) -> StatusCode {
        send(app, json_post(path, ip, body)).await.status
    }

    /// A well-formed sync from `alex-phone` with the given bearer token.
    fn sync_req(ip: &str, token: Option<&str>) -> axum::http::Request<Body> {
        let body = r#"{"device_id":"alex-phone","agent_version":"t","android_sdk":37,"device_owner":true,"date":"2026-10-17"}"#;
        mcp_req("/api/v1/sync", ip, token, body.into())
    }

    async fn sync(app: &Router, ip: &str, token: Option<&str>) -> StatusCode {
        status(app, sync_req(ip, token)).await
    }

    /// A sync from an unknown device (always an authentication failure).
    const UNKNOWN_SYNC: &str = r#"{"device_id":"x","agent_version":"x","android_sdk":37,"device_owner":true,"date":"2026-10-17"}"#;

    /// `GET` an agent APK as device `alex-phone` with the given bearer token.
    fn agent_req(path: &str, ip: &str, token: &str) -> axum::http::Request<Body> {
        axum::http::Request::get(path)
            .header("cf-connecting-ip", ip)
            .header("authorization", format!("Bearer {token}"))
            .header("x-device-id", "alex-phone")
            .body(Body::empty())
            .unwrap()
    }

    fn tools_list() -> String {
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.into()
    }

    fn tools_call(name: &str, args: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
        )
    }

    fn hidden_value(html: &str, name: &str) -> String {
        let pat = format!("name=\"{name}\" value=\"");
        let i = html
            .find(&pat)
            .unwrap_or_else(|| panic!("no hidden {name} in {html}"))
            + pat.len();
        html[i..i + html[i..].find('"').unwrap()].to_string()
    }

    fn query_param(url: &str, k: &str) -> Option<String> {
        let q = url.split_once('?')?.1;
        serde_urlencoded::from_str::<Vec<(String, String)>>(q)
            .ok()?
            .into_iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v)
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or_else(|e| panic!("{e}: {s}"))
    }

    async fn register(app: &Router, ip: &str, body: &str) -> serde_json::Value {
        let r = send(app, json_post("/oauth/register", ip, body.into())).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        json(&r.body)
    }

    fn authorize_params<'a>(client_id: &'a str, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
        vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", CB),
            ("state", "st-1"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("scope", "mcp"),
            ("resource", "https://kidctl.test/mcp"),
        ]
    }

    /// register (public client, like Claude Code) -> authorize (login + consent) -> code.
    async fn client_and_code(app: &Router, ip: &str) -> (String, String) {
        let c = register(
            app,
            ip,
            &format!(r#"{{"client_name":"Claude Code","redirect_uris":["{CB}"],"token_endpoint_auth_method":"none"}}"#),
        )
        .await;
        let client_id = c["client_id"].as_str().unwrap().to_string();
        let challenge = B64.encode(Sha256::digest(VERIFIER.as_bytes()));
        let params = authorize_params(&client_id, &challenge);
        let q = serde_urlencoded::to_string(&params).unwrap();
        let r = send(app, get(&format!("/oauth/authorize?{q}"), ip)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(
            r.body.contains("kidctl"),
            "login page names the resource: {}",
            r.body
        );
        let mut login = params.clone();
        login.extend([("step", "login"), ("password", PW)]);
        let r = send(app, form("/oauth/authorize", ip, &login)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let ticket = hidden_value(&r.body, "ticket");
        let consent = [
            ("step", "consent"),
            ("ticket", ticket.as_str()),
            ("decision", "allow"),
        ];
        let r = send(app, form("/oauth/authorize", ip, &consent)).await;
        assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
        let loc = r.headers[header::LOCATION].to_str().unwrap().to_string();
        assert!(loc.starts_with(&format!("{CB}?")), "{loc}");
        assert_eq!(query_param(&loc, "state").as_deref(), Some("st-1"));
        assert_eq!(query_param(&loc, "iss").as_deref(), Some(ISSUER));
        (client_id, query_param(&loc, "code").unwrap())
    }

    fn exchange<'a>(
        client_id: &'a str,
        code: &'a str,
        verifier: &'a str,
    ) -> Vec<(&'a str, &'a str)> {
        vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CB),
            ("client_id", client_id),
            ("code_verifier", verifier),
            ("resource", "https://kidctl.test/mcp"),
        ]
    }

    /// Full flow; returns (client_id, access token, refresh token).
    async fn login(app: &Router, ip: &str) -> (String, String, String) {
        let (client_id, code) = client_and_code(app, ip).await;
        let r = send(
            app,
            form("/oauth/token", ip, &exchange(&client_id, &code, VERIFIER)),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let t = json(&r.body);
        assert_eq!(t["token_type"], "Bearer");
        (
            client_id,
            t["access_token"].as_str().unwrap().into(),
            t["refresh_token"].as_str().unwrap().into(),
        )
    }

    fn tool_names(body: &str) -> Vec<String> {
        json(body)["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Ban `ip` with `n` scanner probes (unknown paths count).
    async fn ban_with_scanner_paths(app: &Router, ip: &str, n: u32) {
        for i in 0..n {
            let p = if i % 2 == 0 { "/wp-login.php" } else { "/.env" };
            assert_eq!(
                status(app, get(p, ip)).await,
                StatusCode::NOT_FOUND,
                "probe {i} {p}"
            );
        }
        assert_eq!(
            status(app, get("/wp-login.php", ip)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{ip} banned"
        );
    }

    // ------------------------------------------------------------ OAuth

    #[tokio::test]
    async fn unauthenticated_mcp_gets_401_with_resource_metadata() {
        let t = setup(lim(), true, true);
        for method in ["POST", "GET"] {
            let mut req = mcp_req("/mcp", IP, None, tools_list());
            *req.method_mut() = method.parse().unwrap();
            let r = send(&t.app, req).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{method}");
            assert_eq!(
                r.headers[header::WWW_AUTHENTICATE],
                r#"Bearer resource_metadata="https://kidctl.test/.well-known/oauth-protected-resource""#
            );
        }
        // A bearer token we never issued: invalid_token in the challenge.
        let r = send(
            &t.app,
            mcp_req("/mcp", IP, Some("not-a-token"), tools_list()),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            r.headers[header::WWW_AUTHENTICATE],
            r#"Bearer error="invalid_token", resource_metadata="https://kidctl.test/.well-known/oauth-protected-resource""#
        );
        // Requests without a token never count (first contact of every client).
        for _ in 0..15 {
            assert_eq!(
                send(&t.app, mcp_req("/mcp", "192.0.2.1", None, tools_list()))
                    .await
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn metadata_endpoints_reachable() {
        let t = setup(lim(), false, true);
        for p in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let r = send(&t.app, get(p, IP)).await;
            assert_eq!(r.status, StatusCode::OK, "{p}");
            let v = json(&r.body);
            assert_eq!(v["resource"], "https://kidctl.test/mcp");
            assert_eq!(v["authorization_servers"][0], ISSUER);
            assert_eq!(v["resource_name"], "kidctl");
        }
        let r = send(&t.app, get("/.well-known/oauth-authorization-server", IP)).await;
        assert_eq!(r.status, StatusCode::OK);
        let v = json(&r.body);
        assert_eq!(v["issuer"], ISSUER);
        assert_eq!(
            v["authorization_endpoint"],
            "https://kidctl.test/oauth/authorize"
        );
        assert_eq!(v["token_endpoint"], "https://kidctl.test/oauth/token");
        assert_eq!(
            v["registration_endpoint"],
            "https://kidctl.test/oauth/register"
        );
        assert_eq!(v["code_challenge_methods_supported"][0], "S256");
        // Discovery URLs this server does not serve: plain 404, never counted
        // (harmless probes, see discovery_probes_never_count).
        for p in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/mcp",
        ] {
            assert_eq!(
                send(&t.app, get(p, IP)).await.status,
                StatusCode::NOT_FOUND,
                "{p}"
            );
        }
    }

    #[tokio::test]
    async fn oauth_flow_then_mcp_tools() {
        let t = setup(lim(), true, true);
        // Wrong PKCE verifier: invalid_grant, and the code is burnt.
        let (client_id, code) = client_and_code(&t.app, IP).await;
        let r = send(
            &t.app,
            form(
                "/oauth/token",
                IP,
                &exchange(&client_id, &code, &"x".repeat(43)),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(r.body.contains("invalid_grant"), "{}", r.body);
        let r = send(
            &t.app,
            form("/oauth/token", IP, &exchange(&client_id, &code, VERIFIER)),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "code is single use");

        let (client_id, access, refresh) = login(&t.app, IP).await;
        let r = send(&t.app, mcp_req("/mcp", IP, Some(&access), tools_list())).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let names = tool_names(&r.body);
        for want in [
            "list_children",
            "status",
            "usage",
            "apps",
            "policy",
            "events",
            "validate",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} in {names:?}");
        }
        let r = send(
            &t.app,
            mcp_req(
                "/mcp",
                IP,
                Some(&access),
                tools_call("status", r#"{"child":"alex"}"#),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(r.body.contains("limit social"), "{}", r.body);
        // spec/vectors-policy.yaml has notify on: settings and thresholds per limit.
        for want in [
            "notifications: on (fr), downtime notice: 0h05m00s before",
            "notify at 50% 80% 95%, reached today: none",
            "notify at 90%, reached today: none",
            "notify: none",
        ] {
            assert!(r.body.contains(want), "{want:?} in {}", r.body);
        }

        // The legacy URL token keeps working next to OAuth.
        let r = send(
            &t.app,
            mcp_req(&format!("/mcp/t/{}", t.legacy), IP, None, tools_list()),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);

        // Tokens survive a restart (state dir reloaded); refresh rotates.
        let app2 = t.restart();
        assert_eq!(
            send(&app2, mcp_req("/mcp", IP, Some(&access), tools_list()))
                .await
                .status,
            StatusCode::OK
        );
        let rf = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", client_id.as_str()),
        ];
        let r = send(&app2, form("/oauth/token", IP, &rf)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let access2 = json(&r.body)["access_token"].as_str().unwrap().to_string();
        assert_eq!(
            send(&app2, mcp_req("/mcp", IP, Some(&access), tools_list()))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app2, mcp_req("/mcp", IP, Some(&access2), tools_list()))
                .await
                .status,
            StatusCode::OK
        );

        // Revocation.
        assert_eq!(
            send(
                &app2,
                form("/oauth/revoke", IP, &[("token", access2.as_str())])
            )
            .await
            .status,
            StatusCode::OK
        );
        assert_eq!(
            send(&app2, mcp_req("/mcp", IP, Some(&access2), tools_list()))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );

        // Only digests at rest.
        let stored = std::fs::read_to_string(t.state.path().join("oauth-tokens.json")).unwrap();
        assert!(!stored.contains(&access) && !stored.contains(&refresh));
    }

    #[tokio::test]
    async fn invalid_bearer_tokens_are_counted_and_ban_but_valid_bearer_still_served() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            false,
            true,
        );
        let (client_id, access, refresh) = login(&t.app, "1.1.1.1").await;
        for _ in 0..3 {
            let r = send(
                &t.app,
                mcp_req("/mcp", "6.6.6.6", Some("guessed-token"), tools_list()),
            )
            .await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        }
        // Banned now: forged or missing tokens get 429, on every path...
        for bearer in [Some("guessed-token"), None] {
            let r = send(&t.app, mcp_req("/mcp", "6.6.6.6", bearer, tools_list())).await;
            assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{bearer:?}");
        }
        assert_eq!(
            send(
                &t.app,
                form("/oauth/token", "6.6.6.6", &[("grant_type", "x")])
            )
            .await
            .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            sync(&t.app, "6.6.6.6", None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/wp-login.php", "6.6.6.6")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // ...but a valid OAuth bearer on /mcp is served (the home NAT), and so
        // is a valid device token (one ban state, shared-IP mode for both).
        let r = send(
            &t.app,
            mcp_req(
                "/mcp",
                "6.6.6.6",
                Some(&access),
                tools_call("status", r#"{"child":"alex"}"#),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(r.body.contains("limit social"), "{}", r.body);
        assert_eq!(
            sync(&t.app, "6.6.6.6", Some(DEVICE_TOKEN)).await,
            StatusCode::OK
        );
        // The metadata documents (fetched again before a refresh) and a valid
        // refresh are served too.
        assert_eq!(
            send(
                &t.app,
                get("/.well-known/oauth-protected-resource", "6.6.6.6")
            )
            .await
            .status,
            StatusCode::OK
        );
        let rf = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", client_id.as_str()),
        ];
        let r = send(&t.app, form("/oauth/token", "6.6.6.6", &rf)).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let access2 = json(&r.body)["access_token"].as_str().unwrap().to_string();
        assert_eq!(
            send(
                &t.app,
                mcp_req("/mcp", "6.6.6.6", Some(&access2), tools_list())
            )
            .await
            .status,
            StatusCode::OK
        );
        // The owner password is not even checked for a banned IP: 429.
        let challenge = B64.encode(Sha256::digest(VERIFIER.as_bytes()));
        let mut login_form = authorize_params(&client_id, &challenge);
        login_form.extend([("step", "login"), ("password", PW)]);
        assert_eq!(
            send(&t.app, form("/oauth/authorize", "6.6.6.6", &login_form))
                .await
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Other IPs unaffected; health probes exempt.
        assert_eq!(
            send(
                &t.app,
                mcp_req("/mcp", "1.1.1.1", Some(&access2), tools_list())
            )
            .await
            .status,
            StatusCode::OK
        );
        assert_eq!(
            send(&t.app, get("/healthz", "6.6.6.6")).await.status,
            StatusCode::OK,
            "probes stay exempt"
        );
    }

    #[tokio::test]
    async fn device_token_failures_ban_but_oauth_bearer_still_served() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            false,
            true,
        );
        let (_, access, _) = login(&t.app, "1.1.1.1").await;
        for _ in 0..3 {
            assert_eq!(
                post(&t.app, "/api/v1/sync", "6.6.6.6", UNKNOWN_SYNC.into()).await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            post(&t.app, "/api/v1/sync", "6.6.6.6", UNKNOWN_SYNC.into()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            send(
                &t.app,
                mcp_req("/mcp", "6.6.6.6", Some(&access), tools_list())
            )
            .await
            .status,
            StatusCode::OK
        );
        assert_eq!(
            send(
                &t.app,
                mcp_req("/mcp", "6.6.6.6", Some("forged"), tools_list())
            )
            .await
            .status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn wrong_password_and_client_secret_are_counted() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            false,
            true,
        );
        let ip = "5.5.5.5";
        let c = register(
            &t.app,
            ip,
            &format!(
                r#"{{"redirect_uris":["{CB}"],"token_endpoint_auth_method":"client_secret_post"}}"#
            ),
        )
        .await;
        let id = c["client_id"].as_str().unwrap().to_string();
        assert!(c["client_secret"].is_string());
        let login = [
            ("response_type", "code"),
            ("client_id", id.as_str()),
            ("redirect_uri", CB),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
            ("step", "login"),
            ("password", "guess-guess-guess"),
        ];
        for _ in 0..2 {
            let r = send(&t.app, form("/oauth/authorize", ip, &login)).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED);
            assert!(r.body.contains("Wrong password"));
        }
        let bad_secret = [
            ("grant_type", "authorization_code"),
            ("code", "x"),
            ("client_id", id.as_str()),
            ("client_secret", "wrong"),
        ];
        let r = send(&t.app, form("/oauth/token", ip, &bad_secret)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(r.body.contains("invalid_client"), "{}", r.body);
        // 2 passwords + 1 client secret = 3 failures: banned.
        let q = format!("/oauth/authorize?response_type=code&client_id={id}");
        assert_eq!(
            send(&t.app, get(&q, ip)).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            send(&t.app, form("/oauth/authorize", ip, &login))
                .await
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );

        // Unknown clients are rejected (error page / invalid_client), never redirected.
        let r = send(
            &t.app,
            get(
                "/oauth/authorize?response_type=code&client_id=nope",
                "4.3.2.1",
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert!(r.headers.get(header::LOCATION).is_none());
        let r = send(
            &t.app,
            form(
                "/oauth/token",
                "4.3.2.1",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", "x"),
                    ("client_id", "nope"),
                ],
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert!(r.body.contains("invalid_client"));
        // Unregistered redirect URI: refused at registration.
        let r = send(
            &t.app,
            json_post(
                "/oauth/register",
                "4.3.2.1",
                r#"{"redirect_uris":["https://evil.example/cb"]}"#.into(),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oauth_endpoints_go_through_the_guard() {
        let t = setup(
            Limits {
                per_ip_burst: 3.0,
                per_ip_per_min: 0.001,
                ..lim()
            },
            false,
            true,
        );
        for _ in 0..3 {
            assert_eq!(
                send(
                    &t.app,
                    get("/.well-known/oauth-authorization-server", "2.2.2.2")
                )
                .await
                .status,
                StatusCode::OK
            );
        }
        let r = send(
            &t.app,
            get("/.well-known/oauth-protected-resource", "2.2.2.2"),
        )
        .await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers["retry-after"], "30");
        for (path, req) in [
            (
                "register",
                json_post("/oauth/register", "2.2.2.2", "{}".into()),
            ),
            ("authorize", get("/oauth/authorize", "2.2.2.2")),
            ("token", form("/oauth/token", "2.2.2.2", &[])),
            ("revoke", form("/oauth/revoke", "2.2.2.2", &[])),
            ("mcp", mcp_req("/mcp", "2.2.2.2", None, tools_list())),
        ] {
            assert_eq!(
                send(&t.app, req).await.status,
                StatusCode::TOO_MANY_REQUESTS,
                "{path}"
            );
        }
        assert_eq!(
            send(
                &t.app,
                get("/.well-known/oauth-authorization-server", "3.3.3.3")
            )
            .await
            .status,
            StatusCode::OK
        );
        // Body cap applies to the OAuth endpoints too.
        let big = format!(
            r#"{{"redirect_uris":["{CB}"],"client_name":"{}"}}"#,
            "x".repeat(2 * 1024 * 1024)
        );
        assert_eq!(
            send(&t.app, json_post("/oauth/register", "3.3.3.4", big))
                .await
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn mcp_disabled_without_auth() {
        let t = setup(lim(), false, false);
        for p in [
            "/mcp",
            "/mcp/t/good-token",
            "/.well-known/oauth-protected-resource",
            "/oauth/register",
        ] {
            assert_eq!(
                post(&t.app, p, IP, tools_list()).await,
                StatusCode::NOT_FOUND,
                "{p}"
            );
        }
        assert_eq!(
            post(&t.app, "/api/v1/sync", IP, UNKNOWN_SYNC.into()).await,
            StatusCode::UNAUTHORIZED,
            "sync API still served"
        );
    }

    #[test]
    fn invalid_oauth_config_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("devices.yaml"), "devices: []\n").unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let mut bad = oauth_config(state_dir.path());
        bad.issuer = "http://kidctl.example".into();
        let e = app(
            state(dir.path(), lim()),
            McpAuth {
                legacy_token_sha256: None,
                oauth: Some(bad),
            },
            vec![],
        )
        .err()
        .unwrap();
        assert!(e.contains("https"), "{e}");
        let mut bad = oauth_config(state_dir.path());
        bad.owner_password_hash = "plaintext".into();
        assert!(
            app(
                state(dir.path(), lim()),
                McpAuth {
                    legacy_token_sha256: None,
                    oauth: Some(bad)
                },
                vec![]
            )
            .is_err()
        );
    }

    // ------------------------------------------------- legacy MCP URL token

    #[tokio::test]
    async fn legacy_token_works_bad_tokens_get_banned_good_token_still_served() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            false,
        );
        let good = format!("/mcp/t/{}", t.legacy);
        assert_eq!(
            post(&t.app, &good, "1.1.1.1", tools_list()).await,
            StatusCode::OK
        );
        for _ in 0..3 {
            assert_eq!(
                post(&t.app, "/mcp/t/guess", "6.6.6.6", tools_list()).await,
                StatusCode::NOT_FOUND
            );
        }
        // Banned now: further guesses get 429, but the right token is still
        // served (a ban never locks out an authenticated client); other IPs
        // unaffected.
        assert_eq!(
            post(&t.app, "/mcp/t/guess", "6.6.6.6", tools_list()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            post(&t.app, &good, "6.6.6.6", tools_list()).await,
            StatusCode::OK
        );
        assert_eq!(
            post(&t.app, &good, "1.1.1.1", tools_list()).await,
            StatusCode::OK
        );
        // OAuth off: no /mcp, no metadata.
        assert_eq!(
            post(&t.app, "/mcp", "1.1.1.1", tools_list()).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(
                &t.app,
                get("/.well-known/oauth-protected-resource", "1.1.1.1")
            )
            .await
            .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn banned_ip_still_serves_valid_mcp_token() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
        );
        ban_with_scanner_paths(&t.app, "9.9.9.9", 3).await;
        assert_eq!(
            post(
                &t.app,
                &format!("/mcp/t/{}", t.legacy),
                "9.9.9.9",
                tools_list()
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            post(&t.app, "/mcp/t/guess", "9.9.9.9", tools_list()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/robots.txt", "9.9.9.9")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    // ------------------------------------------- unknown paths, harmless probes

    #[tokio::test]
    async fn harmless_paths_never_count_as_failures() {
        // Production failure threshold; a big bucket so only the ban is tested.
        let t = setup(
            Limits {
                per_ip_burst: 1000.0,
                ..lim()
            },
            true,
            true,
        );
        for path in [
            "/",
            "/favicon.ico",
            "/robots.txt",
            "/.well-known/openid-configuration",
            "/.well-known/security.txt",
        ] {
            for method in ["GET", "HEAD"] {
                for _ in 0..20 {
                    let code = status(&t.app, req(method, path, "5.5.5.5")).await;
                    assert_eq!(code, StatusCode::NOT_FOUND, "{method} {path}");
                }
            }
        }
        // 200 harmless requests later the IP is not banned: a probe still gets
        // a plain 404 and a sync with the right token works.
        assert_eq!(
            status(&t.app, get("/wp-login.php", "5.5.5.5")).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            sync(&t.app, "5.5.5.5", Some(DEVICE_TOKEN)).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn scanner_probes_still_ban_at_the_threshold() {
        let t = setup(lim(), true, true);
        ban_with_scanner_paths(&t.app, "7.7.7.7", 10).await;
        assert_eq!(
            status(&t.app, get("/", "7.7.7.7")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "banned IP: 429 everywhere"
        );
        assert_eq!(
            status(&t.app, get("/.env", "8.8.4.4")).await,
            StatusCode::NOT_FOUND,
            "other IPs unaffected"
        );
    }

    #[tokio::test]
    async fn scanner_paths_and_bad_device_tokens_count_as_failures() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
        );
        assert_eq!(
            post(&t.app, "/wp-login.php", "7.7.7.7", String::new()).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(&t.app, "/.env", "7.7.7.7", String::new()).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post(&t.app, "/api/v1/sync", "7.7.7.7", UNKNOWN_SYNC.into()).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&t.app, "/api/v1/sync", "7.7.7.7", UNKNOWN_SYNC.into()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Unknown paths under /mcp count too; a 405 on a known route does not.
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
        );
        for _ in 0..5 {
            assert_eq!(
                status(&t.app, get("/api/v1/sync", "7.7.7.8")).await,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        for _ in 0..3 {
            assert_eq!(
                post(&t.app, "/mcp/x", "7.7.7.8", String::new()).await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            post(&t.app, "/mcp/x", "7.7.7.8", String::new()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    // ------------------------------------------------------- device API

    #[tokio::test]
    async fn banned_ip_still_serves_valid_device_token_only() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
        );
        ban_with_scanner_paths(&t.app, "6.6.6.6", 3).await;
        // Valid device token: normal sync despite the ban (home NAT case).
        assert_eq!(
            sync(&t.app, "6.6.6.6", Some(DEVICE_TOKEN)).await,
            StatusCode::OK
        );
        // Anything unauthenticated from the banned IP: 429.
        assert_eq!(
            sync(&t.app, "6.6.6.6", Some("wrong")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            sync(&t.app, "6.6.6.6", None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        let bad_body = mcp_req("/api/v1/sync", "6.6.6.6", Some(DEVICE_TOKEN), "{".into());
        assert_eq!(
            status(&t.app, bad_body).await,
            StatusCode::TOO_MANY_REQUESTS,
            "unparsed request is not authenticated"
        );
        assert_eq!(
            status(&t.app, get("/api/v1/sync", "6.6.6.6")).await,
            StatusCode::TOO_MANY_REQUESTS,
            "405 path"
        );
        assert_eq!(
            status(&t.app, get("/", "6.6.6.6")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/favicon.ico", "6.6.6.6")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/wp-login.php", "6.6.6.6")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            post(&t.app, "/mcp/t/guess", "6.6.6.6", tools_list()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            send(&t.app, mcp_req("/mcp", "6.6.6.6", None, tools_list()))
                .await
                .status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/healthz", "6.6.6.6")).await,
            StatusCode::OK
        );
        // And the valid device keeps working afterwards.
        assert_eq!(
            sync(&t.app, "6.6.6.6", Some(DEVICE_TOKEN)).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn failures_while_banned_do_not_extend_the_ban() {
        let t = setup(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
        );
        ban_with_scanner_paths(&t.app, "6.6.6.6", 3).await;
        let banned_at = std::time::Instant::now();
        assert!(t.guard.is_banned("6.6.6.6", banned_at));
        // Later failures of every kind while banned: none is counted.
        std::thread::sleep(std::time::Duration::from_millis(100));
        for _ in 0..5 {
            assert_eq!(
                status(&t.app, get("/.env", "6.6.6.6")).await,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                sync(&t.app, "6.6.6.6", Some("wrong")).await,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                post(&t.app, "/mcp/t/guess", "6.6.6.6", tools_list()).await,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                send(
                    &t.app,
                    mcp_req("/mcp", "6.6.6.6", Some("forged"), tools_list())
                )
                .await
                .status,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        // The ban still ends one hour after it started (a failure 100 ms later
        // that extended it would keep the IP banned past that).
        let hour = std::time::Duration::from_secs(3600);
        assert!(t.guard.is_banned(
            "6.6.6.6",
            banned_at + hour - std::time::Duration::from_secs(1)
        ));
        assert!(
            !t.guard.is_banned(
                "6.6.6.6",
                banned_at + hour + std::time::Duration::from_millis(30)
            ),
            "ban not extended"
        );
    }

    #[tokio::test]
    async fn rate_limit_per_ip() {
        let t = setup(
            Limits {
                per_ip_burst: 5.0,
                per_ip_per_min: 1.0,
                ..lim()
            },
            true,
            false,
        );
        let path = format!("/mcp/t/{}", t.legacy);
        for _ in 0..5 {
            assert_eq!(
                post(&t.app, &path, "2.2.2.2", tools_list()).await,
                StatusCode::OK
            );
        }
        assert_eq!(
            post(&t.app, &path, "2.2.2.2", tools_list()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            post(&t.app, &path, "3.3.3.3", tools_list()).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn banned_ip_is_still_rate_limited_with_valid_credentials() {
        let t = setup(
            Limits {
                max_failures: 1,
                per_ip_burst: 4.0,
                per_ip_per_min: 0.001,
                ..lim()
            },
            true,
            true,
        );
        assert_eq!(
            status(&t.app, get("/.env", "6.6.6.6")).await,
            StatusCode::NOT_FOUND
        );
        for _ in 0..3 {
            assert_eq!(
                sync(&t.app, "6.6.6.6", Some(DEVICE_TOKEN)).await,
                StatusCode::OK
            );
        }
        let r = send(&t.app, sync_req("6.6.6.6", Some(DEVICE_TOKEN))).await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers["retry-after"], "30",
            "rate limited, not just banned"
        );
    }

    #[tokio::test]
    async fn oversized_body_rejected_and_healthz_exempt() {
        let t = setup(
            Limits {
                per_ip_burst: 1.0,
                per_ip_per_min: 0.001,
                ..lim()
            },
            true,
            true,
        );
        let big = "x".repeat(2 * 1024 * 1024);
        assert_eq!(
            post(&t.app, "/api/v1/sync", "4.4.4.4", big).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        for _ in 0..5 {
            assert_eq!(
                send(&t.app, get("/healthz", "4.4.4.4")).await.status,
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn bad_device_token_on_agent_download_counts_as_failure() {
        let t = setup(
            Limits {
                max_failures: 2,
                ..lim()
            },
            false,
            false,
        );
        for _ in 0..2 {
            assert_eq!(
                status(&t.app, agent_req("/api/v1/agent/1", "5.5.5.5", "guess")).await,
                StatusCode::UNAUTHORIZED
            );
        }
        // Two bad tokens banned the IP: unauthenticated requests now get 429...
        assert_eq!(
            status(&t.app, agent_req("/api/v1/agent/1", "5.5.5.5", "guess")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&t.app, get("/wp-login.php", "5.5.5.5")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // ...but the right token is still served (nothing published: 404, and
        // a 404 to an authenticated device is not an auth failure).
        assert_eq!(
            status(
                &t.app,
                agent_req("/api/v1/agent/1", "5.5.5.5", DEVICE_TOKEN)
            )
            .await,
            StatusCode::NOT_FOUND
        );
        for _ in 0..3 {
            assert_eq!(
                status(
                    &t.app,
                    agent_req("/api/v1/agent/1", "6.6.6.7", DEVICE_TOKEN)
                )
                .await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            status(&t.app, get("/.env", "6.6.6.7")).await,
            StatusCode::NOT_FOUND,
            "6.6.6.7 not banned"
        );
    }

    #[tokio::test]
    async fn banned_ip_still_downloads_the_agent_with_a_valid_device_token() {
        let (t, shas) = setup_with(
            Limits {
                max_failures: 3,
                ..lim()
            },
            true,
            true,
            &[(2, b"agent v2")],
        );
        ban_with_scanner_paths(&t.app, "6.6.6.6", 3).await;
        // Valid device token: the home NAT keeps getting agent updates.
        let r = t
            .app
            .clone()
            .oneshot(agent_req("/api/v1/agent/2", "6.6.6.6", DEVICE_TOKEN))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(r.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(hex::encode(Sha256::digest(&body)), shas[0]);
        // Invalid token (or an unknown device) from the banned IP: 429.
        assert_eq!(
            status(&t.app, agent_req("/api/v1/agent/2", "6.6.6.6", "wrong")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        let no_device = axum::http::Request::get("/api/v1/agent/2")
            .header("cf-connecting-ip", "6.6.6.6")
            .header("authorization", format!("Bearer {DEVICE_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            status(&t.app, no_device).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // An authenticated device asking for a version not offered: 404, served.
        assert_eq!(
            status(
                &t.app,
                agent_req("/api/v1/agent/3", "6.6.6.6", DEVICE_TOKEN)
            )
            .await,
            StatusCode::NOT_FOUND
        );
        // And the valid device still downloads afterwards.
        assert_eq!(
            status(
                &t.app,
                agent_req("/api/v1/agent/2", "6.6.6.6", DEVICE_TOKEN)
            )
            .await,
            StatusCode::OK
        );
    }

    /// A multi-MB APK goes through every layer (the 1 MiB limit is for request
    /// bodies) and the 30 s timeout only bounds the time to the response head:
    /// a phone reading the body slowly for longer still gets all of it.
    #[tokio::test(start_paused = true)]
    async fn big_agent_download_survives_body_limit_and_slow_reader() {
        let payload: Vec<u8> = (0..6 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let (t, shas) = setup_with(lim(), false, false, &[(2, &payload)]);
        let resp = t
            .app
            .clone()
            .oneshot(agent_req("/api/v1/agent/2", "1.2.3.4", DEVICE_TOKEN))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(body.len(), payload.len() + 4);
        assert_eq!(hex::encode(Sha256::digest(&body)), shas[0]);
    }

    #[tokio::test]
    async fn mcp_shows_reported_version_code_and_offered_release() {
        let (t, _) = setup_with(lim(), true, true, &[(6, b"six")]);
        let (_, access, _) = login(&t.app, IP).await;
        let sync = r#"{"device_id":"alex-phone","agent_version":"0.1.0","agent_version_code":5,"android_sdk":37,"device_owner":true,"date":"2026-10-18"}"#;
        let r = send(
            &t.app,
            mcp_req("/api/v1/sync", IP, Some(DEVICE_TOKEN), sync.into()),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert_eq!(json(&r.body)["agent"]["version_code"], 6);
        for (tool, args) in [("list_children", "{}"), ("status", r#"{"child":"alex"}"#)] {
            let legacy = mcp_req(
                &format!("/mcp/t/{}", t.legacy),
                IP,
                None,
                tools_call(tool, args),
            );
            let oauth = mcp_req("/mcp", IP, Some(&access), tools_call(tool, args));
            for req in [legacy, oauth] {
                let r = send(&t.app, req).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.body);
                assert!(
                    r.body.contains("agent 0.1.0 (code 5)"),
                    "{tool}: {}",
                    r.body
                );
                assert!(r.body.contains("device_owner=true"), "{tool}: {}", r.body);
                assert!(
                    r.body.contains("agent release offered: code 6"),
                    "{tool}: {}",
                    r.body
                );
            }
        }
    }

    #[tokio::test]
    async fn mcp_shows_whether_each_device_has_the_served_policy_and_its_last_error() {
        let t = setup(lim(), true, false);
        // An app of our own on the same config dir and database (a hot reload is
        // a new Store on the same database further down).
        let auth = || McpAuth {
            legacy_token_sha256: Some(Sha256::digest(t.legacy.as_bytes()).into()),
            oauth: None,
        };
        let st = state(t.config.path(), lim());
        let db = st.db.clone();
        let t_app = app(st, auth(), vec![]).unwrap();
        let call = |tool: &str, args: &str| {
            mcp_req(
                &format!("/mcp/t/{}", t.legacy),
                IP,
                None,
                tools_call(tool, args),
            )
        };
        let text = |body: &str| {
            json(body)["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let r = send(&t_app, call("list_children", "{}")).await;
        assert!(
            text(&r.body).contains("  alex-phone: never synced"),
            "{}",
            r.body
        );
        let sync = |has: &str, err: &str| {
            format!(
                r#"{{"device_id":"alex-phone","agent_version":"0.3.0","agent_version_code":3,"android_sdk":37,"device_owner":true,"date":"2026-10-18","policy_version":"{has}","last_error":{err}}}"#
            )
        };
        // First sync: the device has nothing, the policy goes out in the answer.
        let r = send(
            &t_app,
            mcp_req("/api/v1/sync", IP, Some(DEVICE_TOKEN), sync("", "null")),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let v = json(&r.body)["policy_version"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!json(&r.body)["policy"].is_null());
        let behind = format!(
            "policy behind: has none, served {v} (sent at the last sync, confirmed at the next)"
        );
        let list = text(&send(&t_app, call("list_children", "{}")).await.body);
        assert!(
            list.contains(&format!("device_owner=true, {behind}\n")),
            "{list}"
        );
        let status = text(
            &send(&t_app, call("status", r#"{"child":"alex"}"#))
                .await
                .body,
        );
        assert!(
            status.contains(&format!("policy served: version {v}\n")),
            "{status}"
        );
        assert!(
            status.contains(&format!("last sync 0 min ago, {behind}\n")),
            "{status}"
        );
        // Next sync: the device reports that version (and an error).
        let r = send(
            &t_app,
            mcp_req(
                "/api/v1/sync",
                IP,
                Some(DEVICE_TOKEN),
                sync(&v, r#""sync: HTTP 502: bad gateway""#),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        assert!(
            json(&r.body)["policy"].is_null(),
            "up to date: no policy in the answer"
        );
        let up = format!("policy up to date ({v}), last error: sync: HTTP 502: bad gateway\n");
        let list = text(&send(&t_app, call("list_children", "{}")).await.body);
        assert!(
            list.contains(&format!("(code 3), sdk 37, device_owner=true, {up}")),
            "{list}"
        );
        let status = text(
            &send(&t_app, call("status", r#"{"child":"alex"}"#))
                .await
                .body,
        );
        assert!(status.contains(&format!("device alex-phone: agent 0.3.0 (code 3), device_owner=true, last sync 0 min ago, {up}")), "{status}");
        // The policy changes on the server (hot reload): behind until the next sync.
        let c = t.config.path();
        let pol = std::fs::read_to_string(c.join("alex.yaml")).unwrap();
        std::fs::write(
            c.join("alex.yaml"),
            pol.replacen("timezone: Europe/Brussels", "timezone: Europe/Paris", 1),
        )
        .unwrap();
        let st2 = AppState {
            store: Store::open(c.to_path_buf()).unwrap(),
            db,
            ..state(c, lim())
        };
        let app2 = app(st2, auth(), vec![]).unwrap();
        let list = text(&send(&app2, call("list_children", "{}")).await.body);
        assert!(
            list.contains(&format!("policy behind: has {v}, served "))
                && list.contains("(changed since the last sync, sent at the next)"),
            "{list}"
        );
    }

    // ------------------------------------------------ MCP write tools (GitOps)

    use crate::gitops::tests::{OVERRIDES, POLICIES, POLICY, Remote, sh};

    const WRITE_TOOLS: [&str; 12] = [
        "policy_source",
        "add_override",
        "remove_override",
        "prune_overrides",
        "approve_app",
        "block_app",
        "unblock_app",
        "set_limit",
        "set_downtime",
        "set_device",
        "write_policy",
        "validate_policy",
    ];

    /// The served config dir holds what the repo holds (as after an ArgoCD
    /// sync); `gitops`: write tools configured.
    struct G {
        remote: Remote,
        _work: tempfile::TempDir,
        _config: tempfile::TempDir,
        _state: tempfile::TempDir,
        app: Router,
        legacy: String,
    }

    fn setup_gitops(gitops: bool) -> G {
        let remote = Remote::new(POLICY, Some(OVERRIDES));
        let config = tempfile::tempdir().unwrap();
        for f in ["kid.yaml", "kid.overrides.yaml", "devices.yaml"] {
            std::fs::copy(remote.owner().join(POLICIES).join(f), config.path().join(f)).unwrap();
        }
        let work = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        // Many calls from one IP: a big bucket, only the write path is tested.
        let mut st = state(
            config.path(),
            Limits {
                per_ip_burst: 1000.0,
                ..lim()
            },
        );
        st.gitops = gitops.then(|| remote.gitops(work.path()));
        let legacy = "good-token".to_string();
        let auth = McpAuth {
            legacy_token_sha256: Some(Sha256::digest(legacy.as_bytes()).into()),
            oauth: Some(oauth_config(state_dir.path())),
        };
        let app = app(st, auth, vec![]).unwrap();
        G {
            remote,
            _work: work,
            _config: config,
            _state: state_dir,
            app,
            legacy,
        }
    }

    /// tools/call -> (is_error, text). JSON-RPC errors (bad arguments) count as errors.
    async fn call(
        app: &Router,
        access: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> (bool, String) {
        let r = send(
            app,
            mcp_req(
                "/mcp",
                IP,
                Some(access),
                tools_call(tool, &args.to_string()),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let v = json(&r.body);
        if let Some(e) = v.get("error") {
            return (true, e["message"].as_str().unwrap_or_default().to_string());
        }
        let text = v["result"]["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["text"].as_str())
            .collect::<String>();
        (v["result"]["isError"] == true, text)
    }

    async fn ok_call(app: &Router, access: &str, tool: &str, args: serde_json::Value) -> String {
        let (err, text) = call(app, access, tool, args.clone()).await;
        assert!(!err, "{tool} {args}: {text}");
        text
    }

    async fn err_call(app: &Router, access: &str, tool: &str, args: serde_json::Value) -> String {
        let (err, text) = call(app, access, tool, args.clone()).await;
        assert!(err, "{tool} {args} should fail: {text}");
        text
    }

    #[tokio::test]
    async fn write_tools_only_over_oauth_and_only_with_gitops() {
        let g = setup_gitops(true);
        let (_, access, _) = login(&g.app, IP).await;
        let r = send(&g.app, mcp_req("/mcp", IP, Some(&access), tools_list())).await;
        let names = tool_names(&r.body);
        for t in WRITE_TOOLS
            .iter()
            .chain(&["list_children", "status", "validate"])
        {
            assert!(names.iter().any(|n| n == t), "{t} in {names:?}");
        }
        // The legacy URL token is read-only, even with GitOps configured.
        let r = send(
            &g.app,
            mcp_req(&format!("/mcp/t/{}", g.legacy), IP, None, tools_list()),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let legacy_names = tool_names(&r.body);
        assert!(legacy_names.iter().any(|n| n == "status"));
        for t in WRITE_TOOLS {
            assert!(
                !legacy_names.iter().any(|n| n == t),
                "{t} offered on the legacy token"
            );
        }
        let r = send(
            &g.app,
            mcp_req(
                &format!("/mcp/t/{}", g.legacy),
                IP,
                None,
                tools_call(
                    "block_app",
                    r#"{"child":"kid","package":"com.android.chrome"}"#,
                ),
            ),
        )
        .await;
        assert!(r.body.contains("error"), "{}", r.body);
        assert_eq!(
            g.remote.log().len(),
            1,
            "nothing committed through the legacy token"
        );
        // No GitOps: no write tools on OAuth either.
        let g = setup_gitops(false);
        let (_, access, _) = login(&g.app, IP).await;
        let names = tool_names(
            &send(&g.app, mcp_req("/mcp", IP, Some(&access), tools_list()))
                .await
                .body,
        );
        for t in WRITE_TOOLS {
            assert!(!names.iter().any(|n| n == t), "{t} offered without GitOps");
        }
    }

    #[tokio::test]
    async fn every_write_tool_commits_through_oauth() {
        let g = setup_gitops(true);
        let (client_id, access, _) = login(&g.app, IP).await;
        let a = &access;

        // policy_source: the YAML with comments + revision.
        let src = ok_call(
            &g.app,
            a,
            "policy_source",
            serde_json::json!({"child": "kid", "file": "policy"}),
        )
        .await;
        assert!(
            src.contains("# Kid's rules.") && src.contains("revision: "),
            "{src}"
        );

        // add_override (lock, screen) -> commit with the client's name in Requested-By.
        let out = ok_call(&g.app, a, "add_override", serde_json::json!({"child": "kid", "kind": "lock", "screen": true, "until": "+1h", "note": "devoirs"})).await;
        assert!(out.starts_with("committed "), "{out}");
        assert!(
            out.contains("policy version it will produce: ") && out.contains("2-3 minutes"),
            "{out}"
        );
        assert!(
            g.remote
                .show("kid.overrides.yaml")
                .contains("note: devoirs}"),
            "{}",
            g.remote.show("kid.overrides.yaml")
        );
        let msg = g.remote.last_message();
        assert!(
            msg.starts_with(
                "kidctl-mcp: add_override kid: add override {lock: true, screen: true, until: "
            ),
            "{msg}"
        );
        assert!(
            msg.contains(&format!(
                "Requested-By: Claude Code (OAuth client {client_id})"
            )),
            "{msg}"
        );
        // The announced version is what the server serves once the repo is deployed.
        let version = out
            .split("policy version it will produce: ")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        let o = g.remote.show("kid.overrides.yaml");
        let c = crate::policy::compile(
            &g.remote.show("kid.yaml"),
            Some(&o),
            crate::config::now_epoch(),
        )
        .unwrap();
        assert_eq!(crate::policy::version(&c), version);

        ok_call(&g.app, a, "add_override", serde_json::json!({"child": "kid", "kind": "extra", "extra": "30m", "limit": "general", "until": "+2h"})).await;
        let out = err_call(&g.app, a, "add_override", serde_json::json!({"child": "kid", "kind": "extra", "extra": "30m", "limit": "nope", "until": "+2h"})).await;
        assert!(out.contains("unknown limit \"nope\""), "{out}");
        let out = ok_call(
            &g.app,
            a,
            "remove_override",
            serde_json::json!({"child": "kid", "match": "devoirs"}),
        )
        .await;
        assert!(
            out.starts_with("committed ")
                && !g.remote.show("kid.overrides.yaml").contains("devoirs"),
            "{out}"
        );
        let out = ok_call(
            &g.app,
            a,
            "prune_overrides",
            serde_json::json!({"child": "kid"}),
        )
        .await;
        assert!(out.starts_with("nothing to change"), "{out}");

        // Apps.
        ok_call(
            &g.app,
            a,
            "block_app",
            serde_json::json!({"child": "kid", "package": "com.android.chrome"}),
        )
        .await;
        assert!(
            g.remote
                .show("kid.yaml")
                .contains("blocked: [com.zhiliaoapp.musically, com.android.chrome]  # TikTok")
        );
        ok_call(
            &g.app,
            a,
            "unblock_app",
            serde_json::json!({"child": "kid", "package": "com.android.chrome"}),
        )
        .await;
        assert_eq!(
            g.remote.show("kid.yaml"),
            POLICY,
            "block + unblock restores the file"
        );
        ok_call(&g.app, a, "approve_app", serde_json::json!({"child": "kid", "package": "com.duolingo", "mode": "always_allowed"})).await;
        assert!(
            g.remote
                .show("kid.yaml")
                .contains("always_allowed: [com.duolingo]\n")
        );
        ok_call(&g.app, a, "approve_app", serde_json::json!({"child": "kid", "package": "com.duolingo", "mode": "unlimited_outside_downtime"})).await;
        let t = g.remote.show("kid.yaml");
        assert!(
            t.contains("approved: [com.duolingo]\n")
                && t.contains("exclude: [com.duolingo]")
                && t.contains("always_allowed: []\n"),
            "{t}"
        );

        // Limits, downtime, device.
        ok_call(&g.app, a, "set_limit", serde_json::json!({"child": "kid", "name": "general", "daily": {"weekdays": "1h", "weekend": "2h"}})).await;
        assert!(
            g.remote
                .show("kid.yaml")
                .contains("daily: {weekdays: 1h, weekend: 2h}")
        );
        ok_call(&g.app, a, "set_limit", serde_json::json!({"child": "kid", "name": "video", "apps": ["com.netflix.mediaclient"], "daily": {"default": "0", "sat": "2h"}})).await;
        assert!(g.remote.show("kid.yaml").contains("  - {name: video, apps: [com.netflix.mediaclient], daily: {sat: 2h, default: \"0\"}}\n"), "{}", g.remote.show("kid.yaml"));
        ok_call(&g.app, a, "set_downtime", serde_json::json!({"child": "kid", "windows": [{"start": "22:00", "end": "07:00", "lock_screen": true}]})).await;
        assert!(
            g.remote
                .show("kid.yaml")
                .contains("downtime:\n  - {start: \"22:00\", end: \"07:00\", lock_screen: true}\n")
        );
        ok_call(&g.app, a, "set_device", serde_json::json!({"child": "kid", "field": "wifi_ssids", "value": {"deny": ["Hotspot"]}})).await;
        ok_call(
            &g.app,
            a,
            "set_device",
            serde_json::json!({"child": "kid", "field": "camera_disabled", "value": true}),
        )
        .await;
        assert!(
            g.remote
                .show("kid.yaml")
                .ends_with("device:\n  wifi_ssids: {deny: [Hotspot]}\n  camera_disabled: true\n"),
            "{}",
            g.remote.show("kid.yaml")
        );
        let out = err_call(&g.app, a, "set_device", serde_json::json!({"child": "kid", "field": "organization_name", "value": "x".repeat(70)})).await;
        assert!(out.contains("70 characters (max 64)"), "{out}");
        let out = err_call(
            &g.app,
            a,
            "set_device",
            serde_json::json!({"child": "kid", "field": "nope", "value": 1}),
        )
        .await;
        assert!(out.contains("unknown field"), "{out}");
        ok_call(&g.app, a, "set_device", serde_json::json!({"child": "kid", "field": "app_config", "value": {"com.tailscale.ipn": {"ForceEnabled": true, "Hostname": "kid-phone"}}})).await;
        assert!(
            g.remote.show("kid.yaml").contains(
                "  app_config: {com.tailscale.ipn: {ForceEnabled: true, Hostname: kid-phone}}\n"
            ),
            "{}",
            g.remote.show("kid.yaml")
        );
        let out = err_call(&g.app, a, "set_device", serde_json::json!({"child": "kid", "field": "app_config", "value": {"com.tailscale.ipn": {"ForceEnabled": {"x": 1}}}})).await;
        assert!(
            out.contains("nested mappings (bundles) are not supported"),
            "{out}"
        );
        ok_call(
            &g.app,
            a,
            "set_device",
            serde_json::json!({"child": "kid", "field": "app_config", "value": null}),
        )
        .await;
        assert!(
            !g.remote.show("kid.yaml").contains("app_config"),
            "{}",
            g.remote.show("kid.yaml")
        );

        // dry_run: diff, nothing committed.
        let n = g.remote.log().len();
        let out = ok_call(
            &g.app,
            a,
            "block_app",
            serde_json::json!({"child": "kid", "package": "com.android.chrome", "dry_run": true}),
        )
        .await;
        assert!(
            out.starts_with("dry run, valid, nothing committed")
                && out.contains("+blocked: [com.zhiliaoapp.musically, com.android.chrome]"),
            "{out}"
        );
        assert_eq!(g.remote.log().len(), n);

        // write_policy: optimistic concurrency on the file revision.
        let src = ok_call(
            &g.app,
            a,
            "policy_source",
            serde_json::json!({"child": "kid", "file": "policy"}),
        )
        .await;
        let rev = src
            .lines()
            .find_map(|l| l.strip_prefix("revision: "))
            .unwrap()
            .to_string();
        let current = src.split_once("---\n").unwrap().1.to_string();
        g.remote.owner_push(
            "kid.yaml",
            &format!("{current}# owner was here\n"),
            "owner edit",
        );
        let out = err_call(&g.app, a, "write_policy", serde_json::json!({"child": "kid", "file": "policy", "yaml": format!("{current}# mine\n"), "base_revision": rev})).await;
        assert!(out.contains("changed since revision"), "{out}");
        assert!(!g.remote.show("kid.yaml").contains("# mine"));
        let src = ok_call(
            &g.app,
            a,
            "policy_source",
            serde_json::json!({"child": "kid", "file": "policy"}),
        )
        .await;
        let rev = src
            .lines()
            .find_map(|l| l.strip_prefix("revision: "))
            .unwrap()
            .to_string();
        let current = src.split_once("---\n").unwrap().1.to_string();
        let out = ok_call(&g.app, a, "write_policy", serde_json::json!({"child": "kid", "file": "policy", "yaml": format!("{current}# mine\n"), "base_revision": rev})).await;
        assert!(out.starts_with("committed "), "{out}");
        assert!(
            g.remote
                .show("kid.yaml")
                .ends_with("# owner was here\n# mine\n")
        );
        // Invalid full file: refused with the validation messages.
        let out = err_call(&g.app, a, "write_policy", serde_json::json!({"child": "kid", "file": "policy", "yaml": current.replace("Europe/Brussels", "Mars/Base"), "base_revision": "x"})).await;
        assert!(out.contains("changed since revision x"), "{out}");
        let out = err_call(&g.app, a, "validate_policy", serde_json::json!({"child": "kid", "file": "policy", "yaml": current.replace("Europe/Brussels", "Mars/Base")})).await;
        assert!(
            out.contains("invalid, nothing committed") && out.contains("Mars/Base"),
            "{out}"
        );
        let out = ok_call(
            &g.app,
            a,
            "validate_policy",
            serde_json::json!({"child": "kid", "file": "overrides", "yaml": "overrides: []\n"}),
        )
        .await;
        assert!(out.contains("dry run"), "{out}");

        // devices.yaml and path traversal are out of reach.
        let n = g.remote.log().len();
        let out = err_call(&g.app, a, "write_policy", serde_json::json!({"child": "kid", "file": "devices", "yaml": "devices: []\n", "base_revision": "x"})).await;
        assert!(
            out.contains("unknown variant") || out.contains("devices"),
            "{out}"
        );
        for child in ["../kid", "devices", "kid/../devices", "Kid"] {
            for (tool, args) in [
                (
                    "policy_source",
                    serde_json::json!({"child": child, "file": "policy"}),
                ),
                (
                    "block_app",
                    serde_json::json!({"child": child, "package": "com.android.chrome"}),
                ),
                (
                    "write_policy",
                    serde_json::json!({"child": child, "file": "policy", "yaml": "child: x\n", "base_revision": "absent"}),
                ),
            ] {
                let out = err_call(&g.app, a, tool, args).await;
                assert!(
                    out.contains("lowercase letters") || out.contains("not a child"),
                    "{tool} {child}: {out}"
                );
            }
        }
        assert_eq!(g.remote.log().len(), n);
        assert_eq!(
            sh(
                &g.remote.bare(),
                &["show", &format!("main:{POLICIES}/devices.yaml")]
            ),
            std::fs::read_to_string(g.remote.owner().join(POLICIES).join("devices.yaml")).unwrap()
        );
        // Every commit of ours names the client.
        let log = sh(
            &g.remote.bare(),
            &[
                "log",
                "--format=%an|%s|%(trailers:key=Requested-By,valueonly)",
                "main",
            ],
        );
        for l in log.lines().filter(|l| l.contains("kidctl-mcp:")) {
            assert!(l.starts_with("kidctl MCP|kidctl-mcp: "), "{l}");
        }
        let ours: Vec<&str> = log.lines().filter(|l| l.contains("kidctl-mcp:")).collect();
        assert!(
            ours.len() >= 12
                && ours
                    .iter()
                    .all(|l| l.ends_with(&format!("|Claude Code (OAuth client {client_id})"))),
            "{log}"
        );
    }
}
