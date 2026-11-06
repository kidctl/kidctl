//! Abuse protection for everything reachable from the internet (sync API,
//! agent download, MCP, OAuth). Cloudflare's free plan gives us volumetric
//! DDoS mitigation but no spare WAF / rate-limit rules, so request-level limits
//! live here.
//!
//! The implementation is the mcp-oauth crate's guard: the OAuth endpoints
//! report their authentication failures (unknown bearer token, wrong owner
//! password, wrong client secret or client assertion, wrong PKCE verifier)
//! through it, and kidctl reports its own credentials (device token, legacy
//! MCP URL token) with [`Guard::auth_failed`] on the same [`Guard`] (in
//! `AppState`). One ban state for the whole app:
//!
//! - per-client-IP token bucket on every request except `/healthz`, banned
//!   IPs included;
//! - per-IP ban (429) after repeated authentication failures: the OAuth ones
//!   above, a wrong device token (sync, agent download), a wrong legacy MCP
//!   URL token, and unknown/scanner paths ([`count_unknown_path`]). Harmless
//!   probes never count ([`harmless_probe`]: `GET`/`HEAD` on `/`,
//!   `/favicon.ico`, `/robots.txt`, and anything under `/.well-known/`, which
//!   MCP clients probe for discovery);
//! - a ban never locks out an authenticated client: the whole home shares one
//!   public IP (NAT), so kidctl runs the guard in shared-IP mode
//!   (`serve_authenticated_when_banned`). A banned IP's requests still pay the
//!   token bucket, then run, and only responses marked [`Authenticated`] go
//!   back (valid device token on sync and agent download, valid legacy MCP
//!   token, valid OAuth bearer token or token request); anything else becomes
//!   429 (fail closed: a route that does not authenticate is blocked).
//!   Failures while the ban runs are not counted and do not extend it. Tokens
//!   are 256-bit random, so letting a banned IP keep presenting tokens (at the
//!   bucket rate) gives no useful oracle; the owner password is never checked
//!   for a banned IP (the crate answers 429 before looking at it);
//! - body size cap, request timeout, global concurrency cap ([`limits`]).
//!
//! Client IP: `CF-Connecting-IP` (set by Cloudflare; the tunnel is the only
//! ingress), else the leftmost `X-Forwarded-For`, else "unknown". Spoofing the
//! header only lets an attacker spread over buckets they could already get by
//! using more IPs; the global caps still bound the total.

use axum::http::Method;
pub use mcp_oauth::{
    AuthFailures, Authenticated, Guard, Limits, Verdict, authenticated, client_ip, harmless_probe,
    protect,
};
use std::time::Duration;

/// Unknown paths (no route matched: scanners probing `/wp-admin`, `/.env`...)
/// count as authentication failures. The crate never calls this for a
/// [`harmless_probe`].
pub fn count_unknown_path(_: &Method, _: &str) -> bool {
    true
}

/// kidctl's limits: the crate defaults (120/min, burst 40, ban 1 h after 10
/// failures in 10 min, 1 MiB bodies, `/healthz` exempt) with the 30 s request
/// timeout and the 64 concurrent requests kidctl always had (phones sync every
/// minute; nothing here takes long), shared-IP mode (the home NAT) and unknown
/// paths counted.
pub fn limits() -> Limits {
    Limits {
        request_timeout: Duration::from_secs(30),
        max_concurrency: 64,
        serve_authenticated_when_banned: true,
        count_unknown_path: Some(count_unknown_path),
        ..Limits::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn small() -> Guard {
        Guard::new(Limits {
            per_ip_per_min: 60.0,
            per_ip_burst: 3.0,
            max_failures: 3,
            fail_window: Duration::from_secs(60),
            ban_for: Duration::from_secs(100),
            ..limits()
        })
    }

    #[test]
    fn kidctl_limits() {
        let l = limits();
        assert_eq!(
            (l.per_ip_per_min, l.per_ip_burst, l.max_failures),
            (120.0, 40.0, 10)
        );
        assert_eq!(
            (l.fail_window, l.ban_for),
            (Duration::from_secs(600), Duration::from_secs(3600))
        );
        assert_eq!(
            (l.max_body_bytes, l.request_timeout, l.max_concurrency),
            (1024 * 1024, Duration::from_secs(30), 64)
        );
        assert_eq!(l.exempt_paths, vec!["/healthz".to_string()]);
        assert!(
            l.serve_authenticated_when_banned,
            "the home shares one public IP"
        );
        let count = l.count_unknown_path.expect("unknown paths count");
        assert!(count(&Method::GET, "/wp-login.php") && count(&Method::POST, "/.env"));
    }

    #[test]
    fn harmless_probes() {
        for m in [Method::GET, Method::HEAD] {
            for p in [
                "/",
                "/favicon.ico",
                "/robots.txt",
                "/.well-known/openid-configuration",
            ] {
                assert!(harmless_probe(&m, p), "{m} {p}");
            }
        }
        assert!(!harmless_probe(&Method::POST, "/"));
        assert!(!harmless_probe(&Method::GET, "/wp-login.php"));
        assert!(!harmless_probe(&Method::GET, "/.env"));
    }

    #[test]
    fn bucket_refills() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(g.admit("1.2.3.4", t0), Verdict::Ok);
        }
        assert_eq!(g.admit("1.2.3.4", t0), Verdict::RateLimited);
        assert_eq!(g.admit("5.6.7.8", t0), Verdict::Ok, "other IPs unaffected");
        assert_eq!(
            g.admit("1.2.3.4", t0 + Duration::from_secs(1)),
            Verdict::Ok,
            "1 token/s refill"
        );
    }

    #[test]
    fn ban_after_failures_then_expires() {
        let g = small();
        let t0 = Instant::now();
        assert!(!g.auth_failed("9.9.9.9", "t", t0));
        assert!(!g.auth_failed("9.9.9.9", "t", t0));
        assert!(g.auth_failed("9.9.9.9", "t", t0));
        assert_eq!(
            g.admit("9.9.9.9", t0 + Duration::from_secs(50)),
            Verdict::Banned
        );
        assert_eq!(
            g.admit("9.9.9.9", t0 + Duration::from_secs(101)),
            Verdict::Ok
        );
    }

    #[test]
    fn banned_ip_is_still_rate_limited() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            g.auth_failed("9.9.9.9", "t", t0);
        }
        // A banned IP is admitted (to let authenticated clients through) but
        // still pays the token bucket like everyone else.
        for _ in 0..3 {
            assert_eq!(g.admit("9.9.9.9", t0), Verdict::Banned);
        }
        assert_eq!(g.admit("9.9.9.9", t0), Verdict::RateLimited);
    }

    #[test]
    fn failures_while_banned_do_not_extend_the_ban() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            g.auth_failed("9.9.9.9", "t", t0);
        }
        assert!(
            g.auth_failed("9.9.9.9", "t", t0 + Duration::from_secs(50)),
            "still banned"
        );
        assert!(g.is_banned("9.9.9.9", t0 + Duration::from_secs(99)));
        assert_eq!(
            g.admit("9.9.9.9", t0 + Duration::from_secs(101)),
            Verdict::Ok,
            "ban ends on time"
        );
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let g = small();
        let t0 = Instant::now();
        g.auth_failed("8.8.8.8", "t", t0);
        g.auth_failed("8.8.8.8", "t", t0);
        assert!(
            !g.auth_failed("8.8.8.8", "t", t0 + Duration::from_secs(61)),
            "old failures expired"
        );
    }

    #[test]
    fn ip_from_headers() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1, 172.16.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "10.0.0.1");
        h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
        assert_eq!(client_ip(&axum::http::HeaderMap::new()), "unknown");
    }
}
