use clap::{Parser, Subcommand};
use kidctl::{api::AppState, config, db::Db, policy, serve};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "kidctl",
    version,
    about = "GitOps parental control server and tools"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate a whole config directory (policies, overrides, devices.yaml). Exit 1 on error.
    Validate { dir: PathBuf },
    /// Print the compiled JSON of one policy (+ optional overrides) as devices receive it.
    Compile {
        policy: PathBuf,
        overrides: Option<PathBuf>,
    },
    /// Generate a device (or legacy MCP URL) token and print it with its SHA-256.
    Token,
    /// Verify an agent release directory (agent.json + APK) as the server would. Exit 1 on error.
    CheckAgent { dir: PathBuf },
    /// Read the OAuth owner password from stdin (at least 12 characters) and print
    /// its argon2id hash, the value of KIDCTL_OWNER_PASSWORD_HASH.
    HashPassword,
    /// Run the sync API, plus the MCP: OAuth at /mcp when KIDCTL_OWNER_PASSWORD_HASH
    /// is set, legacy /mcp/t/<token> when KIDCTL_MCP_TOKEN_SHA256 is set.
    Serve {
        #[arg(long, env = "KIDCTL_CONFIG", default_value = "/etc/kidctl")]
        config: PathBuf,
        #[arg(long, env = "KIDCTL_DB", default_value = "/data/kidctl.db")]
        db: PathBuf,
        #[arg(long, env = "KIDCTL_LISTEN", default_value = "0.0.0.0:8080")]
        listen: String,
        /// Legacy MCP at /mcp/t/<token>: hex SHA-256 of the URL token.
        #[arg(long, env = "KIDCTL_MCP_TOKEN_SHA256", hide_env_values = true)]
        mcp_token_sha256: Option<String>,
        /// Comma-separated Host headers accepted by the MCP endpoints (empty = any).
        #[arg(long, env = "KIDCTL_ALLOWED_HOSTS", default_value = "")]
        allowed_hosts: String,
        /// Agent release directory (agent.json + APK, see scripts/release-agent.sh);
        /// missing directory = no self-update offered.
        #[arg(long, env = "KIDCTL_AGENT_DIR", default_value = "/data/agent")]
        agent_dir: PathBuf,
        // OAuth MCP at /mcp is enabled by KIDCTL_OWNER_PASSWORD_HASH (argon2id PHC
        // hash of the owner password, `kidctl hash-password`): environment only,
        // never a flag, so it stays out of the process list and of --help.
        /// Public origin (issuer), e.g. https://kidctl.example.net. Required with OAuth.
        #[arg(long, env = "KIDCTL_PUBLIC_URL")]
        public_url: Option<String>,
        /// Directory for OAuth clients and token digests (oauth-clients.json,
        /// oauth-tokens.json). Required with OAuth; must persist across restarts.
        #[arg(long, env = "KIDCTL_STATE_DIR")]
        state_dir: Option<PathBuf>,
        /// Comma-separated redirect URI patterns clients may use (replaces the
        /// defaults: Claude, Claude Code loopback, ChatGPT).
        #[arg(long, env = "KIDCTL_REDIRECT_PATTERNS")]
        redirect_patterns: Option<String>,
        /// Comma-separated client_id URLs accepted as Client ID Metadata Documents;
        /// when set, only those, and dynamic client registration is off.
        #[arg(long, env = "KIDCTL_CIMD_ALLOWLIST")]
        cimd_allowlist: Option<String>,
        #[command(flatten)]
        gitops: Box<GitopsArgs>,
    },
}

/// MCP write tools (OAuth endpoint only): changes are committed and pushed
/// to the GitOps repo. Unset remote: read-only MCP.
#[derive(clap::Args)]
struct GitopsArgs {
    /// Infra repo: ssh URL (git@github.com:owner/infra.git) with a deploy key,
    /// or a local path / file:// URL (tests).
    #[arg(long, env = "KIDCTL_GITOPS_REMOTE")]
    gitops_remote: Option<String>,
    #[arg(long, env = "KIDCTL_GITOPS_BRANCH", default_value = "main")]
    gitops_branch: String,
    /// Policies directory inside the repo, e.g. kidctl/policies.
    #[arg(long, env = "KIDCTL_GITOPS_PATH")]
    gitops_path: Option<String>,
    /// Deploy key (private key file, write access to the infra repo only).
    #[arg(long, env = "KIDCTL_GITOPS_SSH_KEY")]
    gitops_ssh_key: Option<PathBuf>,
    /// known_hosts pinning the git host's key (no trust on first use).
    #[arg(long, env = "KIDCTL_GITOPS_KNOWN_HOSTS")]
    gitops_known_hosts: Option<PathBuf>,
    /// Commit author and committer, "Name <email>".
    #[arg(
        long,
        env = "KIDCTL_GITOPS_AUTHOR",
        default_value = "kidctl MCP <kidctl-mcp@localhost>"
    )]
    gitops_author: String,
    /// Private clone of the repo (on the data volume).
    #[arg(long, env = "KIDCTL_GITOPS_DIR", default_value = "/data/gitops")]
    gitops_dir: PathBuf,
}

fn gitops_config(a: GitopsArgs) -> Result<Option<kidctl::gitops::GitopsConfig>, String> {
    let Some(remote) = a
        .gitops_remote
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let path = a
        .gitops_path
        .map(|s| s.trim().trim_matches('/').to_string())
        .filter(|s| !s.is_empty());
    let (author_name, author_email) = kidctl::gitops::parse_author(&a.gitops_author)?;
    let cfg = kidctl::gitops::GitopsConfig {
        remote,
        branch: a.gitops_branch.trim().to_string(),
        path: path.ok_or("KIDCTL_GITOPS_PATH (policies directory inside the repo) is required with KIDCTL_GITOPS_REMOTE")?,
        ssh_key: a.gitops_ssh_key.filter(|p| !p.as_os_str().is_empty()),
        known_hosts: a.gitops_known_hosts.filter(|p| !p.as_os_str().is_empty()),
        author_name,
        author_email,
        work_dir: a.gitops_dir,
    };
    cfg.validate()?;
    Ok(Some(cfg))
}

/// Trimmed, non-empty environment variable.
fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Comma list, trimmed, empty items dropped.
fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Owner password from stdin (not argv, so it stays out of shell history and
/// the process list); returns the argon2id PHC string.
fn hash_password_cmd() -> Result<String, String> {
    let mut pw = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut pw).map_err(|e| e.to_string())?;
    let pw = pw
        .strip_suffix('\n')
        .map(|p| p.strip_suffix('\r').unwrap_or(p))
        .unwrap_or(&pw);
    if pw.chars().count() < 12 {
        return Err("password must be at least 12 characters".into());
    }
    mcp_oauth::hash_password(pw)
}

struct OAuthArgs {
    owner_password_hash: Option<String>,
    public_url: Option<String>,
    state_dir: Option<PathBuf>,
    redirect_patterns: Option<String>,
    cimd_allowlist: Option<String>,
}

fn oauth_config(a: OAuthArgs) -> Result<Option<mcp_oauth::Config>, String> {
    let Some(hash) = a.owner_password_hash else {
        return Ok(None);
    };
    let nonempty = |v: Option<String>| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    Ok(Some(mcp_oauth::Config {
        issuer: nonempty(a.public_url)
            .ok_or("KIDCTL_PUBLIC_URL (e.g. https://kidctl.example.net) is required with OAuth")?,
        mcp_path: serve::MCP_PATH.into(),
        owner_password_hash: hash,
        state_dir: a
            .state_dir
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or("KIDCTL_STATE_DIR is required with OAuth")?,
        redirect_patterns: match nonempty(a.redirect_patterns) {
            Some(v) => list(&v),
            None => mcp_oauth::DEFAULT_REDIRECT_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
        resource_name: env!("CARGO_PKG_NAME").into(),
        cimd_allowlist: nonempty(a.cimd_allowlist).map(|v| list(&v)),
    }))
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Validate { dir } => match config::load(&dir, config::now_epoch()) {
            Ok(c) => {
                println!(
                    "ok: {} children ({}), {} devices",
                    c.children.len(),
                    c.children.keys().cloned().collect::<Vec<_>>().join(", "),
                    c.devices.len()
                );
                ExitCode::SUCCESS
            }
            Err(es) => {
                for e in es {
                    eprintln!("error: {e}");
                }
                ExitCode::FAILURE
            }
        },
        Cmd::Compile {
            policy: p,
            overrides,
        } => {
            let read = |p: &PathBuf| {
                std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
            };
            let res = read(&p).and_then(|y| Ok((y, overrides.as_ref().map(read).transpose()?)));
            match res {
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
                Ok((y, o)) => match policy::compile(&y, o.as_deref(), 0) {
                    Ok(c) => {
                        println!("{}", serde_json::to_string_pretty(&c).expect("json"));
                        ExitCode::SUCCESS
                    }
                    Err(es) => {
                        for e in es {
                            eprintln!("error: {e}");
                        }
                        ExitCode::FAILURE
                    }
                },
            }
        }
        Cmd::Token => {
            use sha2::{Digest, Sha256};
            let bytes: [u8; 32] = rand::random();
            let token = hex::encode(bytes);
            println!("token:        {token}");
            println!(
                "token_sha256: {}",
                hex::encode(Sha256::digest(token.as_bytes()))
            );
            ExitCode::SUCCESS
        }
        Cmd::CheckAgent { dir } => match kidctl::release::load(&dir) {
            Ok(Some(r)) => {
                println!(
                    "ok: version_code {} ({}), {} bytes, sha256 {}",
                    r.meta.version_code,
                    r.meta.version_name,
                    r.bytes.len(),
                    r.meta.sha256
                );
                ExitCode::SUCCESS
            }
            Ok(None) => {
                eprintln!(
                    "error: no {} in {}",
                    kidctl::release::META_FILE,
                    dir.display()
                );
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::HashPassword => match hash_password_cmd() {
            Ok(h) => {
                println!("{h}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Serve {
            config: dir,
            db,
            listen,
            mcp_token_sha256,
            allowed_hosts,
            agent_dir,
            public_url,
            state_dir,
            redirect_patterns,
            cimd_allowlist,
            gitops,
        } => {
            let gitops = match gitops_config(*gitops)
                .and_then(|c| c.map(kidctl::gitops::Gitops::new).transpose())
            {
                Ok(g) => g.map(std::sync::Arc::new),
                Err(e) => {
                    eprintln!("gitops: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let owner_password_hash = env("KIDCTL_OWNER_PASSWORD_HASH");
            if gitops.is_some() && owner_password_hash.is_none() {
                eprintln!(
                    "gitops: configured, but the write tools are only offered over OAuth (KIDCTL_OWNER_PASSWORD_HASH is unset)"
                );
            }
            let oauth = match oauth_config(OAuthArgs {
                owner_password_hash,
                public_url,
                state_dir,
                redirect_patterns,
                cimd_allowlist,
            }) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let store = match config::Store::open(dir) {
                Ok(s) => s,
                Err(es) => {
                    eprintln!("invalid config:\n  {}", es.join("\n  "));
                    return ExitCode::FAILURE;
                }
            };
            let db = match Db::open(&db) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("db: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mcp_sha = match mcp_token_sha256
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(hex::decode)
            {
                None => None,
                Some(Ok(v)) if v.len() == 32 => Some(v.try_into().expect("32")),
                Some(_) => {
                    eprintln!("KIDCTL_MCP_TOKEN_SHA256 must be 64 hex chars");
                    return ExitCode::FAILURE;
                }
            };
            let hosts = list(&allowed_hosts);
            let auth = serve::McpAuth {
                legacy_token_sha256: mcp_sha,
                oauth,
            };
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async {
                store.spawn_watcher(std::time::Duration::from_secs(10));
                let agent = kidctl::release::ReleaseStore::open(agent_dir);
                agent.spawn_watcher(std::time::Duration::from_secs(10));
                let guard = kidctl::guard::Guard::new(kidctl::guard::limits());
                if let Some(g) = gitops.clone() {
                    // Clone/fetch now so the first write is fast; a failure is
                    // only logged (each write fetches again).
                    tokio::spawn(async move {
                        let c = g.config();
                        match g.warm_up().await {
                            Ok(head) => eprintln!(
                                "gitops: {} branch {} at {head}, policies in {}",
                                c.remote, c.branch, c.path
                            ),
                            Err(e) => eprintln!(
                                "gitops: cannot fetch {} (writes will retry): {e}",
                                c.remote
                            ),
                        }
                    });
                }
                serve::run(
                    AppState {
                        store,
                        db,
                        guard,
                        agent,
                        gitops,
                    },
                    &listen,
                    auth,
                    hosts,
                )
                .await
            })
            .map(|_| ExitCode::SUCCESS)
            .unwrap_or_else(|e| {
                eprintln!("serve: {e}");
                ExitCode::FAILURE
            })
        }
    }
}
