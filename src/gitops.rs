//! GitOps writes: the MCP write tools change a child's rules by committing
//! to the infra repo and pushing, exactly like the owner does by hand. The
//! server never edits its own config directory, SQLite, or the phones: the
//! push goes through ArgoCD -> ConfigMap -> hot reload -> phone sync.
//!
//! One private clone (`KIDCTL_GITOPS_DIR`, on the data volume), one write at
//! a time ([`Gitops::change`] holds a mutex). Each change:
//!
//! 1. `fetch` + hard reset (+ clean) of the clone to `origin/<branch>`;
//! 2. the tool's edit runs on the fresh file texts (`<child>.yaml`,
//!    `<child>.overrides.yaml`; nothing else in the repo is ever written);
//! 3. the whole policies directory is validated exactly like
//!    `kidctl validate` ([`config::load`]); invalid -> refused with the
//!    messages, nothing committed;
//! 4. commit (`kidctl-mcp: <tool> <child>: <summary>`, `Requested-By:`
//!    trailer naming the OAuth client), push without force. A
//!    non-fast-forward (someone pushed meanwhile) re-runs 1-4 once on the new
//!    head (the edit is re-applied to the new text, so `write_policy`'s
//!    revision check sees the concurrent change), then fails cleanly.
//!
//! git is the system binary. Remote: an ssh URL with a deploy key
//! (`KIDCTL_GITOPS_SSH_KEY`) and a pinned `known_hosts`
//! (`KIDCTL_GITOPS_KNOWN_HOSTS`, `StrictHostKeyChecking=yes`, no
//! trust-on-first-use), or a local path / `file://` URL (tests, e2e). git
//! runs with a clean environment (no system/global config, no hooks, no
//! prompts, only the ssh and file transports).

use crate::config;
use crate::policy;
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Each git command (fetch/push over ssh included) must finish within this.
const GIT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug)]
pub struct GitopsConfig {
    /// `git@github.com:owner/infra.git`, `ssh://...`, a local path or `file://...`.
    pub remote: String,
    pub branch: String,
    /// Policies directory inside the repo, e.g. `kidctl/policies`.
    pub path: String,
    /// Deploy key (private key file), required for ssh remotes.
    pub ssh_key: Option<PathBuf>,
    /// known_hosts file pinning the git host's key, required for ssh remotes.
    pub known_hosts: Option<PathBuf>,
    pub author_name: String,
    pub author_email: String,
    /// The clone lives in `<work_dir>/repo`; also HOME and TMPDIR of git.
    pub work_dir: PathBuf,
}

impl GitopsConfig {
    pub fn is_ssh(&self) -> bool {
        is_ssh_remote(&self.remote)
    }

    pub fn validate(&self) -> Result<(), String> {
        let r = self.remote.trim();
        if r.is_empty() {
            return Err("KIDCTL_GITOPS_REMOTE is empty".into());
        }
        if !(is_ssh_remote(r) || r.starts_with("file://") || r.starts_with('/')) {
            return Err(format!(
                "KIDCTL_GITOPS_REMOTE {r:?}: use an ssh URL (git@host:owner/repo.git or ssh://...) with a deploy key, \
                 or a local path / file:// URL"
            ));
        }
        if self.branch.is_empty()
            || self.branch.starts_with('-')
            || self.branch.contains("..")
            || self.branch.contains(char::is_whitespace)
        {
            return Err(format!(
                "KIDCTL_GITOPS_BRANCH {:?} is not a branch name",
                self.branch
            ));
        }
        let p = Path::new(&self.path);
        if self.path.is_empty() || !p.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!(
                "KIDCTL_GITOPS_PATH {:?}: a relative path inside the repo, without '..'",
                self.path
            ));
        }
        if self.is_ssh() {
            for (name, f) in [
                ("KIDCTL_GITOPS_SSH_KEY", &self.ssh_key),
                ("KIDCTL_GITOPS_KNOWN_HOSTS", &self.known_hosts),
            ] {
                let f = f
                    .as_ref()
                    .ok_or_else(|| format!("{name} is required with an ssh remote"))?;
                let s = f.to_str().ok_or_else(|| format!("{name}: not UTF-8"))?;
                if s.contains('\'') {
                    return Err(format!("{name}: path must not contain a quote"));
                }
                std::fs::File::open(f).map_err(|e| format!("{name} {}: {e}", f.display()))?;
            }
        }
        if self.author_name.trim().is_empty() || self.author_email.trim().is_empty() {
            return Err("KIDCTL_GITOPS_AUTHOR must be \"Name <email>\"".into());
        }
        Ok(())
    }
}

/// `git@host:path` (scp-like) or `ssh://`.
fn is_ssh_remote(r: &str) -> bool {
    if r.starts_with("ssh://") {
        return true;
    }
    // scp-like: [user@]host:path, with no '/' before the ':'.
    match r.find(':') {
        Some(i) => !r[..i].contains('/') && !r[..i].is_empty() && !r.contains("://"),
        None => false,
    }
}

/// `"Name <email>"` -> (name, email).
pub fn parse_author(s: &str) -> Result<(String, String), String> {
    let s = s.trim();
    let (name, rest) = s
        .split_once('<')
        .ok_or("KIDCTL_GITOPS_AUTHOR must be \"Name <email>\"")?;
    let email = rest
        .strip_suffix('>')
        .ok_or("KIDCTL_GITOPS_AUTHOR must be \"Name <email>\"")?;
    if name.trim().is_empty() || email.trim().is_empty() || email.contains(['<', '>']) {
        return Err("KIDCTL_GITOPS_AUTHOR must be \"Name <email>\"".into());
    }
    Ok((name.trim().to_string(), email.trim().to_string()))
}

/// Which of a child's two files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// `<child>.yaml`: the rules.
    Policy,
    /// `<child>.overrides.yaml`: temporary exceptions.
    Overrides,
}

impl FileKind {
    pub fn file_name(self, child: &str) -> String {
        match self {
            FileKind::Policy => format!("{child}.yaml"),
            FileKind::Overrides => format!("{child}.overrides.yaml"),
        }
    }
}

/// Child names are the policy file stems: lowercase letters, digits, '-'
/// (same rule as `child:` in the policy). This is also what makes path
/// traversal impossible: no '/', no '.', no '..'. `devices` is reserved:
/// `devices.yaml` (the device token hashes) is never readable or writable
/// through the MCP.
pub fn valid_child(child: &str) -> Result<(), String> {
    if child.is_empty()
        || child.len() > 64
        || !child
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "child {child:?}: lowercase letters, digits and '-' only"
        ));
    }
    if child == "devices" {
        return Err(
            "\"devices\" is not a child: devices.yaml is not editable through the MCP".into(),
        );
    }
    Ok(())
}

/// One file as it is on the branch now.
#[derive(Clone, Debug)]
pub struct Source {
    /// None: the file does not exist.
    pub text: Option<String>,
    /// Git blob id of the file on the branch ("absent" if it does not
    /// exist): the `base_revision` of `write_policy`.
    pub revision: String,
}

/// Both files of a child, at `commit`.
#[derive(Clone, Debug)]
pub struct Files {
    pub child: String,
    pub commit: String,
    pub policy: Source,
    pub overrides: Source,
}

impl Files {
    pub fn get(&self, f: FileKind) -> &Source {
        match f {
            FileKind::Policy => &self.policy,
            FileKind::Overrides => &self.overrides,
        }
    }
}

pub const ABSENT: &str = "absent";

/// What a tool's edit produced.
#[derive(Debug)]
pub struct Edited {
    pub text: String,
    /// One line for the commit message.
    pub summary: String,
}

/// A tool's edit: a function of the files as they are on the branch (so a
/// retry after a concurrent push re-applies it to the new text).
pub type EditFn = dyn Fn(&Files) -> Result<Edited, String> + Send + Sync;

/// One write. Owned: it runs in its own task (see [`Gitops::change`]).
pub struct Change {
    pub tool: String,
    pub child: String,
    pub file: FileKind,
    /// Who asked (OAuth client), for the `Requested-By:` trailer.
    pub requested_by: String,
    pub dry_run: bool,
    pub edit: Box<EditFn>,
}

#[derive(Debug)]
pub struct Outcome {
    /// Commit pushed (None: dry run, or nothing to change).
    pub commit: Option<String>,
    pub summary: String,
    /// `git diff` of the change (empty: nothing to change).
    pub diff: String,
    /// Version of the child's compiled policy after the change (what the
    /// MCP `policy` tool and the phones will show once it is deployed).
    pub version: String,
    /// The first push was rejected (someone pushed meanwhile) and the change
    /// was re-applied on the new head.
    pub retried: bool,
}

pub struct Gitops {
    cfg: GitopsConfig,
    lock: Mutex<()>,
    /// Tests: run before each push attempt (simulates a concurrent push).
    #[cfg(test)]
    pub before_push: std::sync::Mutex<Vec<Box<dyn FnOnce() + Send>>>,
}

#[derive(Debug)]
enum GitError {
    /// The remote has commits we do not have (someone pushed meanwhile).
    NonFastForward(String),
    Other(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::NonFastForward(e) | GitError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// One line, printable, bounded: for commit messages built from tool
/// arguments and client names.
pub fn one_line(s: &str, max: usize) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > max {
        format!("{}...", t.chars().take(max).collect::<String>())
    } else {
        t
    }
}

impl Gitops {
    pub fn new(cfg: GitopsConfig) -> Result<Self, String> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            lock: Mutex::new(()),
            #[cfg(test)]
            before_push: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn config(&self) -> &GitopsConfig {
        &self.cfg
    }

    fn repo(&self) -> PathBuf {
        self.cfg.work_dir.join("repo")
    }

    fn policies_dir(&self) -> PathBuf {
        self.repo().join(&self.cfg.path)
    }

    fn rel(&self, child: &str, f: FileKind) -> String {
        format!(
            "{}/{}",
            self.cfg.path.trim_end_matches('/'),
            f.file_name(child)
        )
    }

    /// Run git (in the clone unless `in_repo` is false) with a clean,
    /// fixed environment; stdout on success.
    async fn git(&self, in_repo: bool, args: &[&str]) -> Result<String, GitError> {
        let tmp = self.cfg.work_dir.join("tmp");
        let _ = std::fs::create_dir_all(&tmp);
        let mut cmd = Command::new("git");
        cmd.env_clear()
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()),
            )
            .env("HOME", &self.cfg.work_dir)
            .env("TMPDIR", &tmp)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", "ssh:file")
            .env("GIT_AUTHOR_NAME", &self.cfg.author_name)
            .env("GIT_AUTHOR_EMAIL", &self.cfg.author_email)
            .env("GIT_COMMITTER_NAME", &self.cfg.author_name)
            .env("GIT_COMMITTER_EMAIL", &self.cfg.author_email)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "protocol.file.allow=always",
            ])
            // Our own clone, even if the volume's ownership changed (restore).
            .arg("-c")
            .arg(format!("safe.directory={}", self.repo().display()))
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null());
        if self.cfg.is_ssh() {
            let key = self
                .cfg
                .ssh_key
                .as_ref()
                .and_then(|p| p.to_str())
                .unwrap_or_default();
            let kh = self
                .cfg
                .known_hosts
                .as_ref()
                .and_then(|p| p.to_str())
                .unwrap_or_default();
            cmd.env(
                "GIT_SSH_COMMAND",
                format!(
                    "ssh -F /dev/null -i '{key}' -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes \
                     -o StrictHostKeyChecking=yes -o UserKnownHostsFile='{kh}' -o GlobalKnownHostsFile=/dev/null \
                     -o UpdateHostKeys=no -o ConnectTimeout=10"
                ),
            );
        }
        if in_repo {
            cmd.current_dir(self.repo());
        } else {
            cmd.current_dir(&self.cfg.work_dir);
        }
        cmd.args(args);
        let out = tokio::time::timeout(GIT_TIMEOUT, cmd.output())
            .await
            .map_err(|_| {
                GitError::Other(format!(
                    "git {} timed out after {}s",
                    args[0],
                    GIT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| GitError::Other(format!("git: {e}")))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = format!("git {} failed: {err}", args[0]);
        if args[0] == "push"
            && (err.contains("non-fast-forward")
                || err.contains("fetch first")
                || err.contains("[rejected]"))
        {
            return Err(GitError::NonFastForward(msg));
        }
        Err(GitError::Other(msg))
    }

    async fn g(&self, args: &[&str]) -> Result<String, String> {
        self.git(true, args).await.map_err(|e| e.to_string())
    }

    /// Bring the clone to exactly `origin/<branch>` (cloning it first). An
    /// existing clone that cannot be updated (e.g. a clone killed half-way)
    /// is replaced by a fresh one.
    async fn sync(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.cfg.work_dir)
            .map_err(|e| format!("{}: {e}", self.cfg.work_dir.display()))?;
        let repo = self.repo();
        if repo.join(".git").exists() {
            match self.update().await {
                Ok(()) => return Ok(()),
                Err(e) => eprintln!(
                    "gitops: cannot update the clone ({}), cloning again",
                    one_line(&e, 300)
                ),
            }
        }
        let _ = std::fs::remove_dir_all(&repo);
        let dest = repo.to_str().ok_or("work dir not UTF-8")?;
        self.git(
            false,
            &[
                "clone",
                "-q",
                "--single-branch",
                "--branch",
                &self.cfg.branch,
                "--",
                &self.cfg.remote,
                dest,
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn update(&self) -> Result<(), String> {
        let repo = self.repo();
        // A git process killed mid-way (request timeout) can leave a lock.
        let _ = std::fs::remove_file(repo.join(".git/index.lock"));
        self.g(&["remote", "set-url", "origin", &self.cfg.remote])
            .await?;
        let refspec = format!("+refs/heads/{0}:refs/remotes/origin/{0}", self.cfg.branch);
        self.g(&["fetch", "-q", "--prune", "origin", &refspec])
            .await?;
        self.g(&[
            "checkout",
            "-q",
            "-f",
            "-B",
            &self.cfg.branch,
            &format!("refs/remotes/origin/{}", self.cfg.branch),
        ])
        .await?;
        self.g(&[
            "reset",
            "-q",
            "--hard",
            &format!("refs/remotes/origin/{}", self.cfg.branch),
        ])
        .await?;
        self.g(&["clean", "-q", "-ffdx"]).await?;
        Ok(())
    }

    async fn source(&self, child: &str, f: FileKind) -> Result<Source, String> {
        let path = self.policies_dir().join(f.file_name(child));
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("{}: {e}", f.file_name(child))),
        };
        let revision = match &text {
            None => ABSENT.to_string(),
            Some(_) => self
                .g(&["rev-parse", &format!("HEAD:{}", self.rel(child, f))])
                .await?
                .trim()
                .to_string(),
        };
        Ok(Source { text, revision })
    }

    async fn files(&self, child: &str) -> Result<Files, String> {
        valid_child(child)?;
        let commit = self.g(&["rev-parse", "HEAD"]).await?.trim().to_string();
        Ok(Files {
            child: child.to_string(),
            commit,
            policy: self.source(child, FileKind::Policy).await?,
            overrides: self.source(child, FileKind::Overrides).await?,
        })
    }

    /// Children with a policy file on the branch.
    fn children(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.policies_dir())
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str().map(String::from))
                    .filter_map(|n| n.strip_suffix(".yaml").map(String::from))
                    .filter(|s| {
                        s != "devices" && !s.ends_with(".overrides") && valid_child(s).is_ok()
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// The child's files as they are on the branch now (fetched first).
    pub async fn read(&self, child: &str) -> Result<Files, String> {
        valid_child(child)?;
        let _g = self.lock.lock().await;
        self.sync().await?;
        let f = self.files(child).await?;
        if f.policy.text.is_none() {
            return Err(self.unknown_child(child));
        }
        Ok(f)
    }

    fn unknown_child(&self, child: &str) -> String {
        format!(
            "unknown child {child:?} in the repo; known: {:?}",
            self.children()
        )
    }

    /// Clone or update now (startup check); errors are only reported.
    pub async fn warm_up(&self) -> Result<String, String> {
        let _g = self.lock.lock().await;
        self.sync().await?;
        Ok(self
            .g(&["rev-parse", "--short", "HEAD"])
            .await?
            .trim()
            .to_string())
    }

    /// Apply one change: see the module documentation. The change runs in
    /// its own task: when the caller goes away (MCP client disconnected,
    /// request timeout), the write still runs to its end (committed and
    /// pushed, or refused) instead of being killed between commit and push,
    /// and the clone stays consistent for the next one.
    pub async fn change(self: &std::sync::Arc<Self>, c: Change) -> Result<Outcome, String> {
        valid_child(&c.child)?;
        let this = self.clone();
        tokio::spawn(async move { this.run_change(&c).await })
            .await
            .map_err(|e| format!("the write task failed: {e}"))?
    }

    async fn run_change(&self, c: &Change) -> Result<Outcome, String> {
        let _g = self.lock.lock().await;
        let mut retried = false;
        loop {
            match self.attempt(c, retried).await {
                Err(GitError::NonFastForward(e)) if !retried => {
                    eprintln!(
                        "gitops: push rejected ({}), re-applying {} {} on the new head",
                        one_line(&e, 200),
                        c.tool,
                        c.child
                    );
                    retried = true;
                }
                Err(e) => {
                    // Leave the clone clean for the next change.
                    let _ = self.sync().await;
                    return Err(match e {
                        GitError::NonFastForward(e) => format!(
                            "the branch moved twice while committing (someone else is pushing); nothing was changed, try again: {e}"
                        ),
                        GitError::Other(e) => e,
                    });
                }
                Ok(o) => return Ok(o),
            }
        }
    }

    async fn attempt(&self, c: &Change, retried: bool) -> Result<Outcome, GitError> {
        let other = GitError::Other;
        self.sync().await.map_err(other)?;
        let files = self.files(&c.child).await.map_err(other)?;
        if files.policy.text.is_none() {
            return Err(GitError::Other(self.unknown_child(&c.child)));
        }
        let name = c.file.file_name(&c.child);
        let Some(current) = files.get(c.file).text.clone() else {
            return Err(GitError::Other(format!(
                "{name} does not exist in the repo. The MCP only edits existing files: create it by hand \
                 (e.g. `overrides: []`) and list it in the kustomization's configMapGenerator, otherwise the \
                 server would never see it"
            )));
        };
        let edited = (c.edit)(&files).map_err(other)?;
        let summary = one_line(&edited.summary, 150);
        if edited.text == current {
            let version = self.version_now(&c.child).map_err(other)?;
            return Ok(Outcome {
                commit: None,
                summary,
                diff: String::new(),
                version,
                retried,
            });
        }
        let path = self.policies_dir().join(&name);
        std::fs::write(&path, &edited.text).map_err(|e| GitError::Other(format!("{name}: {e}")))?;
        // Same validation as `kidctl validate <policies dir>`.
        if let Err(errs) = config::load(&self.policies_dir(), config::now_epoch()) {
            let _ = self.sync().await;
            return Err(GitError::Other(format!(
                "invalid, nothing committed:\n- {}",
                errs.join("\n- ")
            )));
        }
        let version = self.version_now(&c.child).map_err(other)?;
        let rel = self.rel(&c.child, c.file);
        let diff = self
            .g(&["diff", "--no-color", "--", &rel])
            .await
            .map_err(other)?;
        if c.dry_run {
            self.sync().await.map_err(other)?;
            return Ok(Outcome {
                commit: None,
                summary,
                diff,
                version,
                retried,
            });
        }
        self.g(&["add", "--", &rel]).await.map_err(other)?;
        let msg = format!(
            "kidctl-mcp: {} {}: {summary}\n\nRequested-By: {}",
            c.tool,
            c.child,
            one_line(&c.requested_by, 120)
        );
        self.g(&["commit", "-q", "-m", &msg, "--", &rel])
            .await
            .map_err(other)?;
        let commit = self
            .g(&["rev-parse", "HEAD"])
            .await
            .map_err(other)?
            .trim()
            .to_string();
        #[cfg(test)]
        {
            let hook = self.before_push.lock().unwrap().pop();
            if let Some(h) = hook {
                h();
            }
        }
        self.git(
            true,
            &[
                "push",
                "-q",
                "origin",
                &format!("HEAD:refs/heads/{}", self.cfg.branch),
            ],
        )
        .await?;
        eprintln!(
            "gitops: pushed {} ({} {}: {summary})",
            &commit[..12.min(commit.len())],
            c.tool,
            c.child
        );
        Ok(Outcome {
            commit: Some(commit),
            summary,
            diff,
            version,
            retried,
        })
    }

    /// Compiled policy version of `child` from the clone's working tree.
    fn version_now(&self, child: &str) -> Result<String, String> {
        let dir = self.policies_dir();
        let p = std::fs::read_to_string(dir.join(FileKind::Policy.file_name(child)))
            .map_err(|e| e.to_string())?;
        let o = std::fs::read_to_string(dir.join(FileKind::Overrides.file_name(child))).ok();
        policy::compile(&p, o.as_deref(), config::now_epoch())
            .map(|c| policy::version(&c))
            .map_err(|e| e.join("; "))
    }

    /// Validate a full replacement of one file in the context of the whole
    /// policies directory (nothing is committed).
    pub async fn validate(
        self: &std::sync::Arc<Self>,
        child: &str,
        f: FileKind,
        yaml: &str,
    ) -> Result<Outcome, String> {
        let yaml = yaml.to_string();
        let edit = move |_: &Files| {
            Ok(Edited {
                text: yaml.clone(),
                summary: "validate".into(),
            })
        };
        self.change(Change {
            tool: "validate_policy".into(),
            child: child.into(),
            file: f,
            requested_by: String::new(),
            dry_run: true,
            edit: Box::new(edit),
        })
        .await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command as Std;

    pub const POLICIES: &str = "overlays/test/kidctl/policies";

    /// Run git synchronously in `dir` (test setup, "someone else" pushing).
    pub fn sh(dir: &Path, args: &[&str]) -> String {
        let out = Std::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Owner")
            .env("GIT_AUTHOR_EMAIL", "owner@example.net")
            .env("GIT_COMMITTER_NAME", "Owner")
            .env("GIT_COMMITTER_EMAIL", "owner@example.net")
            .args([
                "-c",
                "init.defaultBranch=main",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A bare "infra" repo with a policies dir (`kid` + overrides +
    /// devices.yaml, and an unrelated file), plus the owner's own clone.
    pub struct Remote {
        pub dir: tempfile::TempDir,
    }

    impl Remote {
        pub fn new(policy: &str, overrides: Option<&str>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let bare = dir.path().join("infra.git");
            std::fs::create_dir(&bare).unwrap();
            sh(&bare, &["init", "-q", "--bare", "-b", "main"]);
            let own = dir.path().join("owner");
            sh(
                dir.path(),
                &["clone", "-q", bare.to_str().unwrap(), "owner"],
            );
            let pol = own.join(POLICIES);
            std::fs::create_dir_all(&pol).unwrap();
            std::fs::write(pol.join("kid.yaml"), policy).unwrap();
            if let Some(o) = overrides {
                std::fs::write(pol.join("kid.overrides.yaml"), o).unwrap();
            }
            std::fs::write(
                pol.join("devices.yaml"),
                format!(
                    "devices:\n  - {{id: kid-phone, child: kid, token_sha256: {}}}\n",
                    "ab".repeat(32)
                ),
            )
            .unwrap();
            std::fs::write(own.join("README.md"), "infra\n").unwrap();
            sh(&own, &["add", "-A"]);
            sh(&own, &["commit", "-q", "-m", "initial"]);
            sh(&own, &["push", "-q", "origin", "HEAD:main"]);
            Self { dir }
        }

        pub fn bare(&self) -> PathBuf {
            self.dir.path().join("infra.git")
        }

        pub fn owner(&self) -> PathBuf {
            self.dir.path().join("owner")
        }

        /// The owner edits a file and pushes (a concurrent change).
        pub fn owner_push(&self, file: &str, text: &str, msg: &str) {
            let own = self.owner();
            sh(&own, &["pull", "-q", "--ff-only", "origin", "main"]);
            std::fs::write(own.join(POLICIES).join(file), text).unwrap();
            sh(&own, &["commit", "-q", "-am", msg]);
            sh(&own, &["push", "-q", "origin", "HEAD:main"]);
        }

        /// File content on the remote's main.
        pub fn show(&self, file: &str) -> String {
            sh(&self.bare(), &["show", &format!("main:{POLICIES}/{file}")])
        }

        pub fn log(&self) -> Vec<String> {
            sh(&self.bare(), &["log", "--format=%s", "main"])
                .lines()
                .map(String::from)
                .collect()
        }

        pub fn last_message(&self) -> String {
            sh(&self.bare(), &["log", "-1", "--format=%B", "main"])
        }

        pub fn last_author(&self) -> String {
            sh(&self.bare(), &["log", "-1", "--format=%an <%ae>", "main"])
                .trim()
                .to_string()
        }

        pub fn gitops(&self, work: &Path) -> std::sync::Arc<Gitops> {
            std::sync::Arc::new(
                Gitops::new(GitopsConfig {
                    remote: self.bare().to_str().unwrap().to_string(),
                    branch: "main".into(),
                    path: POLICIES.into(),
                    ssh_key: None,
                    known_hosts: None,
                    author_name: "kidctl MCP".into(),
                    author_email: "kidctl@example.net".into(),
                    work_dir: work.to_path_buf(),
                })
                .unwrap(),
            )
        }
    }

    pub const POLICY: &str = "# Kid's rules.\nchild: kid\ntimezone: Europe/Brussels\nblocked: [com.zhiliaoapp.musically]  # TikTok\nlimits:\n  - {name: general, apps: [\"*\"], daily: {default: 1h}}\n";
    pub const OVERRIDES: &str = "# Temporary exceptions.\noverrides: []\n";

    fn replace(text: &str) -> Box<EditFn> {
        let text = text.to_string();
        Box::new(move |_: &Files| {
            Ok(Edited {
                text: text.clone(),
                summary: "replace".into(),
            })
        })
    }

    fn change(edit: Box<EditFn>, file: FileKind, dry_run: bool) -> Change {
        Change {
            tool: "test_tool".into(),
            child: "kid".into(),
            file,
            requested_by: "Claude (OAuth client abc)".into(),
            dry_run,
            edit,
        }
    }

    #[test]
    fn config_validation() {
        let base = GitopsConfig {
            remote: "/srv/infra.git".into(),
            branch: "main".into(),
            path: "overlays/x/policies".into(),
            ssh_key: None,
            known_hosts: None,
            author_name: "kidctl".into(),
            author_email: "k@example.net".into(),
            work_dir: "/tmp/x".into(),
        };
        assert!(base.validate().is_ok());
        for (remote, ok) in [
            ("git@github.com:owner/infra.git", true),
            ("ssh://git@github.com/owner/infra.git", true),
            ("file:///srv/infra.git", true),
            ("https://github.com/owner/infra.git", false),
            ("ext::sh -c touch% /tmp/pwned", false),
            ("relative/path", false),
        ] {
            let c = GitopsConfig {
                remote: remote.into(),
                ..base.clone()
            };
            let r = c.validate();
            if is_ssh_remote(remote) {
                assert!(
                    r.unwrap_err().contains("KIDCTL_GITOPS_SSH_KEY is required"),
                    "{remote}"
                );
            } else {
                assert_eq!(r.is_ok(), ok, "{remote}: {r:?}");
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        let kh = dir.path().join("known_hosts");
        std::fs::write(&key, "k").unwrap();
        let ssh = GitopsConfig {
            remote: "git@github.com:o/r.git".into(),
            ssh_key: Some(key.clone()),
            ..base.clone()
        };
        assert!(
            ssh.validate()
                .unwrap_err()
                .contains("KIDCTL_GITOPS_KNOWN_HOSTS is required")
        );
        let ssh = GitopsConfig {
            known_hosts: Some(kh.clone()),
            ..ssh
        };
        assert!(
            ssh.validate().unwrap_err().contains("known_hosts"),
            "missing file"
        );
        std::fs::write(&kh, "github.com ssh-ed25519 AAAA\n").unwrap();
        assert!(ssh.validate().is_ok());
        for path in ["../x", "/abs", "a/../b", ""] {
            assert!(
                GitopsConfig {
                    path: path.into(),
                    ..base.clone()
                }
                .validate()
                .is_err(),
                "{path}"
            );
        }
        for b in ["", "-x", "a..b", "a b"] {
            assert!(
                GitopsConfig {
                    branch: b.into(),
                    ..base.clone()
                }
                .validate()
                .is_err(),
                "{b}"
            );
        }
        assert_eq!(
            parse_author("kidctl MCP <k@example.net>").unwrap(),
            ("kidctl MCP".into(), "k@example.net".into())
        );
        assert!(parse_author("kidctl").is_err() && parse_author("<k@x>").is_err());
    }

    #[test]
    fn child_names_cannot_traverse() {
        for bad in [
            "../x",
            "a/b",
            "kid.overrides",
            "devices.yaml",
            "devices",
            "",
            "Kid",
            ".",
            "a b",
        ] {
            assert!(valid_child(bad).is_err(), "{bad}");
        }
        assert!(valid_child("alex-2").is_ok());
    }

    #[tokio::test]
    async fn commit_and_push_with_author_message_and_trailer() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        let f = g.read("kid").await.unwrap();
        assert_eq!(f.policy.text.as_deref(), Some(POLICY));
        assert_eq!(f.overrides.text.as_deref(), Some(OVERRIDES));
        assert_eq!(f.policy.revision.len(), 40);
        let new = POLICY.replace("default: 1h", "default: 2h");
        let e = new.clone();
        let o = g
            .change(change(replace(&e), FileKind::Policy, false))
            .await
            .unwrap();
        let commit = o.commit.clone().unwrap();
        assert!(!o.retried);
        assert!(
            o.diff
                .contains("-  - {name: general, apps: [\"*\"], daily: {default: 1h}}"),
            "{}",
            o.diff
        );
        assert!(
            o.diff
                .contains("+  - {name: general, apps: [\"*\"], daily: {default: 2h}}"),
            "{}",
            o.diff
        );
        assert_eq!(r.show("kid.yaml"), new);
        assert_eq!(sh(&r.bare(), &["rev-parse", "main"]).trim(), commit);
        assert_eq!(
            r.last_message().trim(),
            "kidctl-mcp: test_tool kid: replace\n\nRequested-By: Claude (OAuth client abc)"
        );
        assert_eq!(r.last_author(), "kidctl MCP <kidctl@example.net>");
        let want =
            policy::version(&policy::compile(&new, Some(OVERRIDES), config::now_epoch()).unwrap());
        assert_eq!(o.version, want);
        // Unchanged text: no commit.
        let o = g
            .change(change(replace(&e), FileKind::Policy, false))
            .await
            .unwrap();
        assert!(o.commit.is_none() && o.diff.is_empty());
        assert_eq!(r.log().len(), 2);
    }

    #[tokio::test]
    async fn invalid_edit_refused_nothing_pushed() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        let before = r.log();
        for bad in [
            POLICY.replace("Europe/Brussels", "Mars/Base"),
            POLICY.replace("child: kid", "child: other"),
            "limits: [{name: broken".to_string(),
        ] {
            let e = bad.clone();
            let err = g
                .change(change(replace(&e), FileKind::Policy, false))
                .await
                .unwrap_err();
            assert!(err.starts_with("invalid, nothing committed:"), "{err}");
            assert_eq!(r.log(), before);
        }
        // An override naming an unknown limit: validated with the policy.
        let bad = "overrides: [{extra: 30m, limit: nope, until: \"2099-01-01T10:00\"}]\n";
        let e = bad.to_string();
        let err = g
            .change(change(replace(&e), FileKind::Overrides, false))
            .await
            .unwrap_err();
        assert!(err.contains("unknown limit \"nope\""), "{err}");
        assert_eq!(r.log(), before);
        // The clone is clean again: a valid change goes through.
        let e = "overrides: []\n".to_string();
        assert!(
            g.change(change(replace(&e), FileKind::Overrides, false))
                .await
                .unwrap()
                .commit
                .is_some()
        );
    }

    #[tokio::test]
    async fn dry_run_shows_the_diff_without_committing() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        let new = POLICY.replace("1h", "3h");
        let e = new.clone();
        let o = g
            .change(change(replace(&e), FileKind::Policy, true))
            .await
            .unwrap();
        assert!(o.commit.is_none());
        assert!(
            o.diff
                .contains("+  - {name: general, apps: [\"*\"], daily: {default: 3h}}"),
            "{}",
            o.diff
        );
        assert_eq!(r.show("kid.yaml"), POLICY);
        assert_eq!(r.log().len(), 1);
        // The clone was reset: reading gives the branch's text.
        assert_eq!(
            g.read("kid").await.unwrap().policy.text.as_deref(),
            Some(POLICY)
        );
    }

    #[tokio::test]
    async fn non_fast_forward_is_retried_once_on_the_new_head() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        g.warm_up().await.unwrap();
        // While we commit, the owner pushes another change of the same file.
        let owner_text = POLICY.replace("# Kid's rules.", "# Kid's rules (owner edit).");
        let (bare, own) = (r.bare(), r.owner());
        let ot = owner_text.clone();
        g.before_push.lock().unwrap().push(Box::new(move || {
            sh(&own, &["pull", "-q", "--ff-only", "origin", "main"]);
            std::fs::write(own.join(POLICIES).join("kid.yaml"), &ot).unwrap();
            sh(&own, &["commit", "-q", "-am", "owner edit"]);
            sh(&own, &["push", "-q", bare.to_str().unwrap(), "HEAD:main"]);
        }));
        // The edit is a function of the current text: re-applied on the new head.
        let e = |f: &Files| {
            Ok(Edited {
                text: f
                    .policy
                    .text
                    .as_ref()
                    .unwrap()
                    .replace("default: 1h", "default: 2h"),
                summary: "budget 2h".into(),
            })
        };
        let o = g
            .change(change(Box::new(e), FileKind::Policy, false))
            .await
            .unwrap();
        assert!(o.retried);
        assert_eq!(
            r.show("kid.yaml"),
            owner_text.replace("default: 1h", "default: 2h"),
            "both changes kept"
        );
        assert_eq!(
            r.log(),
            vec![
                "kidctl-mcp: test_tool kid: budget 2h",
                "owner edit",
                "initial"
            ]
        );
    }

    #[tokio::test]
    async fn non_fast_forward_twice_fails_cleanly() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        for i in 0..2 {
            let (bare, own) = (r.bare(), r.owner());
            g.before_push.lock().unwrap().push(Box::new(move || {
                sh(&own, &["pull", "-q", "--ff-only", "origin", "main"]);
                std::fs::write(own.join("README.md"), format!("infra {i}\n")).unwrap();
                sh(&own, &["commit", "-q", "-am", &format!("owner {i}")]);
                sh(&own, &["push", "-q", bare.to_str().unwrap(), "HEAD:main"]);
            }));
        }
        let new = POLICY.replace("1h", "2h");
        let e = new.clone();
        let err = g
            .change(change(replace(&e), FileKind::Policy, false))
            .await
            .unwrap_err();
        assert!(err.contains("the branch moved twice"), "{err}");
        assert_eq!(r.show("kid.yaml"), POLICY, "nothing of ours was pushed");
        assert_eq!(r.log(), vec!["owner 0", "owner 1", "initial"]);
        // And the clone recovers for the next change.
        let o = g
            .change(change(replace(&e), FileKind::Policy, false))
            .await
            .unwrap();
        assert!(o.commit.is_some() && !o.retried);
        assert_eq!(r.show("kid.yaml"), new);
    }

    #[tokio::test]
    async fn concurrent_changes_are_serialized() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        let mut tasks = Vec::new();
        for i in 0..4 {
            let g = g.clone();
            tasks.push(tokio::spawn(async move {
                let e = move |f: &Files| {
                    let t = f.overrides.text.clone().unwrap();
                    Ok(Edited {
                        text: format!("{t}# note {i}\n"),
                        summary: format!("note {i}"),
                    })
                };
                let c = Change {
                    tool: "t".into(),
                    child: "kid".into(),
                    file: FileKind::Overrides,
                    requested_by: "x".into(),
                    dry_run: false,
                    edit: Box::new(e),
                };
                g.change(c).await.map(|o| o.retried)
            }));
        }
        for t in tasks {
            assert_eq!(
                t.await.unwrap(),
                Ok(false),
                "no push was ever rejected: one writer at a time"
            );
        }
        let o = r.show("kid.overrides.yaml");
        for i in 0..4 {
            assert!(o.contains(&format!("# note {i}\n")), "{o}");
        }
        assert_eq!(r.log().len(), 5);
    }

    /// The MCP request is cancelled (client gone, request timeout) while the
    /// write is between commit and push: the write still completes, and the
    /// next one starts from the pushed head.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_caller_does_not_cut_a_write_in_half() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        g.before_push
            .lock()
            .unwrap()
            .push(Box::new(|| std::thread::sleep(Duration::from_millis(1500))));
        let new = POLICY.replace("default: 1h", "default: 2h");
        let cut = tokio::time::timeout(
            Duration::from_millis(300),
            g.change(change(replace(&new), FileKind::Policy, false)),
        )
        .await;
        assert!(cut.is_err(), "the caller gave up before the push");
        // The next write waits for the first one (one writer at a time) and
        // sees its result.
        let o = g.read("kid").await.unwrap();
        assert_eq!(o.policy.text.as_deref(), Some(new.as_str()));
        assert_eq!(
            r.show("kid.yaml"),
            new,
            "pushed although nobody waited for it"
        );
        assert_eq!(r.log().len(), 2);
        let again = new.replace("default: 2h", "default: 3h");
        assert!(
            g.change(change(replace(&again), FileKind::Policy, false))
                .await
                .unwrap()
                .commit
                .is_some()
        );
        assert_eq!(r.show("kid.yaml"), again);
    }

    #[tokio::test]
    async fn broken_clone_is_replaced() {
        let r = Remote::new(POLICY, Some(OVERRIDES));
        let work = tempfile::tempdir().unwrap();
        // A clone killed half-way: a .git with nothing usable in it.
        std::fs::create_dir_all(work.path().join("repo/.git/objects")).unwrap();
        std::fs::write(work.path().join("repo/.git/HEAD"), "garbage\n").unwrap();
        let g = r.gitops(work.path());
        assert_eq!(
            g.read("kid").await.unwrap().policy.text.as_deref(),
            Some(POLICY)
        );
        // A local change left in the clone (a crash before reset) is dropped.
        std::fs::write(
            work.path().join("repo").join(POLICIES).join("kid.yaml"),
            "junk",
        )
        .unwrap();
        std::fs::write(work.path().join("repo/.git/index.lock"), "").unwrap();
        assert_eq!(
            g.read("kid").await.unwrap().policy.text.as_deref(),
            Some(POLICY)
        );
    }

    #[tokio::test]
    async fn unknown_child_and_missing_files() {
        let r = Remote::new(POLICY, None);
        let work = tempfile::tempdir().unwrap();
        let g = r.gitops(work.path());
        let err = g.read("nobody").await.unwrap_err();
        assert!(
            err.contains("unknown child \"nobody\"") && err.contains("[\"kid\"]"),
            "{err}"
        );
        let err = g.read("../x").await.unwrap_err();
        assert!(err.contains("lowercase letters"), "{err}");
        let f = g.read("kid").await.unwrap();
        assert_eq!(
            (f.overrides.text.is_none(), f.overrides.revision.as_str()),
            (true, ABSENT)
        );
        let e = "overrides: []\n".to_string();
        let err = g
            .change(change(replace(&e), FileKind::Overrides, false))
            .await
            .unwrap_err();
        assert!(err.contains("kid.overrides.yaml does not exist"), "{err}");
        assert_eq!(r.log().len(), 1);
    }
}
