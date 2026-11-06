//! Agent self-update: the agent APK release the server offers to phones.
//!
//! Release directory (`KIDCTL_AGENT_DIR`, default `/data/agent`, i.e. on the
//! server's data volume, so publishing a release needs no image build):
//!
//! ```text
//! agent.json            {"version_code": 7, "version_name": "0.1.0",
//!                        "sha256": "<64 hex>", "file": "kidctl-agent-7.apk"}
//! kidctl-agent-7.apk    the APK, signed with the release key
//! ```
//!
//! Written by `scripts/release-agent.sh` (APK first, `agent.json` last, both
//! by rename). The server re-hashes the APK and refuses the release when the
//! hash does not match `agent.json`. It keeps the verified bytes in memory
//! (an agent APK is a few MB), so what it serves is exactly what it hashed,
//! with no window between check and download. A broken publish keeps the
//! previous release being offered; deleting `agent.json` withdraws it.

use axum::body::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const META_FILE: &str = "agent.json";
/// Refuse anything bigger (the server holds the release in memory).
pub const MAX_APK_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// Android versionCode of the APK; phones update when it is above theirs.
    pub version_code: i64,
    #[serde(default)]
    pub version_name: String,
    /// Lowercase hex SHA-256 of the APK file.
    pub sha256: String,
    /// APK file name inside the release directory.
    pub file: String,
}

#[derive(Debug)]
pub struct Release {
    pub meta: Meta,
    pub bytes: Bytes,
}

fn plain_file_name(f: &str) -> bool {
    !f.is_empty() && !f.starts_with('.') && !f.contains(['/', '\\']) && f.ends_with(".apk")
}

/// Load and verify the release in `dir`. `Ok(None)`: no release published
/// (no directory or no `agent.json`).
pub fn load(dir: &Path) -> Result<Option<Release>, String> {
    let meta_path = dir.join(META_FILE);
    let text = match std::fs::read_to_string(&meta_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", meta_path.display())),
    };
    let meta: Meta = serde_json::from_str(&text).map_err(|e| format!("{META_FILE}: {e}"))?;
    if meta.version_code <= 0 || meta.version_code > i64::from(i32::MAX) {
        return Err(format!(
            "{META_FILE}: version_code {} out of range 1..=2147483647",
            meta.version_code
        ));
    }
    if meta.sha256.len() != 64
        || !meta
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "{META_FILE}: sha256 must be 64 lowercase hex chars"
        ));
    }
    if !plain_file_name(&meta.file) {
        return Err(format!(
            "{META_FILE}: file {:?} must be a plain *.apk file name in the release directory",
            meta.file
        ));
    }
    if meta.version_name.len() > 64 {
        return Err(format!("{META_FILE}: version_name longer than 64 chars"));
    }
    let apk_path = dir.join(&meta.file);
    let len = std::fs::metadata(&apk_path)
        .map_err(|e| format!("{}: {e}", meta.file))?
        .len();
    if len > MAX_APK_BYTES {
        return Err(format!(
            "{}: {len} bytes, more than the {MAX_APK_BYTES} allowed",
            meta.file
        ));
    }
    let bytes = std::fs::read(&apk_path).map_err(|e| format!("{}: {e}", meta.file))?;
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err(format!("{}: not an APK (zip) file", meta.file));
    }
    let got = hex::encode(Sha256::digest(&bytes));
    if got != meta.sha256 {
        return Err(format!(
            "{}: sha256 is {got}, {META_FILE} says {}",
            meta.file, meta.sha256
        ));
    }
    Ok(Some(Release {
        meta,
        bytes: Bytes::from(bytes),
    }))
}

/// The release currently offered, reloaded when the directory changes.
#[derive(Clone, Default)]
pub struct ReleaseStore {
    dir: Option<PathBuf>,
    cur: Arc<RwLock<Option<Arc<Release>>>>,
}

impl ReleaseStore {
    /// No release directory: never offers an update.
    pub fn none() -> Self {
        Self::default()
    }

    /// Never fails: a missing or broken release must not stop the policy server.
    pub fn open(dir: PathBuf) -> Self {
        let s = Self {
            dir: Some(dir),
            cur: Arc::default(),
        };
        s.reload();
        s
    }

    pub fn get(&self) -> Option<Arc<Release>> {
        self.cur.read().expect("release lock").clone()
    }

    pub fn reload(&self) {
        let Some(dir) = &self.dir else { return };
        let mut cur = self.cur.write().expect("release lock");
        match load(dir) {
            Ok(Some(r)) => {
                if cur.as_ref().map(|c| &c.meta) != Some(&r.meta) {
                    eprintln!(
                        "agent release: version_code {} ({}), {} bytes, sha256 {}",
                        r.meta.version_code,
                        r.meta.version_name,
                        r.bytes.len(),
                        r.meta.sha256
                    );
                }
                *cur = Some(Arc::new(r));
            }
            Ok(None) => {
                if cur.is_some() {
                    eprintln!(
                        "agent release withdrawn ({} has no {META_FILE})",
                        dir.display()
                    );
                } else {
                    eprintln!(
                        "no agent release published ({} has no {META_FILE})",
                        dir.display()
                    );
                }
                *cur = None;
            }
            Err(e) => eprintln!(
                "agent release rejected, {}: {e}",
                match cur.as_ref() {
                    Some(c) => format!("keeping version_code {}", c.meta.version_code),
                    None => "none offered".into(),
                }
            ),
        }
    }

    /// Poll the directory every `every`; reload when anything in it changes.
    pub fn spawn_watcher(&self, every: Duration) {
        let Some(dir) = self.dir.clone() else { return };
        let me = self.clone();
        tokio::spawn(async move {
            let mut last = crate::config::fingerprint(&dir);
            loop {
                tokio::time::sleep(every).await;
                let fp = crate::config::fingerprint(&dir);
                if fp != last {
                    last = fp;
                    me.reload();
                }
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fake "APK" (zip magic + payload) published in `dir`; returns its sha256.
    pub(crate) fn publish(dir: &Path, version_code: i64, payload: &[u8]) -> String {
        let mut apk = b"PK\x03\x04".to_vec();
        apk.extend_from_slice(payload);
        let sha = hex::encode(Sha256::digest(&apk));
        let file = format!("kidctl-agent-{version_code}.apk");
        std::fs::write(dir.join(&file), &apk).unwrap();
        let meta = Meta {
            version_code,
            version_name: "0.1.0".into(),
            sha256: sha.clone(),
            file,
        };
        std::fs::write(dir.join(META_FILE), serde_json::to_string(&meta).unwrap()).unwrap();
        sha
    }

    #[test]
    fn no_dir_or_no_meta_is_no_release() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(&d.path().join("missing")).unwrap().is_none());
        assert!(load(d.path()).unwrap().is_none());
    }

    #[test]
    fn valid_release_loads_with_its_bytes() {
        let d = tempfile::tempdir().unwrap();
        let sha = publish(d.path(), 7, b"hello");
        let r = load(d.path()).unwrap().unwrap();
        assert_eq!(r.meta.version_code, 7);
        assert_eq!(r.meta.sha256, sha);
        assert_eq!(&r.bytes[..], b"PK\x03\x04hello");
    }

    #[test]
    fn sha_mismatch_and_bad_metadata_rejected() {
        let d = tempfile::tempdir().unwrap();
        publish(d.path(), 7, b"hello");
        // APK replaced after agent.json was written.
        std::fs::write(d.path().join("kidctl-agent-7.apk"), b"PK\x03\x04tampered").unwrap();
        let e = load(d.path()).unwrap_err();
        assert!(e.contains("sha256 is"), "{e}");

        let bad = |json: &str| {
            std::fs::write(d.path().join(META_FILE), json).unwrap();
            load(d.path()).unwrap_err()
        };
        let sha = "a".repeat(64);
        assert!(
            bad(&format!(
                r#"{{"version_code":0,"sha256":"{sha}","file":"x.apk"}}"#
            ))
            .contains("out of range")
        );
        assert!(
            bad(r#"{"version_code":1,"sha256":"ABC","file":"x.apk"}"#).contains("64 lowercase hex")
        );
        assert!(
            bad(&format!(
                r#"{{"version_code":1,"sha256":"{sha}","file":"../etc/passwd.apk"}}"#
            ))
            .contains("plain")
        );
        assert!(
            bad(&format!(
                r#"{{"version_code":1,"sha256":"{sha}","file":"x.txt"}}"#
            ))
            .contains("plain")
        );
        assert!(
            bad(&format!(
                r#"{{"version_code":1,"sha256":"{sha}","file":"x.apk","extra":1}}"#
            ))
            .contains("unknown field")
        );
        // Not a zip.
        std::fs::write(d.path().join("x.apk"), b"hello").unwrap();
        let sha_x = hex::encode(Sha256::digest(b"hello"));
        assert!(
            bad(&format!(
                r#"{{"version_code":1,"sha256":"{sha_x}","file":"x.apk"}}"#
            ))
            .contains("not an APK")
        );
    }

    #[test]
    fn store_keeps_previous_on_broken_publish_and_withdraws_on_delete() {
        let d = tempfile::tempdir().unwrap();
        publish(d.path(), 3, b"v3");
        let s = ReleaseStore::open(d.path().to_path_buf());
        assert_eq!(s.get().unwrap().meta.version_code, 3);
        // v4 with a wrong hash: v3 keeps being offered.
        publish(d.path(), 4, b"v4");
        std::fs::write(d.path().join("kidctl-agent-4.apk"), b"PK\x03\x04other").unwrap();
        s.reload();
        assert_eq!(s.get().unwrap().meta.version_code, 3);
        publish(d.path(), 4, b"v4");
        s.reload();
        assert_eq!(s.get().unwrap().meta.version_code, 4);
        std::fs::remove_file(d.path().join(META_FILE)).unwrap();
        s.reload();
        assert!(s.get().is_none());
        assert!(ReleaseStore::none().get().is_none());
    }
}
