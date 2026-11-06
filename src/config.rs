//! The config directory (a ConfigMap mounted read-only in k8s, or a plain
//! directory locally):
//!
//! ```text
//! <child>.yaml            policy (see policy::PolicyFile)
//! <child>.overrides.yaml  optional temporary overrides
//! devices.yaml            devices: [{id, child, token_sha256}]
//! ```
//!
//! [`Store`] reloads the directory when any file changes. A broken edit is
//! logged and the last valid config keeps being served.

use crate::policy::{self, Compiled};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub child: String,
    /// Hex SHA-256 of the device token (`kidctl token` prints both).
    pub token_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicesFile {
    #[serde(default)]
    devices: Vec<Device>,
}

/// Raw texts of one child's files (compiled on demand, because overrides
/// expire with time).
#[derive(Debug, Clone)]
pub struct ChildSrc {
    pub policy: String,
    pub overrides: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub children: BTreeMap<String, ChildSrc>,
    pub devices: Vec<Device>,
}

impl Config {
    pub fn compiled(&self, child: &str, now: i64) -> Option<Result<Compiled, Vec<String>>> {
        self.children
            .get(child)
            .map(|s| policy::compile(&s.policy, s.overrides.as_deref(), now))
    }
}

fn read_dir_files(dir: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for ent in rd {
        let ent = ent.map_err(|e| e.to_string())?;
        let name = ent.file_name().to_string_lossy().to_string();
        // ConfigMap mounts contain ..data / ..<timestamp> helper entries.
        if name.starts_with('.') || !(name.ends_with(".yaml") || name.ends_with(".yml")) {
            continue;
        }
        let text = std::fs::read_to_string(ent.path()).map_err(|e| format!("{name}: {e}"))?;
        out.insert(name, text);
    }
    Ok(out)
}

/// Load and fully validate a config directory. Errors are prefixed by file name.
pub fn load(dir: &Path, now: i64) -> Result<Config, Vec<String>> {
    let files = read_dir_files(dir).map_err(|e| vec![e])?;
    let mut errs = Vec::new();
    let mut cfg = Config::default();
    for (name, text) in &files {
        let stem = name.trim_end_matches(".yaml").trim_end_matches(".yml");
        if stem == "devices" {
            match serde_yaml_ng::from_str::<DevicesFile>(text) {
                Ok(d) => cfg.devices = d.devices,
                Err(e) => errs.push(format!("{name}: {e}")),
            }
        } else if let Some(child) = stem.strip_suffix(".overrides") {
            let _ = child; // attached below
        } else {
            let overrides = files
                .get(&format!("{stem}.overrides.yaml"))
                .or_else(|| files.get(&format!("{stem}.overrides.yml")))
                .cloned();
            cfg.children.insert(
                stem.to_string(),
                ChildSrc {
                    policy: text.clone(),
                    overrides,
                },
            );
        }
    }
    for name in files.keys() {
        let stem = name.trim_end_matches(".yaml").trim_end_matches(".yml");
        if let Some(child) = stem.strip_suffix(".overrides")
            && !cfg.children.contains_key(child)
        {
            errs.push(format!("{name}: no policy file {child}.yaml"));
        }
    }
    for (stem, src) in &cfg.children {
        match policy::compile(&src.policy, src.overrides.as_deref(), now) {
            Ok(c) if c.child != *stem => errs.push(format!(
                "{stem}.yaml: child: {:?} must match the file name",
                c.child
            )),
            Ok(_) => {}
            Err(es) => errs.extend(es.into_iter().map(|e| format!("{stem}.yaml: {e}"))),
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for d in &cfg.devices {
        if !ids.insert(&d.id) {
            errs.push(format!("devices.yaml: id {:?} used twice", d.id));
        }
        if !cfg.children.contains_key(&d.child) {
            errs.push(format!(
                "devices.yaml: device {:?}: unknown child {:?}",
                d.id, d.child
            ));
        }
        if d.token_sha256.len() != 64 || hex::decode(&d.token_sha256).is_err() {
            errs.push(format!(
                "devices.yaml: device {:?}: token_sha256 must be 64 hex chars",
                d.id
            ));
        }
    }
    if errs.is_empty() { Ok(cfg) } else { Err(errs) }
}

pub(crate) fn fingerprint(dir: &Path) -> Vec<(String, SystemTime, u64)> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            // metadata() follows symlinks, so ConfigMap atomic swaps are seen.
            if let Ok(m) = std::fs::metadata(e.path()) {
                v.push((
                    e.file_name().to_string_lossy().to_string(),
                    m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    m.len(),
                ));
            }
        }
    }
    v.sort();
    v
}

#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    inner: Arc<RwLock<Arc<Config>>>,
}

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Store {
    pub fn open(dir: PathBuf) -> Result<Self, Vec<String>> {
        let cfg = load(&dir, now_epoch())?;
        Ok(Self {
            dir,
            inner: Arc::new(RwLock::new(Arc::new(cfg))),
        })
    }

    pub fn get(&self) -> Arc<Config> {
        self.inner.read().expect("lock").clone()
    }

    /// Poll the directory every `every`; swap in a new config only when it is valid.
    pub fn spawn_watcher(&self, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut last = fingerprint(&me.dir);
            loop {
                tokio::time::sleep(every).await;
                let fp = fingerprint(&me.dir);
                if fp == last {
                    continue;
                }
                last = fp;
                match load(&me.dir, now_epoch()) {
                    Ok(cfg) => {
                        eprintln!(
                            "config reloaded: {} children, {} devices",
                            cfg.children.len(),
                            cfg.devices.len()
                        );
                        *me.inner.write().expect("lock") = Arc::new(cfg);
                    }
                    Err(es) => eprintln!(
                        "config reload rejected, keeping previous:\n  {}",
                        es.join("\n  ")
                    ),
                }
            }
        });
    }
}
