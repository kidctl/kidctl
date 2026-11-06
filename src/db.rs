//! SQLite state: what devices report (usage, installed apps, health). Policy
//! never lives here — it comes from git via the config directory.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

#[derive(Debug, Serialize, Clone)]
pub struct DeviceSeen {
    pub id: String,
    pub last_seen: i64,
    pub agent_version: String,
    pub android_sdk: i64,
    pub device_owner: bool,
    pub policy_version: String,
    pub last_error: Option<String>,
    /// Android versionCode of the agent (None: agent older than self-update).
    pub agent_version_code: Option<i64>,
    /// Policy version the server served in its answer to that sync (the
    /// device reports the version it got at its next sync). None: synced
    /// before this was recorded.
    pub policy_served: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct App {
    pub package: String,
    pub label: String,
    pub user_installed: bool,
    pub suspended: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct Event {
    pub ts: i64,
    pub kind: String,
    pub detail: String,
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let c = Connection::open(path)?;
        Self::init(c)
    }

    pub fn memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(c: Connection) -> rusqlite::Result<Self> {
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS device (
               id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL, agent_version TEXT NOT NULL,
               android_sdk INTEGER NOT NULL, device_owner INTEGER NOT NULL, policy_version TEXT NOT NULL,
               last_error TEXT);
             CREATE TABLE IF NOT EXISTS usage (
               device TEXT NOT NULL, date TEXT NOT NULL, package TEXT NOT NULL, secs INTEGER NOT NULL,
               PRIMARY KEY (device, date, package));
             CREATE TABLE IF NOT EXISTS app (
               device TEXT NOT NULL, package TEXT NOT NULL, label TEXT NOT NULL,
               user_installed INTEGER NOT NULL, suspended INTEGER NOT NULL,
               PRIMARY KEY (device, package));
             CREATE TABLE IF NOT EXISTS event (
               device TEXT NOT NULL, ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS event_dev_ts ON event(device, ts);",
        )?;
        // Columns added after the first release (databases created before them).
        let has_col = |col: &str| -> rusqlite::Result<bool> {
            let mut st = c.prepare("SELECT 1 FROM pragma_table_info('device') WHERE name=?1")?;
            st.exists(params![col])
        };
        if !has_col("agent_version_code")? {
            c.execute_batch("ALTER TABLE device ADD COLUMN agent_version_code INTEGER;")?;
        }
        if !has_col("policy_served")? {
            c.execute_batch("ALTER TABLE device ADD COLUMN policy_served TEXT;")?;
        }
        Ok(Self(Arc::new(Mutex::new(c))))
    }

    pub fn record_sync(
        &self,
        seen: &DeviceSeen,
        date: &str,
        usage: &BTreeMap<String, u64>,
        apps: Option<&[App]>,
        events: &[Event],
    ) -> rusqlite::Result<()> {
        let mut c = self.0.lock().expect("db lock");
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO device (id,last_seen,agent_version,android_sdk,device_owner,policy_version,last_error,agent_version_code,
               policy_served)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(id) DO UPDATE SET last_seen=?2, agent_version=?3, android_sdk=?4, device_owner=?5,
               policy_version=?6, last_error=?7, agent_version_code=?8, policy_served=?9",
            params![
                seen.id,
                seen.last_seen,
                seen.agent_version,
                seen.android_sdk,
                seen.device_owner,
                seen.policy_version,
                seen.last_error,
                seen.agent_version_code,
                seen.policy_served
            ],
        )?;
        // The device sends whole-day totals: replace the day.
        tx.execute(
            "DELETE FROM usage WHERE device=?1 AND date=?2",
            params![seen.id, date],
        )?;
        for (p, s) in usage {
            tx.execute(
                "INSERT INTO usage (device,date,package,secs) VALUES (?1,?2,?3,?4)",
                params![seen.id, date, p, *s as i64],
            )?;
        }
        if let Some(apps) = apps {
            tx.execute("DELETE FROM app WHERE device=?1", params![seen.id])?;
            for a in apps {
                tx.execute(
                    "INSERT INTO app (device,package,label,user_installed,suspended) VALUES (?1,?2,?3,?4,?5)",
                    params![seen.id, a.package, a.label, a.user_installed, a.suspended],
                )?;
            }
        }
        for e in events {
            tx.execute(
                "INSERT INTO event (device,ts,kind,detail) VALUES (?1,?2,?3,?4)",
                params![seen.id, e.ts, e.kind, e.detail],
            )?;
        }
        tx.commit()
    }

    pub fn device(&self, id: &str) -> rusqlite::Result<Option<DeviceSeen>> {
        let c = self.0.lock().expect("db lock");
        c.query_row(
            "SELECT id,last_seen,agent_version,android_sdk,device_owner,policy_version,last_error,agent_version_code,
               policy_served
             FROM device WHERE id=?1",
            params![id],
            |r| {
                Ok(DeviceSeen {
                    id: r.get(0)?,
                    last_seen: r.get(1)?,
                    agent_version: r.get(2)?,
                    android_sdk: r.get(3)?,
                    device_owner: r.get(4)?,
                    policy_version: r.get(5)?,
                    last_error: r.get(6)?,
                    agent_version_code: r.get(7)?,
                    policy_served: r.get(8)?,
                })
            },
        )
        .optional()
    }

    /// An event recorded by the server itself about a device (e.g. an agent download).
    pub fn add_event(&self, device: &str, e: &Event) -> rusqlite::Result<()> {
        let c = self.0.lock().expect("db lock");
        c.execute(
            "INSERT INTO event (device,ts,kind,detail) VALUES (?1,?2,?3,?4)",
            params![device, e.ts, e.kind, e.detail],
        )?;
        Ok(())
    }

    /// Usage of several devices summed per package for one local date.
    pub fn usage(&self, devices: &[String], date: &str) -> rusqlite::Result<BTreeMap<String, u64>> {
        let c = self.0.lock().expect("db lock");
        let mut out = BTreeMap::new();
        let mut st = c.prepare("SELECT package, secs FROM usage WHERE device=?1 AND date=?2")?;
        for d in devices {
            let rows = st.query_map(params![d, date], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (p, s) = row?;
                *out.entry(p).or_insert(0) += s.max(0) as u64;
            }
        }
        Ok(out)
    }

    pub fn apps(&self, device: &str) -> rusqlite::Result<Vec<App>> {
        let c = self.0.lock().expect("db lock");
        let mut st = c.prepare(
            "SELECT package,label,user_installed,suspended FROM app WHERE device=?1 ORDER BY label",
        )?;
        let rows = st.query_map(params![device], |r| {
            Ok(App {
                package: r.get(0)?,
                label: r.get(1)?,
                user_installed: r.get(2)?,
                suspended: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn events(&self, device: &str, since: i64) -> rusqlite::Result<Vec<Event>> {
        let c = self.0.lock().expect("db lock");
        let mut st = c.prepare("SELECT ts,kind,detail FROM event WHERE device=?1 AND ts>=?2 ORDER BY ts DESC LIMIT 200")?;
        let rows = st.query_map(params![device, since], |r| {
            Ok(Event {
                ts: r.get(0)?,
                kind: r.get(1)?,
                detail: r.get(2)?,
            })
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_a_database_created_before_agent_version_code_and_policy_served() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            // Schema of the first release.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE device (
                   id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL, agent_version TEXT NOT NULL,
                   android_sdk INTEGER NOT NULL, device_owner INTEGER NOT NULL, policy_version TEXT NOT NULL,
                   last_error TEXT);
                 INSERT INTO device VALUES ('p', 5, '0.1.0', 37, 1, 'v', NULL);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let d = db.device("p").unwrap().unwrap();
        assert_eq!(
            (
                d.agent_version.as_str(),
                d.agent_version_code,
                d.policy_served.as_deref()
            ),
            ("0.1.0", None, None)
        );
        let seen = DeviceSeen {
            agent_version_code: Some(9),
            policy_served: Some("abc".into()),
            ..d
        };
        db.record_sync(&seen, "2026-10-18", &BTreeMap::new(), None, &[])
            .unwrap();
        let d = db.device("p").unwrap().unwrap();
        assert_eq!(
            (
                d.agent_version_code,
                d.policy_served.as_deref(),
                d.policy_version.as_str()
            ),
            (Some(9), Some("abc"), "v")
        );
        // Opening again does not try to add the column twice.
        drop(db);
        Db::open(&path).unwrap();
    }
}
