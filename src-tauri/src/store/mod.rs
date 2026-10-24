//! SQLite persistence, retention and the per-install salt. OWNER: WP3.
//!
//! CONTRACT (frozen):
//! - `rusqlite` (bundled). Tables: `wifi_sightings`, `ble_sightings`, `alerts`, `settings`,
//!   `meta` (salt). Observations are grouped by their scan's `scanned_at` so
//!   [`Store::get_history`] can rebuild [`ScanSnapshot`]s.
//! - Salt: 32 random bytes generated on first open, persisted (file/DB mode 0600), never
//!   logged. A second fresh store gets a different salt; reopening yields the same one.
//! - [`Store::migrate`] is idempotent. [`Store::insert_scan`] never stores raw identifiers
//!   (they arrive already hashed).
//! - Retention: [`Store::purge`] deletes exactly the rows older than the cutoff.
//!   Callers purge after every insert batch (the integrator wires this).
//! - [`Store::upsert_alerts`] dedupes by `(kind, subject_hash)`: an existing alert only gets
//!   `last_seen` (and severity/detail) refreshed and keeps `first_seen` and `dismissed`.
//!   It returns only the alerts that were NEWLY created, which drive notifications.
//! - `Store` holds a non-`Sync` connection; the integrator wraps it in a `Mutex`.

use crate::model::{
    Alert, AlertKind, BleObservation, History, Millis, Salt, ScanResult, ScanSnapshot, Settings,
    WifiObservation,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: i64 = 1;
const SALT_LEN: usize = 32;
const DB_FILE: &str = "store.sqlite3";
/// The salt lives in its own 0600 file, NOT in the database: a copy, backup or export of the
/// DB (which holds hashed identifiers) then cannot be brute-forced back to BSSIDs/UUIDs.
const SALT_FILE: &str = "salt.key";
const MS_PER_HOUR: i64 = 3_600_000;

/// Any store failure, as a message. Never contains scan content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(e.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

pub struct Store {
    conn: Connection,
    salt: Salt,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Store { .. }")
    }
}

fn err<E: fmt::Display>(ctx: &str, e: E) -> StoreError {
    StoreError(format!("{ctx}: {e}"))
}

fn to_json<T: Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(|e| err("serialize", e))
}

/// Enums are stored as their camelCase JSON string (the same form the contract uses).
fn from_json<T: DeserializeOwned>(s: &str) -> StoreResult<T> {
    serde_json::from_str(s).map_err(|e| err("deserialize", e))
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| err("set file mode", e))
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> StoreResult<()> {
    Ok(())
}

/// Load the salt file, or create it atomically (temp file at 0600, then hard-link into place
/// so two racing openers cannot overwrite each other's salt).
fn load_or_create_salt(dir: &Path) -> StoreResult<Salt> {
    let path = dir.join(SALT_FILE);
    if !path.exists() {
        let mut bytes = vec![0u8; SALT_LEN];
        rand::fill(&mut bytes[..]);
        let tmp = dir.join(format!("{SALT_FILE}.tmp{}", std::process::id()));
        let _ = fs::remove_file(&tmp);
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| err("create salt", e))?;
            f.write_all(&bytes).map_err(|e| err("write salt", e))?;
            f.sync_all().map_err(|e| err("sync salt", e))?;
        }
        let linked = fs::hard_link(&tmp, &path);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(err("install salt", e)),
        }
    }
    set_mode_0600(&path)?; // also repairs a file whose mode was loosened
    let mut buf = Vec::new();
    fs::File::open(&path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .map_err(|e| err("read salt", e))?;
    if buf.len() != SALT_LEN {
        // Never regenerate silently: that would orphan every stored hash.
        return Err(StoreError("salt file is corrupt (wrong length)".into()));
    }
    Ok(Salt::from_bytes(buf))
}

impl Store {
    /// Open (creating if needed) the store in directory `path` (the integrator passes the
    /// Tauri app-data dir): `store.sqlite3` plus `salt.key`. Runs [`Store::migrate`] and loads
    /// or creates the salt.
    pub fn open(path: &Path) -> StoreResult<Store> {
        fs::create_dir_all(path).map_err(|e| err("create store dir", e))?;
        let salt = load_or_create_salt(path)?;
        let db_path: PathBuf = path.join(DB_FILE);
        let conn = Connection::open(&db_path)?;
        set_mode_0600(&db_path)?;
        let mut store = Store { conn, salt };
        store.migrate()?;
        Ok(store)
    }

    /// Create any missing tables. Safe to call repeatedly.
    pub fn migrate(&mut self) -> StoreResult<()> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS scans (
                 scanned_at INTEGER PRIMARY KEY
             );
             CREATE TABLE IF NOT EXISTS wifi_sightings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 scan_at INTEGER NOT NULL,
                 ssid TEXT,
                 bssid_hash TEXT,
                 rssi INTEGER NOT NULL,
                 channel INTEGER,
                 security TEXT NOT NULL,
                 seen_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_wifi_scan_at ON wifi_sightings(scan_at);
             CREATE TABLE IF NOT EXISTS ble_sightings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 scan_at INTEGER NOT NULL,
                 name TEXT,
                 peripheral_hash TEXT NOT NULL,
                 rssi INTEGER,
                 tracker TEXT,
                 manufacturer_id INTEGER,
                 seen_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_ble_scan_at ON ble_sightings(scan_at);
             CREATE TABLE IF NOT EXISTS alerts (
                 id TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 title TEXT NOT NULL,
                 detail TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL,
                 subject_hash TEXT NOT NULL,
                 dismissed INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (kind, subject_hash)
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_id ON alerts(id);
             CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        let has_version: bool =
            tx.query_row("SELECT EXISTS(SELECT 1 FROM schema_version)", [], |r| {
                r.get(0)
            })?;
        if !has_version {
            tx.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [SCHEMA_VERSION],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The per-install salt. Pass it to `wifi::scan` / `ble::scan`.
    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Persist every observation in `scan`, then purge by the stored `retention_hours`
    /// (relative to this scan's time). Insert and purge are one transaction.
    pub fn insert_scan(&mut self, scan: &ScanResult) -> StoreResult<()> {
        let retention = self.get_settings()?.retention_hours;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO scans (scanned_at) VALUES (?1)",
            [scan.scanned_at],
        )?;
        {
            let mut w = tx.prepare(
                "INSERT INTO wifi_sightings (scan_at, ssid, bssid_hash, rssi, channel, security, seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for o in &scan.wifi {
                let sec = to_json(&o.security)?;
                w.execute(params![
                    scan.scanned_at,
                    o.ssid,
                    o.bssid_hash,
                    o.rssi,
                    o.channel,
                    sec,
                    o.seen_at
                ])?;
            }
            let mut b = tx.prepare(
                "INSERT INTO ble_sightings (scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for o in &scan.ble {
                let tracker = o.tracker.as_ref().map(to_json).transpose()?;
                b.execute(params![
                    scan.scanned_at,
                    o.name,
                    o.peripheral_hash,
                    o.rssi,
                    tracker,
                    o.manufacturer_id,
                    o.seen_at
                ])?;
            }
        }
        purge_tx(&tx, retention, scan.scanned_at)?;
        tx.commit()?;
        Ok(())
    }

    /// All scans with `scanned_at >= since`, ascending.
    pub fn get_history(&self, since: Millis) -> StoreResult<History> {
        let mut map: BTreeMap<Millis, ScanSnapshot> = BTreeMap::new();
        let mut q = self
            .conn
            .prepare("SELECT scanned_at FROM scans WHERE scanned_at >= ?1")?;
        for t in q.query_map([since], |r| r.get::<_, Millis>(0))? {
            let t = t?;
            map.insert(
                t,
                ScanSnapshot {
                    scanned_at: t,
                    wifi: vec![],
                    ble: vec![],
                },
            );
        }
        let mut q = self.conn.prepare(
            "SELECT scan_at, ssid, bssid_hash, rssi, channel, security, seen_at
             FROM wifi_sightings WHERE scan_at >= ?1 ORDER BY id",
        )?;
        let rows = q.query_map([since], |r| {
            Ok((
                r.get::<_, Millis>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i32>(3)?,
                r.get::<_, Option<u32>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Millis>(6)?,
            ))
        })?;
        for row in rows {
            let (scan_at, ssid, bssid_hash, rssi, channel, sec, seen_at) = row?;
            let obs = WifiObservation {
                ssid,
                bssid_hash,
                rssi,
                channel,
                security: from_json(&sec)?,
                seen_at,
            };
            map.entry(scan_at)
                .or_insert_with(|| ScanSnapshot {
                    scanned_at: scan_at,
                    wifi: vec![],
                    ble: vec![],
                })
                .wifi
                .push(obs);
        }
        let mut q = self.conn.prepare(
            "SELECT scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at
             FROM ble_sightings WHERE scan_at >= ?1 ORDER BY id",
        )?;
        let rows = q.query_map([since], |r| {
            Ok((
                r.get::<_, Millis>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i16>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<u16>>(5)?,
                r.get::<_, Millis>(6)?,
            ))
        })?;
        for row in rows {
            let (scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at) = row?;
            let obs = BleObservation {
                name,
                peripheral_hash,
                rssi,
                tracker: tracker.as_deref().map(from_json).transpose()?,
                manufacturer_id,
                seen_at,
            };
            map.entry(scan_at)
                .or_insert_with(|| ScanSnapshot {
                    scanned_at: scan_at,
                    wifi: vec![],
                    ble: vec![],
                })
                .ble
                .push(obs);
        }
        Ok(History {
            scans: map.into_values().collect(),
        })
    }

    /// Merge `alerts` into the stored set. Returns the newly created ones only.
    pub fn upsert_alerts(&mut self, alerts: &[Alert]) -> StoreResult<Vec<Alert>> {
        let tx = self.conn.transaction()?;
        let mut created = Vec::new();
        for a in alerts {
            let kind = to_json(&a.kind)?;
            let sev = to_json(&a.severity)?;
            let updated = tx.execute(
                "UPDATE alerts SET last_seen = MAX(last_seen, ?1), severity = ?2, title = ?3, detail = ?4
                 WHERE kind = ?5 AND subject_hash = ?6",
                params![a.last_seen, sev, a.title, a.detail, kind, a.subject_hash],
            )?;
            if updated == 0 {
                tx.execute(
                    "INSERT INTO alerts (id, kind, severity, title, detail, first_seen, last_seen, subject_hash, dismissed)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                    params![
                        a.id, kind, sev, a.title, a.detail, a.first_seen, a.last_seen,
                        a.subject_hash
                    ],
                )?;
                let mut n = a.clone();
                n.dismissed = false;
                created.push(n);
            }
        }
        tx.commit()?;
        Ok(created)
    }

    /// Stored alerts, newest `last_seen` first.
    pub fn get_alerts(&self, include_dismissed: bool) -> StoreResult<Vec<Alert>> {
        let sql = if include_dismissed {
            "SELECT id, kind, severity, title, detail, first_seen, last_seen, subject_hash, dismissed
             FROM alerts ORDER BY last_seen DESC, id"
        } else {
            "SELECT id, kind, severity, title, detail, first_seen, last_seen, subject_hash, dismissed
             FROM alerts WHERE dismissed = 0 ORDER BY last_seen DESC, id"
        };
        let mut q = self.conn.prepare(sql)?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Millis>(5)?,
                r.get::<_, Millis>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, bool>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, sev, title, detail, first_seen, last_seen, subject_hash, dismissed) =
                row?;
            let kind: AlertKind = from_json(&kind)?;
            out.push(Alert {
                id,
                kind,
                severity: from_json(&sev)?,
                title,
                detail,
                first_seen,
                last_seen,
                subject_hash,
                dismissed,
            });
        }
        Ok(out)
    }

    /// Mark an alert dismissed. Unknown id is not an error.
    pub fn dismiss_alert(&mut self, id: &str) -> StoreResult<()> {
        self.conn
            .execute("UPDATE alerts SET dismissed = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Stored settings, or `Settings::default()` if none were saved.
    pub fn get_settings(&self) -> StoreResult<Settings> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'settings'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match raw {
            Some(s) => from_json(&s), // `#[serde(default)]` fills fields added later
            None => Ok(Settings::default()),
        }
    }

    pub fn set_settings(&mut self, settings: &Settings) -> StoreResult<()> {
        let json = to_json(settings)?;
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES ('settings', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [json],
        )?;
        Ok(())
    }

    /// Delete sightings (and alerts whose `last_seen`) older than `now - retention_hours`.
    /// A row exactly at the cutoff is kept. Returns the number of sighting + alert rows
    /// removed (the per-scan bookkeeping rows are removed too but not counted).
    pub fn purge(&mut self, retention_hours: u32, now: Millis) -> StoreResult<usize> {
        let tx = self.conn.transaction()?;
        let n = purge_tx(&tx, retention_hours, now)?;
        tx.commit()?;
        Ok(n)
    }
}

fn purge_tx(
    tx: &rusqlite::Transaction<'_>,
    retention_hours: u32,
    now: Millis,
) -> StoreResult<usize> {
    let cutoff = now.saturating_sub(i64::from(retention_hours) * MS_PER_HOUR);
    let mut n = tx.execute("DELETE FROM wifi_sightings WHERE scan_at < ?1", [cutoff])?;
    n += tx.execute("DELETE FROM ble_sightings WHERE scan_at < ?1", [cutoff])?;
    n += tx.execute("DELETE FROM alerts WHERE last_seen < ?1", [cutoff])?;
    tx.execute("DELETE FROM scans WHERE scanned_at < ?1", [cutoff])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AlertToggles, PermissionState, Security, Severity, TrackerKind, TrustedNetwork,
    };
    use tempfile::TempDir;

    const H: i64 = MS_PER_HOUR;

    fn open() -> (TempDir, Store) {
        let d = TempDir::new().unwrap();
        let s = Store::open(d.path()).unwrap();
        (d, s)
    }

    fn wifi(n: u8, at: Millis) -> WifiObservation {
        WifiObservation {
            ssid: Some(format!("Net-{n}")),
            bssid_hash: Some(format!("{n:02x}").repeat(32)),
            rssi: -50 - i32::from(n),
            channel: Some(36),
            security: Security::Wpa2Personal,
            seen_at: at,
        }
    }

    fn ble(n: u8, at: Millis) -> BleObservation {
        BleObservation {
            name: None,
            peripheral_hash: format!("{n:02x}").repeat(32),
            rssi: Some(-70),
            tracker: Some(TrackerKind::Tile),
            manufacturer_id: Some(0x004C),
            seen_at: at,
        }
    }

    fn scan(at: Millis, nw: u8, nb: u8) -> ScanResult {
        ScanResult {
            scanned_at: at,
            wifi: (0..nw).map(|i| wifi(i, at)).collect(),
            ble: (0..nb).map(|i| ble(i, at)).collect(),
            errors: vec![],
            permissions: PermissionState::UNKNOWN,
        }
    }

    fn alert(kind: AlertKind, subj: &str, first: Millis, last: Millis) -> Alert {
        Alert {
            id: format!("{kind:?}-{subj}"),
            kind,
            severity: Severity::High,
            title: "Net-A twin".into(),
            detail: "synthetic".into(),
            first_seen: first,
            last_seen: last,
            subject_hash: subj.into(),
            dismissed: false,
        }
    }

    #[test]
    fn migrate_twice_is_idempotent() {
        let (_d, mut s) = open();
        s.insert_scan(&scan(1000, 2, 1)).unwrap();
        s.migrate().unwrap();
        s.migrate().unwrap();
        let versions: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(versions, 1);
        assert_eq!(s.get_history(0).unwrap().scans.len(), 1); // data survived
    }

    #[test]
    fn purge_boundary_deletes_exactly_expired() {
        let (_d, mut s) = open();
        let now = 100 * H;
        let cutoff = now - 24 * H;
        for at in [cutoff - 1, cutoff, cutoff + 1] {
            // raw insert: insert_scan itself purges relative to its own scan time
            s.conn
                .execute("INSERT INTO scans VALUES (?1)", [at])
                .unwrap();
            s.conn
                .execute(
                    "INSERT INTO wifi_sightings (scan_at, ssid, bssid_hash, rssi, channel, security, seen_at)
                     VALUES (?1, 'Net-A', NULL, -60, NULL, '\"open\"', ?1)",
                    [at],
                )
                .unwrap();
            s.conn
                .execute(
                    "INSERT INTO ble_sightings (scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at)
                     VALUES (?1, NULL, 'aa', NULL, NULL, NULL, ?1)",
                    [at],
                )
                .unwrap();
        }
        s.upsert_alerts(&[
            alert(AlertKind::EvilTwin, "old", cutoff - 5, cutoff - 1),
            alert(AlertKind::EvilTwin, "edge", cutoff - 5, cutoff),
        ])
        .unwrap();
        let removed = s.purge(24, now).unwrap();
        assert_eq!(removed, 1 + 1 + 1); // 1 wifi + 1 ble + 1 alert, all strictly older
        let h = s.get_history(0).unwrap();
        let times: Vec<_> = h.scans.iter().map(|x| x.scanned_at).collect();
        assert_eq!(times, vec![cutoff, cutoff + 1]);
        assert!(h
            .scans
            .iter()
            .all(|x| x.wifi.len() == 1 && x.ble.len() == 1));
        let left: Vec<_> = s
            .get_alerts(true)
            .unwrap()
            .into_iter()
            .map(|a| a.subject_hash)
            .collect();
        assert_eq!(left, vec!["edge".to_string()]);
        assert_eq!(s.purge(24, now).unwrap(), 0);
    }

    #[test]
    fn insert_scan_purges_by_stored_retention() {
        let (_d, mut s) = open();
        let st = Settings {
            retention_hours: 2,
            ..Settings::default()
        };
        s.set_settings(&st).unwrap();
        s.insert_scan(&scan(10 * H, 1, 1)).unwrap();
        s.insert_scan(&scan(11 * H, 1, 1)).unwrap();
        s.insert_scan(&scan(13 * H, 1, 1)).unwrap(); // cutoff 11h: 10h goes, 11h stays
        let times: Vec<_> = s
            .get_history(0)
            .unwrap()
            .scans
            .iter()
            .map(|x| x.scanned_at)
            .collect();
        assert_eq!(times, vec![11 * H, 13 * H]);
    }

    #[test]
    fn history_roundtrip_ascending_and_since() {
        let (_d, mut s) = open();
        s.insert_scan(&scan(3000, 2, 2)).unwrap();
        s.insert_scan(&scan(1000, 1, 0)).unwrap();
        s.insert_scan(&scan(2000, 0, 0)).unwrap(); // empty scan still counts
        let h = s.get_history(0).unwrap();
        let times: Vec<_> = h.scans.iter().map(|x| x.scanned_at).collect();
        assert_eq!(times, vec![1000, 2000, 3000]);
        assert_eq!(h.scans[2].wifi, scan(3000, 2, 2).wifi);
        assert_eq!(h.scans[2].ble, scan(3000, 2, 2).ble);
        assert_eq!(s.get_history(2000).unwrap().scans.len(), 2);
    }

    #[test]
    fn salt_persists_across_reopen() {
        let d = TempDir::new().unwrap();
        let a = Store::open(d.path()).unwrap().salt().clone();
        let b = Store::open(d.path()).unwrap().salt().clone();
        assert_eq!(a, b);
        assert_eq!(a.as_bytes().len(), 32);
    }

    #[test]
    fn fresh_stores_have_different_salts() {
        let (_d1, s1) = open();
        let (_d2, s2) = open();
        assert_ne!(s1.salt(), s2.salt());
    }

    #[cfg(unix)]
    #[test]
    fn salt_and_db_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = TempDir::new().unwrap();
        let _s = Store::open(d.path()).unwrap();
        for f in [SALT_FILE, DB_FILE] {
            let mode = fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
        // a loosened mode is repaired on the next open
        fs::set_permissions(d.path().join(SALT_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        let _s = Store::open(d.path()).unwrap();
        let mode = fs::metadata(d.path().join(SALT_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn salt_not_in_database_or_debug() {
        let d = TempDir::new().unwrap();
        let s = Store::open(d.path()).unwrap();
        let hexsalt = hex::encode(s.salt().as_bytes());
        assert!(!format!("{s:?}").contains(&hexsalt));
        drop(s);
        let db = fs::read(d.path().join(DB_FILE)).unwrap();
        let salt = fs::read(d.path().join(SALT_FILE)).unwrap();
        assert!(!db.windows(salt.len()).any(|w| w == salt.as_slice()));
    }

    #[test]
    fn corrupt_salt_is_an_error_not_a_regeneration() {
        let d = TempDir::new().unwrap();
        drop(Store::open(d.path()).unwrap());
        fs::write(d.path().join(SALT_FILE), b"short").unwrap();
        assert!(Store::open(d.path()).is_err());
    }

    #[test]
    fn settings_defaults_and_roundtrip() {
        let (_d, mut s) = open();
        assert_eq!(s.get_settings().unwrap(), Settings::default());
        let d = s.get_settings().unwrap();
        assert_eq!(
            (d.scan_interval_secs, d.retention_hours, d.notify),
            (60, 24, true)
        );
        let custom = Settings {
            trusted_networks: vec![TrustedNetwork {
                ssid: "Cafe-Guest".into(),
                known_bssid_hashes: vec!["ab".repeat(32)],
                expected_security: Security::Wpa3Personal,
            }],
            scan_interval_secs: 30,
            ble_scan_secs: 5,
            retention_hours: 6,
            notify: false,
            alert_toggles: AlertToggles {
                new_device: true,
                ..AlertToggles::default()
            },
            tracker_min_scans: 3,
            tracker_min_minutes: 10,
        };
        s.set_settings(&custom).unwrap();
        assert_eq!(s.get_settings().unwrap(), custom);
        s.set_settings(&Settings::default()).unwrap();
        assert_eq!(s.get_settings().unwrap(), Settings::default());
    }

    #[test]
    fn settings_persist_across_reopen() {
        let d = TempDir::new().unwrap();
        let mut s = Store::open(d.path()).unwrap();
        let st = Settings {
            retention_hours: 7,
            ..Settings::default()
        };
        s.set_settings(&st).unwrap();
        drop(s);
        assert_eq!(
            Store::open(d.path())
                .unwrap()
                .get_settings()
                .unwrap()
                .retention_hours,
            7
        );
    }

    #[test]
    fn alert_upsert_dedupes_and_keeps_first_seen_and_dismissed() {
        let (_d, mut s) = open();
        let a = alert(AlertKind::EvilTwin, "subj", 100, 100);
        let created = s.upsert_alerts(&[a.clone(), a.clone()]).unwrap();
        assert_eq!(created.len(), 1); // dedupes inside one batch too
        assert_eq!(s.get_alerts(true).unwrap().len(), 1);

        s.dismiss_alert(&a.id).unwrap();
        let mut again = alert(AlertKind::EvilTwin, "subj", 999, 500);
        again.detail = "updated".into();
        assert!(s.upsert_alerts(&[again]).unwrap().is_empty()); // not new => no notification
        assert!(s.get_alerts(false).unwrap().is_empty()); // still dismissed
        let all = s.get_alerts(true).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].first_seen, all[0].last_seen), (100, 500));
        assert!(all[0].dismissed);
        assert_eq!(all[0].detail, "updated");

        // same subject, different kind => a distinct alert
        let created = s
            .upsert_alerts(&[alert(AlertKind::NewDevice, "subj", 1, 2)])
            .unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(s.get_alerts(true).unwrap().len(), 2);
    }

    #[test]
    fn alerts_order_newest_first_and_unknown_dismiss_ok() {
        let (_d, mut s) = open();
        s.upsert_alerts(&[
            alert(AlertKind::EvilTwin, "a", 1, 10),
            alert(AlertKind::EvilTwin, "b", 1, 30),
            alert(AlertKind::EvilTwin, "c", 1, 20),
        ])
        .unwrap();
        let order: Vec<_> = s
            .get_alerts(false)
            .unwrap()
            .into_iter()
            .map(|a| a.subject_hash)
            .collect();
        assert_eq!(order, vec!["b", "c", "a"]);
        s.dismiss_alert("no-such-id").unwrap();
    }

    #[test]
    fn open_creates_nested_dir() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("a").join("b");
        Store::open(&p).unwrap();
        assert!(p.join(DB_FILE).exists());
    }
}
