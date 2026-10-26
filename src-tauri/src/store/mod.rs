//! SQLite persistence, retention and the per-install salt. OWNER: WP3.
//!
//! CONTRACT (frozen):
//! - `rusqlite` (bundled). Tables: `wifi_sightings`, `ble_sightings`, `alerts`, `settings`,
//!   `meta` (salt); v4 adds `lan_devices.source`; v3 adds `places`, `place_sightings`, `mine`, `watchlist`, `lan_devices`
//!   and the `vendor` / `group_id` columns on `wifi_sightings`. Observations are grouped by their scan's `scanned_at` so
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
    Alert, AlertKind, BleObservation, History, LanDevice, LanSource, Millis, MineEntry, MineKind,
    Place, PlaceSighting, Salt, ScanResult, ScanSnapshot, Settings, SightingKind, WatchKind,
    WatchMatch, WatchlistEntry, WifiObservation,
};
mod lan_queries;
mod places_queries;

use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: i64 = 4;
const SALT_LEN: usize = 32;
const DB_FILE: &str = "store.sqlite3";
/// The salt lives in its own 0600 file, NOT in the database: a copy, backup or export of the
/// DB (which holds hashed identifiers) then cannot be brute-forced back to BSSIDs/UUIDs.
const SALT_FILE: &str = "salt.key";
const MS_PER_HOUR: i64 = 3_600_000;
const MS_PER_DAY: i64 = 24 * MS_PER_HOUR;

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

fn add_column_if_missing(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
    decl: &str,
) -> StoreResult<()> {
    let has: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        [table, column],
        |r| r.get(0),
    )?;
    if !has {
        tx.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        )?;
    }
    Ok(())
}

fn add_owner_state_column(tx: &rusqlite::Transaction<'_>) -> StoreResult<()> {
    add_column_if_missing(tx, "ble_sightings", "owner_state", "TEXT")
}

/// v2 -> v3: vendor and multi-radio group on Wi-Fi sightings. The new tables are created
/// unconditionally by `migrate`.
fn add_wifi_vendor_group_columns(tx: &rusqlite::Transaction<'_>) -> StoreResult<()> {
    add_column_if_missing(tx, "wifi_sightings", "vendor", "TEXT")?;
    add_column_if_missing(tx, "wifi_sightings", "group_id", "TEXT")
}

/// v3 -> v4: how a LAN device was learned (neighbor table, mDNS announcement, or both).
fn add_lan_source_column(tx: &rusqlite::Transaction<'_>) -> StoreResult<()> {
    add_column_if_missing(tx, "lan_devices", "source", "TEXT")
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
             CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS places (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 label TEXT,
                 members TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS place_sightings (
                 kind TEXT NOT NULL,
                 id_hash TEXT NOT NULL,
                 place_id INTEGER NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL,
                 scans INTEGER NOT NULL,
                 PRIMARY KEY (kind, id_hash, place_id)
             );
             CREATE INDEX IF NOT EXISTS idx_place_sightings_place ON place_sightings(place_id);
             CREATE TABLE IF NOT EXISTS mine (
                 kind TEXT NOT NULL,
                 id_hash TEXT NOT NULL,
                 label TEXT,
                 added_at INTEGER NOT NULL,
                 PRIMARY KEY (kind, id_hash)
             );
             CREATE TABLE IF NOT EXISTS watchlist (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind TEXT NOT NULL,
                 pattern TEXT NOT NULL,
                 match_mode TEXT NOT NULL,
                 added_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS lan_devices (
                 network_key TEXT NOT NULL,
                 mac_hash TEXT NOT NULL,
                 vendor TEXT,
                 hostname TEXT,
                 services TEXT NOT NULL,
                 first_seen INTEGER NOT NULL,
                 last_seen INTEGER NOT NULL,
                 PRIMARY KEY (network_key, mac_hash)
             );",
        )?;
        let version: Option<i64> =
            tx.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))?;
        match version {
            None => {
                // Fresh database: the v1 CREATE above has no owner_state / v3 columns yet.
                add_owner_state_column(&tx)?;
                add_wifi_vendor_group_columns(&tx)?;
                add_lan_source_column(&tx)?;
                tx.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    [SCHEMA_VERSION],
                )?;
            }
            Some(v) if v < 2 => {
                // v1 -> v2: owner_state column. v1 rows classified every Apple type 0x12
                // advert as a tracker, including nearby-owner ones, and cannot be told apart
                // now, so they stop counting as trackers rather than keep feeding alerts.
                add_owner_state_column(&tx)?;
                tx.execute(
                    "UPDATE ble_sightings SET tracker = NULL WHERE tracker = '\"appleFindMy\"'",
                    [],
                )?;
                add_wifi_vendor_group_columns(&tx)?;
                add_lan_source_column(&tx)?;
                tx.execute("UPDATE schema_version SET version = ?1", [SCHEMA_VERSION])?;
            }
            Some(v) if v < 3 => {
                // v2 -> v3: vendor/group_id columns (tables were created above).
                add_wifi_vendor_group_columns(&tx)?;
                add_lan_source_column(&tx)?;
                tx.execute("UPDATE schema_version SET version = ?1", [SCHEMA_VERSION])?;
            }
            Some(v) if v < 4 => {
                // v3 -> v4: lan_devices.source. Existing rows read back as None.
                add_lan_source_column(&tx)?;
                tx.execute("UPDATE schema_version SET version = ?1", [SCHEMA_VERSION])?;
            }
            Some(_) => {}
        }
        // Idempotent and independent of the schema version: the network name saved with an
        // access-point mark (the sweep gate checks it).
        add_column_if_missing(&tx, "mine", "ssid", "TEXT")?;
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
                "INSERT INTO wifi_sightings (scan_at, ssid, bssid_hash, rssi, channel, security, seen_at, vendor, group_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
                    o.seen_at,
                    o.vendor,
                    o.group_id
                ])?;
            }
            let mut b = tx.prepare(
                "INSERT INTO ble_sightings (scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at, owner_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for o in &scan.ble {
                let tracker = o.tracker.as_ref().map(to_json).transpose()?;
                let owner_state = o.owner_state.as_ref().map(to_json).transpose()?;
                b.execute(params![
                    scan.scanned_at,
                    o.name,
                    o.peripheral_hash,
                    o.rssi,
                    tracker,
                    o.manufacturer_id,
                    o.seen_at,
                    owner_state
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
            "SELECT scan_at, ssid, bssid_hash, rssi, channel, security, seen_at, vendor, group_id
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
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        for row in rows {
            let (scan_at, ssid, bssid_hash, rssi, channel, sec, seen_at, vendor, group_id) = row?;
            let obs = WifiObservation {
                ssid,
                bssid_hash,
                rssi,
                channel,
                security: from_json(&sec)?,
                seen_at,
                vendor,
                group_id,
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
            "SELECT scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at, owner_state
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
                r.get::<_, Option<String>>(7)?,
            ))
        })?;
        for row in rows {
            let (scan_at, name, peripheral_hash, rssi, tracker, manufacturer_id, seen_at, owner) =
                row?;
            let obs = BleObservation {
                name,
                peripheral_hash,
                rssi,
                tracker: tracker.as_deref().map(from_json).transpose()?,
                owner_state: owner.as_deref().map(from_json).transpose()?,
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
            // A dismissed flood summary whose overflow has grown is news again: un-dismiss it
            // and announce it once more (otherwise one dismissal silences every later flood).
            let grew = match crate::detect::flood_summary_count(a) {
                Some(new_n) => {
                    let old: Option<(String, bool)> = tx
                        .query_row(
                            "SELECT title, dismissed FROM alerts WHERE kind = ?1 AND subject_hash = ?2",
                            params![kind, a.subject_hash],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    old.is_some_and(|(title, dismissed)| {
                        dismissed
                            && title
                                .split_whitespace()
                                .next()
                                .and_then(|w| w.parse::<usize>().ok())
                                .is_some_and(|old_n| new_n > old_n)
                    })
                }
                None => false,
            };
            let updated = tx.execute(
                "UPDATE alerts SET last_seen = MAX(last_seen, ?1), severity = ?2, title = ?3, detail = ?4
                 WHERE kind = ?5 AND subject_hash = ?6",
                params![a.last_seen, sev, a.title, a.detail, kind, a.subject_hash],
            )?;
            if grew {
                tx.execute(
                    "UPDATE alerts SET dismissed = 0 WHERE kind = ?1 AND subject_hash = ?2",
                    params![kind, a.subject_hash],
                )?;
                let mut n = a.clone();
                n.dismissed = false;
                created.push(n);
            }
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

    // -- Places ------------------------------------------------------------

    /// All places, oldest first.
    pub fn list_places(&self) -> StoreResult<Vec<Place>> {
        let mut q = self
            .conn
            .prepare("SELECT id, label, members, first_seen, last_seen FROM places ORDER BY id")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Millis>(3)?,
                r.get::<_, Millis>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, label, members, first_seen, last_seen) = row?;
            out.push(Place {
                id,
                label,
                members: from_json(&members)?,
                first_seen,
                last_seen,
            });
        }
        Ok(out)
    }

    /// Create a place and return it with its assigned id.
    pub fn insert_place(
        &mut self,
        label: Option<&str>,
        members: &[String],
        now: Millis,
    ) -> StoreResult<Place> {
        self.conn.execute(
            "INSERT INTO places (label, members, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
            params![label, to_json(&members)?, now],
        )?;
        Ok(Place {
            id: self.conn.last_insert_rowid(),
            label: label.map(str::to_string),
            members: members.to_vec(),
            first_seen: now,
            last_seen: now,
        })
    }

    /// Replace members and `last_seen` of an existing place (the match-and-update step).
    /// Unknown id is not an error.
    pub fn update_place_members(
        &mut self,
        id: i64,
        members: &[String],
        last_seen: Millis,
    ) -> StoreResult<()> {
        self.conn.execute(
            "UPDATE places SET members = ?1, last_seen = MAX(last_seen, ?2) WHERE id = ?3",
            params![to_json(&members)?, last_seen, id],
        )?;
        Ok(())
    }

    /// Set or clear (`None` or blank) a place's label. Unknown id is not an error.
    pub fn rename_place(&mut self, id: i64, label: Option<&str>) -> StoreResult<()> {
        let label = label.map(str::trim).filter(|l| !l.is_empty());
        self.conn.execute(
            "UPDATE places SET label = ?1 WHERE id = ?2",
            params![label, id],
        )?;
        Ok(())
    }

    /// Forget a place and every sighting recorded there.
    pub fn forget_place(&mut self, id: i64) -> StoreResult<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM place_sightings WHERE place_id = ?1", [id])?;
        tx.execute("DELETE FROM places WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Insert a sighting, or on conflict widen `first_seen`/`last_seen` and take the larger
    /// `scans` count.
    pub fn upsert_place_sighting(&mut self, s: &PlaceSighting) -> StoreResult<()> {
        self.conn.execute(
            "INSERT INTO place_sightings (kind, id_hash, place_id, first_seen, last_seen, scans)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(kind, id_hash, place_id) DO UPDATE SET
                 first_seen = MIN(first_seen, excluded.first_seen),
                 last_seen = MAX(last_seen, excluded.last_seen),
                 scans = MAX(scans, excluded.scans)",
            params![
                to_json(&s.kind)?,
                s.id_hash,
                s.place_id,
                s.first_seen,
                s.last_seen,
                s.scans
            ],
        )?;
        Ok(())
    }

    /// Every stored place sighting (retention is separate and short, so this stays small).
    pub fn list_place_sightings(&self) -> StoreResult<Vec<PlaceSighting>> {
        let mut q = self.conn.prepare(
            "SELECT kind, id_hash, place_id, first_seen, last_seen, scans
             FROM place_sightings ORDER BY place_id, kind, id_hash",
        )?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Millis>(3)?,
                r.get::<_, Millis>(4)?,
                r.get::<_, u32>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id_hash, place_id, first_seen, last_seen, scans) = row?;
            out.push(PlaceSighting {
                kind: from_json::<SightingKind>(&kind)?,
                id_hash,
                place_id,
                first_seen,
                last_seen,
                scans,
            });
        }
        Ok(out)
    }

    // -- Mine --------------------------------------------------------------

    /// Everything marked mine, oldest first.
    pub fn list_mine(&self) -> StoreResult<Vec<MineEntry>> {
        let mut q = self.conn.prepare(
            "SELECT kind, id_hash, label, added_at, ssid FROM mine ORDER BY added_at, id_hash",
        )?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Millis>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id_hash, label, added_at, ssid) = row?;
            out.push(MineEntry {
                kind: from_json(&kind)?,
                id_hash,
                label,
                ssid,
                added_at,
            });
        }
        Ok(out)
    }

    /// Mark something mine. Marking it again updates the label and keeps `added_at`.
    pub fn add_mine(&mut self, e: &MineEntry) -> StoreResult<()> {
        self.conn.execute(
            "INSERT INTO mine (kind, id_hash, label, added_at, ssid) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(kind, id_hash) DO UPDATE SET label = excluded.label,
                 ssid = COALESCE(excluded.ssid, ssid)",
            params![to_json(&e.kind)?, e.id_hash, e.label, e.added_at, e.ssid],
        )?;
        Ok(())
    }

    /// [`Store::add_mine`], then the entry as stored: a re-mark without a network name keeps
    /// the saved one, and the caller (the UI's list) must see that rather than its own input.
    pub fn mark_mine(&mut self, e: &MineEntry) -> StoreResult<MineEntry> {
        self.add_mine(e)?;
        Ok(self
            .list_mine()?
            .into_iter()
            .find(|m| m.kind == e.kind && m.id_hash == e.id_hash)
            .unwrap_or_else(|| e.clone()))
    }

    /// Unmark. Unknown entry is not an error.
    pub fn remove_mine(&mut self, kind: MineKind, id_hash: &str) -> StoreResult<()> {
        self.conn.execute(
            "DELETE FROM mine WHERE kind = ?1 AND id_hash = ?2",
            params![to_json(&kind)?, id_hash],
        )?;
        Ok(())
    }

    // -- Watchlist ---------------------------------------------------------

    /// Watchlist entries, oldest first.
    pub fn list_watchlist(&self) -> StoreResult<Vec<WatchlistEntry>> {
        let mut q = self
            .conn
            .prepare("SELECT id, kind, pattern, match_mode, added_at FROM watchlist ORDER BY id")?;
        let rows = q.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Millis>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, pattern, mode, added_at) = row?;
            out.push(WatchlistEntry {
                id,
                kind: from_json(&kind)?,
                pattern,
                match_mode: from_json(&mode)?,
                added_at,
            });
        }
        Ok(out)
    }

    /// Add an entry. The pattern is trimmed; an empty one is an error.
    pub fn add_watchlist(
        &mut self,
        kind: WatchKind,
        pattern: &str,
        match_mode: WatchMatch,
        now: Millis,
    ) -> StoreResult<WatchlistEntry> {
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return Err(StoreError("watchlist pattern is empty".into()));
        }
        self.conn.execute(
            "INSERT INTO watchlist (kind, pattern, match_mode, added_at) VALUES (?1, ?2, ?3, ?4)",
            params![to_json(&kind)?, pattern, to_json(&match_mode)?, now],
        )?;
        Ok(WatchlistEntry {
            id: self.conn.last_insert_rowid(),
            kind,
            pattern: pattern.to_string(),
            match_mode,
            added_at: now,
        })
    }

    /// Remove an entry. Unknown id is not an error.
    pub fn remove_watchlist(&mut self, id: i64) -> StoreResult<()> {
        self.conn
            .execute("DELETE FROM watchlist WHERE id = ?1", [id])?;
        Ok(())
    }

    // -- LAN devices -------------------------------------------------------

    /// Stored LAN devices (all networks, or one `network_key`), newest `last_seen` first.
    /// `ip` is always `None` here (never persisted); `mine` reflects the Mine table.
    pub fn list_lan_devices(&self, network_key: Option<&str>) -> StoreResult<Vec<LanDevice>> {
        let mine = to_json(&MineKind::Lan)?;
        let mut q = self.conn.prepare(
            "SELECT d.network_key, d.mac_hash, d.vendor, d.hostname, d.services, d.first_seen,
                    d.last_seen,
                    EXISTS(SELECT 1 FROM mine m WHERE m.kind = ?2 AND m.id_hash = d.mac_hash),
                    d.source
             FROM lan_devices d
             WHERE (?1 IS NULL OR d.network_key = ?1)
             ORDER BY d.last_seen DESC, d.mac_hash",
        )?;
        let rows = q.query_map(params![network_key, mine], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Millis>(5)?,
                r.get::<_, Millis>(6)?,
                r.get::<_, bool>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                network_key,
                mac_hash,
                vendor,
                hostname,
                services,
                first_seen,
                last_seen,
                mine,
                source,
            ) = row?;
            out.push(LanDevice {
                network_key,
                mac_hash,
                vendor,
                hostname,
                services: from_json(&services)?,
                first_seen,
                last_seen,
                ip: None,
                mine,
                source: source.as_deref().and_then(LanSource::parse),
                possibly_same_as: None,
            });
        }
        // Hint only: a not-Mine device that announced the hostname of a Mine row on the same
        // network may be that device, but only the user can say so.
        let labels: Vec<(String, String, String)> = out
            .iter()
            .filter(|d| d.mine)
            .filter_map(|d| {
                let label = self.lan_mine_label(&d.mac_hash).ok()??;
                Some((d.network_key.clone(), d.mac_hash.clone(), label))
            })
            .collect();
        if !labels.is_empty() {
            for d in out.iter_mut().filter(|d| !d.mine) {
                let Some(host) = &d.hostname else { continue };
                let hk = crate::lan::host_key(&self.salt, host);
                if let Some((_, _, label)) = labels
                    .iter()
                    .find(|(n, h, _)| *n == d.network_key && *h == hk && *h != d.mac_hash)
                {
                    d.possibly_same_as = Some(label.clone());
                }
            }
        }
        Ok(out)
    }

    /// The label of a Mine LAN entry, or a generic name when it has none. `None` if not Mine.
    fn lan_mine_label(&self, id_hash: &str) -> StoreResult<Option<String>> {
        let found: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT label FROM mine WHERE kind = ?1 AND id_hash = ?2",
                params![to_json(&MineKind::Lan)?, id_hash],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.map(|l| l.unwrap_or_else(|| "a device you marked as yours".to_string())))
    }

    /// Remove one stored LAN device and return it (with `mine` filled), or `None` if absent.
    /// Used to fold a hostname-keyed row into its MAC-keyed row once a hardware address is known.
    pub fn take_lan_device(
        &mut self,
        network_key: &str,
        mac_hash: &str,
    ) -> StoreResult<Option<LanDevice>> {
        let found = self
            .list_lan_devices(Some(network_key))?
            .into_iter()
            .find(|d| d.mac_hash == mac_hash);
        if found.is_some() {
            self.conn.execute(
                "DELETE FROM lan_devices WHERE network_key = ?1 AND mac_hash = ?2",
                params![network_key, mac_hash],
            )?;
        }
        Ok(found)
    }

    /// Insert a device, or on conflict keep `first_seen` and refresh `last_seen`, vendor,
    /// hostname and services (a missing new value does not erase an old one).
    pub fn upsert_lan_device(&mut self, d: &LanDevice) -> StoreResult<()> {
        self.conn.execute(
            "INSERT INTO lan_devices (network_key, mac_hash, vendor, hostname, services, first_seen, last_seen, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(network_key, mac_hash) DO UPDATE SET
                 vendor = COALESCE(excluded.vendor, vendor),
                 hostname = COALESCE(excluded.hostname, hostname),
                 services = CASE WHEN excluded.services = '[]' THEN services ELSE excluded.services END,
                 last_seen = MAX(last_seen, excluded.last_seen),
                 source = CASE
                     WHEN source IS NULL THEN excluded.source
                     WHEN excluded.source IS NULL OR source = excluded.source THEN source
                     ELSE 'both' END",
            params![
                d.network_key,
                d.mac_hash,
                d.vendor,
                d.hostname,
                to_json(&d.services)?,
                d.first_seen,
                d.last_seen,
                d.source.map(LanSource::as_str)
            ],
        )?;
        Ok(())
    }

    /// Delete place memory older than `now - place_retention_days`: place sightings, places and
    /// LAN devices by `last_seen`. LAN devices marked mine never expire. Returns rows removed.
    pub fn purge_places(&mut self, place_retention_days: u32, now: Millis) -> StoreResult<usize> {
        let cutoff = now.saturating_sub(i64::from(place_retention_days) * MS_PER_DAY);
        let mine_lan = to_json(&MineKind::Lan)?;
        let tx = self.conn.transaction()?;
        let mut n = tx.execute("DELETE FROM place_sightings WHERE last_seen < ?1", [cutoff])?;
        n += tx.execute("DELETE FROM places WHERE last_seen < ?1", [cutoff])?;
        n += tx.execute(
            "DELETE FROM lan_devices WHERE last_seen < ?1
             AND NOT EXISTS (SELECT 1 FROM mine m WHERE m.kind = ?2 AND m.id_hash = lan_devices.mac_hash)",
            params![cutoff, mine_lan],
        )?;
        tx.commit()?;
        Ok(n)
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
            vendor: Some("Vendor-A".into()),
            group_id: Some(format!("{n:02x}").repeat(32)),
        }
    }

    fn ble(n: u8, at: Millis) -> BleObservation {
        BleObservation {
            name: None,
            peripheral_hash: format!("{n:02x}").repeat(32),
            rssi: Some(-70),
            tracker: Some(TrackerKind::Tile),
            owner_state: None,
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
    fn v1_database_migrates_and_drops_old_find_my_trackers() {
        let dir = tempfile::tempdir().unwrap();
        {
            // Hand-built v1 schema (no owner_state column) with two stored tracker rows.
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version VALUES (1);
                 CREATE TABLE ble_sightings (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, scan_at INTEGER NOT NULL, name TEXT,
                   peripheral_hash TEXT NOT NULL, rssi INTEGER, tracker TEXT,
                   manufacturer_id INTEGER, seen_at INTEGER NOT NULL);
                 INSERT INTO ble_sightings (scan_at, peripheral_hash, tracker, seen_at)
                   VALUES (9999999999999, 'aa', '\"appleFindMy\"', 1),
                          (9999999999999, 'bb', '\"tile\"', 1);",
            )
            .unwrap();
        }
        let s = Store::open(dir.path()).unwrap();
        let v: i64 = s
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 4);
        let h = s.get_history(0).unwrap();
        let ble = &h.scans[0].ble;
        assert_eq!(ble.len(), 2);
        assert_eq!(ble[0].tracker, None, "old Find My row stops counting");
        assert_eq!(ble[1].tracker, Some(TrackerKind::Tile));
        assert_eq!(ble[0].owner_state, None);
    }

    /// The tables v3 adds, for the migration tests.
    const V3_TABLES: [&str; 5] = [
        "places",
        "place_sightings",
        "mine",
        "watchlist",
        "lan_devices",
    ];

    fn table_exists(s: &Store, name: &str) -> bool {
        s.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [name],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn v2_database_migrates_to_v3_and_keeps_its_data() {
        let dir = tempfile::tempdir().unwrap();
        {
            // Hand-built v2 schema: owner_state present, no vendor/group_id, no v3 tables.
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version VALUES (2);
                 CREATE TABLE scans (scanned_at INTEGER PRIMARY KEY);
                 INSERT INTO scans VALUES (9999999999999);
                 CREATE TABLE wifi_sightings (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, scan_at INTEGER NOT NULL, ssid TEXT,
                   bssid_hash TEXT, rssi INTEGER NOT NULL, channel INTEGER,
                   security TEXT NOT NULL, seen_at INTEGER NOT NULL);
                 INSERT INTO wifi_sightings (scan_at, ssid, bssid_hash, rssi, security, seen_at)
                   VALUES (9999999999999, 'Net-A', 'aa', -60, '\"wpa2Personal\"', 1);
                 CREATE TABLE ble_sightings (
                   id INTEGER PRIMARY KEY AUTOINCREMENT, scan_at INTEGER NOT NULL, name TEXT,
                   peripheral_hash TEXT NOT NULL, rssi INTEGER, tracker TEXT,
                   manufacturer_id INTEGER, seen_at INTEGER NOT NULL, owner_state TEXT);
                 INSERT INTO ble_sightings (scan_at, peripheral_hash, tracker, seen_at, owner_state)
                   VALUES (9999999999999, 'bb', '\"appleFindMy\"', 1, '\"separated\"');
                 CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO settings VALUES ('settings', '{\"retentionHours\": 6}');",
            )
            .unwrap();
        }
        let mut s = Store::open(dir.path()).unwrap();
        let v: i64 = s
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 4);
        for t in V3_TABLES {
            assert!(table_exists(&s, t), "{t} missing after v2 -> v3");
        }
        // Old rows survive; the new columns read back as None; v2 tracker rows are untouched.
        let h = s.get_history(0).unwrap();
        let w = &h.scans[0].wifi[0];
        assert_eq!(w.ssid.as_deref(), Some("Net-A"));
        assert_eq!((&w.vendor, &w.group_id), (&None, &None));
        assert_eq!(h.scans[0].ble[0].tracker, Some(TrackerKind::AppleFindMy));
        // Old settings load with the new defaults filled in.
        let st = s.get_settings().unwrap();
        assert_eq!((st.retention_hours, st.place_retention_days), (6, 14));
        assert!(!st.lan_active_sweep);
        // New columns and tables are writable.
        s.insert_scan(&scan(10_000_000_000_000, 1, 0)).unwrap();
        let last = s.get_history(10_000_000_000_000).unwrap();
        assert_eq!(last.scans[0].wifi[0].vendor.as_deref(), Some("Vendor-A"));
        s.add_mine(&mine(MineKind::Ble, "x", 1)).unwrap();
        // Re-opening a v3 database changes nothing.
        drop(s);
        let s = Store::open(dir.path()).unwrap();
        assert_eq!(s.list_mine().unwrap().len(), 1);
    }

    #[test]
    fn v3_database_migrates_to_v4_and_keeps_its_lan_devices() {
        let dir = tempfile::tempdir().unwrap();
        {
            // Hand-built v3 schema: lan_devices without the `source` column.
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version VALUES (3);
                 CREATE TABLE lan_devices (
                   network_key TEXT NOT NULL, mac_hash TEXT NOT NULL, vendor TEXT, hostname TEXT,
                   services TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                   PRIMARY KEY (network_key, mac_hash));
                 INSERT INTO lan_devices VALUES ('net', 'old', 'Vendor-A', NULL, '[]', 10, 20);",
            )
            .unwrap();
        }
        let mut s = Store::open(dir.path()).unwrap();
        let v: i64 = s
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 4);
        let old = s.list_lan_devices(Some("net")).unwrap();
        assert_eq!(old.len(), 1);
        assert_eq!((old[0].first_seen, old[0].last_seen), (10, 20));
        assert_eq!(old[0].source, None, "pre-v4 rows have no source");
        // The new column is writable, and an old row learns its source on the next sighting.
        let mut d = lan_dev("net", "old", 30);
        d.source = Some(LanSource::Neighbor);
        s.upsert_lan_device(&d).unwrap();
        let got = s.list_lan_devices(Some("net")).unwrap();
        assert_eq!(got[0].source, Some(LanSource::Neighbor));
        assert_eq!(got[0].first_seen, 10);
        // Re-opening a v4 database changes nothing.
        drop(s);
        let s = Store::open(dir.path()).unwrap();
        assert_eq!(s.list_lan_devices(None).unwrap().len(), 1);
    }

    #[test]
    fn fresh_database_has_the_lan_source_column() {
        let (_d, s) = open();
        let has: bool = s
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('lan_devices') WHERE name = 'source')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(has);
        let v: i64 = s
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 4);
    }

    #[test]
    fn lan_source_merges_to_both_and_never_loses_information() {
        let (_d, mut s) = open();
        let seen = |src: Option<LanSource>, at: Millis| {
            let mut d = lan_dev("net", "dev", at);
            d.source = src;
            d
        };
        let read = |s: &Store| s.list_lan_devices(Some("net")).unwrap()[0].source;
        s.upsert_lan_device(&seen(Some(LanSource::Announced), 1))
            .unwrap();
        assert_eq!(read(&s), Some(LanSource::Announced));
        s.upsert_lan_device(&seen(Some(LanSource::Announced), 2))
            .unwrap();
        assert_eq!(read(&s), Some(LanSource::Announced), "same source stays");
        s.upsert_lan_device(&seen(Some(LanSource::Neighbor), 3))
            .unwrap();
        assert_eq!(
            read(&s),
            Some(LanSource::Both),
            "a different source merges to both"
        );
        s.upsert_lan_device(&seen(Some(LanSource::Neighbor), 4))
            .unwrap();
        assert_eq!(read(&s), Some(LanSource::Both), "both is sticky");
        s.upsert_lan_device(&seen(None, 5)).unwrap();
        assert_eq!(
            read(&s),
            Some(LanSource::Both),
            "an unknown source erases nothing"
        );
    }

    #[test]
    fn take_lan_device_removes_and_returns_only_the_named_row() {
        let (_d, mut s) = open();
        s.upsert_lan_device(&lan_dev("net", "a", 1)).unwrap();
        s.upsert_lan_device(&lan_dev("net", "b", 2)).unwrap();
        s.upsert_lan_device(&lan_dev("other", "a", 3)).unwrap();
        assert!(s.take_lan_device("net", "zzz").unwrap().is_none());
        let got = s.take_lan_device("net", "a").unwrap().unwrap();
        assert_eq!((got.mac_hash.as_str(), got.first_seen), ("a", 1));
        assert!(s.take_lan_device("net", "a").unwrap().is_none(), "gone");
        assert_eq!(
            s.list_lan_devices(None).unwrap().len(),
            2,
            "other rows untouched"
        );
    }

    #[test]
    fn fresh_database_has_every_v3_table_and_column() {
        let (_d, s) = open();
        for t in V3_TABLES {
            assert!(table_exists(&s, t), "{t}");
        }
        for c in ["vendor", "group_id"] {
            let has: bool = s
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('wifi_sightings') WHERE name = ?1)",
                    [c],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(has, "{c}");
        }
    }

    fn mine(kind: MineKind, id: &str, at: Millis) -> MineEntry {
        MineEntry {
            kind,
            id_hash: id.into(),
            label: None,
            ssid: None,
            added_at: at,
        }
    }

    fn lan_dev(net: &str, mac: &str, at: Millis) -> LanDevice {
        LanDevice {
            network_key: net.into(),
            mac_hash: mac.into(),
            vendor: Some("Vendor-A".into()),
            hostname: None,
            services: vec![],
            first_seen: at,
            last_seen: at,
            ip: Some("192.0.2.9".into()),
            mine: false,
            source: None,
            possibly_same_as: None,
        }
    }

    #[test]
    fn places_crud_rename_and_forget() {
        let (_d, mut s) = open();
        let members = vec!["aa".to_string(), "bb".to_string()];
        let p = s.insert_place(None, &members, 100).unwrap();
        let q = s.insert_place(Some("Place-B"), &[], 200).unwrap();
        assert_ne!(p.id, q.id);
        s.update_place_members(p.id, &["aa".to_string()], 300)
            .unwrap();
        s.rename_place(p.id, Some("  Home  ")).unwrap();
        let got = s.list_places().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].label.as_deref(), Some("Home"));
        assert_eq!(
            (got[0].members.clone(), got[0].last_seen),
            (vec!["aa".to_string()], 300)
        );
        s.rename_place(p.id, Some("   ")).unwrap();
        assert_eq!(s.list_places().unwrap()[0].label, None);

        let sight = |place_id, first, last, scans| PlaceSighting {
            kind: SightingKind::Wifi,
            id_hash: "cc".into(),
            place_id,
            first_seen: first,
            last_seen: last,
            scans,
        };
        s.upsert_place_sighting(&sight(p.id, 100, 150, 2)).unwrap();
        s.upsert_place_sighting(&sight(p.id, 90, 200, 5)).unwrap(); // widens, takes larger count
        s.upsert_place_sighting(&sight(q.id, 1, 2, 1)).unwrap();
        let all = s.list_place_sightings().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].first_seen, all[0].last_seen, all[0].scans),
            (90, 200, 5)
        );

        s.forget_place(p.id).unwrap();
        assert_eq!(s.list_places().unwrap().len(), 1);
        let left = s.list_place_sightings().unwrap();
        assert_eq!(left.len(), 1, "forgetting a place drops its sightings");
        assert_eq!(left[0].place_id, q.id);
        s.forget_place(9999).unwrap(); // unknown id is fine
    }

    #[test]
    fn mine_crud_is_per_kind_and_relabel_keeps_added_at() {
        let (_d, mut s) = open();
        s.add_mine(&mine(MineKind::WifiAp, "aa", 10)).unwrap();
        s.add_mine(&mine(MineKind::WifiGroup, "aa", 20)).unwrap(); // same hash, other kind
        let mut again = mine(MineKind::WifiAp, "aa", 99);
        again.label = Some("Router-A".into());
        s.add_mine(&again).unwrap();
        let all = s.list_mine().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].label.as_deref(), Some("Router-A"));
        assert_eq!(all[0].added_at, 10);
        s.remove_mine(MineKind::WifiAp, "aa").unwrap();
        s.remove_mine(MineKind::Lan, "nope").unwrap();
        assert_eq!(s.list_mine().unwrap()[0].kind, MineKind::WifiGroup);
    }

    #[test]
    fn watchlist_crud_trims_and_rejects_empty() {
        let (_d, mut s) = open();
        let e = s
            .add_watchlist(WatchKind::Ssid, "  Net-A  ", WatchMatch::Contains, 5)
            .unwrap();
        assert_eq!(e.pattern, "Net-A");
        assert!(s
            .add_watchlist(WatchKind::Vendor, "   ", WatchMatch::Exact, 6)
            .is_err());
        let v = s
            .add_watchlist(WatchKind::Vendor, "Vendor-A", WatchMatch::Exact, 7)
            .unwrap();
        let list = s.list_watchlist().unwrap();
        assert_eq!(list, vec![e.clone(), v]);
        s.remove_watchlist(e.id).unwrap();
        s.remove_watchlist(12345).unwrap();
        assert_eq!(s.list_watchlist().unwrap().len(), 1);
    }

    #[test]
    fn lan_devices_upsert_keeps_first_seen_never_stores_ip_and_flags_mine() {
        let (_d, mut s) = open();
        let mut d = lan_dev("net1", "m1", 100);
        d.services = vec!["_http._tcp".into()];
        s.upsert_lan_device(&d).unwrap();
        let mut later = lan_dev("net1", "m1", 500);
        later.vendor = None; // a missing value does not erase the stored one
        s.upsert_lan_device(&later).unwrap();
        s.upsert_lan_device(&lan_dev("net2", "m2", 50)).unwrap();
        let on1 = s.list_lan_devices(Some("net1")).unwrap();
        assert_eq!(on1.len(), 1);
        assert_eq!((on1[0].first_seen, on1[0].last_seen), (100, 500));
        assert_eq!(on1[0].vendor.as_deref(), Some("Vendor-A"));
        assert_eq!(on1[0].services, vec!["_http._tcp".to_string()]);
        assert_eq!(on1[0].ip, None, "IPs are never persisted");
        assert!(!on1[0].mine);
        assert_eq!(s.list_lan_devices(None).unwrap().len(), 2);
        s.add_mine(&mine(MineKind::Lan, "m1", 1)).unwrap();
        assert!(s.list_lan_devices(Some("net1")).unwrap()[0].mine);
    }

    #[test]
    fn purge_places_expires_by_days_and_spares_mine_lan_devices() {
        let (_d, mut s) = open();
        let day = MS_PER_DAY;
        let now = 100 * day;
        let cutoff = now - 14 * day;
        let old = s.insert_place(None, &[], cutoff - 1).unwrap();
        let edge = s.insert_place(None, &[], cutoff).unwrap();
        for p in [&old, &edge] {
            s.upsert_place_sighting(&PlaceSighting {
                kind: SightingKind::Ble,
                id_hash: "dd".into(),
                place_id: p.id,
                first_seen: p.first_seen,
                last_seen: p.last_seen,
                scans: 3,
            })
            .unwrap();
        }
        s.upsert_lan_device(&lan_dev("n", "old", cutoff - 1))
            .unwrap();
        s.upsert_lan_device(&lan_dev("n", "kept-mine", cutoff - 1))
            .unwrap();
        s.add_mine(&mine(MineKind::Lan, "kept-mine", 1)).unwrap();
        s.upsert_lan_device(&lan_dev("n", "edge", cutoff)).unwrap();
        assert_eq!(s.purge_places(14, now).unwrap(), 3); // place + sighting + one device
        assert_eq!(s.list_places().unwrap().len(), 1);
        assert_eq!(s.list_place_sightings().unwrap().len(), 1);
        let kept: Vec<_> = s
            .list_lan_devices(None)
            .unwrap()
            .into_iter()
            .map(|d| d.mac_hash)
            .collect();
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&"kept-mine".to_string()) && kept.contains(&"edge".to_string()));
        assert_eq!(s.purge_places(14, now).unwrap(), 0);
    }

    #[test]
    fn owner_state_round_trips_through_the_store() {
        let (_d, mut s) = open();
        let mut sc = scan(1000, 0, 1);
        sc.ble[0].owner_state = Some(crate::model::OwnerState::NearOwner);
        sc.ble[0].tracker = None;
        s.insert_scan(&sc).unwrap();
        let got = &s.get_history(0).unwrap().scans[0].ble[0];
        assert_eq!(got.owner_state, Some(crate::model::OwnerState::NearOwner));
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
            place_retention_days: 30,
            lan_active_sweep: true,
            lan_neighbor_helper: true,
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

    #[test]
    fn a_mine_mark_keeps_its_ssid_and_a_remark_without_one_does_not_erase_it() {
        let (_d, mut s) = open();
        let mut e = MineEntry {
            kind: MineKind::WifiAp,
            id_hash: "b1".into(),
            label: None,
            ssid: Some("Net-A".into()),
            added_at: 10,
        };
        s.add_mine(&e).unwrap();
        assert_eq!(s.list_mine().unwrap()[0].ssid.as_deref(), Some("Net-A"));
        // Re-marking with only a new label keeps the saved name.
        e.ssid = None;
        e.label = Some("Home".into());
        s.add_mine(&e).unwrap();
        let got = &s.list_mine().unwrap()[0];
        assert_eq!(
            (got.label.as_deref(), got.ssid.as_deref()),
            (Some("Home"), Some("Net-A"))
        );
        // Re-marking from another network name replaces it.
        e.ssid = Some("Net-B".into());
        s.add_mine(&e).unwrap();
        assert_eq!(s.list_mine().unwrap()[0].ssid.as_deref(), Some("Net-B"));
    }

    #[test]
    fn an_older_mine_table_gains_the_ssid_column_and_its_marks_have_no_name() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version VALUES (4);
                 CREATE TABLE mine (kind TEXT NOT NULL, id_hash TEXT NOT NULL, label TEXT,
                   added_at INTEGER NOT NULL, PRIMARY KEY (kind, id_hash));
                 INSERT INTO mine VALUES ('\"wifiAp\"', 'old', NULL, 5);",
            )
            .unwrap();
        }
        let mut s = Store::open(dir.path()).unwrap();
        let got = s.list_mine().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ssid, None, "a pre-existing mark has no saved name");
        // Migrating again changes nothing.
        s.migrate().unwrap();
        assert_eq!(s.list_mine().unwrap().len(), 1);
    }

    fn summary(count: usize) -> Alert {
        let kind = AlertKind::NewLanDevice;
        let subject = crate::detect::flood_summary_subject(kind);
        Alert {
            id: format!("sum-{count}"),
            kind,
            severity: Severity::Medium,
            title: format!("{count} more new devices on your network"),
            detail: "grouped".into(),
            first_seen: 1,
            last_seen: 2,
            subject_hash: subject,
            dismissed: false,
        }
    }

    #[test]
    fn a_dismissed_flood_summary_comes_back_only_when_the_overflow_grows() {
        let (_d, mut s) = open();
        assert_eq!(s.upsert_alerts(&[summary(10)]).unwrap().len(), 1);
        let id = s.get_alerts(true).unwrap()[0].id.clone();
        s.dismiss_alert(&id).unwrap();
        // Same overflow, or a smaller one: stays dismissed and silent.
        assert!(s.upsert_alerts(&[summary(10)]).unwrap().is_empty());
        assert!(s.upsert_alerts(&[summary(7)]).unwrap().is_empty());
        assert!(s.get_alerts(false).unwrap().is_empty(), "still dismissed");
        // More devices than before: un-dismissed and announced again.
        let again = s.upsert_alerts(&[summary(25)]).unwrap();
        assert_eq!(again.len(), 1, "re-notified");
        let shown = s.get_alerts(false).unwrap();
        assert_eq!(shown.len(), 1);
        assert!(shown[0].title.starts_with("25 "));
        // NEGATIVE CONTROL: an ordinary alert that is dismissed stays dismissed when it repeats.
        let mut a = summary(1);
        a.subject_hash = "plain".into();
        a.title = "5 not a summary".into();
        s.upsert_alerts(&[a.clone()]).unwrap();
        s.dismiss_alert(&a.id).unwrap();
        a.title = "50 not a summary".into();
        assert!(s.upsert_alerts(&[a]).unwrap().is_empty());
    }

    #[test]
    fn renaming_a_mark_returns_the_stored_entry_with_its_saved_ssid() {
        let (_d, mut s) = open();
        let mut e = MineEntry {
            kind: MineKind::WifiGroup,
            id_hash: "g1".into(),
            label: Some("Router".into()),
            ssid: Some("Net-A".into()),
            added_at: 5,
        };
        s.mark_mine(&e).unwrap();
        // The rename sends no ssid and a later added_at.
        e.label = Some("Router (renamed)".into());
        e.ssid = None;
        e.added_at = 99;
        let back = s.mark_mine(&e).unwrap();
        assert_eq!(
            back.ssid.as_deref(),
            Some("Net-A"),
            "ssid carried through the rename"
        );
        assert_eq!(back.label.as_deref(), Some("Router (renamed)"));
        assert_eq!(back.added_at, 5, "added_at is kept");
    }
}
