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

use crate::model::{Alert, History, Millis, Salt, ScanResult, Settings};
use std::fmt;
use std::path::Path;

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
    _conn: rusqlite::Connection,
}

impl Store {
    /// Open (creating if needed) the database at `path`, run [`Store::migrate`], and load or
    /// create the salt.
    pub fn open(_path: &Path) -> StoreResult<Store> {
        unimplemented!("WP3")
    }

    /// Create any missing tables. Safe to call repeatedly.
    pub fn migrate(&mut self) -> StoreResult<()> {
        unimplemented!("WP3")
    }

    /// The per-install salt. Pass it to `wifi::scan` / `ble::scan`.
    pub fn salt(&self) -> &Salt {
        unimplemented!("WP3")
    }

    /// Persist every observation in `scan`.
    pub fn insert_scan(&mut self, _scan: &ScanResult) -> StoreResult<()> {
        unimplemented!("WP3")
    }

    /// All scans with `scanned_at >= since`, ascending.
    pub fn get_history(&self, _since: Millis) -> StoreResult<History> {
        unimplemented!("WP3")
    }

    /// Merge `alerts` into the stored set. Returns the newly created ones only.
    pub fn upsert_alerts(&mut self, _alerts: &[Alert]) -> StoreResult<Vec<Alert>> {
        unimplemented!("WP3")
    }

    /// Stored alerts, newest `last_seen` first.
    pub fn get_alerts(&self, _include_dismissed: bool) -> StoreResult<Vec<Alert>> {
        unimplemented!("WP3")
    }

    /// Mark an alert dismissed. Unknown id is not an error.
    pub fn dismiss_alert(&mut self, _id: &str) -> StoreResult<()> {
        unimplemented!("WP3")
    }

    /// Stored settings, or `Settings::default()` if none were saved.
    pub fn get_settings(&self) -> StoreResult<Settings> {
        unimplemented!("WP3")
    }

    pub fn set_settings(&mut self, _settings: &Settings) -> StoreResult<()> {
        unimplemented!("WP3")
    }

    /// Delete sightings (and alerts whose `last_seen`) older than `now - retention_hours`.
    /// Returns the number of rows removed.
    pub fn purge(&mut self, _retention_hours: u32, _now: Millis) -> StoreResult<usize> {
        unimplemented!("WP3")
    }
}
