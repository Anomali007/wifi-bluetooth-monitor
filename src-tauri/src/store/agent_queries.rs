//! Store queries for the agent tools (`wbm` CLI and MCP server) and the app's status snapshot.
//!
//! Everything here is plain SQLite over the same file the app uses. Edits are short
//! transactions (`BEGIN IMMEDIATE`) behind a busy timeout, so the running app and an agent can
//! write the same database without losing each other's rows.

use super::{err, Store, StoreError, StoreResult, SCHEMA_VERSION};
use crate::model::{Millis, Salt, TrustedNetwork};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::time::Duration;

const STATUS_KEY: &str = "agent_status";
/// How long a connection waits for another writer before giving up.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Why an agent could not open the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// No database file at the given path (the app has never run, or the path is wrong).
    Missing,
    /// The file exists but is not a database this build understands (too old or not SQLite).
    Unsupported(String),
    Other(StoreError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Missing => f.write_str("no database at that path"),
            OpenError::Unsupported(m) => write!(f, "unsupported database: {m}"),
            OpenError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        OpenError::Other(StoreError::from(e))
    }
}

/// Row counts for `wbm status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCounts {
    pub scans: i64,
    pub alerts_active: i64,
    pub alerts_dismissed: i64,
    pub mine: i64,
    pub watchlist: i64,
    pub places: i64,
    pub lan_devices: i64,
}

/// WAL (readers never block the app's writer), a busy timeout (writers queue instead of
/// failing). Applied to every connection the crate opens.
pub(super) fn configure(conn: &Connection) -> StoreResult<()> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(|e| err("busy timeout", e))?;
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(|e| err("journal mode", e))?;
    if !mode.eq_ignore_ascii_case("wal") {
        // Some filesystems cannot do WAL; the busy timeout still protects writers.
        return Ok(());
    }
    conn.execute_batch("PRAGMA synchronous = NORMAL;")
        .map_err(|e| err("synchronous", e))?;
    Ok(())
}

/// How an agent opens the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// `SQLITE_OPEN_READ_ONLY`: SQLite itself refuses every write on this connection.
    Read,
    /// Read-write, WAL, for the four allowed edits.
    Edit,
}

impl Store {
    /// Open an EXISTING database file for an agent. Never creates a file, never migrates and
    /// never touches the salt: `wbm` reads hashes the app already made and hashes nothing.
    /// A schema older than this build's is refused (the app migrates it when it next runs).
    pub fn open_db_file(db: &Path, mode: OpenMode) -> Result<Store, OpenError> {
        if !db.is_file() {
            return Err(OpenError::Missing);
        }
        let access = match mode {
            OpenMode::Read => OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenMode::Edit => OpenFlags::SQLITE_OPEN_READ_WRITE,
        };
        let conn = Connection::open_with_flags(db, access | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|e| OpenError::Unsupported(e.to_string()))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| OpenError::Other(err("busy timeout", e)))?;
        if mode == OpenMode::Edit {
            // The app already runs in WAL; this only matters for a store it has not reopened
            // since upgrading. A file that is not SQLite fails here, on the first statement.
            configure(&conn).map_err(|e| {
                if e.0.contains("not a database") {
                    OpenError::Unsupported("the file is not a SQLite database".into())
                } else {
                    OpenError::Other(e)
                }
            })?;
        }
        let version: Option<i64> = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .map_err(|_| OpenError::Unsupported("not a Wi-Fi Bluetooth Monitor store".into()))?;
        match version {
            Some(v) if v >= SCHEMA_VERSION => Ok(Store {
                conn,
                // Empty on purpose: `wbm` never reads the salt file and hashes nothing. The one store
                // path that hashes (the possibly-the-same-device hint on LAN devices) is skipped
                // when the salt is empty, so agents simply do not get that hint.
                salt: Salt::from_bytes(Vec::new()),
            }),
            other => Err(OpenError::Unsupported(format!(
                "schema {} is older than {SCHEMA_VERSION}; open the app once to upgrade it",
                other.map_or_else(|| "none".to_string(), |v| v.to_string())
            ))),
        }
    }

    /// The app's last published status snapshot (opaque JSON), if any.
    pub fn app_status(&self) -> StoreResult<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [STATUS_KEY], |r| {
                r.get::<_, String>(0)
            })
            .optional()?)
    }

    /// Publish the status snapshot (the app calls this after every scan).
    pub fn set_app_status(&mut self, json: &str) -> StoreResult<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![STATUS_KEY, json],
        )?;
        Ok(())
    }

    /// Time of the newest stored scan.
    pub fn latest_scan_at(&self) -> StoreResult<Option<Millis>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(scanned_at) FROM scans", [], |r| {
                r.get::<_, Option<Millis>>(0)
            })?)
    }

    pub fn counts(&self) -> StoreResult<StoreCounts> {
        let n = |sql: &str| -> StoreResult<i64> { Ok(self.conn.query_row(sql, [], |r| r.get(0))?) };
        Ok(StoreCounts {
            scans: n("SELECT COUNT(*) FROM scans")?,
            alerts_active: n("SELECT COUNT(*) FROM alerts WHERE dismissed = 0")?,
            alerts_dismissed: n("SELECT COUNT(*) FROM alerts WHERE dismissed = 1")?,
            mine: n("SELECT COUNT(*) FROM mine")?,
            watchlist: n("SELECT COUNT(*) FROM watchlist")?,
            places: n("SELECT COUNT(*) FROM places")?,
            lan_devices: n("SELECT COUNT(*) FROM lan_devices")?,
        })
    }

    /// Change ONLY the trusted-network list, in one short transaction on top of whatever is
    /// stored right now. Every other setting is carried over untouched, which is what keeps an
    /// agent from ever changing a toggle, an interval or retention.
    pub fn update_trusted_networks<R>(
        &mut self,
        change: impl FnOnce(&mut Vec<TrustedNetwork>) -> R,
    ) -> StoreResult<R> {
        self.edit_stored_settings(|s| change(&mut s.trusted_networks))
    }
}
