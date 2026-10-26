//! Agent tools: one read/edit path shared by the `wbm` CLI and its MCP server.
//!
//! - [`tools`]  the tool table: name, description, input schema, access class, implementation.
//!   The CLI and the MCP server both call [`tools::call`], so they cannot drift apart.
//! - [`status`] the snapshot the running app publishes after every scan, and how `wbm status`
//!   reports its age.
//! - [`cli`]    argument parsing and human output.
//! - [`mcp`]    the MCP stdio server (official `rmcp` SDK).
//!
//! Boundaries, enforced by `tests/agent_tools.rs` and `tests/lan_listen_only.rs`:
//! - Reads come from the SQLite file; edits are limited to trusted networks, Mine, the
//!   watchlist and alert dismissal. Nothing here starts a scan or a sweep, and nothing here
//!   writes any setting other than the trusted-network list.
//! - No socket, no child process.

pub mod cli;
pub mod mcp;
pub mod status;
pub mod tools;

use crate::model::Millis;
use std::path::{Path, PathBuf};

/// Bundle identifier the app stores its data under.
pub const APP_ID: &str = "com.anomali007.wifibtmonitor";
pub const DB_FILE: &str = "store.sqlite3";

/// Why a tool call failed. Each variant has a fixed CLI exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// Bad arguments or an unknown command or tool. Exit 2.
    Usage(String),
    /// No database at the path. Exit 3.
    NoDatabase(String),
    /// The database is not one this build can use (too old, or not a store). Exit 4.
    Unsupported(String),
    /// The thing named does not exist (alert id, hash, SSID not seen, ...). Exit 5.
    NotFound(String),
    /// Anything else (I/O, SQLite). Exit 1.
    Failed(String),
}

impl AgentError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AgentError::Failed(_) => 1,
            AgentError::Usage(_) => 2,
            AgentError::NoDatabase(_) => 3,
            AgentError::Unsupported(_) => 4,
            AgentError::NotFound(_) => 5,
        }
    }
    pub fn message(&self) -> &str {
        match self {
            AgentError::Usage(m)
            | AgentError::NoDatabase(m)
            | AgentError::Unsupported(m)
            | AgentError::NotFound(m)
            | AgentError::Failed(m) => m,
        }
    }
    /// Stable machine-readable code used in `--json` error output.
    pub fn code(&self) -> &'static str {
        match self {
            AgentError::Failed(_) => "failed",
            AgentError::Usage(_) => "usage",
            AgentError::NoDatabase(_) => "noDatabase",
            AgentError::Unsupported(_) => "unsupportedDatabase",
            AgentError::NotFound(_) => "notFound",
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AgentError {}

impl From<crate::store::StoreError> for AgentError {
    fn from(e: crate::store::StoreError) -> Self {
        AgentError::Failed(e.to_string())
    }
}

impl From<crate::store::OpenError> for AgentError {
    fn from(e: crate::store::OpenError) -> Self {
        use crate::store::OpenError;
        match e {
            OpenError::Missing => AgentError::NoDatabase(
                "no database found; has the app run yet? (pass --db <path> to point elsewhere)"
                    .into(),
            ),
            OpenError::Unsupported(m) => AgentError::Unsupported(m),
            OpenError::Other(e) => AgentError::Failed(e.to_string()),
        }
    }
}

/// The app's usual database: `~/Library/Application Support/<bundle id>/store.sqlite3`.
pub fn default_db_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        Path::new(&home)
            .join("Library/Application Support")
            .join(APP_ID)
            .join(DB_FILE),
    )
}

/// Everything a tool call needs besides its arguments. Injectable so tests need no clock, no
/// process table and no real database.
#[derive(Clone)]
pub struct Ctx {
    pub db: PathBuf,
    /// Unix milliseconds "now".
    pub now: fn() -> Millis,
    /// Is a process with this pid alive? (`kill(pid, 0)`; sends no signal.)
    pub pid_alive: fn(u32) -> bool,
}

impl Ctx {
    pub fn new(db: PathBuf) -> Ctx {
        Ctx {
            db,
            now: crate::pipeline::now_ms,
            pid_alive: status::process_alive,
        }
    }
}

/// Parse `30m`, `6h`, `7d`, `90s` (relative to `now`) or a bare Unix-millisecond timestamp.
pub fn parse_since(text: &str, now: Millis) -> Result<Millis, AgentError> {
    let t = text.trim();
    let bad = || {
        AgentError::Usage(format!(
            "cannot read {text:?} as a time: use 30m, 6h, 7d, 90s, or Unix milliseconds"
        ))
    };
    if t.is_empty() {
        return Err(bad());
    }
    if let Some(unit) = t.chars().last().filter(|c| c.is_ascii_alphabetic()) {
        let n: i64 = t[..t.len() - 1].parse().map_err(|_| bad())?;
        let secs = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            _ => return Err(bad()),
        };
        if n < 0 {
            return Err(bad());
        }
        return Ok(now.saturating_sub(n.saturating_mul(secs).saturating_mul(1_000)));
    }
    let ms: i64 = t.parse().map_err(|_| bad())?;
    if ms < 0 {
        return Err(bad());
    }
    Ok(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_accepts_durations_and_millis() {
        let now = 1_000_000_000;
        assert_eq!(parse_since("30m", now).unwrap(), now - 1_800_000);
        assert_eq!(parse_since("6h", now).unwrap(), now - 21_600_000);
        assert_eq!(parse_since("7d", now).unwrap(), now - 604_800_000);
        assert_eq!(parse_since("90s", now).unwrap(), now - 90_000);
        assert_eq!(
            parse_since("1700000000000", now).unwrap(),
            1_700_000_000_000
        );
    }

    #[test]
    fn since_rejects_nonsense() {
        for bad in ["", "h", "x5", "5x", "-5m", "1.5h", "yesterday"] {
            assert!(
                matches!(parse_since(bad, 10), Err(AgentError::Usage(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn exit_codes_are_distinct_and_stable() {
        let all = [
            AgentError::Failed(String::new()),
            AgentError::Usage(String::new()),
            AgentError::NoDatabase(String::new()),
            AgentError::Unsupported(String::new()),
            AgentError::NotFound(String::new()),
        ];
        let codes: Vec<i32> = all.iter().map(AgentError::exit_code).collect();
        assert_eq!(codes, [1, 2, 3, 4, 5]);
    }
}
