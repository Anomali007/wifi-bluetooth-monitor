//! The status snapshot. An agent runs outside the app, so it cannot ask CoreWLAN, CoreBluetooth
//! or the Login Items service anything. The app therefore writes what it knows to the `meta`
//! table after every scan, and `wbm status` returns that with its age.
//!
//! The snapshot holds the same facts the app's own UI shows (current network name and hashes,
//! permission states, counts) and nothing the UI does not: no raw BSSIDs, no IP addresses.

use crate::lan::helper::HelperStatus;
use crate::model::{Millis, NetworkInfo, PermissionState, ScanResult};
use crate::store::{Store, StoreCounts, StoreResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Bump when a field is removed or changes meaning.
pub const SNAPSHOT_VERSION: u32 = 1;
/// Never call a snapshot stale before this, however fast the scan interval.
const MIN_STALE_SECS: i64 = 180;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusNetwork {
    pub ssid: Option<String>,
    pub bssid_hash: Option<String>,
    pub group_id: Option<String>,
    /// The joined access point (or its radio group) is in Mine.
    pub is_mine: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCounts {
    pub wifi: u32,
    pub ble: u32,
    /// Scan errors in this cycle (e.g. Bluetooth permission denied).
    pub errors: u32,
    /// Alerts created by this cycle.
    pub new_alerts: u32,
}

/// What the app publishes. Field names are the documented JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub snapshot_version: u32,
    /// When the snapshot was written (Unix ms).
    pub written_at: Millis,
    /// Process id of the app, so `wbm` can tell a running app from a stale file.
    pub pid: u32,
    pub app_version: String,
    /// When the scan this snapshot describes started (Unix ms).
    pub last_scan_at: Millis,
    pub scan_interval_secs: u32,
    pub permissions: PermissionState,
    pub helper: HelperStatus,
    /// `None` when not on Wi-Fi, or when macOS withholds the network name.
    pub network: Option<StatusNetwork>,
    pub scan: ScanCounts,
}

/// Assemble the snapshot for a finished scan cycle. Pure.
#[allow(clippy::too_many_arguments)]
pub fn build(
    scan: &ScanResult,
    network: Option<&NetworkInfo>,
    helper: HelperStatus,
    scan_interval_secs: u32,
    new_alerts: usize,
    pid: u32,
    app_version: &str,
    now: Millis,
) -> AppStatus {
    AppStatus {
        snapshot_version: SNAPSHOT_VERSION,
        written_at: now,
        pid,
        app_version: app_version.to_string(),
        last_scan_at: scan.scanned_at,
        scan_interval_secs,
        permissions: scan.permissions,
        helper,
        network: network
            .filter(|n| n.ssid.is_some() || n.bssid_hash.is_some() || n.group_id.is_some())
            .map(|n| StatusNetwork {
                ssid: n.ssid.clone(),
                bssid_hash: n.bssid_hash.clone(),
                group_id: n.group_id.clone(),
                is_mine: n.is_mine,
            }),
        scan: ScanCounts {
            wifi: scan.wifi.len() as u32,
            ble: scan.ble.len() as u32,
            errors: scan.errors.len() as u32,
            new_alerts: new_alerts as u32,
        },
    }
}

/// Write the snapshot. A failure must never fail a scan cycle, so callers ignore the result.
pub fn publish(store: &mut Store, status: &AppStatus) -> StoreResult<()> {
    let json = serde_json::to_string(status)
        .map_err(|e| crate::store::StoreError(format!("serialize status: {e}")))?;
    store.set_app_status(&json)
}

/// `kill(pid, 0)`: asks the kernel whether the process exists and sends nothing.
pub fn process_alive(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // SAFETY: signal 0 performs only the existence and permission check.
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// How much to trust a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Freshness {
    /// Written recently by a running app.
    Live,
    /// The app process exists but has not finished a scan for too long.
    Stale,
    /// The process that wrote it is gone.
    AppNotRunning,
    /// The app never published one (never ran a scan, or an older version).
    NoSnapshot,
}

/// Judge a snapshot. `pid_alive` is injected for tests.
pub fn freshness(
    status: Option<&AppStatus>,
    now: Millis,
    pid_alive: fn(u32) -> bool,
) -> (Freshness, Option<i64>) {
    let Some(s) = status else {
        return (Freshness::NoSnapshot, None);
    };
    let age = ((now - s.written_at) / 1_000).max(0);
    if !pid_alive(s.pid) {
        return (Freshness::AppNotRunning, Some(age));
    }
    let limit = (i64::from(s.scan_interval_secs) * 3).max(MIN_STALE_SECS);
    if age > limit {
        (Freshness::Stale, Some(age))
    } else {
        (Freshness::Live, Some(age))
    }
}

fn human_age(secs: i64) -> String {
    match secs {
        s if s < 90 => format!("{s}s"),
        s if s < 5_400 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3_600),
        s => format!("{}d", s / 86_400),
    }
}

/// The `status` tool's result.
pub fn report(
    store: &Store,
    now: Millis,
    pid_alive: fn(u32) -> bool,
) -> Result<Value, crate::agent::AgentError> {
    let raw = store.app_status()?;
    let parsed: Option<AppStatus> = raw.as_deref().and_then(|r| serde_json::from_str(r).ok());
    let (fresh, age) = freshness(parsed.as_ref(), now, pid_alive);
    let message = match (fresh, age) {
        (Freshness::Live, _) => "The app is running; the snapshot is current.".to_string(),
        (Freshness::Stale, Some(a)) => format!(
            "The app is running but its last scan finished {} ago, so permissions, helper \
             status and the current network may be out of date (scanning could be paused or \
             blocked).",
            human_age(a)
        ),
        (Freshness::AppNotRunning, Some(a)) => format!(
            "The app is not running. The snapshot is {} old and shows how things were when it \
             last scanned; stored alerts, networks and devices below are still readable.",
            human_age(a)
        ),
        _ => "The app has not published a status snapshot (it has not completed a scan since \
              this feature was added, or it has never run). Stored data is still readable."
            .to_string(),
    };
    Ok(json!({
        "freshness": fresh,
        "appRunning": match fresh {
            Freshness::Live | Freshness::Stale => json!(true),
            Freshness::AppNotRunning => json!(false),
            Freshness::NoSnapshot => Value::Null,
        },
        "snapshotAgeSecs": age,
        "message": message,
        "snapshot": parsed,
        "latestScanAt": store.latest_scan_at()?,
        "counts": store.counts()?,
    }))
}

/// Re-exported for the shape documentation.
pub type Counts = StoreCounts;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PermissionStatus, ScanResult};

    fn scan() -> ScanResult {
        ScanResult {
            scanned_at: 1_000,
            wifi: vec![],
            ble: vec![],
            errors: vec![],
            permissions: PermissionState {
                bluetooth: PermissionStatus::Granted,
                location: PermissionStatus::Denied,
            },
        }
    }

    fn snap(interval: u32) -> AppStatus {
        build(
            &scan(),
            None,
            HelperStatus::Off,
            interval,
            0,
            4242,
            "0.1.0",
            1_000_000,
        )
    }

    #[test]
    fn freshness_live_stale_gone_and_missing() {
        let s = snap(60);
        let alive: fn(u32) -> bool = |_| true;
        let dead: fn(u32) -> bool = |_| false;
        let t = s.written_at;
        assert_eq!(freshness(Some(&s), t + 60_000, alive).0, Freshness::Live);
        // 3 intervals is 180 s, the floor: 181 s is stale.
        assert_eq!(freshness(Some(&s), t + 181_000, alive).0, Freshness::Stale);
        assert_eq!(
            freshness(Some(&s), t + 5_000, dead).0,
            Freshness::AppNotRunning
        );
        assert_eq!(freshness(None, t, alive), (Freshness::NoSnapshot, None));
        // A slow interval stretches the limit past the floor.
        let slow = snap(300);
        assert_eq!(
            freshness(Some(&slow), slow.written_at + 800_000, alive).0,
            Freshness::Live
        );
        assert_eq!(
            freshness(Some(&slow), slow.written_at + 901_000, alive).0,
            Freshness::Stale
        );
    }

    #[test]
    fn this_process_is_alive_and_pid_zero_is_not() {
        assert!(process_alive(std::process::id()));
        assert!(!process_alive(0));
    }

    #[test]
    fn snapshot_withholds_a_network_with_nothing_to_show() {
        let n = NetworkInfo::default();
        let s = build(&scan(), Some(&n), HelperStatus::Off, 60, 0, 1, "x", 5);
        assert!(s.network.is_none());
        let named = NetworkInfo {
            ssid: Some("Net-A".into()),
            ..NetworkInfo::default()
        };
        let s = build(&scan(), Some(&named), HelperStatus::Off, 60, 0, 1, "x", 5);
        assert_eq!(s.network.unwrap().ssid.as_deref(), Some("Net-A"));
    }

    #[test]
    fn snapshot_serialises_with_the_documented_field_names() {
        let v = serde_json::to_value(snap(60)).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "appVersion",
                "helper",
                "lastScanAt",
                "network",
                "permissions",
                "pid",
                "scan",
                "scanIntervalSecs",
                "snapshotVersion",
                "writtenAt"
            ]
        );
        assert_eq!(v["helper"], "off");
        assert_eq!(v["permissions"]["location"], "denied");
    }
}
