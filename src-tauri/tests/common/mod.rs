//! Synthetic database for the agent-tool tests: `Net-A`, `02:00:00:...` addresses, `Vendor-A`.
//! Always a temp directory; never the real store.
#![allow(dead_code)]

use app_lib::model::Salt;
use app_lib::model::{
    hash_identifier, Alert, AlertKind, BleObservation, LanDevice, LanSource, Millis, OwnerState,
    PermissionState, PermissionStatus, ScanResult, Security, Severity, TrackerKind,
    WifiObservation,
};
use app_lib::pipeline::now_ms;
use app_lib::store::Store;
use std::path::PathBuf;
use tempfile::TempDir;

pub fn salt() -> Salt {
    Salt::from_bytes(vec![9; 32])
}

pub fn h(raw: &str) -> String {
    hash_identifier(&salt(), raw)
}

pub struct Fixture {
    pub dir: TempDir,
    pub db: PathBuf,
    pub now: Millis,
}

pub fn wifi(
    ssid: Option<&str>,
    mac: &str,
    rssi: i32,
    sec: Security,
    at: Millis,
) -> WifiObservation {
    WifiObservation {
        ssid: ssid.map(String::from),
        bssid_hash: Some(h(mac)),
        rssi,
        channel: Some(36),
        security: sec,
        seen_at: at,
        vendor: Some("Vendor-A".into()),
        group_id: Some(h(&format!("group-{mac}"))),
    }
}

pub fn ble(
    name: Option<&str>,
    id: &str,
    tracker: Option<TrackerKind>,
    at: Millis,
) -> BleObservation {
    BleObservation {
        name: name.map(String::from),
        peripheral_hash: h(id),
        rssi: Some(-60),
        tracker,
        owner_state: tracker.map(|_| OwnerState::Separated),
        manufacturer_id: Some(0x004C),
        seen_at: at,
    }
}

/// Two scans a minute apart: Net-A on two APs (one WPA2, one WPA3), Net-B open, a hidden
/// network, and two BLE devices (one tracker-shaped). One active alert, one LAN device.
pub fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let now = now_ms();
    for (i, at) in [now - 120_000, now - 60_000].into_iter().enumerate() {
        let scan = ScanResult {
            scanned_at: at,
            wifi: vec![
                wifi(
                    Some("Net-A"),
                    "02:00:00:00:00:01",
                    -40,
                    Security::Wpa2Personal,
                    at,
                ),
                wifi(
                    Some("Net-A"),
                    "02:00:00:00:00:02",
                    -55,
                    Security::Wpa3Personal,
                    at,
                ),
                wifi(Some("Net-B"), "02:00:00:00:00:03", -70, Security::Open, at),
                wifi(None, "02:00:00:00:00:04", -80, Security::Wpa2Personal, at),
            ],
            ble: vec![
                ble(Some("Device-A"), "synthetic-ble-1", None, at),
                ble(None, "synthetic-ble-2", Some(TrackerKind::Tile), at),
            ],
            errors: vec![],
            permissions: PermissionState {
                bluetooth: PermissionStatus::Granted,
                location: PermissionStatus::Granted,
            },
        };
        store.insert_scan(&scan).unwrap();
        let _ = i;
    }
    store
        .upsert_alerts(&[Alert {
            id: "alert-1".into(),
            kind: AlertKind::EvilTwin,
            severity: Severity::High,
            title: "Net-A has two security modes".into(),
            detail: "synthetic".into(),
            first_seen: now - 100_000,
            last_seen: now - 60_000,
            subject_hash: h("subject-1"),
            dismissed: false,
        }])
        .unwrap();
    store
        .upsert_lan_device(&LanDevice {
            network_key: h("net-key-1"),
            mac_hash: h("02:00:00:00:10:01"),
            vendor: Some("Vendor-A".into()),
            hostname: Some("host-a.local".into()),
            services: vec!["_http._tcp".into()],
            first_seen: now - 90_000,
            last_seen: now - 30_000,
            ip: None,
            mine: false,
            source: Some(LanSource::Neighbor),
        })
        .unwrap();
    let db = dir.path().join("store.sqlite3");
    Fixture { dir, db, now }
}
