//! One scan cycle, minus the OS: assemble a [`ScanResult`], then store -> detect -> upsert.
//!
//! Kept free of Tauri types so the whole path can be exercised with synthetic observations
//! (`tests/pipeline.rs`). The Tauri-facing loop lives in [`crate::commands`].

use crate::detect;
use crate::model::{
    Alert, AlertKind, BleObservation, Millis, PermissionState, PermissionStatus, ScanError,
    ScanErrorCode, ScanResult, ScanSource, WifiObservation,
};
use crate::store::{Store, StoreResult};

/// Current Unix time in milliseconds.
pub fn now_ms() -> Millis {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as Millis)
        .unwrap_or(0)
}

/// Combine the two scan outcomes into one [`ScanResult`]. Failures become entries in
/// `errors` (they reach the UI), never a panic and never a printed line.
///
/// A Wi-Fi scan that succeeded but returned only nameless networks while Location is not
/// granted is flagged with a `PermissionDenied` error as well, so the UI explains why SSIDs
/// are missing.
pub fn assemble(
    scanned_at: Millis,
    wifi: Result<Vec<WifiObservation>, ScanError>,
    ble: Result<Vec<BleObservation>, ScanError>,
    permissions: PermissionState,
) -> ScanResult {
    let mut errors = Vec::new();
    let wifi = wifi.unwrap_or_else(|e| {
        errors.push(e);
        Vec::new()
    });
    let ble = ble.unwrap_or_else(|e| {
        errors.push(e);
        Vec::new()
    });
    if permissions.location != PermissionStatus::Granted
        && !wifi.is_empty()
        && wifi.iter().all(|o| o.ssid.is_none())
        && !errors.iter().any(|e| e.source == ScanSource::Wifi)
    {
        errors.push(ScanError {
            source: ScanSource::Wifi,
            code: ScanErrorCode::PermissionDenied,
            message: "Wi-Fi names are hidden until Location access is granted".into(),
        });
    }
    ScanResult {
        scanned_at,
        wifi,
        ble,
        errors,
        permissions,
    }
}

/// Store the scan, evaluate the retention window, upsert the alerts. Returns only the alerts
/// created by this call: those drive events and notifications, so a repeat sighting of the
/// same condition returns nothing.
pub fn ingest(store: &mut Store, scan: &ScanResult, now: Millis) -> StoreResult<Vec<Alert>> {
    store.insert_scan(scan)?;
    let settings = store.get_settings()?;
    let since = now - Millis::from(settings.retention_hours) * 3_600_000;
    let history = store.get_history(since)?;
    let alerts = detect::evaluate(&history, &settings, now);
    store.upsert_alerts(&alerts)
}

/// Text for the OS notification of a new alert. Deliberately generic: it names the kind of
/// finding and never an SSID, hash or device name.
pub fn notification_text(alert: &Alert) -> (&'static str, &'static str) {
    match alert.kind {
        AlertKind::PersistentTracker => (
            "Possible tracker nearby",
            "A device matching a tracker signature keeps showing up near you. Open the app for details.",
        ),
        AlertKind::EvilTwin => (
            "Possible evil-twin Wi-Fi network",
            "Two access points share a network name with different security. Open the app for details.",
        ),
        AlertKind::OpenLookalike => (
            "Open network imitating a trusted one",
            "An unencrypted network looks like one of your trusted networks. Open the app for details.",
        ),
        AlertKind::TrustedNetworkChanged => (
            "Trusted network changed",
            "One of your trusted networks looks different than before. Open the app for details.",
        ),
        AlertKind::NewDevice => (
            "New Bluetooth device",
            "A device you have not seen before appeared nearby. Open the app for details.",
        ),
    }
}
