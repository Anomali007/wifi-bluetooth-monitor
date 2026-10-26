//! One scan cycle, minus the OS: assemble a [`ScanResult`], then store -> detect -> upsert.
//!
//! Kept free of Tauri types so the whole path can be exercised with synthetic observations
//! (`tests/pipeline.rs`). The Tauri-facing loop lives in [`crate::commands`].

use crate::detect::{self, DetectContext};
use crate::lan::{self, LanScanOutcome};
use crate::model::{
    Alert, AlertKind, BleObservation, Millis, PermissionState, PermissionStatus, ScanError,
    ScanErrorCode, ScanResult, ScanSource, Severity, WifiObservation,
};
use crate::places;
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
    ingest_with(store, scan, None, now)
}

/// [`ingest`] plus this cycle's LAN observation: store the scan, record LAN devices, update
/// place memory, purge place data by `place_retention_days`, then evaluate with a
/// [`DetectContext`] built from the store.
pub fn ingest_with(
    store: &mut Store,
    scan: &ScanResult,
    lan_outcome: Option<&LanScanOutcome>,
    now: Millis,
) -> StoreResult<Vec<Alert>> {
    store.insert_scan(scan)?;
    let settings = store.get_settings()?;
    if let Some(outcome) = lan_outcome {
        lan::record(store, outcome, now)?;
    }
    places::update(store, scan, &settings, now)?;
    store.purge_places(settings.place_retention_days, now)?;
    let since = now - Millis::from(settings.retention_hours) * 3_600_000;
    let history = store.get_history(since)?;
    let ctx = DetectContext {
        mine: store.list_mine()?,
        watchlist: store.list_watchlist()?,
        places: store.list_places()?,
        place_sightings: store.list_place_sightings()?,
        lan_devices: store.list_lan_devices(None)?,
        current_network: lan_outcome.map(|o| o.network.clone()),
    };
    let alerts = detect::evaluate_with(&history, &settings, &ctx, now);
    store.upsert_alerts(&alerts)
}

/// [`ingest_with`], then publish the status snapshot an agent (`wbm status`) reads, because it
/// cannot ask CoreWLAN, CoreBluetooth or the Login Items service itself. Publishing is best
/// effort: a failed snapshot write never fails the cycle.
pub fn ingest_and_publish(
    store: &mut Store,
    scan: &ScanResult,
    lan_outcome: Option<&LanScanOutcome>,
    helper: crate::lan::helper::HelperStatus,
    pid: u32,
    now: Millis,
) -> StoreResult<Vec<Alert>> {
    let created = ingest_with(store, scan, lan_outcome, now)?;
    let interval = store.get_settings()?.scan_interval_secs;
    let snapshot = crate::agent::status::build(
        scan,
        lan_outcome.map(|o| &o.network),
        helper,
        interval,
        created.len(),
        pid,
        env!("CARGO_PKG_VERSION"),
        now_ms(),
    );
    let _ = crate::agent::status::publish(store, &snapshot);
    Ok(created)
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
        AlertKind::FollowedAcrossPlaces => (
            "Possible device following you",
            "Something has shown up at more than one of your places. Open the app for details.",
        ),
        AlertKind::Watchlist => (
            "Watchlist match",
            "Something on your watchlist is nearby. Open the app for details.",
        ),
        AlertKind::NewLanDevice => (
            "New device on your network",
            "A device you have not seen before joined a network you marked as yours. Open the app for details.",
        ),
    }
}

/// OS notifications per scan cycle before the rest collapse into one "N more alerts" summary.
pub const MAX_NOTIFICATIONS_PER_CYCLE: usize = 3;

/// One OS notification to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub body: String,
}

/// The notifications for a cycle's new alerts: High-severity alerts first (never dropped, never
/// summarised), then the rest in order until [`MAX_NOTIFICATIONS_PER_CYCLE`] are used, then one
/// summary for whatever is left. A flood of spoofed devices or watchlisted names therefore
/// cannot bury a real alert or spam the user.
pub fn plan_notifications(alerts: &[Alert]) -> Vec<Notice> {
    let mut ordered: Vec<&Alert> = alerts.iter().collect();
    ordered.sort_by_key(|a| std::cmp::Reverse(a.severity)); // stable: ties keep their order
    let high = ordered
        .iter()
        .filter(|a| a.severity == Severity::High)
        .count();
    let shown = high.max(MAX_NOTIFICATIONS_PER_CYCLE).min(ordered.len());
    let mut out: Vec<Notice> = ordered[..shown]
        .iter()
        .map(|a| {
            let (t, b) = notification_text(a);
            Notice {
                title: t.into(),
                body: b.into(),
            }
        })
        .collect();
    let rest = ordered.len() - shown;
    if rest > 0 {
        out.push(Notice {
            title: "More alerts".into(),
            body: format!("{rest} more alerts were raised. Open the app for details."),
        });
    }
    out
}

#[cfg(test)]
mod notify_tests {
    use super::*;

    fn alert(kind: AlertKind, sev: Severity, n: usize) -> Alert {
        Alert {
            id: format!("id{n}"),
            kind,
            severity: sev,
            title: format!("t{n}"),
            detail: String::new(),
            first_seen: 0,
            last_seen: 0,
            subject_hash: format!("s{n}"),
            dismissed: false,
        }
    }

    #[test]
    fn a_flood_of_new_alerts_produces_a_capped_number_of_notifications() {
        let alerts: Vec<Alert> = (0..510)
            .map(|n| alert(AlertKind::NewLanDevice, Severity::Medium, n))
            .collect();
        let plan = plan_notifications(&alerts);
        assert_eq!(plan.len(), MAX_NOTIFICATIONS_PER_CYCLE + 1);
        let last = plan.last().unwrap();
        assert!(last
            .body
            .contains(&format!("{}", 510 - MAX_NOTIFICATIONS_PER_CYCLE)));
        // NEGATIVE CONTROL: at or under the cap there is no summary.
        let few = plan_notifications(&alerts[..MAX_NOTIFICATIONS_PER_CYCLE]);
        assert_eq!(few.len(), MAX_NOTIFICATIONS_PER_CYCLE);
        assert!(few.iter().all(|n| n.title == "New device on your network"));
    }

    #[test]
    fn high_severity_alerts_are_never_the_ones_dropped_from_notification() {
        // The High alerts come LAST in the input, where a naive "first N" would drop them.
        let mut alerts: Vec<Alert> = (0..50)
            .map(|n| alert(AlertKind::Watchlist, Severity::Medium, n))
            .collect();
        alerts.push(alert(AlertKind::EvilTwin, Severity::High, 900));
        alerts.push(alert(AlertKind::OpenLookalike, Severity::High, 901));
        let plan = plan_notifications(&alerts);
        assert!(plan
            .iter()
            .any(|n| n.title == "Possible evil-twin Wi-Fi network"));
        assert!(plan
            .iter()
            .any(|n| n.title == "Open network imitating a trusted one"));
        assert!(plan.len() <= MAX_NOTIFICATIONS_PER_CYCLE + 1);
        // Even more High alerts than the cap: all of them are shown, none summarised away.
        let many_high: Vec<Alert> = (0..5)
            .map(|n| alert(AlertKind::EvilTwin, Severity::High, n))
            .collect();
        let plan = plan_notifications(&many_high);
        assert_eq!(plan.len(), 5);
    }
}
