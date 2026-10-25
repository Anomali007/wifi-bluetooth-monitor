//! One full cycle on synthetic data: assemble -> store -> detect -> upsert, twice.
//! The point: the first pass creates alerts, the second creates none, so notifications
//! (which fire only for newly created alerts) are deduplicated.

use app_lib::model::*;
use app_lib::pipeline::{assemble, ingest, notification_text};
use app_lib::store::Store;

const MIN: Millis = 60_000;

fn salt() -> Salt {
    Salt::from_bytes(vec![9; 32])
}

fn ap(ssid: &str, n: u8, security: Security, at: Millis) -> WifiObservation {
    WifiObservation {
        ssid: Some(ssid.into()),
        bssid_hash: Some(hash_identifier(&salt(), &format!("02:00:00:00:00:{n:02x}"))),
        rssi: -60,
        channel: Some(6),
        security,
        seen_at: at,
        vendor: None,
        group_id: None,
    }
}

fn tracker(at: Millis) -> BleObservation {
    BleObservation {
        name: None,
        peripheral_hash: hash_identifier(&salt(), "synthetic-peripheral-1"),
        rssi: Some(-70),
        tracker: Some(TrackerKind::Tile),
        owner_state: None,
        manufacturer_id: None,
        seen_at: at,
    }
}

fn scan_at(at: Millis) -> ScanResult {
    assemble(
        at,
        Ok(vec![
            ap("Net-A", 1, Security::Wpa2Personal, at),
            ap("Net-A", 2, Security::Open, at),
        ]),
        Ok(vec![tracker(at)]),
        PermissionState {
            bluetooth: PermissionStatus::Granted,
            location: PermissionStatus::Granted,
        },
    )
}

#[test]
fn first_pass_creates_alerts_second_pass_creates_none() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();

    // Six scans, five minutes apart, ending "now": a tracker present for 25 minutes and an
    // evil-twin pair (same name, one open, one WPA2).
    let end = app_lib::pipeline::now_ms();
    let mut first_pass = Vec::new();
    for i in 0..6 {
        let at = end - (5 - i) * 5 * MIN;
        first_pass.extend(ingest(&mut store, &scan_at(at), at).unwrap());
    }
    let kinds: Vec<AlertKind> = first_pass.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&AlertKind::EvilTwin), "kinds: {kinds:?}");
    assert!(
        kinds.contains(&AlertKind::PersistentTracker),
        "kinds: {kinds:?}"
    );
    // Each (kind, subject) is announced exactly once across the whole first pass.
    let mut ids: Vec<&str> = first_pass.iter().map(|a| a.id.as_str()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "an alert was announced twice");

    // Second pass: the same conditions, one more scan.
    let again = ingest(&mut store, &scan_at(end + 5 * MIN), end + 5 * MIN).unwrap();
    assert!(
        again.is_empty(),
        "repeat sightings must not re-announce: {again:?}"
    );

    // Everything is stored; dismissing hides it and a further pass keeps it dismissed.
    let stored = store.get_alerts(false).unwrap();
    assert_eq!(stored.len(), total);
    store.dismiss_alert(&stored[0].id).unwrap();
    assert_eq!(store.get_alerts(false).unwrap().len(), total - 1);
    let later = ingest(&mut store, &scan_at(end + 10 * MIN), end + 10 * MIN).unwrap();
    assert!(later.is_empty());
    assert_eq!(store.get_alerts(false).unwrap().len(), total - 1);
}

#[test]
fn notification_text_never_carries_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let end = app_lib::pipeline::now_ms();
    let mut alerts = Vec::new();
    for i in 0..6 {
        let at = end - (5 - i) * 5 * MIN;
        alerts.extend(ingest(&mut store, &scan_at(at), at).unwrap());
    }
    assert!(!alerts.is_empty());
    for a in &alerts {
        let (title, body) = notification_text(a);
        let text = format!("{title} {body}");
        assert!(!text.contains("Net-A"), "{text}");
        assert!(!text.contains(&a.subject_hash), "{text}");
        assert!(!text.contains("02:00"), "{text}");
    }
    let tracker_alert = alerts
        .iter()
        .find(|a| a.kind == AlertKind::PersistentTracker)
        .unwrap();
    assert!(
        notification_text(tracker_alert)
            .0
            .contains("possible tracker")
            || notification_text(tracker_alert)
                .0
                .contains("Possible tracker")
    );
}

#[test]
fn location_withheld_ssids_surface_as_an_error() {
    let nameless = WifiObservation {
        ssid: None,
        bssid_hash: None,
        rssi: -70,
        channel: None,
        security: Security::Unknown,
        seen_at: 1,
        vendor: None,
        group_id: None,
    };
    let denied = PermissionState {
        bluetooth: PermissionStatus::Granted,
        location: PermissionStatus::NotDetermined,
    };
    let r = assemble(1, Ok(vec![nameless.clone()]), Ok(vec![]), denied);
    assert!(r
        .errors
        .iter()
        .any(|e| e.source == ScanSource::Wifi && e.code == ScanErrorCode::PermissionDenied));
    // Granted: no such error. And a hard scan error is passed through, not duplicated.
    let granted = PermissionState {
        location: PermissionStatus::Granted,
        ..denied
    };
    let r = assemble(1, Ok(vec![nameless]), Ok(vec![]), granted);
    assert!(r.errors.is_empty());
}

#[test]
fn ingest_with_lan_outcome_and_v2_state_runs_and_stays_quiet() {
    use app_lib::lan::LanScanOutcome;
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    store
        .add_mine(&MineEntry {
            kind: MineKind::WifiAp,
            id_hash: hash_identifier(&salt(), "02:00:00:00:00:01"),
            label: Some("Router-A".into()),
            added_at: 1,
        })
        .unwrap();
    store
        .add_watchlist(WatchKind::Ssid, "Net-A", WatchMatch::Exact, 1)
        .unwrap();
    let outcome = LanScanOutcome::default();
    let end = app_lib::pipeline::now_ms();
    // Stubbed v2 rules produce nothing; the pass must succeed and v1 rules still work.
    let alerts =
        app_lib::pipeline::ingest_with(&mut store, &scan_at(end), Some(&outcome), end).unwrap();
    assert!(alerts.iter().all(|a| !matches!(
        a.kind,
        AlertKind::FollowedAcrossPlaces | AlertKind::NewLanDevice
    )));
    assert!(store.list_places().unwrap().is_empty());
}

#[test]
fn every_alert_kind_has_generic_notification_text() {
    for kind in [
        AlertKind::EvilTwin,
        AlertKind::OpenLookalike,
        AlertKind::TrustedNetworkChanged,
        AlertKind::PersistentTracker,
        AlertKind::NewDevice,
        AlertKind::FollowedAcrossPlaces,
        AlertKind::Watchlist,
        AlertKind::NewLanDevice,
    ] {
        let a = Alert {
            id: "x".into(),
            kind,
            severity: Severity::Low,
            title: "Net-A".into(),
            detail: "Net-A at Place-A".into(),
            first_seen: 1,
            last_seen: 1,
            subject_hash: "ab".repeat(32),
            dismissed: false,
        };
        let (t, b) = notification_text(&a);
        assert!(!t.is_empty() && !b.is_empty());
        assert!(!format!("{t} {b}").contains("Net-A"), "{kind:?}");
    }
}
