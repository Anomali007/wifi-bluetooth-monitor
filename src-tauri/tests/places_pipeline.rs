//! Place memory + FollowedAcrossPlaces through the real pipeline (`ingest_with`), synthetic
//! scans only. Positive: a tracker that dwells with the user at two places raises exactly one
//! alert. Negative: transit, one place, and a non-tracker device raise none.

use app_lib::model::*;
use app_lib::pipeline::{assemble, ingest_with};
use app_lib::store::Store;

const MIN: Millis = 60_000;
const T0: Millis = 1_700_000_000_000;

fn salt() -> Salt {
    Salt::from_bytes(vec![9; 32])
}

fn ap(n: u32, at: Millis) -> WifiObservation {
    WifiObservation {
        ssid: Some("Net-A".into()),
        bssid_hash: Some(hash_identifier(
            &salt(),
            &format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff),
        )),
        rssi: -60,
        channel: Some(6),
        security: Security::Wpa2Personal,
        seen_at: at,
        vendor: None,
        group_id: None,
    }
}

fn ble(tracker: Option<TrackerKind>, at: Millis) -> BleObservation {
    BleObservation {
        name: None,
        peripheral_hash: hash_identifier(&salt(), "synthetic-peripheral-1"),
        rssi: Some(-70),
        tracker,
        owner_state: None,
        manufacturer_id: None,
        seen_at: at,
    }
}

fn scan(at: Millis, aps: std::ops::Range<u32>, dev: Option<BleObservation>) -> ScanResult {
    assemble(
        at,
        Ok(aps.map(|n| ap(n, at)).collect()),
        Ok(dev.into_iter().collect()),
        PermissionState {
            bluetooth: PermissionStatus::Granted,
            location: PermissionStatus::Granted,
        },
    )
}

/// `scans` one-minute-apart scans at a place identified by its AP range.
fn stay(
    store: &mut Store,
    start: Millis,
    scans: i64,
    aps: std::ops::Range<u32>,
    tracker: Option<TrackerKind>,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for i in 0..scans {
        let at = start + i * MIN;
        let s = scan(at, aps.clone(), Some(ble(tracker, at)));
        alerts.extend(ingest_with(store, &s, None, at).unwrap());
    }
    alerts
}

fn open() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let mut s = Store::open(d.path()).unwrap();
    // A tracker that dwells for an hour is also a PersistentTracker finding; that rule has its
    // own tests, so switch it off to count only what the places rule says.
    let mut settings = Settings::default();
    settings.alert_toggles.persistent_tracker = false;
    s.set_settings(&settings).unwrap();
    (d, s)
}

#[test]
fn tracker_dwelling_at_two_places_raises_exactly_one_alert() {
    let (_d, mut store) = open();
    let mut all = stay(&mut store, T0, 4, 0..8, Some(TrackerKind::Tile));
    assert!(all.is_empty(), "one place is not following: {all:?}");
    // Walk between places: scans with ever-changing APs, no tracker in range.
    for i in 0..20u32 {
        let at = T0 + (10 + i64::from(i)) * MIN;
        let s = scan(at, 1000 + i * 10..1008 + i * 10, None);
        all.extend(ingest_with(&mut store, &s, None, at).unwrap());
    }
    all.extend(stay(
        &mut store,
        T0 + 60 * MIN,
        4,
        100..108,
        Some(TrackerKind::Tile),
    ));
    // Staying a while longer must not announce it again.
    all.extend(stay(
        &mut store,
        T0 + 70 * MIN,
        4,
        100..108,
        Some(TrackerKind::Tile),
    ));

    assert_eq!(all.len(), 1, "alerts: {all:?}");
    assert_eq!(all[0].kind, AlertKind::FollowedAcrossPlaces);
    assert_eq!(all[0].severity, Severity::Medium);
    assert!(all[0].detail.contains("Place "), "{}", all[0].detail);
    assert_eq!(store.list_places().unwrap().len(), 2);
}

#[test]
fn a_third_place_escalates_the_same_alert_to_high() {
    let (_d, mut store) = open();
    stay(&mut store, T0, 4, 0..8, Some(TrackerKind::Tile));
    let second = stay(
        &mut store,
        T0 + 60 * MIN,
        4,
        100..108,
        Some(TrackerKind::Tile),
    );
    assert_eq!(second.len(), 1);
    // The upsert reports only newly created alerts; severity is checked from the store.
    stay(
        &mut store,
        T0 + 120 * MIN,
        4,
        200..208,
        Some(TrackerKind::Tile),
    );
    let stored = store.get_alerts(true).unwrap();
    let f: Vec<_> = stored
        .iter()
        .filter(|a| a.kind == AlertKind::FollowedAcrossPlaces)
        .collect();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::High);
}

#[test]
fn transit_only_raises_nothing() {
    let (_d, mut store) = open();
    let mut all = Vec::new();
    // Tracker present throughout a bus ride; every scan sees different APs.
    for i in 0..40u32 {
        let at = T0 + i64::from(i) * MIN;
        let s = scan(
            at,
            i * 10..i * 10 + 8,
            Some(ble(Some(TrackerKind::Tile), at)),
        );
        all.extend(ingest_with(&mut store, &s, None, at).unwrap());
    }
    assert!(
        all.iter()
            .all(|a| a.kind != AlertKind::FollowedAcrossPlaces),
        "{all:?}"
    );
    assert!(store.list_places().unwrap().is_empty());
}

#[test]
fn non_tracker_device_at_two_places_raises_nothing() {
    let (_d, mut store) = open();
    let mut all = stay(&mut store, T0, 4, 0..8, None);
    all.extend(stay(&mut store, T0 + 60 * MIN, 4, 100..108, None));
    assert!(
        all.iter()
            .all(|a| a.kind != AlertKind::FollowedAcrossPlaces),
        "{all:?}"
    );
    assert_eq!(store.list_places().unwrap().len(), 2);
}

#[test]
fn a_tracker_marked_mine_raises_nothing() {
    let (_d, mut store) = open();
    store
        .add_mine(&MineEntry {
            kind: MineKind::Ble,
            id_hash: hash_identifier(&salt(), "synthetic-peripheral-1"),
            label: Some("My tag".into()),
            ssid: None,
            added_at: T0,
        })
        .unwrap();
    let mut all = stay(&mut store, T0, 4, 0..8, Some(TrackerKind::Tile));
    all.extend(stay(
        &mut store,
        T0 + 60 * MIN,
        4,
        100..108,
        Some(TrackerKind::Tile),
    ));
    assert!(
        all.iter()
            .all(|a| a.kind != AlertKind::FollowedAcrossPlaces),
        "{all:?}"
    );
}

#[test]
fn a_portable_access_point_at_two_places_is_reported_as_a_network_not_a_landmark() {
    let (_d, mut store) = open();
    let mut all = Vec::new();
    for (start, base) in [(T0, 0u32), (T0 + 60 * MIN, 100)] {
        for i in 0..4 {
            let at = start + i * MIN;
            let mut s = scan(at, base..base + 8, None);
            s.wifi.push(ap(9999, at)); // the same synthetic AP travels with the user
            all.extend(ingest_with(&mut store, &s, None, at).unwrap());
        }
    }
    let f: Vec<_> = all
        .iter()
        .filter(|a| a.kind == AlertKind::FollowedAcrossPlaces)
        .collect();
    assert_eq!(f.len(), 1, "{all:?}");
    assert_eq!(f[0].title, "A network that appears wherever you go");
    // Two separate places, and the portable AP is in neither fingerprint.
    let places = store.list_places().unwrap();
    assert_eq!(places.len(), 2);
    let portable = hash_identifier(&salt(), "02:00:00:00:27:0f");
    assert!(places.iter().all(|p| !p.members.contains(&portable)));
}
