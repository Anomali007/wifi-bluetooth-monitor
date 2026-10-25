//! Watchlist end to end on synthetic data: mapping-style vendor/group fields -> store ->
//! `ingest_with` -> alert. Includes the negative controls (Mine, no entries).

use app_lib::model::*;
use app_lib::pipeline::{assemble, ingest_with, notification_text, now_ms};
use app_lib::store::Store;
use app_lib::vendor;

fn salt() -> Salt {
    Salt::from_bytes(vec![9; 32])
}

/// One radio of the synthetic router, computed the way `wifi::mapping` does before hashing.
fn radio(last: u8, at: Millis) -> WifiObservation {
    let raw = format!("02:00:00:00:aa:{last:02x}");
    WifiObservation {
        ssid: Some("Net-A".into()),
        bssid_hash: Some(hash_identifier(&salt(), &raw)),
        rssi: -50,
        channel: Some(36),
        security: Security::Wpa2Personal,
        seen_at: at,
        vendor: vendor::vendor_for(&raw),
        group_id: vendor::group_id(&salt(), &raw),
    }
}

fn scan(at: Millis) -> ScanResult {
    assemble(
        at,
        Ok(vec![radio(0x04, at), radio(0x08, at), radio(0x0c, at)]),
        Ok(vec![]),
        PermissionState {
            bluetooth: PermissionStatus::Granted,
            location: PermissionStatus::Granted,
        },
    )
}

fn watchlist_alerts(alerts: &[Alert]) -> Vec<&Alert> {
    alerts
        .iter()
        .filter(|a| a.kind == AlertKind::Watchlist)
        .collect()
}

#[test]
fn matching_entry_alerts_once_for_the_whole_router_then_stays_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    store
        .add_watchlist(WatchKind::Ssid, "net-a", WatchMatch::Exact, 1)
        .unwrap();
    store
        .add_watchlist(WatchKind::Vendor, "private", WatchMatch::Contains, 2)
        .unwrap();
    let now = now_ms();
    let first = ingest_with(&mut store, &scan(now), None, now).unwrap();
    // Three radios, one group: one alert per entry, not per radio.
    let hits = watchlist_alerts(&first);
    assert_eq!(hits.len(), 2, "{first:?}");
    assert!(hits.iter().any(|a| a.title == "Watchlist match: Net-A"));
    for a in &hits {
        let (t, b) = notification_text(a);
        assert!(!format!("{t} {b}").contains("Net-A"));
    }
    // Same scan again: nothing new is announced.
    let again = ingest_with(&mut store, &scan(now + 1), None, now + 1).unwrap();
    assert!(watchlist_alerts(&again).is_empty());
}

#[test]
fn negative_controls_stay_silent() {
    let now = now_ms();
    let run = |setup: &dyn Fn(&mut Store)| {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        setup(&mut store);
        ingest_with(&mut store, &scan(now), None, now).unwrap()
    };
    // No entries.
    assert!(watchlist_alerts(&run(&|_| {})).is_empty());
    // Entries that do not match.
    let other = run(&|s| {
        s.add_watchlist(WatchKind::Ssid, "Cafe-Z", WatchMatch::Contains, 1)
            .unwrap();
        s.add_watchlist(WatchKind::Vendor, "Vendor-B", WatchMatch::Exact, 1)
            .unwrap();
    });
    assert!(watchlist_alerts(&other).is_empty());
    // A matching entry, but the router is marked mine (as a group).
    let group = vendor::group_id(&salt(), "02:00:00:00:aa:04").unwrap();
    let mine = run(&|s| {
        s.add_watchlist(WatchKind::Ssid, "Net-A", WatchMatch::Exact, 1)
            .unwrap();
        s.add_mine(&MineEntry {
            kind: MineKind::WifiGroup,
            id_hash: group.clone(),
            label: None,
            added_at: 1,
        })
        .unwrap();
    });
    assert!(watchlist_alerts(&mine).is_empty());
    // Control for the above: the same entry without Mine does alert.
    let unmarked = run(&|s| {
        s.add_watchlist(WatchKind::Ssid, "Net-A", WatchMatch::Exact, 1)
            .unwrap();
    });
    assert_eq!(watchlist_alerts(&unmarked).len(), 1);
}
