//! LAN devices through the real pipeline on synthetic data: record -> context -> NewLanDevice.

use app_lib::lan::LanScanOutcome;
use app_lib::model::*;
use app_lib::pipeline::{assemble, ingest_with};
use app_lib::store::Store;

const MIN: Millis = 60_000;
const KEY: &str = "net-a-key";

fn empty_scan(at: Millis) -> ScanResult {
    assemble(
        at,
        Ok(vec![]),
        Ok(vec![]),
        PermissionState {
            bluetooth: PermissionStatus::Granted,
            location: PermissionStatus::Granted,
        },
    )
}

fn device(mac: &str, at: Millis) -> LanDevice {
    LanDevice {
        network_key: KEY.into(),
        mac_hash: mac.into(),
        vendor: Some("Vendor-A".into()),
        hostname: None,
        services: vec![],
        first_seen: at,
        last_seen: at,
        ip: Some("192.0.2.10".into()),
        mine: false,
    }
}

fn outcome(devices: Vec<LanDevice>) -> LanScanOutcome {
    LanScanOutcome {
        network: NetworkInfo {
            network_key: Some(KEY.into()),
            ssid: Some("Net-A".into()),
            bssid_hash: Some("ap-1".into()),
            is_mine: true,
            ..NetworkInfo::default()
        },
        devices,
    }
}

fn mine_ap(store: &mut Store, at: Millis) {
    store
        .add_mine(&MineEntry {
            kind: MineKind::WifiAp,
            id_hash: "ap-1".into(),
            label: None,
            added_at: at,
        })
        .unwrap();
}

fn lan_alerts(store: &Store) -> Vec<Alert> {
    store
        .get_alerts(true)
        .unwrap()
        .into_iter()
        .filter(|a| a.kind == AlertKind::NewLanDevice)
        .collect()
}

/// Baseline at `t0`, a newcomer an hour later.
fn run_flow(store: &mut Store, t0: Millis) -> (usize, usize) {
    let first = ingest_with(
        store,
        &empty_scan(t0),
        Some(&outcome(vec![device("old", t0)])),
        t0,
    )
    .unwrap();
    let later = t0 + 60 * MIN;
    let second = ingest_with(
        store,
        &empty_scan(later),
        Some(&outcome(vec![device("old", later), device("new", later)])),
        later,
    )
    .unwrap();
    (
        first
            .iter()
            .filter(|a| a.kind == AlertKind::NewLanDevice)
            .count(),
        second
            .iter()
            .filter(|a| a.kind == AlertKind::NewLanDevice)
            .count(),
    )
}

#[test]
fn new_device_on_a_mine_network_alerts_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    let (baseline, newcomer) = run_flow(&mut store, t0);
    assert_eq!(baseline, 0, "devices present while learning are not news");
    assert_eq!(newcomer, 1);
    // Re-ingesting the same observation creates no new alert (notifications dedupe).
    let later = t0 + 61 * MIN;
    let again = ingest_with(
        &mut store,
        &empty_scan(later),
        Some(&outcome(vec![device("old", later), device("new", later)])),
        later,
    )
    .unwrap();
    assert!(again.iter().all(|a| a.kind != AlertKind::NewLanDevice));
    assert_eq!(lan_alerts(&store).len(), 1);
    // Both devices were recorded, hashed, without an IP.
    let stored = store.list_lan_devices(Some(KEY)).unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|d| d.ip.is_none()));
}

#[test]
fn same_flow_on_a_network_that_is_not_mine_never_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    // NEGATIVE CONTROL: identical observations, no Mine entry for the access point.
    let (baseline, newcomer) = run_flow(&mut store, t0);
    assert_eq!((baseline, newcomer), (0, 0));
    assert!(lan_alerts(&store).is_empty());
    // Passive discovery still remembered the devices.
    assert_eq!(store.list_lan_devices(Some(KEY)).unwrap().len(), 2);
}

#[test]
fn marking_a_device_mine_silences_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    store
        .add_mine(&MineEntry {
            kind: MineKind::Lan,
            id_hash: "new".into(),
            label: Some("My device".into()),
            added_at: t0,
        })
        .unwrap();
    let (_, newcomer) = run_flow(&mut store, t0);
    assert_eq!(newcomer, 0);
}
