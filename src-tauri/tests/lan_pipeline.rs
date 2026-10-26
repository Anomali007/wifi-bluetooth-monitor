//! LAN devices through the real pipeline on synthetic data: record -> context -> NewLanDevice.

use app_lib::lan::{host_key, LanScanOutcome};
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
        source: None,
        possibly_same_as: None,
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

fn named(hash: &str, host: &str, source: LanSource, at: Millis) -> LanDevice {
    LanDevice {
        mac_hash: hash.into(),
        hostname: Some(host.into()),
        vendor: if source == LanSource::Announced {
            None
        } else {
            Some("Vendor-A".into())
        },
        source: Some(source),
        ..device(hash, at)
    }
}

#[test]
fn announced_only_devices_alert_like_any_other_once_learning_is_over() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    let old = host_key(store.salt(), "device-a.local");
    let new = host_key(store.salt(), "device-b.local");
    let first = ingest_with(
        &mut store,
        &empty_scan(t0),
        Some(&outcome(vec![named(
            &old,
            "device-a.local",
            LanSource::Announced,
            t0,
        )])),
        t0,
    )
    .unwrap();
    assert!(first.iter().all(|a| a.kind != AlertKind::NewLanDevice));
    let later = t0 + 60 * MIN;
    let second = ingest_with(
        &mut store,
        &empty_scan(later),
        Some(&outcome(vec![
            named(&old, "device-a.local", LanSource::Announced, later),
            named(&new, "device-b.local", LanSource::Announced, later),
        ])),
        later,
    )
    .unwrap();
    let alerts: Vec<_> = second
        .iter()
        .filter(|a| a.kind == AlertKind::NewLanDevice)
        .collect();
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].detail.contains("device-b.local"));
    assert!(
        alerts[0].detail.contains("unknown vendor"),
        "no MAC, no vendor"
    );
}

#[test]
fn a_known_host_that_gains_a_mac_is_not_news() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    let hk = host_key(store.salt(), "device-a.local");
    let anchor = host_key(store.salt(), "anchor.local");
    ingest_with(
        &mut store,
        &empty_scan(t0),
        Some(&outcome(vec![
            named(&anchor, "anchor.local", LanSource::Announced, t0),
            named(&hk, "device-a.local", LanSource::Announced, t0),
        ])),
        t0,
    )
    .unwrap();
    // An hour later the same host shows up in the neighbor table: new key, same device.
    let later = t0 + 60 * MIN;
    let upgraded = ingest_with(
        &mut store,
        &empty_scan(later),
        Some(&outcome(vec![
            named(&anchor, "anchor.local", LanSource::Announced, later),
            named("mac-key", "device-a.local", LanSource::Both, later),
        ])),
        later,
    )
    .unwrap();
    assert!(
        upgraded.iter().all(|a| a.kind != AlertKind::NewLanDevice),
        "the upgrade must not look like a stranger"
    );
    let stored = store.list_lan_devices(Some(KEY)).unwrap();
    assert_eq!(stored.len(), 2, "one row per physical device");
    let d = stored.iter().find(|d| d.mac_hash == "mac-key").unwrap();
    assert_eq!(d.first_seen, t0);
    // NEGATIVE CONTROL: a genuinely different MAC-keyed device at the same moment DOES alert.
    let third = later + MIN;
    let fresh = ingest_with(
        &mut store,
        &empty_scan(third),
        Some(&outcome(vec![named(
            "mac-other",
            "device-z.local",
            LanSource::Both,
            third,
        )])),
        third,
    )
    .unwrap();
    assert_eq!(
        fresh
            .iter()
            .filter(|a| a.kind == AlertKind::NewLanDevice)
            .count(),
        1
    );
}

#[test]
fn marking_a_hostname_keyed_device_mine_silences_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    let old = host_key(store.salt(), "device-a.local");
    let new = host_key(store.salt(), "device-b.local");
    store
        .add_mine(&MineEntry {
            kind: MineKind::Lan,
            id_hash: new.clone(),
            label: Some("My device".into()),
            added_at: t0,
        })
        .unwrap();
    ingest_with(
        &mut store,
        &empty_scan(t0),
        Some(&outcome(vec![named(
            &old,
            "device-a.local",
            LanSource::Announced,
            t0,
        )])),
        t0,
    )
    .unwrap();
    let later = t0 + 60 * MIN;
    let second = ingest_with(
        &mut store,
        &empty_scan(later),
        Some(&outcome(vec![
            named(&old, "device-a.local", LanSource::Announced, later),
            named(&new, "device-b.local", LanSource::Announced, later),
        ])),
        later,
    )
    .unwrap();
    assert!(second.iter().all(|a| a.kind != AlertKind::NewLanDevice));
}

/// M1: a stranger that announces a Mine device's mDNS hostname (A record with its own IP) is
/// joined to its own ARP MAC by the scan. That MAC row must NOT inherit Mine or the old
/// `first_seen`: it is news, and the user is only told it might be their device.
#[test]
fn a_stranger_announcing_a_mine_hostname_does_not_inherit_mine() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    let hk = host_key(store.salt(), "device-a.local");
    let anchor = host_key(store.salt(), "anchor.local");
    store
        .add_mine(&MineEntry {
            kind: MineKind::Lan,
            id_hash: hk.clone(),
            label: Some("My Laptop".into()),
            added_at: t0,
        })
        .unwrap();
    ingest_with(
        &mut store,
        &empty_scan(t0),
        Some(&outcome(vec![
            named(&anchor, "anchor.local", LanSource::Announced, t0),
            named(&hk, "device-a.local", LanSource::Announced, t0),
        ])),
        t0,
    )
    .unwrap();
    let later = t0 + 60 * MIN;
    let stranger = "02:00:00:00:00:99";
    let alerts = ingest_with(
        &mut store,
        &empty_scan(later),
        Some(&outcome(vec![
            named(&anchor, "anchor.local", LanSource::Announced, later),
            named(stranger, "device-a.local", LanSource::Both, later),
        ])),
        later,
    )
    .unwrap();
    let mine = store.list_mine().unwrap();
    assert!(
        !mine
            .iter()
            .any(|m| m.kind == MineKind::Lan && m.id_hash == stranger),
        "the stranger's MAC must not be added to Mine"
    );
    let stored = store.list_lan_devices(Some(KEY)).unwrap();
    let s = stored.iter().find(|d| d.mac_hash == stranger).unwrap();
    assert!(!s.mine);
    assert_eq!(s.first_seen, later, "no inherited first_seen");
    assert_eq!(s.possibly_same_as.as_deref(), Some("My Laptop"));
    assert_eq!(
        alerts
            .iter()
            .filter(|a| a.kind == AlertKind::NewLanDevice)
            .count(),
        1,
        "the stranger is announced as a new device"
    );
    // The user's own hostname row is untouched and still Mine.
    let own = stored.iter().find(|d| d.mac_hash == hk).unwrap();
    assert!(own.mine);
    assert_eq!(own.possibly_same_as, None);
}

/// M2 end to end: ~510 spoofed LAN devices on a Mine network through the real pipeline create a
/// handful of alerts (and so a handful of notifications), not 510.
#[test]
fn a_spoofed_device_flood_creates_a_capped_number_of_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let t0 = app_lib::pipeline::now_ms() - 3 * 60 * MIN;
    mine_ap(&mut store, t0 - MIN);
    ingest_with(
        &mut store,
        &empty_scan(t0),
        Some(&outcome(vec![device("old", t0)])),
        t0,
    )
    .unwrap();
    let later = t0 + 60 * MIN;
    let mut flood = vec![device("old", later)];
    flood.extend((0..510).map(|n| {
        device(
            &format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256),
            later,
        )
    }));
    let created =
        ingest_with(&mut store, &empty_scan(later), Some(&outcome(flood)), later).unwrap();
    let lan: Vec<_> = created
        .iter()
        .filter(|a| a.kind == AlertKind::NewLanDevice)
        .collect();
    assert_eq!(lan.len(), app_lib::detect::MAX_FLOOD_ALERTS_PER_KIND + 1);
    let notices = app_lib::pipeline::plan_notifications(&created);
    assert!(notices.len() <= app_lib::pipeline::MAX_NOTIFICATIONS_PER_CYCLE + 1);
}
