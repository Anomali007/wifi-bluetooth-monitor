//! Local-network discovery: ARP table, receive-only mDNS, opt-in sweep. OWNER: WP-D.
//!
//! CONTRACT (frozen signatures):
//! - Passive (always): read the ARP table via `sysctl`, listen on mDNS (never send).
//! - Active sweep: only when `settings.lan_active_sweep` AND the joined access point is in
//!   Mine, or when `force_sweep` is set by the user's "Sweep now" (the same gate still applies).
//!   One zero-byte UDP datagram per host to port 9, rate-limited. No TCP, no port scans.
//! - [`scan`] is blocking; callers run it on a blocking thread. [`record`] persists the
//!   outcome (devices by MAC hash, never an IP).
//!
//! Layout: [`gate`] decides (pure), [`sweep`] is the only file that transmits, [`arp`] and
//! [`mdns`] only read, [`net`] reads the joined network. [`scan`] reaches `run_sweep` only
//! through [`gate::may_sweep`].

pub mod arp;
pub mod gate;
pub mod mdns;
pub mod net;
pub mod sweep;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::model::{
    hash_identifier, LanDevice, LanMode, Millis, MineEntry, NetworkInfo, Salt, ScanError, Settings,
};
use crate::store::{Store, StoreResult};
use crate::vendor;

use gate::{GateInput, SweepRefusal};
use mdns::Announcement;
use net::Link;

/// How long to wait after the sweep before reading the ARP table, so replies can be learned.
const ARP_SETTLE: Duration = Duration::from_secs(2);

fn now_ms() -> Millis {
    crate::pipeline::now_ms()
}

/// Everything [`scan`] needs, so the signature can stay frozen while the inputs grow.
#[derive(Debug, Clone)]
pub struct LanInputs {
    pub salt: Salt,
    pub settings: Settings,
    pub mine: Vec<MineEntry>,
    /// The user pressed "Sweep now". Still subject to the sweep gate.
    pub force_sweep: bool,
}

/// State kept between cycles (sweep cadence). Lives in `AppState`.
#[derive(Debug, Clone, Default)]
pub struct LanState {
    pub last_sweep_at: Option<Millis>,
    /// Network key the last sweep ran on, so a sweep of one network never throttles another.
    pub last_sweep_network: Option<String>,
}

impl LanState {
    /// When the network `key` was last swept.
    fn last_sweep_for(&self, key: Option<&str>) -> Option<Millis> {
        match (&self.last_sweep_network, key) {
            (Some(n), Some(k)) if n == k => self.last_sweep_at,
            _ => None,
        }
    }
}

/// What one LAN observation produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LanScanOutcome {
    pub network: NetworkInfo,
    pub devices: Vec<LanDevice>,
}

/// The gate input for a link. Shared by every caller so the gate is always fed the same way.
fn gate_for<'a>(link: &Link, inputs: &LanInputs, key: Option<&'a str>) -> GateInput<'a> {
    GateInput {
        setting_on: inputs.settings.lan_active_sweep,
        network_key: key,
        ap_is_mine: gate::ap_is_mine(
            &inputs.mine,
            link.bssid_hash.as_deref(),
            link.group_id.as_deref(),
        ),
        subnet: link.subnet,
    }
}

fn key_of(link: &Link) -> Option<String> {
    net::network_key(link.bssid_hash.as_deref(), link.group_id.as_deref())
}

/// The joined network and whether a sweep may run on it, from plain inputs (no I/O).
fn build_info(link: &Link, inputs: &LanInputs, state: &LanState) -> NetworkInfo {
    let key = key_of(link);
    let gate_in = gate_for(link, inputs, key.as_deref());
    let sweep_enabled = gate::sweep_gate(&gate_in).is_ok();
    let last_sweep_at = state.last_sweep_for(key.as_deref());
    NetworkInfo {
        ssid: link.ssid.clone(),
        bssid_hash: link.bssid_hash.clone(),
        group_id: link.group_id.clone(),
        subnet: link.subnet.map(|s| s.cidr()),
        is_mine: gate_in.ap_is_mine,
        sweep_enabled,
        mode: if sweep_enabled && last_sweep_at.is_some() {
            LanMode::Sweep
        } else {
            LanMode::Passive
        },
        last_sweep_at,
        network_key: key,
    }
}

/// Devices from an ARP dump: this interface only, inside its subnet, never our own address,
/// one per hardware address. IPs are carried for display and never persisted.
fn devices_from_arp(
    entries: &[arp::ArpEntry],
    link: &Link,
    key: &str,
    salt: &Salt,
    now: Millis,
    lookup: impl Fn(Ipv4Addr) -> Option<Announcement>,
) -> Vec<LanDevice> {
    let (Some(if_index), Some(subnet)) = (link.if_index, link.subnet) else {
        return Vec::new();
    };
    let mut by_mac: BTreeMap<String, LanDevice> = BTreeMap::new();
    for e in entries {
        if e.if_index != if_index || !subnet.contains(e.ip) || e.ip == subnet.addr {
            continue;
        }
        let mac = arp::format_mac(&e.mac);
        let mac_hash = hash_identifier(salt, &mac);
        let dev = by_mac.entry(mac_hash.clone()).or_insert_with(|| {
            let announced = lookup(e.ip).unwrap_or_default();
            LanDevice {
                network_key: key.to_string(),
                mac_hash,
                vendor: vendor::vendor_for(&mac),
                hostname: announced.hostname,
                services: announced.services.into_iter().collect(),
                first_seen: now,
                last_seen: now,
                ip: Some(e.ip.to_string()),
                mine: false,
            }
        });
        // Several addresses for one MAC: show the lowest, deterministically.
        if let Some(cur) = dev.ip.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()) {
            if e.ip < cur {
                dev.ip = Some(e.ip.to_string());
            }
        }
    }
    by_mac.into_values().collect()
}

/// Observe the joined network: always the ARP table and the mDNS cache; additionally one sweep
/// when [`gate::may_sweep`] allows it. A failed ARP read yields no devices, not an error: the
/// LAN is an extra and must not cost a Wi-Fi/BLE cycle.
pub fn scan(inputs: &LanInputs, state: &mut LanState) -> Result<LanScanOutcome, ScanError> {
    let now = now_ms();
    let mdns = mdns::ensure_listener();
    let link = net::read_link(&inputs.salt);
    let key = key_of(&link);

    // The only route to a transmit: the gate (setting ON + AP Mine + subnet <= /23) and cadence.
    let decision = gate::may_sweep(
        &gate_for(&link, inputs, key.as_deref()),
        inputs.force_sweep,
        state.last_sweep_for(key.as_deref()),
        now,
    );
    if let Ok(subnet) = decision {
        if let Ok(mut sink) = sweep::UdpSink::new() {
            sweep::run_sweep(&mut sink, &subnet.hosts(), std::thread::sleep);
            state.last_sweep_at = Some(now);
            state.last_sweep_network = key.clone();
            std::thread::sleep(ARP_SETTLE);
        }
    }

    let network = build_info(&link, inputs, state);
    let mut arp_rows = 0usize;
    let devices = match key.as_deref() {
        Some(k) => {
            let entries = arp::read_arp_table().unwrap_or_default();
            arp_rows = entries.len();
            devices_from_arp(&entries, &link, k, &inputs.salt, now_ms(), |ip| {
                mdns.lookup(ip)
            })
        }
        None => Vec::new(),
    };
    let mdns_counts = mdns::listener_counts();
    // Counts only: never a name, address or hash.
    log::info!(
        "lan: network identified={}, subnet known={}, arp rows={}, devices={}, mdns sources={}, mdns socket bound={}, bind failures={}, datagrams={}",
        key.is_some(),
        link.subnet.is_some(),
        arp_rows,
        devices.len(),
        mdns.announced_sources(),
        mdns_counts.0,
        mdns_counts.1,
        mdns_counts.2
    );
    Ok(LanScanOutcome { network, devices })
}

/// The currently joined network without touching the LAN: no sweep, no ARP read.
pub fn current_network(inputs: &LanInputs, state: &LanState) -> NetworkInfo {
    build_info(&net::read_link(&inputs.salt), inputs, state)
}

/// Why a sweep would not run right now (honouring `inputs.force_sweep` for the cadence), or
/// `None` when it would. Lets "Sweep now" explain a refusal instead of silently doing nothing.
pub fn sweep_refusal(inputs: &LanInputs, state: &LanState) -> Option<&'static str> {
    let link = net::read_link(&inputs.salt);
    let key = key_of(&link);
    gate::may_sweep(
        &gate_for(&link, inputs, key.as_deref()),
        inputs.force_sweep,
        state.last_sweep_for(key.as_deref()),
        now_ms(),
    )
    .err()
    .map(SweepRefusal::message)
}

/// Persist an outcome's devices (hashed MACs; the live IP is dropped by the store).
pub fn record(store: &mut Store, outcome: &LanScanOutcome, _now: Millis) -> StoreResult<()> {
    for d in &outcome.devices {
        store.upsert_lan_device(d)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MineKind;
    use gate::Subnet;

    fn salt() -> Salt {
        Salt::from_bytes(vec![1; 32])
    }

    fn inputs(sweep: bool, mine: Vec<MineEntry>) -> LanInputs {
        LanInputs {
            salt: salt(),
            settings: Settings {
                lan_active_sweep: sweep,
                ..Settings::default()
            },
            mine,
            force_sweep: false,
        }
    }

    fn mine_ap(hash: &str) -> MineEntry {
        MineEntry {
            kind: MineKind::WifiAp,
            id_hash: hash.into(),
            label: None,
            added_at: 1,
        }
    }

    fn link() -> Link {
        Link {
            ssid: Some("Net-A".into()),
            bssid_hash: Some("ap-1".into()),
            group_id: None,
            if_index: Some(11),
            subnet: Some(Subnet {
                addr: Ipv4Addr::new(192, 0, 2, 7),
                prefix: 24,
            }),
        }
    }

    fn arp_entry(last: u8, if_index: u16, mac_last: u8) -> arp::ArpEntry {
        arp::ArpEntry {
            ip: Ipv4Addr::new(192, 0, 2, last),
            mac: [0x02, 0, 0, 0, 0, mac_last],
            if_index,
        }
    }

    #[test]
    fn build_info_reflects_gate_inputs() {
        let st = LanState::default();
        // Sweep on + AP Mine -> enabled.
        let n = build_info(&link(), &inputs(true, vec![mine_ap("ap-1")]), &st);
        assert!(n.is_mine && n.sweep_enabled);
        assert_eq!(n.subnet.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(n.network_key.as_deref(), Some("ap-1"));
        // NEGATIVE: sweep off.
        let n = build_info(&link(), &inputs(false, vec![mine_ap("ap-1")]), &st);
        assert!(n.is_mine && !n.sweep_enabled);
        // NEGATIVE: AP not Mine.
        let n = build_info(&link(), &inputs(true, vec![]), &st);
        assert!(!n.is_mine && !n.sweep_enabled);
        // NEGATIVE: look-alike (Mine holds a different BSSID).
        let n = build_info(&link(), &inputs(true, vec![mine_ap("ap-other")]), &st);
        assert!(!n.is_mine && !n.sweep_enabled);
        // NEGATIVE: no network at all.
        let n = build_info(&Link::default(), &inputs(true, vec![mine_ap("ap-1")]), &st);
        assert_eq!(n, NetworkInfo::default());
    }

    #[test]
    fn mode_and_last_sweep_follow_the_network() {
        let mut st = LanState {
            last_sweep_at: Some(5_000),
            last_sweep_network: Some("ap-1".into()),
        };
        let inp = inputs(true, vec![mine_ap("ap-1")]);
        let n = build_info(&link(), &inp, &st);
        assert_eq!(n.mode, LanMode::Sweep);
        assert_eq!(n.last_sweep_at, Some(5_000));
        // A sweep of another network does not count for this one.
        st.last_sweep_network = Some("someone-else".into());
        let n = build_info(&link(), &inp, &st);
        assert_eq!(n.mode, LanMode::Passive);
        assert_eq!(n.last_sweep_at, None);
        assert_eq!(st.last_sweep_for(Some("ap-1")), None);
    }

    #[test]
    fn devices_are_filtered_hashed_and_deduplicated() {
        let entries = vec![
            arp_entry(10, 11, 1),
            arp_entry(5, 11, 1), // same MAC, lower IP wins
            arp_entry(11, 11, 2),
            arp_entry(12, 99, 3), // other interface
            arp_entry(7, 11, 4),  // our own address
            arp::ArpEntry {
                ip: Ipv4Addr::new(198, 51, 100, 9), // outside the subnet
                mac: [0x02, 0, 0, 0, 0, 5],
                if_index: 11,
            },
        ];
        let mut announced = Announcement {
            hostname: Some("device-a.local".into()),
            ..Announcement::default()
        };
        announced.services.insert("_http._tcp".into());
        let devs = devices_from_arp(&entries, &link(), "key", &salt(), 777, |ip| {
            (ip == Ipv4Addr::new(192, 0, 2, 10)).then(|| announced.clone())
        });
        assert_eq!(devs.len(), 2);
        let d1 = devs
            .iter()
            .find(|d| d.mac_hash == hash_identifier(&salt(), "02:00:00:00:00:01"))
            .unwrap();
        assert_eq!(d1.ip.as_deref(), Some("192.0.2.5"));
        assert_eq!(d1.network_key, "key");
        assert_eq!((d1.first_seen, d1.last_seen), (777, 777));
        // mDNS was looked up by the first-seen IP (.10) for this MAC.
        assert_eq!(d1.hostname.as_deref(), Some("device-a.local"));
        assert_eq!(d1.services, vec!["_http._tcp".to_string()]);
        // No raw MAC anywhere.
        let json = serde_json::to_string(&devs).unwrap();
        assert!(!json.contains("02:00:00"));
    }

    #[test]
    fn no_interface_or_subnet_means_no_devices() {
        let entries = vec![arp_entry(10, 11, 1)];
        let mut l = link();
        l.if_index = None;
        assert!(devices_from_arp(&entries, &l, "k", &salt(), 0, |_| None).is_empty());
        let mut l = link();
        l.subnet = None;
        assert!(devices_from_arp(&entries, &l, "k", &salt(), 0, |_| None).is_empty());
    }

    #[test]
    fn record_persists_hashed_devices_without_ip_and_keeps_first_seen() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let mk = |at: Millis| LanDevice {
            network_key: "key".into(),
            mac_hash: "h1".into(),
            vendor: Some("Vendor-A".into()),
            hostname: None,
            services: vec![],
            first_seen: at,
            last_seen: at,
            ip: Some("192.0.2.10".into()),
            mine: false,
        };
        let out = |at| LanScanOutcome {
            network: NetworkInfo::default(),
            devices: vec![mk(at)],
        };
        record(&mut store, &out(100), 100).unwrap();
        record(&mut store, &out(200), 200).unwrap();
        let got = store.list_lan_devices(Some("key")).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].first_seen, got[0].last_seen), (100, 200));
        assert_eq!(got[0].ip, None, "IPs are never persisted");
        // An empty outcome stores nothing.
        record(&mut store, &LanScanOutcome::default(), 300).unwrap();
        assert_eq!(store.list_lan_devices(None).unwrap().len(), 1);
    }

    /// Reads the live network passively (no sweep: the setting is off). Counts only.
    /// `cargo test -- --ignored lan_live --nocapture`.
    #[test]
    #[ignore]
    fn lan_live() {
        let out = scan(&inputs(false, vec![]), &mut LanState::default()).unwrap();
        println!(
            "lan_live: network={} mine={} sweep_enabled={} devices={} with_vendor={}",
            out.network.network_key.is_some(),
            out.network.is_mine,
            out.network.sweep_enabled,
            out.devices.len(),
            out.devices.iter().filter(|d| d.vendor.is_some()).count()
        );
    }
}
