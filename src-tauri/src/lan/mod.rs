//! Local-network discovery: neighbor tables, receive-only mDNS, and an opt-in sweep. OWNER: WP-D.
//!
//! CONTRACT:
//! - Passive (always): read the IPv6 and IPv4 neighbor tables via `sysctl` first; where macOS
//!   hides a family's rows on the Wi-Fi interface from non-platform binaries, read the output of
//!   Apple's own `/usr/sbin/ndp -an` / `/usr/sbin/arp -an`, which an opt-in background item
//!   ([`helper`], launchd jobs, off by default) writes to files; the app spawns nothing. Listen on mDNS (never send). Devices come from the joined sources: neighbor rows
//!   (hardware address + IPv6/IPv4 address) and mDNS announcements (hostname + services per
//!   source address). Dropped: incomplete entries, permanent/own entries, multicast, other
//!   interfaces.
//! - Active sweep: only when `settings.lan_active_sweep` AND the joined access point is in
//!   Mine, or when `force_sweep` is set by the user's "Sweep now" (the same gate still applies).
//!   ONE ICMPv6 echo request to `ff02::1`, plus one zero-byte UDP datagram to port 9 of each
//!   IPv4 host (at most 50/s, subnets up to /23), then the neighbor tables are re-read. No TCP,
//!   no port scans, no mDNS queries.
//! - [`scan`] is blocking; callers run it on a blocking thread. [`record`] persists the
//!   outcome (devices by MAC hash, or a namespaced hostname hash when no MAC is known; never
//!   an IP).
//!
//! Layout: [`gate`] decides (pure), [`sweep`] is the only file that transmits, [`nd6`], [`arp`],
//! [`systools`], [`helper`] and [`mdns`] only read (nothing in the crate spawns a process), [`net`] reads the joined network. [`scan`] reaches `run_sweep` only
//! through [`gate::may_sweep`].

pub mod arp;
pub mod gate;
pub mod helper;
pub mod mdns;
pub mod nd6;
pub mod net;
pub mod sweep;
pub mod systools;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::model::{
    hash_identifier, LanDevice, LanMode, LanSource, Millis, MineEntry, NetworkInfo, Salt,
    ScanError, Settings,
};
use crate::store::{Store, StoreResult};
use crate::vendor;

use gate::{GateInput, SweepRefusal};
use net::Link;

/// How long to wait after the sweep before reading the neighbor table, so replies are learned.
const NEIGHBOR_SETTLE: Duration = Duration::from_secs(2);
/// Service types kept per device in one scan.
const MAX_SERVICES: usize = 24;

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
    /// Set after a scan that could not read any neighbor table (sysctl empty AND the Apple
    /// tools unavailable): why, for the Network page. `None` when neighbors were readable.
    pub neighbor_note: Option<String>,
    /// Last text read from the background item's files (see [`helper::Cache`]).
    pub helper_cache: helper::Cache,
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
        if_index: link.if_index,
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
        neighbor_note: state.neighbor_note.clone(),
    }
}

/// The key a device with no known hardware address is stored under: a salted hash of its mDNS
/// hostname, namespaced so it can never equal a MAC hash (a MAC hash is the hash of
/// six colon-separated hex pairs; this is the hash of `mdns-host:<name>`).
pub fn host_key(salt: &Salt, hostname: &str) -> String {
    hash_identifier(
        salt,
        &format!("mdns-host:{}", hostname.to_ascii_lowercase()),
    )
}

/// Raw observations from one pass, before they are joined into devices.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub neighbors: Vec<nd6::NeighborEntry>,
    pub arp: Vec<arp::ArpEntry>,
    pub heard: Vec<mdns::Heard>,
}

/// One physical device keyed by hardware address, while joining.
#[derive(Debug, Default)]
struct MacRow {
    v6: BTreeSet<Ipv6Addr>,
    v4: BTreeSet<Ipv4Addr>,
    hostname: Option<String>,
    services: BTreeSet<String>,
    announced: bool,
}

/// One announcing host with no hardware address, while joining.
#[derive(Debug, Default)]
struct HostRow {
    hostname: String,
    services: BTreeSet<String>,
    ip: Option<IpAddr>,
}

/// The neighbor rows for the Wi-Fi interface, and why the Apple tools were not enough if so.
#[derive(Debug, Default)]
pub struct Neighbors {
    pub v6: Vec<nd6::NeighborEntry>,
    pub v4: Vec<arp::ArpEntry>,
    /// Set only when NO neighbor row could be had for the interface and a tool failed.
    pub failure: Option<systools::ToolFailure>,
    /// Counts for the log: which tools ran, how many rows they gave for the Wi-Fi interface, and
    /// how many usable rows they printed for any interface.
    pub tools: ToolLog,
}

/// What the Apple tools did in one pass. Counts only.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ToolLog {
    pub ndp_ran: bool,
    pub arp_ran: bool,
    pub ndp_rows: usize,
    pub arp_rows: usize,
    pub ndp_wifi: usize,
    pub arp_wifi: usize,
    pub failed: usize,
    /// Non-empty output lines per tool (all interfaces), to tell "printed nothing" from "printed
    /// rows we skipped".
    pub ndp_lines: usize,
    pub arp_lines: usize,
}

/// Join the kernel-table reads (the first attempt) with Apple's `arp`/`ndp` (used per family
/// when sysctl gave no row on the Wi-Fi interface). Never fails; a tool problem is data.
pub fn gather_neighbors<R: systools::Runner + ?Sized>(
    link: &Link,
    sysctl_v6: Vec<nd6::NeighborEntry>,
    sysctl_v4: Vec<arp::ArpEntry>,
    runner: &R,
) -> Neighbors {
    let (Some(idx), Some(name)) = (link.if_index, link.if_name.as_deref()) else {
        return Neighbors {
            v6: sysctl_v6,
            v4: sysctl_v4,
            ..Neighbors::default()
        };
    };
    let mut out = Neighbors {
        v6: sysctl_v6,
        v4: sysctl_v4,
        ..Neighbors::default()
    };
    let mut first_failure = None;
    if !out.v6.iter().any(|e| e.if_index == idx) {
        let r = systools::read_tool(runner, systools::Tool::Ndp);
        let mine = systools::nd6_entries(&r.rows, name, idx);
        out.tools.ndp_ran = true;
        out.tools.ndp_rows = r.rows.len();
        out.tools.ndp_lines = r.lines;
        out.tools.ndp_wifi = mine.len();
        out.tools.failed += usize::from(r.failure.is_some());
        out.v6.extend(mine);
        first_failure = first_failure.or(r.failure);
    }
    if !out.v4.iter().any(|e| e.if_index == idx) {
        let r = systools::read_tool(runner, systools::Tool::Arp);
        let mine = systools::arp_entries(&r.rows, name, idx);
        out.tools.arp_ran = true;
        out.tools.arp_rows = r.rows.len();
        out.tools.arp_lines = r.lines;
        out.tools.arp_wifi = mine.len();
        out.tools.failed += usize::from(r.failure.is_some());
        out.v4.extend(mine);
        first_failure = first_failure.or(r.failure);
    }
    let any = out.v6.iter().any(|e| e.if_index == idx) || out.v4.iter().any(|e| e.if_index == idx);
    // No Wi-Fi row from any source: say why. A tool that failed is the reason; tools that ran
    // fine and still gave nothing mean macOS is hiding the entries from this app.
    let ran = out.tools.ndp_ran || out.tools.arp_ran;
    out.failure = if any {
        None
    } else {
        first_failure.or(ran.then_some(systools::ToolFailure::Hidden))
    };
    out
}

fn merge_services(into: &mut BTreeSet<String>, from: &BTreeSet<String>) {
    for s in from {
        if into.len() < MAX_SERVICES {
            into.insert(s.clone());
        }
    }
}

/// A global/ULA IPv6 address is a better thing to show than a link-local one.
fn display_v6(set: &BTreeSet<Ipv6Addr>) -> Option<Ipv6Addr> {
    set.iter()
        .find(|a| a.octets()[0] != 0xfe || a.octets()[1] & 0xc0 != 0x80)
        .or_else(|| set.iter().next())
        .copied()
}

/// Join the three sources into devices. Pure: no I/O, so every case is unit-testable.
///
/// - Neighbor and ARP rows on the Wi-Fi interface become devices keyed by hashed MAC (one per
///   hardware address, however many addresses it has).
/// - An announcement joins a device when its source address, or any address its hostname owns,
///   matches a neighbor/ARP row; the device then reads `Both`.
/// - An announcement with a hostname that matches nothing is still a device, keyed by
///   [`host_key`], vendor `None`, source `Announced`. Several announcements of one hostname are
///   one device, and a hostname already joined to a MAC never also becomes a second row.
pub fn build_devices(
    obs: &Observed,
    link: &Link,
    key: &str,
    salt: &Salt,
    now: Millis,
) -> Vec<LanDevice> {
    let Some(if_index) = link.if_index else {
        return Vec::new();
    };
    let own_v4 = link.subnet.map(|s| s.addr);
    let mut rows: BTreeMap<[u8; 6], MacRow> = BTreeMap::new();
    let mut by_ip: HashMap<IpAddr, [u8; 6]> = HashMap::new();

    for e in &obs.neighbors {
        if e.if_index != if_index || link.own_v6.contains(&e.ip) {
            continue;
        }
        rows.entry(e.mac).or_default().v6.insert(e.ip);
        by_ip.insert(IpAddr::V6(e.ip), e.mac);
    }
    if let Some(subnet) = link.subnet {
        for e in &obs.arp {
            if e.if_index != if_index || !subnet.contains(e.ip) || e.ip == subnet.addr {
                continue;
            }
            rows.entry(e.mac).or_default().v4.insert(e.ip);
            by_ip.insert(IpAddr::V4(e.ip), e.mac);
        }
    }

    // Is this announcement from a host on this Wi-Fi network (and not us)?
    let on_link = |h: &mdns::Heard| match h.from {
        IpAddr::V4(a) => link.subnet.is_some_and(|s| s.contains(a)) && Some(a) != own_v4,
        IpAddr::V6(a) => {
            !link.own_v6.contains(&a)
                && (h.scope == u32::from(if_index) || by_ip.contains_key(&h.from))
        }
    };
    let mut heard: Vec<&mdns::Heard> = obs.heard.iter().filter(|h| on_link(h)).collect();
    heard.sort_by_key(|h| h.from);

    let mut host_to_mac: HashMap<String, [u8; 6]> = HashMap::new();
    let mut unmatched: Vec<&mdns::Heard> = Vec::new();
    for h in heard {
        let mac = by_ip.get(&h.from).copied().or_else(|| {
            h.info
                .addrs
                .iter()
                .filter(|a| match a {
                    IpAddr::V6(v6) => !link.own_v6.contains(v6),
                    IpAddr::V4(v4) => Some(*v4) != own_v4,
                })
                .find_map(|a| by_ip.get(a).copied())
        });
        match mac {
            Some(mac) => {
                let row = rows.entry(mac).or_default();
                row.announced = true;
                if row.hostname.is_none() {
                    row.hostname = h.info.hostname.clone();
                }
                merge_services(&mut row.services, &h.info.services);
                if let Some(host) = &h.info.hostname {
                    host_to_mac.entry(host.to_ascii_lowercase()).or_insert(mac);
                }
            }
            None => unmatched.push(h),
        }
    }

    let mut hosts: BTreeMap<String, HostRow> = BTreeMap::new();
    for h in unmatched {
        let Some(host) = &h.info.hostname else {
            continue; // services alone, from an address with no hardware address: nothing to key on
        };
        let lower = host.to_ascii_lowercase();
        if let Some(mac) = host_to_mac.get(&lower) {
            // The same host, heard from an address we could not place: fold into its device.
            if let Some(row) = rows.get_mut(mac) {
                merge_services(&mut row.services, &h.info.services);
            }
            continue;
        }
        let row = hosts.entry(lower).or_insert_with(|| HostRow {
            hostname: host.clone(),
            ..HostRow::default()
        });
        merge_services(&mut row.services, &h.info.services);
        // Prefer showing an IPv4 address; otherwise the first heard.
        if row.ip.is_none() || (row.ip.is_some_and(|i| i.is_ipv6()) && h.from.is_ipv4()) {
            row.ip = Some(h.from);
        }
    }

    let mut out = Vec::with_capacity(rows.len() + hosts.len());
    for (mac, row) in rows {
        let text = arp::format_mac(&mac);
        let ip = row
            .v4
            .iter()
            .next()
            .map(|a| a.to_string())
            .or_else(|| display_v6(&row.v6).map(|a| a.to_string()));
        out.push(LanDevice {
            network_key: key.to_string(),
            mac_hash: hash_identifier(salt, &text),
            vendor: vendor::vendor_for(&text),
            hostname: row.hostname,
            services: row.services.into_iter().collect(),
            first_seen: now,
            last_seen: now,
            ip,
            mine: false,
            source: Some(if row.announced {
                LanSource::Both
            } else {
                LanSource::Neighbor
            }),
            possibly_same_as: None,
        });
    }
    for (lower, row) in hosts {
        out.push(LanDevice {
            network_key: key.to_string(),
            mac_hash: host_key(salt, &lower),
            vendor: None,
            hostname: Some(row.hostname),
            services: row.services.into_iter().collect(),
            first_seen: now,
            last_seen: now,
            ip: row.ip.map(|i| i.to_string()),
            mine: false,
            source: Some(LanSource::Announced),
            possibly_same_as: None,
        });
    }
    out
}

/// Counts for the log line. Never a name, address or hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceCounts {
    pub total: usize,
    pub with_mac: usize,
    pub with_vendor: usize,
    pub with_name: usize,
    pub neighbor: usize,
    pub announced: usize,
    pub both: usize,
}

pub fn count_devices(devices: &[LanDevice]) -> DeviceCounts {
    let src = |s| devices.iter().filter(|d| d.source == Some(s)).count();
    DeviceCounts {
        total: devices.len(),
        // Hardware address known = anything not announced-only.
        with_mac: devices
            .iter()
            .filter(|d| d.source != Some(LanSource::Announced))
            .count(),
        with_vendor: devices.iter().filter(|d| d.vendor.is_some()).count(),
        with_name: devices.iter().filter(|d| d.hostname.is_some()).count(),
        neighbor: src(LanSource::Neighbor),
        announced: src(LanSource::Announced),
        both: src(LanSource::Both),
    }
}

/// Observe the joined network: always the neighbor tables and the mDNS cache; additionally one
/// sweep when [`gate::may_sweep`] allows it. A failed table read yields no rows from that
/// source, not an error: the LAN is an extra and must not cost a Wi-Fi/BLE cycle.
pub fn scan(inputs: &LanInputs, state: &mut LanState) -> Result<LanScanOutcome, ScanError> {
    let now = now_ms();
    let mdns = mdns::ensure_listener();
    let link = net::read_link(&inputs.salt);
    let key = key_of(&link);

    // The only route to a transmit: the gate (setting ON + AP Mine + known interface) and cadence.
    let decision = gate::may_sweep(
        &gate_for(&link, inputs, key.as_deref()),
        inputs.force_sweep,
        state.last_sweep_for(key.as_deref()),
        now,
    );
    let mut swept = SweepLog::default();
    if let Ok(token) = decision {
        if let Ok(mut sink) = sweep::NetSink::new(token) {
            let stats = sweep::run_sweep(&mut sink, token.if_index(), link.subnet.as_ref());
            swept = SweepLog {
                ran: true,
                sent_v6: stats.sent_v6,
                sent_v4: stats.sent_v4,
                failed: stats.failed,
                v4_skipped: stats.v4_skip.is_some(),
            };
            state.last_sweep_at = Some(now);
            state.last_sweep_network = key.clone();
            std::thread::sleep(NEIGHBOR_SETTLE);
        }
    }

    let network = build_info(&link, inputs, state);
    let mut obs = Observed::default();
    let mut devices = Vec::new();
    let mut tools = ToolLog::default();
    if let Some(k) = key.as_deref() {
        let runner = helper::FileRunner::new(
            helper::data_dir(),
            inputs.settings.lan_neighbor_helper,
            std::time::SystemTime::now(),
            std::mem::take(&mut state.helper_cache),
        );
        let nb = gather_neighbors(
            &link,
            nd6::read_neighbor_table().unwrap_or_default(),
            arp::read_arp_table().unwrap_or_default(),
            &runner,
        );
        state.helper_cache = runner.into_cache();
        state.neighbor_note = nb.failure.map(systools::ToolFailure::reason);
        tools = nb.tools;
        obs.neighbors = nb.v6;
        obs.arp = nb.v4;
        obs.heard = mdns.snapshot();
        devices = build_devices(&obs, &link, k, &inputs.salt, now_ms());
    }
    let on_if = |i: u16| Some(i) == link.if_index;
    let c = count_devices(&devices);
    let mc = mdns::listener_counts();
    // Counts only: never a name, address or hash.
    log::info!(
        "lan: network identified={}, nd6 rows={} (wifi {}), arp rows={}, mdns sources={}, devices={} (neighbor {}, announced {}, both {}; with mac {}, vendor {}, name {}), sweep ran={} sent v6={} v4={} failed={} v4 skipped={}, helper setting={} status={:?}, ndp read={} lines={} rows={} wifi={}, arp read={} lines={} rows={} wifi={}, failed={}, mdns bound v4={} v6={}, bind failures={}, datagrams={}",
        key.is_some(),
        obs.neighbors.len(),
        obs.neighbors.iter().filter(|e| on_if(e.if_index)).count(),
        obs.arp.len(),
        mdns.announced_sources(),
        c.total,
        c.neighbor,
        c.announced,
        c.both,
        c.with_mac,
        c.with_vendor,
        c.with_name,
        swept.ran,
        swept.sent_v6,
        swept.sent_v4,
        swept.failed,
        swept.v4_skipped,
        inputs.settings.lan_neighbor_helper,
        helper::status(),
        tools.ndp_ran,
        tools.ndp_lines,
        tools.ndp_rows,
        tools.ndp_wifi,
        tools.arp_ran,
        tools.arp_lines,
        tools.arp_rows,
        tools.arp_wifi,
        tools.failed,
        mc.bound_v4,
        mc.bound_v6,
        mc.bind_failures,
        mc.datagrams
    );
    Ok(LanScanOutcome { network, devices })
}

#[derive(Debug, Clone, Copy, Default)]
struct SweepLog {
    ran: bool,
    sent_v6: usize,
    sent_v4: usize,
    failed: usize,
    v4_skipped: bool,
}

/// The currently joined network without touching the LAN: no sweep, no table reads.
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

/// Persist an outcome's devices (hashed MACs or namespaced hostname hashes; the live IP is
/// dropped by the store).
///
/// A device first stored by hostname alone that now has a hardware address is ONE device
/// again: its hostname-keyed row is folded into the MAC-keyed row, keeping the earlier
/// `first_seen` so the upgrade is not "news" to the NewLanDevice rule.
///
/// Exception: when the hostname-keyed row is Mine the fold does NOT happen. Anyone on the
/// network can announce a Mine device's hostname with an A record carrying their own IP, which
/// the scan joins to their own MAC. That MAC row starts fresh (not Mine, its own `first_seen`,
/// so it is news) and the user's Mine row stays; the listing shows it as "possibly the same
/// device as <label>" for the user to confirm by hand.
pub fn record(store: &mut Store, outcome: &LanScanOutcome, _now: Millis) -> StoreResult<()> {
    for d in &outcome.devices {
        let mut d = d.clone();
        if d.source == Some(LanSource::Both) {
            if let Some(host) = &d.hostname {
                let old_key = host_key(store.salt(), host);
                if old_key != d.mac_hash {
                    let old_is_mine = store
                        .list_lan_devices(Some(&d.network_key))?
                        .iter()
                        .any(|o| o.mac_hash == old_key && o.mine);
                    if !old_is_mine {
                        if let Some(old) = store.take_lan_device(&d.network_key, &old_key)? {
                            d.first_seen = d.first_seen.min(old.first_seen);
                        }
                    }
                }
            }
        }
        store.upsert_lan_device(&d)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MineKind;
    use gate::Subnet;
    use mdns::{Announcement, Heard};

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

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn link() -> Link {
        Link {
            ssid: Some("Net-A".into()),
            bssid_hash: Some("ap-1".into()),
            group_id: None,
            if_index: Some(11),
            if_name: Some("en0".into()),
            subnet: Some(Subnet {
                addr: Ipv4Addr::new(192, 0, 2, 7),
                prefix: 24,
            }),
            own_v6: vec![v6("fe80::7"), v6("2001:db8::7")],
        }
    }

    fn mac(last: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, last]
    }

    fn mac_hash(last: u8) -> String {
        hash_identifier(&salt(), &arp::format_mac(&mac(last)))
    }

    fn nb(ip: &str, last: u8, if_index: u16) -> nd6::NeighborEntry {
        nd6::NeighborEntry {
            ip: v6(ip),
            mac: mac(last),
            if_index,
        }
    }

    fn arp_entry(last: u8, if_index: u16, mac_last: u8) -> arp::ArpEntry {
        arp::ArpEntry {
            ip: Ipv4Addr::new(192, 0, 2, last),
            mac: mac(mac_last),
            if_index,
        }
    }

    fn heard(from: IpAddr, scope: u32, host: Option<&str>, svcs: &[&str], addrs: &[&str]) -> Heard {
        Heard {
            from,
            scope,
            info: Announcement {
                hostname: host.map(str::to_string),
                services: svcs.iter().map(|s| s.to_string()).collect(),
                addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            },
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn build(obs: &Observed) -> Vec<LanDevice> {
        build_devices(obs, &link(), "key", &salt(), 777)
    }

    fn by_hash<'a>(devs: &'a [LanDevice], h: &str) -> &'a LanDevice {
        devs.iter().find(|d| d.mac_hash == h).expect("device")
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
        // An IPv6-only network (no IPv4 subnet) can still be swept.
        let mut l = link();
        l.subnet = None;
        let n = build_info(&l, &inputs(true, vec![mine_ap("ap-1")]), &st);
        assert!(n.sweep_enabled && n.subnet.is_none());
        // NEGATIVE: no Wi-Fi interface.
        l.if_index = None;
        let n = build_info(&l, &inputs(true, vec![mine_ap("ap-1")]), &st);
        assert!(!n.sweep_enabled);
    }

    #[test]
    fn mode_and_last_sweep_follow_the_network() {
        let mut st = LanState {
            last_sweep_at: Some(5_000),
            last_sweep_network: Some("ap-1".into()),
            neighbor_note: None,
            helper_cache: Default::default(),
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
    fn neighbor_only_device_has_mac_vendor_source_and_one_row_per_mac() {
        let obs = Observed {
            neighbors: vec![
                nb("fe80::10", 1, 11),
                nb("2001:db8::10", 1, 11), // same MAC, second address: still one device
                nb("fe80::20", 2, 11),
                nb("fe80::30", 3, 99),    // other interface
                nb("fe80::7", 4, 11),     // our own address
                nb("2001:db8::7", 5, 11), // our own address
            ],
            ..Observed::default()
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 2);
        let d1 = by_hash(&devs, &mac_hash(1));
        assert_eq!(d1.source, Some(LanSource::Neighbor));
        assert_eq!(d1.network_key, "key");
        assert_eq!((d1.first_seen, d1.last_seen), (777, 777));
        assert_eq!(
            d1.ip.as_deref(),
            Some("2001:db8::10"),
            "global shown over link-local"
        );
        assert_eq!(d1.hostname, None);
        assert_eq!(by_hash(&devs, &mac_hash(2)).ip.as_deref(), Some("fe80::20"));
        // No raw MAC or address-derived text in what is serialised for storage keys.
        assert!(!devs.iter().any(|d| d.mac_hash.contains("02:00")));
        // NEGATIVE: with no interface known, nothing is listed.
        let mut l = link();
        l.if_index = None;
        assert!(build_devices(&obs, &l, "key", &salt(), 1).is_empty());
    }

    #[test]
    fn mdns_only_host_is_a_device_keyed_by_a_namespaced_hostname_hash() {
        let obs = Observed {
            heard: vec![heard(
                ip("192.0.2.40"),
                0,
                Some("device-a.local"),
                &["_http._tcp"],
                &[],
            )],
            ..Observed::default()
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.source, Some(LanSource::Announced));
        assert_eq!(d.vendor, None);
        assert_eq!(d.hostname.as_deref(), Some("device-a.local"));
        assert_eq!(d.services, vec!["_http._tcp".to_string()]);
        assert_eq!(d.mac_hash, host_key(&salt(), "device-a.local"));
        assert_eq!(d.ip.as_deref(), Some("192.0.2.40"));
        // Case-insensitive host key; and it cannot collide with a MAC hash.
        assert_eq!(host_key(&salt(), "DEVICE-A.local"), d.mac_hash);
        assert_ne!(
            host_key(&salt(), "device-a.local"),
            host_key(&salt(), "device-b.local")
        );
        for last in 0..=255u8 {
            assert_ne!(mac_hash(last), d.mac_hash);
        }
        // A different salt gives a different key (not a bare hash of the hostname).
        assert_ne!(
            host_key(&Salt::from_bytes(vec![2; 32]), "device-a.local"),
            d.mac_hash
        );
    }

    #[test]
    fn announcement_joins_a_neighbor_by_aaaa_address() {
        let obs = Observed {
            neighbors: vec![nb("2001:db8::10", 1, 11)],
            // Heard over IPv4; its AAAA record names the neighbor's IPv6 address.
            heard: vec![heard(
                ip("192.0.2.40"),
                0,
                Some("device-a.local"),
                &["_airplay._tcp"],
                &["2001:db8::10"],
            )],
            ..Observed::default()
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 1, "one physical device, one row");
        let d = &devs[0];
        assert_eq!(d.mac_hash, mac_hash(1));
        assert_eq!(d.source, Some(LanSource::Both));
        assert_eq!(d.hostname.as_deref(), Some("device-a.local"));
        assert_eq!(d.services, vec!["_airplay._tcp".to_string()]);
    }

    #[test]
    fn announcement_joins_by_its_own_source_ipv6_and_by_arp_ipv4() {
        let obs = Observed {
            neighbors: vec![nb("fe80::10", 1, 11)],
            arp: vec![arp_entry(50, 11, 2)],
            heard: vec![
                // Source IPv6 matches the neighbor entry (scope 11 = the Wi-Fi interface).
                heard(
                    ip("fe80::10"),
                    11,
                    Some("device-a.local"),
                    &[],
                    &["fe80::10"],
                ),
                // Source IPv4 matches an ARP row.
                heard(ip("192.0.2.50"), 0, Some("device-b.local"), &[], &[]),
            ],
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 2);
        assert_eq!(
            by_hash(&devs, &mac_hash(1)).hostname.as_deref(),
            Some("device-a.local")
        );
        assert_eq!(
            by_hash(&devs, &mac_hash(2)).hostname.as_deref(),
            Some("device-b.local")
        );
        assert!(devs.iter().all(|d| d.source == Some(LanSource::Both)));
        // IPv4 from ARP is preferred for display.
        assert_eq!(
            by_hash(&devs, &mac_hash(2)).ip.as_deref(),
            Some("192.0.2.50")
        );
    }

    #[test]
    fn duplicates_collapse_to_one_device() {
        let obs = Observed {
            neighbors: vec![nb("2001:db8::10", 1, 11)],
            heard: vec![
                // Same host over IPv4 (names its AAAA) and over IPv6, plus a third packet
                // from an address we cannot place that repeats the hostname.
                heard(
                    ip("192.0.2.40"),
                    0,
                    Some("device-a.local"),
                    &["_http._tcp"],
                    &["2001:db8::10"],
                ),
                heard(
                    ip("2001:db8::10"),
                    11,
                    Some("Device-A.local"),
                    &["_ipp._tcp"],
                    &[],
                ),
                heard(
                    ip("192.0.2.41"),
                    0,
                    Some("device-a.local"),
                    &["_ssh._tcp"],
                    &[],
                ),
                // Two unplaced announcements of another host: one row.
                heard(
                    ip("192.0.2.60"),
                    0,
                    Some("device-c.local"),
                    &["_http._tcp"],
                    &[],
                ),
                heard(
                    ip("192.0.2.61"),
                    0,
                    Some("DEVICE-C.local"),
                    &["_ipp._tcp"],
                    &[],
                ),
            ],
            ..Observed::default()
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 2, "device-a joined to its MAC, device-c alone");
        let a = by_hash(&devs, &mac_hash(1));
        assert_eq!(a.source, Some(LanSource::Both));
        assert_eq!(
            a.services.len(),
            3,
            "services merged from all three packets"
        );
        let c = by_hash(&devs, &host_key(&salt(), "device-c.local"));
        assert_eq!(c.source, Some(LanSource::Announced));
        assert_eq!(c.services.len(), 2);
    }

    #[test]
    fn announcements_from_elsewhere_or_from_us_are_ignored() {
        let obs = Observed {
            heard: vec![
                heard(ip("198.51.100.9"), 0, Some("far.local"), &[], &[]), // outside the subnet
                heard(ip("192.0.2.7"), 0, Some("me.local"), &[], &[]),     // our IPv4
                heard(ip("fe80::7"), 11, Some("me.local"), &[], &[]),      // our IPv6
                heard(ip("fe80::99"), 4, Some("other-if.local"), &[], &[]), // another interface
                heard(ip("fe80::98"), 0, Some("no-scope.local"), &[], &[]), // unknown scope, unknown neighbor
                heard(ip("192.0.2.70"), 0, None, &["_http._tcp"], &[]), // services only, no MAC, no name
            ],
            ..Observed::default()
        };
        assert!(build(&obs).is_empty());
        // CONTROL: the same shapes on the right link are accepted.
        let obs = Observed {
            heard: vec![
                heard(ip("fe80::99"), 11, Some("on-link.local"), &[], &[]),
                heard(ip("192.0.2.71"), 0, Some("in-subnet.local"), &[], &[]),
            ],
            ..Observed::default()
        };
        assert_eq!(build(&obs).len(), 2);
        // An IPv4 announcement with no known subnet cannot be placed on this link.
        let mut l = link();
        l.subnet = None;
        let obs = Observed {
            heard: vec![heard(
                ip("192.0.2.71"),
                0,
                Some("in-subnet.local"),
                &[],
                &[],
            )],
            ..Observed::default()
        };
        assert!(build_devices(&obs, &l, "key", &salt(), 1).is_empty());
    }

    #[test]
    fn a_claimed_address_nobody_owns_does_not_steal_a_mac() {
        // The announcement claims an AAAA that matches no neighbor: it stays its own device.
        let obs = Observed {
            neighbors: vec![nb("fe80::10", 1, 11)],
            heard: vec![heard(
                ip("192.0.2.80"),
                0,
                Some("claimed.local"),
                &[],
                &["2001:db8::dead"],
            )],
            ..Observed::default()
        };
        let devs = build(&obs);
        assert_eq!(devs.len(), 2);
        assert_eq!(
            by_hash(&devs, &mac_hash(1)).source,
            Some(LanSource::Neighbor)
        );
        assert_eq!(
            by_hash(&devs, &host_key(&salt(), "claimed.local")).source,
            Some(LanSource::Announced)
        );
    }

    #[test]
    fn counts_by_source() {
        let obs = Observed {
            neighbors: vec![nb("2001:db8::10", 1, 11), nb("2001:db8::20", 2, 11)],
            heard: vec![
                heard(ip("2001:db8::10"), 11, Some("a.local"), &[], &[]),
                heard(ip("192.0.2.90"), 0, Some("b.local"), &[], &[]),
            ],
            ..Observed::default()
        };
        let c = count_devices(&build(&obs));
        assert_eq!(
            c,
            DeviceCounts {
                total: 3,
                with_mac: 2,
                with_vendor: 2,
                with_name: 2,
                neighbor: 1,
                announced: 1,
                both: 1
            }
        );
    }

    fn lan_dev(hash: &str, host: Option<&str>, source: LanSource, at: Millis) -> LanDevice {
        LanDevice {
            network_key: "key".into(),
            mac_hash: hash.into(),
            vendor: Some("Vendor-A".into()),
            hostname: host.map(str::to_string),
            services: vec![],
            first_seen: at,
            last_seen: at,
            ip: Some("192.0.2.10".into()),
            mine: false,
            source: Some(source),
            possibly_same_as: None,
        }
    }

    fn out(d: LanDevice) -> LanScanOutcome {
        LanScanOutcome {
            network: NetworkInfo::default(),
            devices: vec![d],
        }
    }

    #[test]
    fn record_persists_hashed_devices_without_ip_and_keeps_first_seen() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        record(
            &mut store,
            &out(lan_dev("h1", None, LanSource::Neighbor, 100)),
            100,
        )
        .unwrap();
        record(
            &mut store,
            &out(lan_dev("h1", None, LanSource::Neighbor, 200)),
            200,
        )
        .unwrap();
        let got = store.list_lan_devices(Some("key")).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].first_seen, got[0].last_seen), (100, 200));
        assert_eq!(got[0].ip, None, "IPs are never persisted");
        assert_eq!(got[0].source, Some(LanSource::Neighbor));
        // An empty outcome stores nothing.
        record(&mut store, &LanScanOutcome::default(), 300).unwrap();
        assert_eq!(store.list_lan_devices(None).unwrap().len(), 1);
    }

    #[test]
    fn a_hostname_only_device_that_gains_a_mac_is_folded_into_one_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let hk = host_key(store.salt(), "device-a.local");
        // Day 1: heard announcing, no hardware address.
        record(
            &mut store,
            &out(lan_dev(
                &hk,
                Some("device-a.local"),
                LanSource::Announced,
                100,
            )),
            100,
        )
        .unwrap();
        // Day 2: the same host is now in the neighbor table.
        record(
            &mut store,
            &out(lan_dev(
                "mac-hash",
                Some("device-a.local"),
                LanSource::Both,
                900,
            )),
            900,
        )
        .unwrap();
        let got = store.list_lan_devices(Some("key")).unwrap();
        assert_eq!(got.len(), 1, "the hostname-keyed row is gone");
        assert_eq!(got[0].mac_hash, "mac-hash");
        assert_eq!(got[0].first_seen, 100, "first_seen survives the upgrade");
        assert_eq!(got[0].source, Some(LanSource::Both));
        // NEGATIVE CONTROL: an unrelated hostname-keyed row is left alone.
        let other = host_key(store.salt(), "device-z.local");
        record(
            &mut store,
            &out(lan_dev(
                &other,
                Some("device-z.local"),
                LanSource::Announced,
                50,
            )),
            50,
        )
        .unwrap();
        record(
            &mut store,
            &out(lan_dev(
                "mac-2",
                Some("device-b.local"),
                LanSource::Both,
                60,
            )),
            60,
        )
        .unwrap();
        assert_eq!(store.list_lan_devices(Some("key")).unwrap().len(), 3);
    }

    #[test]
    fn marking_a_hostname_row_mine_does_not_carry_over_to_a_mac_row() {
        // M1: anyone can announce a Mine hostname, so Mine never follows a hostname -> MAC fold.
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let hk = host_key(store.salt(), "device-a.local");
        record(
            &mut store,
            &out(lan_dev(
                &hk,
                Some("device-a.local"),
                LanSource::Announced,
                100,
            )),
            100,
        )
        .unwrap();
        store
            .add_mine(&MineEntry {
                kind: MineKind::Lan,
                id_hash: hk.clone(),
                label: Some("My Laptop".into()),
                added_at: 110,
            })
            .unwrap();
        record(
            &mut store,
            &out(lan_dev(
                "mac-hash",
                Some("device-a.local"),
                LanSource::Both,
                900,
            )),
            900,
        )
        .unwrap();
        let got = store.list_lan_devices(Some("key")).unwrap();
        assert_eq!(
            got.len(),
            2,
            "the Mine hostname row stays, the MAC row is new"
        );
        let mac = got.iter().find(|d| d.mac_hash == "mac-hash").unwrap();
        assert!(!mac.mine, "not Mine under its new key");
        assert_eq!(mac.first_seen, 900, "no inherited first_seen");
        assert_eq!(mac.possibly_same_as.as_deref(), Some("My Laptop"));
        assert!(got.iter().find(|d| d.mac_hash == hk).unwrap().mine);
    }

    /// Reads the live network passively (no sweep: the setting is off). Counts only.
    /// `cargo test -- --ignored lan_live --nocapture`.
    #[test]
    #[ignore]
    fn lan_live() {
        let out = scan(&inputs(false, vec![]), &mut LanState::default()).unwrap();
        let c = count_devices(&out.devices);
        println!(
            "lan_live: network={} mine={} sweep_enabled={} devices={} with_mac={} with_vendor={} with_name={} neighbor={} announced={} both={}",
            out.network.network_key.is_some(),
            out.network.is_mine,
            out.network.sweep_enabled,
            c.total,
            c.with_mac,
            c.with_vendor,
            c.with_name,
            c.neighbor,
            c.announced,
            c.both
        );
    }

    // ---- neighbor sources: sysctl first, Apple's tools when sysctl is empty ----

    struct Canned {
        arp: Result<String, systools::ToolFailure>,
        ndp: Result<String, systools::ToolFailure>,
        calls: std::cell::RefCell<Vec<systools::Tool>>,
    }

    impl systools::Runner for Canned {
        fn run(&self, tool: systools::Tool) -> Result<String, systools::ToolFailure> {
            self.calls.borrow_mut().push(tool);
            match tool {
                systools::Tool::Arp => self.arp.clone(),
                systools::Tool::Ndp => self.ndp.clone(),
            }
        }
    }

    fn canned(arp: &str, ndp: &str) -> Canned {
        Canned {
            arp: Ok(arp.into()),
            ndp: Ok(ndp.into()),
            calls: Default::default(),
        }
    }

    const TOOL_ARP: &str = "\
? (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope [ethernet]
? (192.0.2.20) at 2:0:0:0:0:14 on en0 ifscope [ethernet]
? (192.0.2.21) at (incomplete) on en0 ifscope [ethernet]
? (192.0.2.7) at 2:0:0:0:0:7 on en0 ifscope permanent [ethernet]
? (198.51.100.4) at 2:0:0:0:0:4 on en5 ifscope [ethernet]
";
    const TOOL_NDP: &str = "\
Neighbor Linklayer Address Netif Expire St Flgs Prbs
fe80::1%en0 2:0:0:0:0:1 en0 23h59m55s S R
2001:db8::14 2:0:0:0:0:14 en0 10h47m46s S
2001:db8::7 2:0:0:0:0:7 en0 permanent R
fe80::7%en0 2:0:0:0:0:7 en0 permanent R
";

    #[test]
    fn tool_rows_join_with_mdns_by_address_and_read_both() {
        let r = canned(TOOL_ARP, TOOL_NDP);
        let got = gather_neighbors(&link(), vec![], vec![], &r);
        assert_eq!(got.failure, None);
        assert_eq!(
            got.v4.len(),
            2,
            "incomplete, permanent and other-interface rows dropped"
        );
        assert_eq!(
            got.v6.len(),
            2,
            "permanent rows (our own addresses) are dropped"
        );
        let obs = Observed {
            neighbors: got.v6,
            arp: got.v4,
            heard: vec![
                heard(
                    ip("192.0.2.20"),
                    0,
                    Some("printer.local"),
                    &["_ipp._tcp"],
                    &[],
                ),
                heard(ip("192.0.2.99"), 0, Some("ghost.local"), &["_x._tcp"], &[]),
            ],
        };
        let devs = build(&obs);
        // MACs .1 and .14 from tools, plus the unmatched announcer.
        assert_eq!(devs.len(), 3);
        let printer = by_hash(&devs, &mac_hash(0x14));
        assert_eq!(printer.source, Some(LanSource::Both));
        assert_eq!(printer.hostname.as_deref(), Some("printer.local"));
        assert_eq!(printer.ip.as_deref(), Some("192.0.2.20"));
        let gw = by_hash(&devs, &mac_hash(1));
        assert_eq!(gw.source, Some(LanSource::Neighbor));
        assert_eq!(
            devs.iter()
                .filter(|d| d.source == Some(LanSource::Announced))
                .count(),
            1
        );
        assert_eq!(
            devs.iter()
                .filter(|d| d.source == Some(LanSource::Neighbor))
                .count(),
            1
        );
    }

    #[test]
    fn our_own_tool_rows_are_not_devices() {
        // 2001:db8::7 is in link().own_v6; its tool row (non-permanent here) must not list.
        let ndp = "2001:db8::7 2:0:0:0:0:7 en0 1h S\nfe80::50%en0 2:0:0:0:0:50 en0 1h S\n";
        let r = canned("", ndp);
        let got = gather_neighbors(&link(), vec![], vec![], &r);
        let devs = build(&Observed {
            neighbors: got.v6,
            arp: got.v4,
            heard: vec![],
        });
        assert_eq!(devs.len(), 2 - 1);
        assert_eq!(devs[0].mac_hash, mac_hash(0x50));
    }

    #[test]
    fn sysctl_rows_win_and_the_tools_are_not_run_for_that_family() {
        let r = canned(TOOL_ARP, TOOL_NDP);
        let got = gather_neighbors(
            &link(),
            vec![nb("fe80::10", 0x10, 11)],
            vec![arp_entry(30, 11, 0x30)],
            &r,
        );
        assert!(
            r.calls.borrow().is_empty(),
            "sysctl had Wi-Fi rows for both families"
        );
        assert_eq!((got.v6.len(), got.v4.len()), (1, 1));
        // NEGATIVE: sysctl rows on ANOTHER interface do not count, so the tool runs.
        let r = canned(TOOL_ARP, TOOL_NDP);
        let got = gather_neighbors(&link(), vec![nb("fe80::10", 0x10, 99)], vec![], &r);
        assert_eq!(r.calls.borrow().len(), 2);
        assert_eq!(got.v4.len(), 2);
        // Only the empty family triggers its tool.
        let r = canned(TOOL_ARP, TOOL_NDP);
        gather_neighbors(&link(), vec![nb("fe80::10", 0x10, 11)], vec![], &r);
        assert_eq!(*r.calls.borrow(), vec![systools::Tool::Arp]);
    }

    #[test]
    fn tool_failure_becomes_a_note_only_when_nothing_else_was_readable() {
        use systools::{Tool, ToolFailure};
        let both_missing = Canned {
            arp: Err(ToolFailure::NoOutput(Tool::Arp)),
            ndp: Err(ToolFailure::NoOutput(Tool::Ndp)),
            calls: Default::default(),
        };
        let got = gather_neighbors(&link(), vec![], vec![], &both_missing);
        assert!(got.v4.is_empty() && got.v6.is_empty());
        assert_eq!(got.failure, Some(ToolFailure::NoOutput(Tool::Ndp)));
        // Announced devices still build with no neighbor rows.
        let devs = build(&Observed {
            heard: vec![heard(ip("192.0.2.99"), 0, Some("ghost.local"), &[], &[])],
            ..Observed::default()
        });
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].source, Some(LanSource::Announced));
        // Timeout and garbage are failures too.
        for f in [
            Err(ToolFailure::Stale(Tool::Arp)),
            Err(ToolFailure::HelperOff(Tool::Arp)),
            Ok("Segmentation fault\n".to_string()),
        ] {
            let r = Canned {
                arp: f,
                ndp: Ok(String::new()),
                calls: Default::default(),
            };
            let got = gather_neighbors(&link(), vec![], vec![], &r);
            assert!(got.failure.is_some());
        }
        // NEGATIVE CONTROL: one tool failing while the other yields rows is not "announced only".
        let half = Canned {
            arp: Err(ToolFailure::HelperOff(Tool::Arp)),
            ndp: Ok(TOOL_NDP.into()),
            calls: Default::default(),
        };
        let got = gather_neighbors(&link(), vec![], vec![], &half);
        assert_eq!(got.failure, None);
        assert_eq!(got.v6.len(), 2);
        // Working tools that print nothing for the Wi-Fi interface mean macOS hides the entries.
        let quiet = canned("", "Neighbor Linklayer Address Netif Expire St Flgs Prbs\n");
        let got = gather_neighbors(&link(), vec![], vec![], &quiet);
        assert_eq!(got.failure, Some(ToolFailure::Hidden));
        assert!(got.tools.ndp_ran && got.tools.arp_ran && got.tools.failed == 0);
        assert!(got
            .failure
            .unwrap()
            .reason()
            .contains("no neighbor entries"));
        // NEGATIVE CONTROL: tools that did not need to run (sysctl had rows) give no note.
        let r = canned("", "");
        let got = gather_neighbors(
            &link(),
            vec![nb("fe80::10", 0x10, 11)],
            vec![arp_entry(30, 11, 0x30)],
            &r,
        );
        assert_eq!(got.failure, None);
    }

    #[test]
    fn no_interface_name_means_no_tool_run() {
        let mut l = link();
        l.if_name = None;
        let r = canned(TOOL_ARP, TOOL_NDP);
        let got = gather_neighbors(&l, vec![], vec![], &r);
        assert!(r.calls.borrow().is_empty());
        assert!(got.v4.is_empty() && got.failure.is_none());
    }

    #[test]
    fn the_note_reaches_network_info() {
        let st = LanState {
            neighbor_note: Some("no arp output".into()),
            ..LanState::default()
        };
        let n = build_info(&link(), &inputs(false, vec![]), &st);
        assert_eq!(n.neighbor_note.as_deref(), Some("no arp output"));
        assert_eq!(
            build_info(&link(), &inputs(false, vec![]), &LanState::default()).neighbor_note,
            None
        );
    }
}
