//! The sweep gate: pure functions that decide whether the opt-in sweep may run, and the
//! rate-limit arithmetic. No I/O here, so every refusal path is unit-testable.
//!
//! The gate is the one thing standing between a listen-only app and a transmitting one, so it
//! fails closed: any missing input (no network, no subnet, no Mine entry) is a refusal.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::model::{Millis, MineEntry, MineKind};

/// The only port the sweep ever addresses (UDP "discard").
pub const SWEEP_PORT: u16 = 9;
/// Hard ceiling on datagrams per second.
pub const SWEEP_RATE_PER_SEC: u32 = 50;
/// Widest subnet swept: a /23 is 512 addresses.
pub const MAX_SWEEP_HOSTS: usize = 512;
/// Shortest prefix (widest network) the gate accepts.
pub const MIN_PREFIX: u8 = 23;
/// Longest prefix with at least one other host (/31 and /32 have none to sweep).
pub const MAX_PREFIX: u8 = 30;
/// Automatic sweeps are at most this often.
pub const AUTO_SWEEP_INTERVAL_MS: Millis = 10 * 60 * 1000;
/// A user-triggered "Sweep now" still waits this long after the previous sweep.
pub const FORCED_SWEEP_MIN_GAP_MS: Millis = 30 * 1000;

/// Gap between two datagrams: 1 s / 50 = 20 ms.
pub fn send_interval() -> Duration {
    Duration::from_micros(1_000_000 / u64::from(SWEEP_RATE_PER_SEC))
}

/// Earliest offset from the start of a sweep at which datagram `index` (0-based) may go out.
pub fn send_offset(index: usize) -> Duration {
    send_interval() * u32::try_from(index).unwrap_or(u32::MAX)
}

/// Whether the joined access point is in Mine: an exact `wifiAp` match on the joined BSSID hash,
/// or a `wifiGroup` match on its radio-group id. Entries of other kinds never count, and a
/// look-alike access point (same name, different BSSID/group) does not match.
pub fn ap_is_mine(mine: &[MineEntry], bssid_hash: Option<&str>, group_id: Option<&str>) -> bool {
    mine_entry_for_ap(mine, bssid_hash, group_id).is_some()
}

/// The Mine entry that makes the joined access point mine (the oldest, when both forms exist).
pub fn mine_entry_for_ap<'a>(
    mine: &'a [MineEntry],
    bssid_hash: Option<&str>,
    group_id: Option<&str>,
) -> Option<&'a MineEntry> {
    mine.iter()
        .filter(|m| match m.kind {
            MineKind::WifiAp => bssid_hash.is_some_and(|b| b == m.id_hash),
            MineKind::WifiGroup => group_id.is_some_and(|g| g == m.id_hash),
            MineKind::Ble | MineKind::Lan => false,
        })
        .min_by_key(|m| m.added_at)
}

/// The interface's own address with its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    /// `None` when the mask is not a contiguous run of ones (a malformed or exotic mask).
    pub fn from_addr_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Option<Subnet> {
        let m = u32::from(mask);
        let prefix = m.leading_ones() as u8;
        let contiguous = if prefix == 0 {
            m == 0
        } else {
            m == u32::MAX << (32 - u32::from(prefix))
        };
        contiguous.then_some(Subnet { addr, prefix })
    }

    fn mask_bits(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        }
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask_bits())
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask_bits())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask_bits() == u32::from(self.network())
    }

    /// `192.0.2.0/24`.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network(), self.prefix)
    }

    /// Every address to sweep: the subnet minus network, broadcast and our own address.
    /// Empty outside `MIN_PREFIX..=MAX_PREFIX`, so a caller cannot get an oversized list.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        if !(MIN_PREFIX..=MAX_PREFIX).contains(&self.prefix) {
            return Vec::new();
        }
        let (net, bc) = (u32::from(self.network()), u32::from(self.broadcast()));
        (net + 1..bc)
            .map(Ipv4Addr::from)
            .filter(|ip| *ip != self.addr)
            .collect()
    }
}

/// Why the sweep may not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepRefusal {
    /// `lan_active_sweep` is off.
    Disabled,
    /// Not on Wi-Fi, or macOS withholds the access point's identity (no Location access).
    NoNetwork,
    /// The joined access point is not in Mine.
    NotMine,
    /// No IPv4 address/mask on the Wi-Fi interface.
    NoSubnet,
    /// Wider than a /23.
    SubnetTooLarge,
    /// A /31 or /32: nothing to sweep.
    SubnetTooSmall,
    /// Swept too recently.
    TooSoon,
}

impl SweepRefusal {
    /// Plain-language reason, shown next to "Sweep now".
    pub fn message(self) -> &'static str {
        match self {
            SweepRefusal::Disabled => "The active sweep is switched off in Settings.",
            SweepRefusal::NoNetwork => {
                "Not joined to a Wi-Fi network that can be identified (Location access may be missing)."
            }
            SweepRefusal::NotMine => {
                "This access point is not marked as yours. Mark it as mine first."
            }
            SweepRefusal::NoSubnet => "The Wi-Fi interface has no IPv4 address yet.",
            SweepRefusal::SubnetTooLarge => {
                "This network is larger than a /23 (512 addresses); the sweep only runs on small networks."
            }
            SweepRefusal::SubnetTooSmall => "This network has no other addresses to sweep.",
            SweepRefusal::TooSoon => "A sweep ran moments ago; wait a little before the next one.",
        }
    }
}

/// Everything the gate looks at.
#[derive(Debug, Clone, Copy)]
pub struct GateInput<'a> {
    /// `Settings::lan_active_sweep`.
    pub setting_on: bool,
    /// The joined network's key; `None` = no identifiable network.
    pub network_key: Option<&'a str>,
    /// Result of [`ap_is_mine`] for the joined access point.
    pub ap_is_mine: bool,
    pub subnet: Option<Subnet>,
}

/// THE sweep gate. `Ok(subnet)` only when the setting is on, the network is identified, its
/// access point is Mine, and the subnet is between /23 and /30. Checks run cheapest-to-explain
/// first, and every one must pass.
pub fn sweep_gate(input: &GateInput) -> Result<Subnet, SweepRefusal> {
    if !input.setting_on {
        return Err(SweepRefusal::Disabled);
    }
    if input.network_key.is_none() {
        return Err(SweepRefusal::NoNetwork);
    }
    if !input.ap_is_mine {
        return Err(SweepRefusal::NotMine);
    }
    let subnet = input.subnet.ok_or(SweepRefusal::NoSubnet)?;
    if subnet.prefix < MIN_PREFIX {
        return Err(SweepRefusal::SubnetTooLarge);
    }
    if subnet.prefix > MAX_PREFIX {
        return Err(SweepRefusal::SubnetTooSmall);
    }
    Ok(subnet)
}

/// Cadence: a forced sweep needs [`FORCED_SWEEP_MIN_GAP_MS`] since the last one, an automatic
/// one [`AUTO_SWEEP_INTERVAL_MS`]. A clock that went backwards counts as "too soon".
pub fn cadence_ok(force: bool, last: Option<Millis>, now: Millis) -> Result<(), SweepRefusal> {
    let Some(last) = last else { return Ok(()) };
    let need = if force {
        FORCED_SWEEP_MIN_GAP_MS
    } else {
        AUTO_SWEEP_INTERVAL_MS
    };
    if now >= last && now - last >= need {
        Ok(())
    } else {
        Err(SweepRefusal::TooSoon)
    }
}

/// Gate plus cadence: the single decision point `lan::scan` consults before it transmits.
pub fn may_sweep(
    input: &GateInput,
    force: bool,
    last: Option<Millis>,
    now: Millis,
) -> Result<Subnet, SweepRefusal> {
    let subnet = sweep_gate(input)?;
    cadence_ok(force, last, now)?;
    Ok(subnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn sub(addr: &str, prefix: u8) -> Subnet {
        Subnet {
            addr: ip(addr),
            prefix,
        }
    }

    fn entry(kind: MineKind, id: &str, at: Millis) -> MineEntry {
        MineEntry {
            kind,
            id_hash: id.into(),
            label: None,
            added_at: at,
        }
    }

    fn open_input() -> GateInput<'static> {
        GateInput {
            setting_on: true,
            network_key: Some("net-key"),
            ap_is_mine: true,
            subnet: Some(sub("192.0.2.7", 24)),
        }
    }

    #[test]
    fn gate_truth_table() {
        type Tweak = fn(&mut GateInput);
        let cases: Vec<(&str, Tweak, Result<u8, SweepRefusal>)> = vec![
            ("all conditions met", |_| {}, Ok(24)),
            (
                "NEGATIVE: sweep switched off",
                |i| i.setting_on = false,
                Err(SweepRefusal::Disabled),
            ),
            (
                "NEGATIVE: sweep on but AP not Mine",
                |i| i.ap_is_mine = false,
                Err(SweepRefusal::NotMine),
            ),
            (
                "NEGATIVE: no network",
                |i| i.network_key = None,
                Err(SweepRefusal::NoNetwork),
            ),
            (
                "NEGATIVE: no subnet",
                |i| i.subnet = None,
                Err(SweepRefusal::NoSubnet),
            ),
            (
                "NEGATIVE: /22 is wider than /23",
                |i| i.subnet = Some(sub("192.0.2.7", 22)),
                Err(SweepRefusal::SubnetTooLarge),
            ),
            (
                "NEGATIVE: /16",
                |i| i.subnet = Some(sub("192.0.2.7", 16)),
                Err(SweepRefusal::SubnetTooLarge),
            ),
            (
                "NEGATIVE: /0",
                |i| i.subnet = Some(sub("192.0.2.7", 0)),
                Err(SweepRefusal::SubnetTooLarge),
            ),
            (
                "/23 is the widest allowed",
                |i| i.subnet = Some(sub("192.0.2.7", 23)),
                Ok(23),
            ),
            (
                "/30 is the narrowest",
                |i| i.subnet = Some(sub("192.0.2.5", 30)),
                Ok(30),
            ),
            (
                "NEGATIVE: /31 has nothing to sweep",
                |i| i.subnet = Some(sub("192.0.2.5", 31)),
                Err(SweepRefusal::SubnetTooSmall),
            ),
            (
                "NEGATIVE: setting off beats everything else",
                |i| {
                    i.setting_on = false;
                    i.ap_is_mine = false;
                    i.network_key = None;
                },
                Err(SweepRefusal::Disabled),
            ),
        ];
        let mut ran = 0;
        for (name, tweak, want) in cases {
            let mut input = open_input();
            tweak(&mut input);
            let got = sweep_gate(&input).map(|s| s.prefix);
            assert_eq!(got, want, "case: {name}");
            ran += 1;
        }
        assert_eq!(ran, 12, "every gate case must run");
    }

    #[test]
    fn look_alike_access_point_does_not_open_the_gate() {
        // Mine holds the real AP (BSSID hash "ap-real", group "grp-real").
        let mine = vec![
            entry(MineKind::WifiAp, "ap-real", 1),
            entry(MineKind::WifiGroup, "grp-real", 1),
        ];
        // Same SSID "Net-A" but a different BSSID and a different group: a look-alike.
        assert!(!ap_is_mine(&mine, Some("ap-twin"), Some("grp-twin")));
        // Different BSSID, group unknown (not computed).
        assert!(!ap_is_mine(&mine, Some("ap-twin"), None));
        // BSSID withheld.
        assert!(!ap_is_mine(&mine, None, None));
        // The real one matches by either form.
        assert!(ap_is_mine(&mine, Some("ap-real"), None));
        assert!(ap_is_mine(&mine, Some("ap-twin"), Some("grp-real")));
        // Through the full gate: the look-alike is refused as NotMine.
        let mut input = open_input();
        input.ap_is_mine = ap_is_mine(&mine, Some("ap-twin"), Some("grp-twin"));
        assert_eq!(sweep_gate(&input), Err(SweepRefusal::NotMine));
    }

    #[test]
    fn only_wifi_entries_make_an_access_point_mine() {
        // A BLE or LAN Mine entry whose hash happens to equal the joined AP must not count.
        let mine = vec![
            entry(MineKind::Ble, "same-hash", 1),
            entry(MineKind::Lan, "same-hash", 1),
        ];
        assert!(!ap_is_mine(&mine, Some("same-hash"), Some("same-hash")));
        // And a wifiAp entry is not matched against the group id, nor a group entry against the BSSID.
        let ap_only = vec![entry(MineKind::WifiAp, "x", 1)];
        assert!(!ap_is_mine(&ap_only, None, Some("x")));
        let grp_only = vec![entry(MineKind::WifiGroup, "x", 1)];
        assert!(!ap_is_mine(&grp_only, Some("x"), None));
        assert!(!ap_is_mine(&[], Some("x"), Some("x")));
    }

    #[test]
    fn mine_entry_for_ap_is_the_oldest_match() {
        let mine = vec![
            entry(MineKind::WifiGroup, "g", 50),
            entry(MineKind::WifiAp, "a", 20),
        ];
        assert_eq!(
            mine_entry_for_ap(&mine, Some("a"), Some("g")).map(|m| m.added_at),
            Some(20)
        );
    }

    #[test]
    fn cadence_truth_table() {
        const MIN: Millis = 60_000;
        let now = 100 * MIN;
        let cases = [
            ("never swept, auto", false, None, true),
            ("never swept, forced", true, None, true),
            ("auto 9 min ago", false, Some(now - 9 * MIN), false),
            ("auto exactly 10 min ago", false, Some(now - 10 * MIN), true),
            ("forced 10 s ago", true, Some(now - 10_000), false),
            ("forced 31 s ago", true, Some(now - 31_000), true),
            ("clock went backwards", false, Some(now + MIN), false),
        ];
        for (name, force, last, want) in cases {
            assert_eq!(cadence_ok(force, last, now).is_ok(), want, "case: {name}");
        }
    }

    #[test]
    fn may_sweep_needs_gate_and_cadence() {
        let now = 1_000_000;
        assert!(may_sweep(&open_input(), false, None, now).is_ok());
        assert_eq!(
            may_sweep(&open_input(), false, Some(now - 1000), now),
            Err(SweepRefusal::TooSoon)
        );
        let mut closed = open_input();
        closed.ap_is_mine = false;
        // A forced sweep does not bypass the gate.
        assert_eq!(
            may_sweep(&closed, true, None, now),
            Err(SweepRefusal::NotMine)
        );
    }

    #[test]
    fn rate_limit_math() {
        assert_eq!(send_interval(), Duration::from_millis(20));
        assert_eq!(send_offset(0), Duration::ZERO);
        assert_eq!(send_offset(50), Duration::from_secs(1));
        // No one-second window ever holds more than 50 datagrams.
        let offsets: Vec<Duration> = (0..MAX_SWEEP_HOSTS).map(send_offset).collect();
        for start in &offsets {
            let in_window = offsets
                .iter()
                .filter(|o| *o >= start && **o < *start + Duration::from_secs(1))
                .count();
            assert!(
                in_window <= SWEEP_RATE_PER_SEC as usize,
                "window {in_window}"
            );
        }
        // A full /23 takes at least 10.2 s.
        assert!(send_offset(MAX_SWEEP_HOSTS - 1) >= Duration::from_millis(10_220));
    }

    #[test]
    fn subnet_math() {
        let s = Subnet::from_addr_mask(ip("192.0.2.77"), ip("255.255.255.0")).unwrap();
        assert_eq!(s.prefix, 24);
        assert_eq!(s.cidr(), "192.0.2.0/24");
        assert_eq!(s.broadcast(), ip("192.0.2.255"));
        assert!(s.contains(ip("192.0.2.1")));
        assert!(!s.contains(ip("192.0.3.1")));
        let hosts = s.hosts();
        assert_eq!(hosts.len(), 253); // 254 usable minus our own address
        assert!(!hosts.contains(&ip("192.0.2.77")));
        assert!(!hosts.contains(&ip("192.0.2.0")));
        assert!(!hosts.contains(&ip("192.0.2.255")));
        // Non-contiguous masks are rejected.
        assert_eq!(
            Subnet::from_addr_mask(ip("192.0.2.1"), ip("255.0.255.0")),
            None
        );
        assert_eq!(
            Subnet::from_addr_mask(ip("192.0.2.1"), ip("0.0.0.255")),
            None
        );
        assert!(Subnet::from_addr_mask(ip("192.0.2.1"), ip("0.0.0.0")).is_some());
    }

    #[test]
    fn host_list_never_exceeds_the_cap() {
        for prefix in 0..=32u8 {
            let n = sub("192.0.2.7", prefix).hosts().len();
            assert!(n <= MAX_SWEEP_HOSTS, "/{prefix} gave {n}");
            if !(MIN_PREFIX..=MAX_PREFIX).contains(&prefix) {
                assert_eq!(n, 0, "/{prefix} must yield no hosts");
            }
        }
        assert_eq!(sub("192.0.2.7", 23).hosts().len(), 509);
    }
}
