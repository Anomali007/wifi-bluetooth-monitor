//! The sweep gate: pure functions that decide whether the opt-in sweep (one ICMPv6 echo to the
//! link-local all-nodes address) may run, and its cadence. No I/O here, so every refusal path
//! is unit-testable.
//!
//! The gate is the one thing standing between a listen-only app and a transmitting one, so it
//! fails closed: any missing input (no network, no interface, no Mine entry) is a refusal.

use std::net::Ipv4Addr;

use crate::model::{Millis, MineEntry, MineKind};

/// Automatic sweeps are at most this often.
pub const AUTO_SWEEP_INTERVAL_MS: Millis = 10 * 60 * 1000;
/// A user-triggered "Sweep now" still waits this long after the previous sweep.
pub const FORCED_SWEEP_MIN_GAP_MS: Millis = 30 * 1000;

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

/// The interface's own IPv4 address with its prefix length. Used to keep announcements and ARP
/// rows to this network and for display; the sweep itself does not need it.
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
    /// No Wi-Fi interface to scope the echo to.
    NoInterface,
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
            SweepRefusal::NoInterface => "There is no Wi-Fi interface to send on.",
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
    /// OS index of the Wi-Fi interface the echo would be scoped to.
    pub if_index: Option<u16>,
}

/// THE sweep gate. `Ok(if_index)` only when the setting is on, the network is identified, its
/// access point is Mine, and the Wi-Fi interface is known. Checks run cheapest-to-explain
/// first, and every one must pass.
pub fn sweep_gate(input: &GateInput) -> Result<u16, SweepRefusal> {
    if !input.setting_on {
        return Err(SweepRefusal::Disabled);
    }
    if input.network_key.is_none() {
        return Err(SweepRefusal::NoNetwork);
    }
    if !input.ap_is_mine {
        return Err(SweepRefusal::NotMine);
    }
    input.if_index.ok_or(SweepRefusal::NoInterface)
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
) -> Result<u16, SweepRefusal> {
    let if_index = sweep_gate(input)?;
    cadence_ok(force, last, now)?;
    Ok(if_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
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
            if_index: Some(11),
        }
    }

    #[test]
    fn gate_truth_table() {
        type Tweak = fn(&mut GateInput);
        let cases: Vec<(&str, Tweak, Result<u16, SweepRefusal>)> = vec![
            ("all conditions met", |_| {}, Ok(11)),
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
                "NEGATIVE: no Wi-Fi interface",
                |i| i.if_index = None,
                Err(SweepRefusal::NoInterface),
            ),
            (
                "an IPv6-only network (no IPv4 subnet) is fine",
                |i| i.if_index = Some(4),
                Ok(4),
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
            let got = sweep_gate(&input);
            assert_eq!(got, want, "case: {name}");
            ran += 1;
        }
        assert_eq!(ran, 7, "every gate case must run");
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
    fn subnet_math() {
        let s = Subnet::from_addr_mask(ip("192.0.2.77"), ip("255.255.255.0")).unwrap();
        assert_eq!(s.prefix, 24);
        assert_eq!(s.cidr(), "192.0.2.0/24");
        assert_eq!(s.broadcast(), ip("192.0.2.255"));
        assert!(s.contains(ip("192.0.2.1")));
        assert!(!s.contains(ip("192.0.3.1")));
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
}
