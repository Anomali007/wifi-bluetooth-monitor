//! NewLanDevice rule. OWNER: WP-D.
//!
//! Fires only when `ctx.current_network` is a network whose access point is marked mine, for a
//! device in `ctx.lan_devices` on that network that was first seen after the network was being
//! learned. Skips devices in Mine (`ctx.mine` or the listing's `mine` flag).
//!
//! "Learning": devices first seen within [`LEARNING_MS`] of the start of observation (the
//! network's oldest remembered device, or the moment the access point was marked mine, whichever
//! is later) are the baseline, not news. Without that, marking a network as yours, or joining it
//! for the first time, would alert on every device already there.

use super::{subject_key, Collector, DetectContext};
use crate::lan::gate::mine_entry_for_ap;
use crate::model::{AlertKind, History, LanDevice, Millis, Settings, Severity};

/// How long after observation starts that newly seen devices still count as the baseline.
const LEARNING_MS: Millis = 15 * 60 * 1000;

pub(super) fn new_lan_device(
    _history: &History,
    settings: &Settings,
    ctx: &DetectContext,
    now: Millis,
    out: &mut Collector,
) {
    let Some(net) = &ctx.current_network else {
        return;
    };
    let Some(key) = net.network_key.as_deref() else {
        return;
    };
    // Re-derive "mine" from the context's Mine list rather than trusting the flag alone.
    let Some(ap_mine) = mine_entry_for_ap(
        &ctx.mine,
        net.bssid_hash.as_deref(),
        net.group_id.as_deref(),
    ) else {
        return;
    };
    let on_net: Vec<&LanDevice> = ctx
        .lan_devices
        .iter()
        .filter(|d| d.network_key == key)
        .collect();
    let Some(oldest) = on_net.iter().map(|d| d.first_seen).min() else {
        return;
    };
    let learning_ends = oldest.max(ap_mine.added_at) + LEARNING_MS;
    let window_start = now - Millis::from(settings.retention_hours) * 3_600_000;
    let ssid = net.ssid.as_deref().unwrap_or("your network");
    for d in on_net {
        if d.mine || ctx.is_mine(&[crate::model::MineKind::Lan], &d.mac_hash) {
            continue;
        }
        if d.first_seen < learning_ends || d.first_seen < window_start {
            continue;
        }
        let mut what = d
            .vendor
            .clone()
            .unwrap_or_else(|| "unknown vendor".to_string());
        if let Some(h) = &d.hostname {
            what = format!("{what}, {h}");
        }
        out.add(
            AlertKind::NewLanDevice,
            Severity::Medium,
            format!("New device on {ssid}"),
            format!(
                "A device you have not seen before ({what}) appeared on a network you marked as yours."
            ),
            d.first_seen,
            d.last_seen,
            subject_key("lanDevice", &format!("{key}\u{1f}{}", d.mac_hash)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::evaluate_with;
    use crate::model::{MineEntry, MineKind, NetworkInfo};

    const T0: Millis = 1_700_000_000_000;
    const MIN: Millis = 60_000;
    const KEY: &str = "net-a-key";

    fn mine_ap(added_at: Millis) -> MineEntry {
        MineEntry {
            kind: MineKind::WifiAp,
            id_hash: "ap-1".into(),
            label: None,
            ssid: None,
            added_at,
        }
    }

    fn device(mac: &str, first_seen: Millis) -> LanDevice {
        LanDevice {
            network_key: KEY.into(),
            mac_hash: mac.into(),
            vendor: Some("Vendor-A".into()),
            hostname: None,
            services: vec![],
            first_seen,
            last_seen: first_seen,
            ip: None,
            mine: false,
            source: None,
            possibly_same_as: None,
        }
    }

    fn net(mine: bool) -> NetworkInfo {
        NetworkInfo {
            network_key: Some(KEY.into()),
            ssid: Some("Net-A".into()),
            bssid_hash: Some("ap-1".into()),
            is_mine: mine,
            ..NetworkInfo::default()
        }
    }

    fn ctx(
        mine: Vec<MineEntry>,
        devices: Vec<LanDevice>,
        net: Option<NetworkInfo>,
    ) -> DetectContext {
        DetectContext {
            mine,
            lan_devices: devices,
            current_network: net,
            ..DetectContext::default()
        }
    }

    fn run(c: &DetectContext, settings: &Settings) -> Vec<crate::model::Alert> {
        evaluate_with(&History::default(), settings, c, T0 + 120 * MIN)
            .into_iter()
            .filter(|a| a.kind == AlertKind::NewLanDevice)
            .collect()
    }

    /// Baseline device long ago, a newcomer well after the learning window.
    fn known_and_new() -> Vec<LanDevice> {
        vec![device("old", T0), device("new", T0 + 60 * MIN)]
    }

    #[test]
    fn must_alert_for_a_new_device_on_a_mine_network() {
        let c = ctx(vec![mine_ap(T0 - MIN)], known_and_new(), Some(net(true)));
        let alerts = run(&c, &Settings::default());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Medium);
        assert!(alerts[0].title.contains("Net-A"));
        assert!(!alerts[0].detail.contains("new"), "no hash in the text");
        // Same inputs again: same alert id (the store dedupes on it).
        assert_eq!(run(&c, &Settings::default())[0].id, alerts[0].id);
    }

    #[test]
    #[allow(clippy::vec_init_then_push)] // cases are built with interleaved setup
    fn must_not_alert_cases() {
        let s = Settings::default();
        let mut cases: Vec<(&str, DetectContext)> = Vec::new();
        // AP not Mine.
        cases.push((
            "network not Mine",
            ctx(vec![], known_and_new(), Some(net(false))),
        ));
        // Look-alike: Mine holds a different AP.
        cases.push((
            "look-alike AP",
            ctx(
                vec![MineEntry {
                    id_hash: "ap-twin".into(),
                    ..mine_ap(T0 - MIN)
                }],
                known_and_new(),
                Some(net(true)),
            ),
        ));
        // is_mine flag set but Mine list empty: the list is authoritative.
        cases.push((
            "flag without Mine entry",
            ctx(vec![], known_and_new(), Some(net(true))),
        ));
        // No observation this cycle.
        cases.push((
            "no current network",
            ctx(vec![mine_ap(T0 - MIN)], known_and_new(), None),
        ));
        // Network identity withheld.
        cases.push((
            "no network key",
            ctx(
                vec![mine_ap(T0 - MIN)],
                known_and_new(),
                Some(NetworkInfo {
                    network_key: None,
                    ..net(true)
                }),
            ),
        ));
        // Newcomer is itself marked mine (via the list).
        cases.push((
            "device is Mine",
            ctx(
                vec![
                    mine_ap(T0 - MIN),
                    MineEntry {
                        kind: MineKind::Lan,
                        id_hash: "new".into(),
                        label: None,
                        ssid: None,
                        added_at: T0,
                    },
                ],
                known_and_new(),
                Some(net(true)),
            ),
        ));
        // Newcomer flagged mine by the listing.
        let mut flagged = known_and_new();
        flagged[1].mine = true;
        cases.push((
            "device flagged mine",
            ctx(vec![mine_ap(T0 - MIN)], flagged, Some(net(true))),
        ));
        // Within the learning window of the oldest device.
        cases.push((
            "still learning",
            ctx(
                vec![mine_ap(T0 - MIN)],
                vec![device("old", T0), device("new", T0 + 5 * MIN)],
                Some(net(true)),
            ),
        ));
        // AP marked mine only just now: devices already there are baseline.
        cases.push((
            "marked mine recently",
            ctx(
                vec![mine_ap(T0 + 55 * MIN)],
                known_and_new(),
                Some(net(true)),
            ),
        ));
        // Device on a different network.
        let mut elsewhere = known_and_new();
        elsewhere[1].network_key = "other-net".into();
        cases.push((
            "device on another network",
            ctx(vec![mine_ap(T0 - MIN)], elsewhere, Some(net(true))),
        ));
        // Too old for the retention window (first seen 3 days before "now").
        cases.push((
            "outside retention window",
            ctx(
                vec![mine_ap(T0 - 10_000 * MIN)],
                vec![
                    device("old", T0 - 10_000 * MIN),
                    device("new", T0 - 5_000 * MIN),
                ],
                Some(net(true)),
            ),
        ));
        // Nothing remembered at all.
        cases.push((
            "no devices",
            ctx(vec![mine_ap(T0 - MIN)], vec![], Some(net(true))),
        ));
        let n = cases.len();
        for (name, c) in &cases {
            assert!(run(c, &s).is_empty(), "case must not alert: {name}");
        }
        assert_eq!(n, 12, "every negative case must run");
    }

    #[test]
    fn hostname_keyed_and_mac_keyed_devices_are_judged_the_same_way() {
        // Namespaced hostname hashes and MAC hashes are both just opaque keys to the rule.
        let host_key = "mdns-host-key-0001";
        let mac_key = "mac-key-0001";
        for newcomer in [host_key, mac_key] {
            let devs = vec![device("old", T0), device(newcomer, T0 + 60 * MIN)];
            let c = ctx(vec![mine_ap(T0 - MIN)], devs.clone(), Some(net(true)));
            assert_eq!(
                run(&c, &Settings::default()).len(),
                1,
                "must alert: {newcomer}"
            );
            // NEGATIVE: the same newcomer, marked mine under that key.
            let c = ctx(
                vec![
                    mine_ap(T0 - MIN),
                    MineEntry {
                        kind: MineKind::Lan,
                        id_hash: newcomer.into(),
                        label: None,
                        ssid: None,
                        added_at: T0,
                    },
                ],
                devs,
                Some(net(true)),
            );
            assert!(run(&c, &Settings::default()).is_empty(), "mine: {newcomer}");
        }
        // NEGATIVE: marking the hostname key mine does not silence a different key.
        let devs = vec![
            device("old", T0),
            device(host_key, T0 + 60 * MIN),
            device(mac_key, T0 + 61 * MIN),
        ];
        let c = ctx(
            vec![
                mine_ap(T0 - MIN),
                MineEntry {
                    kind: MineKind::Lan,
                    id_hash: host_key.into(),
                    label: None,
                    ssid: None,
                    added_at: T0,
                },
            ],
            devs,
            Some(net(true)),
        );
        let alerts = run(&c, &Settings::default());
        assert_eq!(alerts.len(), 1);
        // A device with no vendor (announced only) still reads sensibly.
        let mut anon = device(host_key, T0 + 60 * MIN);
        anon.vendor = None;
        anon.hostname = Some("device-a.local".into());
        let c = ctx(
            vec![mine_ap(T0 - MIN)],
            vec![device("old", T0), anon],
            Some(net(true)),
        );
        let alerts = run(&c, &Settings::default());
        assert!(alerts[0].detail.contains("unknown vendor, device-a.local"));
    }

    #[test]
    fn toggle_off_silences_the_rule() {
        let c = ctx(vec![mine_ap(T0 - MIN)], known_and_new(), Some(net(true)));
        let mut s = Settings::default();
        assert_eq!(run(&c, &s).len(), 1, "control: fires with the toggle on");
        s.alert_toggles.new_lan_device = false;
        assert!(run(&c, &s).is_empty());
    }

    #[test]
    fn one_alert_per_new_device_and_hostname_in_detail() {
        let mut devs = known_and_new();
        devs.push(device("new2", T0 + 70 * MIN));
        devs[1].hostname = Some("device-a.local".into());
        let c = ctx(vec![mine_ap(T0 - MIN)], devs, Some(net(true)));
        let alerts = run(&c, &Settings::default());
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().any(|a| a.detail.contains("device-a.local")));
        assert_ne!(alerts[0].subject_hash, alerts[1].subject_hash);
    }
}
