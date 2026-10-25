//! Watchlist rule. OWNER: WP-C.
//!
//! Matches `ctx.watchlist` entries against the SSID and vendor of Wi-Fi observations
//! (case-insensitive; SSID entries also match look-alikes), skips anything in `ctx.mine`.
//!
//! One alert per (entry, access point): the access point is its multi-radio group when the
//! observation has one, else its BSSID hash, else (hidden BSSID) the folded SSID. The title
//! may carry the SSID like the other Wi-Fi alerts; `detail` stays generic and no raw
//! identifier appears in either.

use super::{fold_ssid, is_lookalike, named, subject_key, Collector, DetectContext};
use crate::model::{
    AlertKind, History, Millis, MineKind, Settings, Severity, WatchKind, WatchMatch,
    WatchlistEntry, WifiObservation,
};

/// SSID entries: exact (or look-alike) for `Exact`; substring, on raw lowercase or folded
/// text, for `Contains`. A blank pattern never matches (an empty substring matches everything).
fn ssid_matches(entry: &WatchlistEntry, ssid: &str) -> bool {
    let pat = entry.pattern.trim();
    if pat.is_empty() {
        return false;
    }
    match entry.match_mode {
        WatchMatch::Exact => {
            ssid.trim().to_lowercase() == pat.to_lowercase() || is_lookalike(ssid, pat)
        }
        WatchMatch::Contains => {
            ssid.to_lowercase().contains(&pat.to_lowercase()) || {
                let (f, p) = (fold_ssid(ssid), fold_ssid(pat));
                !p.is_empty() && f.contains(&p)
            }
        }
    }
}

fn vendor_matches(entry: &WatchlistEntry, vendor: &str) -> bool {
    let (pat, v) = (entry.pattern.trim().to_lowercase(), vendor.to_lowercase());
    if pat.is_empty() {
        return false;
    }
    match entry.match_mode {
        WatchMatch::Exact => v == pat,
        WatchMatch::Contains => v.contains(&pat),
    }
}

fn is_mine(ctx: &DetectContext, o: &WifiObservation) -> bool {
    o.bssid_hash
        .as_deref()
        .is_some_and(|b| ctx.is_mine(&[MineKind::WifiAp], b))
        || o.group_id
            .as_deref()
            .is_some_and(|g| ctx.is_mine(&[MineKind::WifiGroup], g))
}

pub(super) fn watchlist(
    history: &History,
    _settings: &Settings,
    ctx: &DetectContext,
    _now: Millis,
    out: &mut Collector,
) {
    if ctx.watchlist.is_empty() {
        return;
    }
    for scan in &history.scans {
        for o in scan.wifi.iter().filter(|o| !is_mine(ctx, o)) {
            for entry in &ctx.watchlist {
                let hit = match entry.kind {
                    WatchKind::Ssid => named(o).is_some_and(|s| ssid_matches(entry, s)),
                    WatchKind::Vendor => o
                        .vendor
                        .as_deref()
                        .is_some_and(|v| vendor_matches(entry, v)),
                };
                if !hit {
                    continue;
                }
                let ap = o
                    .group_id
                    .clone()
                    .or_else(|| o.bssid_hash.clone())
                    .unwrap_or_else(|| fold_ssid(named(o).unwrap_or_default()));
                let title = match (entry.kind, named(o), o.vendor.as_deref()) {
                    (WatchKind::Ssid, Some(ssid), _) => format!("Watchlist match: {ssid}"),
                    (_, _, Some(vendor)) => format!("Watchlist match: vendor {vendor}"),
                    _ => "Watchlist match".to_string(),
                };
                out.add(
                    AlertKind::Watchlist,
                    Severity::Medium,
                    title,
                    "A nearby Wi-Fi access point matches an entry on your watchlist.".to_string(),
                    scan.scanned_at,
                    scan.scanned_at,
                    subject_key("watchlist", &format!("{}\u{1f}{ap}", entry.id)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::evaluate_with;
    use crate::model::{Alert, MineEntry, ScanSnapshot, Security, WatchlistEntry, WifiObservation};

    const T0: Millis = 1_700_000_000_000;

    fn entry(id: i64, kind: WatchKind, pattern: &str, m: WatchMatch) -> WatchlistEntry {
        WatchlistEntry {
            id,
            kind,
            pattern: pattern.to_string(),
            match_mode: m,
            added_at: 0,
        }
    }
    fn ap(ssid: Option<&str>, vendor: Option<&str>, n: u8, group: Option<&str>) -> WifiObservation {
        WifiObservation {
            ssid: ssid.map(String::from),
            bssid_hash: Some(format!("bssid-{n}")),
            rssi: -60,
            channel: Some(36),
            security: Security::Wpa2Personal,
            seen_at: T0,
            vendor: vendor.map(String::from),
            group_id: group.map(String::from),
        }
    }
    fn hist(scans: Vec<Vec<WifiObservation>>) -> History {
        History {
            scans: scans
                .into_iter()
                .enumerate()
                .map(|(i, wifi)| ScanSnapshot {
                    scanned_at: T0 + i as i64 * 60_000,
                    wifi,
                    ble: vec![],
                })
                .collect(),
        }
    }
    fn run(
        h: &History,
        entries: Vec<WatchlistEntry>,
        mine: Vec<MineEntry>,
        on: bool,
    ) -> Vec<Alert> {
        let mut s = Settings::default();
        s.alert_toggles.watchlist = on;
        let ctx = DetectContext {
            watchlist: entries,
            mine,
            ..DetectContext::default()
        };
        evaluate_with(h, &s, &ctx, T0)
            .into_iter()
            .filter(|a| a.kind == AlertKind::Watchlist)
            .collect()
    }
    fn mine(kind: MineKind, id: &str) -> MineEntry {
        MineEntry {
            kind,
            id_hash: id.to_string(),
            label: None,
            added_at: 0,
        }
    }

    // (label, ssid, entry, expected alerts)
    #[test]
    fn ssid_table_with_negative_controls() {
        use WatchKind::Ssid;
        use WatchMatch::{Contains, Exact};
        let cases: Vec<(&str, &str, WatchlistEntry, usize)> = vec![
            (
                "exact, same case",
                "Net-A",
                entry(1, Ssid, "Net-A", Exact),
                1,
            ),
            (
                "exact, different case",
                "NET-a",
                entry(1, Ssid, "net-a", Exact),
                1,
            ),
            (
                "contains",
                "Guest Net-A 5G",
                entry(1, Ssid, "net-a", Contains),
                1,
            ),
            (
                "look-alike (digit swap)",
                "Ne1-A",
                entry(1, Ssid, "Net-A", Exact),
                1,
            ),
            (
                "look-alike (one edit)",
                "Net-AA",
                entry(1, Ssid, "Net-A", Exact),
                1,
            ),
            (
                "look-alike under contains",
                "Guest N3t-A",
                entry(1, Ssid, "net-a", Contains),
                0,
            ),
            (
                "NEG exact vs different name",
                "Cafe-Z",
                entry(1, Ssid, "Net-A", Exact),
                0,
            ),
            (
                "NEG exact does not substring",
                "Guest Net-A",
                entry(1, Ssid, "Net-A", Exact),
                0,
            ),
            (
                "NEG contains, absent",
                "Cafe-Z",
                entry(1, Ssid, "Net-A", Contains),
                0,
            ),
            (
                "NEG blank pattern (exact)",
                "Net-A",
                entry(1, Ssid, "  ", Exact),
                0,
            ),
            (
                "NEG blank pattern (contains)",
                "Net-A",
                entry(1, Ssid, "", Contains),
                0,
            ),
        ];
        for (label, ssid, e, want) in cases {
            let h = hist(vec![vec![ap(Some(ssid), None, 1, None)]]);
            assert_eq!(run(&h, vec![e], vec![], true).len(), want, "{label}");
        }
    }

    #[test]
    fn vendor_table_with_negative_controls() {
        use WatchKind::Vendor;
        use WatchMatch::{Contains, Exact};
        let cases: Vec<(&str, Option<&str>, WatchlistEntry, usize)> = vec![
            (
                "exact",
                Some("Vendor-A"),
                entry(1, Vendor, "vendor-a", Exact),
                1,
            ),
            (
                "contains",
                Some("Vendor-A Networks"),
                entry(1, Vendor, "vendor-a", Contains),
                1,
            ),
            (
                "NEG exact is not substring",
                Some("Vendor-A Networks"),
                entry(1, Vendor, "Vendor-A", Exact),
                0,
            ),
            (
                "NEG different vendor",
                Some("Vendor-B"),
                entry(1, Vendor, "Vendor-A", Contains),
                0,
            ),
            (
                "NEG unknown vendor",
                None,
                entry(1, Vendor, "Vendor-A", Contains),
                0,
            ),
            (
                "NEG blank pattern",
                Some("Vendor-A"),
                entry(1, Vendor, " ", Contains),
                0,
            ),
        ];
        for (label, vendor, e, want) in cases {
            let h = hist(vec![vec![ap(Some("Net-A"), vendor, 1, None)]]);
            assert_eq!(run(&h, vec![e], vec![], true).len(), want, "{label}");
        }
    }

    #[test]
    fn ssid_entry_never_matches_on_vendor_text_and_vice_versa() {
        let h = hist(vec![vec![ap(Some("Net-A"), Some("Vendor-A"), 1, None)]]);
        let wrong = vec![
            entry(1, WatchKind::Ssid, "Vendor-A", WatchMatch::Contains),
            entry(2, WatchKind::Vendor, "Net-A", WatchMatch::Contains),
        ];
        assert!(run(&h, wrong, vec![], true).is_empty());
    }

    #[test]
    fn toggle_off_and_empty_watchlist_give_no_alert() {
        let h = hist(vec![vec![ap(Some("Net-A"), None, 1, None)]]);
        let e = entry(1, WatchKind::Ssid, "Net-A", WatchMatch::Exact);
        assert_eq!(
            run(&h, vec![e.clone()], vec![], true).len(),
            1,
            "control: rule fires"
        );
        assert!(run(&h, vec![e], vec![], false).is_empty(), "toggle off");
        assert!(run(&h, vec![], vec![], true).is_empty(), "empty watchlist");
    }

    #[test]
    fn mine_is_excluded_by_ap_hash_or_group() {
        let e = entry(1, WatchKind::Ssid, "Net-A", WatchMatch::Exact);
        let h = hist(vec![vec![ap(Some("Net-A"), None, 1, Some("grp-1"))]]);
        assert_eq!(run(&h, vec![e.clone()], vec![], true).len(), 1, "control");
        let by_ap = vec![mine(MineKind::WifiAp, "bssid-1")];
        let by_group = vec![mine(MineKind::WifiGroup, "grp-1")];
        assert!(run(&h, vec![e.clone()], by_ap, true).is_empty());
        assert!(run(&h, vec![e.clone()], by_group, true).is_empty());
        // Mine of another device or another kind does not suppress it.
        let other = vec![
            mine(MineKind::WifiAp, "bssid-2"),
            mine(MineKind::Ble, "bssid-1"),
            mine(MineKind::WifiGroup, "bssid-1"),
        ];
        assert_eq!(run(&h, vec![e], other, true).len(), 1);
    }

    #[test]
    fn one_alert_per_entry_and_access_point() {
        let e = entry(1, WatchKind::Ssid, "Net-A", WatchMatch::Contains);
        // Three radios of one group, over two scans: one alert.
        let radios = vec![
            ap(Some("Net-A"), None, 1, Some("grp-1")),
            ap(Some("Net-A"), None, 2, Some("grp-1")),
            ap(Some("Net-A-5G"), None, 3, Some("grp-1")),
        ];
        let h = hist(vec![radios.clone(), radios]);
        let a = run(&h, vec![e.clone()], vec![], true);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].last_seen - a[0].first_seen, 60_000);
        // A second AP, and a second entry on the same AP, each get their own alert.
        let h2 = hist(vec![vec![
            ap(Some("Net-A"), None, 1, Some("grp-1")),
            ap(Some("Net-A"), None, 9, Some("grp-9")),
        ]]);
        assert_eq!(run(&h2, vec![e.clone()], vec![], true).len(), 2);
        let e2 = entry(2, WatchKind::Ssid, "net", WatchMatch::Contains);
        assert_eq!(run(&h2, vec![e, e2], vec![], true).len(), 4);
    }

    #[test]
    fn title_may_name_the_ssid_but_detail_and_subject_hold_no_identifier() {
        let h = hist(vec![vec![
            ap(Some("Net-A"), Some("Vendor-A"), 1, Some("grp-1")),
            ap(None, Some("Vendor-A"), 2, None),
        ]]);
        let es = vec![
            entry(1, WatchKind::Ssid, "Net-A", WatchMatch::Exact),
            entry(2, WatchKind::Vendor, "Vendor-A", WatchMatch::Exact),
        ];
        let alerts = run(&h, es, vec![], true);
        assert_eq!(alerts.len(), 3);
        assert!(alerts.iter().any(|a| a.title == "Watchlist match: Net-A"));
        assert!(alerts
            .iter()
            .any(|a| a.title == "Watchlist match: vendor Vendor-A"));
        for a in &alerts {
            assert_eq!(a.severity, Severity::Medium);
            assert!(
                !a.detail.contains("Net-A")
                    && !a.detail.contains("bssid")
                    && !a.detail.contains("grp")
            );
            assert_eq!(a.subject_hash.len(), 64);
            assert!(!a.title.contains("bssid") && !a.title.contains("grp"));
        }
    }

    #[test]
    fn hidden_network_matches_vendor_entries_only() {
        let h = hist(vec![vec![ap(None, Some("Vendor-A"), 1, None)]]);
        let s = entry(1, WatchKind::Ssid, "Net-A", WatchMatch::Contains);
        let v = entry(2, WatchKind::Vendor, "Vendor-A", WatchMatch::Exact);
        assert!(run(&h, vec![s], vec![], true).is_empty());
        assert_eq!(run(&h, vec![v], vec![], true).len(), 1);
    }
}
