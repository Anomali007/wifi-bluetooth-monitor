//! FollowedAcrossPlaces rule. OWNER: WP-AB.
//!
//! Reads `ctx.places` / `ctx.place_sightings` (hashed ids only), skips anything in `ctx.mine`,
//! says "possible", and never reports coordinates, only place labels. The places module only
//! records sightings during confirmed dwells, and only for tracker-signature BLE devices, so
//! transit and ordinary devices never reach this rule. Retention (`place_retention_days`) is
//! applied by the pipeline's purge, so what is here is what is allowed to be considered.

use super::{Collector, DetectContext};
use crate::model::{
    AlertKind, History, Millis, MineKind, Place, PlaceSighting, Settings, Severity, SightingKind,
};
use std::collections::BTreeMap;

/// Visits to different places must be at least this far apart to count as separate.
const MIN_GAP_MS: Millis = 30 * 60 * 1000;
/// Places needed for a medium alert; at `HIGH_PLACES` the severity is high.
const MIN_PLACES: usize = 2;
const HIGH_PLACES: usize = 3;

pub(super) fn followed_across_places(
    _history: &History,
    settings: &Settings,
    ctx: &DetectContext,
    now: Millis,
    out: &mut Collector,
) {
    if !settings.alert_toggles.followed_across_places {
        return;
    }
    let retention = Millis::from(settings.place_retention_days) * 24 * 3_600_000;
    let mut by_subject: BTreeMap<(u8, &str), Vec<&PlaceSighting>> = BTreeMap::new();
    for s in &ctx.place_sightings {
        let (kinds, wanted): (&[MineKind], bool) = match s.kind {
            SightingKind::Ble => (&[MineKind::Ble], true),
            SightingKind::Wifi => (&[MineKind::WifiAp, MineKind::WifiGroup], true),
            SightingKind::Lan => (&[], false),
        };
        if !wanted || ctx.is_mine(kinds, &s.id_hash) || now - s.last_seen > retention {
            continue;
        }
        by_subject
            .entry((u8::from(s.kind == SightingKind::Ble), s.id_hash.as_str()))
            .or_default()
            .push(s);
    }

    for ((is_ble, id_hash), mut visits) in by_subject {
        visits.sort_by_key(|s| (s.first_seen, s.place_id));
        // Greedy chain of visits, each starting >= 30 min after the previous one ended, each at a
        // place not already in the chain.
        let mut chain: Vec<&PlaceSighting> = Vec::new();
        for v in &visits {
            let ok = match chain.last() {
                None => true,
                Some(prev) => {
                    v.first_seen - prev.last_seen >= MIN_GAP_MS
                        && chain.iter().all(|c| c.place_id != v.place_id)
                }
            };
            if ok {
                chain.push(v);
            }
        }
        if chain.len() < MIN_PLACES {
            continue;
        }
        let severity = if chain.len() >= HIGH_PLACES {
            Severity::High
        } else {
            Severity::Medium
        };
        let names = place_names(&ctx.places, &chain);
        let (title, detail) = if is_ble == 1 {
            (
                "Possible device following you".to_string(),
                format!(
                    "A device matching a tracker signature was nearby at {} places ({}), at least \
                     30 minutes apart. This is a best guess: it may be someone else's item, \
                     your own, or a coincidence.",
                    chain.len(),
                    names
                ),
            )
        } else {
            (
                "A network that appears wherever you go".to_string(),
                format!(
                    "The same access point was nearby at {} places ({}), at least 30 minutes \
                     apart. It may be a portable access point, or a coincidence.",
                    chain.len(),
                    names
                ),
            )
        };
        out.add(
            AlertKind::FollowedAcrossPlaces,
            severity,
            title,
            detail,
            chain.first().map_or(0, |c| c.first_seen),
            chain.last().map_or(0, |c| c.last_seen),
            id_hash.to_string(),
        );
    }
}

/// "Home, Place 2": labels the user typed, else "Place N". Never an identifier.
fn place_names(places: &[Place], chain: &[&PlaceSighting]) -> String {
    chain
        .iter()
        .map(|c| {
            places
                .iter()
                .find(|p| p.id == c.place_id)
                .and_then(|p| p.label.clone())
                .unwrap_or_else(|| format!("Place {}", c.place_id))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::evaluate_with;
    use crate::model::{AlertToggles, MineEntry};

    const T0: Millis = 1_700_000_000_000;
    const MIN: Millis = 60_000;

    fn place(id: i64, label: Option<&str>) -> Place {
        Place {
            id,
            label: label.map(str::to_string),
            members: vec![],
            first_seen: T0,
            last_seen: T0,
        }
    }
    fn sight(
        kind: SightingKind,
        id: &str,
        place_id: i64,
        from: Millis,
        to: Millis,
    ) -> PlaceSighting {
        PlaceSighting {
            kind,
            id_hash: id.into(),
            place_id,
            first_seen: T0 + from * MIN,
            last_seen: T0 + to * MIN,
            scans: 3,
        }
    }
    fn ctx(sightings: Vec<PlaceSighting>) -> DetectContext {
        DetectContext {
            places: vec![
                place(1, Some("Place-A")),
                place(2, None),
                place(3, Some("Place-C")),
            ],
            place_sightings: sightings,
            ..Default::default()
        }
    }
    fn run(c: &DetectContext, s: &Settings) -> Vec<crate::model::Alert> {
        evaluate_with(&History { scans: vec![] }, s, c, T0 + 600 * MIN)
            .into_iter()
            .filter(|a| a.kind == AlertKind::FollowedAcrossPlaces)
            .collect()
    }

    #[test]
    fn two_places_alerts_medium_with_labels() {
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 5),
            sight(SightingKind::Ble, "dev-1", 2, 60, 70),
        ]);
        let a = run(&c, &Settings::default());
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Medium);
        assert!(a[0].title.starts_with("Possible"));
        assert!(a[0].detail.contains("Place-A") && a[0].detail.contains("Place 2"));
        assert!(!a[0].detail.contains("dev-1") && !a[0].title.contains("dev-1"));
    }

    #[test]
    fn three_places_is_high() {
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 5),
            sight(SightingKind::Ble, "dev-1", 2, 60, 70),
            sight(SightingKind::Ble, "dev-1", 3, 140, 150),
        ]);
        let a = run(&c, &Settings::default());
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::High);
    }

    #[test]
    fn wifi_access_point_uses_network_wording() {
        let c = ctx(vec![
            sight(SightingKind::Wifi, "ap-1", 1, 0, 5),
            sight(SightingKind::Wifi, "ap-1", 2, 60, 70),
        ]);
        let a = run(&c, &Settings::default());
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].title, "A network that appears wherever you go");
    }

    // ---- negative controls: each of these must stay silent ----

    #[test]
    fn same_place_only_is_silent() {
        let c = ctx(vec![sight(SightingKind::Ble, "dev-1", 1, 0, 600)]);
        assert!(run(&c, &Settings::default()).is_empty());
    }

    #[test]
    fn two_places_under_thirty_minutes_apart_is_silent() {
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 10),
            sight(SightingKind::Ble, "dev-1", 2, 39, 50),
        ]);
        assert!(run(&c, &Settings::default()).is_empty());
        // Control: the same shape with a 30-minute gap does alert.
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 10),
            sight(SightingKind::Ble, "dev-1", 2, 40, 50),
        ]);
        assert_eq!(run(&c, &Settings::default()).len(), 1);
    }

    #[test]
    fn mine_device_is_silent() {
        let mut c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 5),
            sight(SightingKind::Ble, "dev-1", 2, 60, 70),
            sight(SightingKind::Wifi, "grp-1", 1, 0, 5),
            sight(SightingKind::Wifi, "grp-1", 2, 60, 70),
        ]);
        assert_eq!(run(&c, &Settings::default()).len(), 2);
        let mine = |kind, id: &str| MineEntry {
            kind,
            id_hash: id.into(),
            label: None,
            added_at: T0,
        };
        c.mine = vec![
            mine(MineKind::Ble, "dev-1"),
            mine(MineKind::WifiGroup, "grp-1"),
        ];
        assert!(run(&c, &Settings::default()).is_empty());
    }

    #[test]
    fn toggle_off_is_silent() {
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 5),
            sight(SightingKind::Ble, "dev-1", 2, 60, 70),
        ]);
        let s = Settings {
            alert_toggles: AlertToggles {
                followed_across_places: false,
                ..AlertToggles::default()
            },
            ..Settings::default()
        };
        assert!(run(&c, &s).is_empty());
        assert_eq!(run(&c, &Settings::default()).len(), 1);
    }

    #[test]
    fn lan_sightings_are_not_this_rule() {
        let c = ctx(vec![
            sight(SightingKind::Lan, "mac-1", 1, 0, 5),
            sight(SightingKind::Lan, "mac-1", 2, 60, 70),
        ]);
        assert!(run(&c, &Settings::default()).is_empty());
    }

    #[test]
    fn sightings_past_retention_are_ignored() {
        let c = ctx(vec![
            sight(SightingKind::Ble, "dev-1", 1, 0, 5),
            sight(SightingKind::Ble, "dev-1", 2, 60, 70),
        ]);
        let s = Settings {
            place_retention_days: 1,
            ..Settings::default()
        };
        let late = T0 + 3 * 24 * 60 * MIN;
        let a = evaluate_with(&History { scans: vec![] }, &s, &c, late);
        assert!(a.iter().all(|a| a.kind != AlertKind::FollowedAcrossPlaces));
    }
}
