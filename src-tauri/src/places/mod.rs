//! Place memory: Wi-Fi fingerprints, dwell tracking and place sightings. OWNER: WP-AB.
//!
//! CONTRACT (frozen signature):
//! - [`update`] runs once per scan, after the scan is stored and before detection. It matches
//!   the scan to a known place (or creates one), tracks dwell, and writes `places` /
//!   `place_sightings` through the `Store`. Returns the matched place id, if any.
//! - It reads only hashed identifiers already in the `ScanResult`.
//!
//! How it works:
//! - A place is the set of the strongest access-point hashes (RSSI >= -80, at most 40) seen
//!   there. A scan needs >= 3 usable APs to say anything about where it is. A scan matches a
//!   place at Jaccard >= 0.3.
//! - A scan counts toward a visit only after 3 consecutive scans match the same place, which
//!   filters transit (bus or train Wi-Fi). A brand-new place is created only when the third
//!   consecutive scan still resembles the first, so a ride past a thousand access points
//!   leaves no places behind. Sightings from the two earlier scans are held back and credited
//!   once the dwell is confirmed.
//! - An access point that turns up in two places is not a landmark, it is a follower
//!   candidate: it is dropped from every place's members and from future fingerprints.
//! - The dwell state is one JSON value in the store's `meta` table.

use crate::model::{
    BleObservation, Millis, Place, PlaceSighting, ScanResult, Settings, SightingKind,
    WifiObservation,
};
use crate::store::{Store, StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Weakest signal that still counts toward a fingerprint (and a Wi-Fi place sighting).
pub const MIN_RSSI: i32 = -80;
/// Fewer usable access points than this and the scan's place is unknown.
pub const MIN_USABLE_APS: usize = 3;
/// Jaccard overlap needed to call a scan the same place.
pub const MATCH_JACCARD: f64 = 0.3;
/// A place keeps at most this many (strongest) members.
pub const MAX_MEMBERS: usize = 40;
/// Consecutive matching scans before a scan counts as a visit.
pub const DWELL_SCANS: u32 = 3;
/// Remembered mobile access points are capped so the state value stays small.
const MAX_MOBILE: usize = 500;

/// What one pre-dwell scan saw, held until the dwell is confirmed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Held {
    wifi: Vec<String>,
    ble: Vec<String>,
    at: Millis,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct DwellState {
    /// Known place the current streak is on.
    place_id: Option<i64>,
    /// Fingerprint of an unmatched, not-yet-created place the streak is on.
    candidate: Vec<String>,
    streak: u32,
    /// Sightings from the pre-dwell scans of this streak, credited at confirmation.
    held: Vec<Held>,
    /// Access points seen in two or more places; never part of a fingerprint.
    mobile: Vec<String>,
    last_scan: Millis,
}

/// Usable fingerprint of one scan: BSSID hashes with RSSI >= [`MIN_RSSI`], strongest first,
/// one entry per hash, at most [`MAX_MEMBERS`], skipping `mobile`.
pub fn fingerprint(wifi: &[WifiObservation], mobile: &BTreeSet<String>) -> Vec<String> {
    let mut aps: Vec<(&str, i32)> = Vec::new();
    for o in wifi {
        let Some(h) = o.bssid_hash.as_deref() else {
            continue;
        };
        if o.rssi < MIN_RSSI || mobile.contains(h) {
            continue;
        }
        match aps.iter_mut().find(|(x, _)| *x == h) {
            Some(e) => e.1 = e.1.max(o.rssi),
            None => aps.push((h, o.rssi)),
        }
    }
    aps.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    aps.into_iter()
        .take(MAX_MEMBERS)
        .map(|(h, _)| h.to_string())
        .collect()
}

/// Jaccard similarity of two hash sets (0.0 when both are empty).
pub fn jaccard(a: &[String], b: &[String]) -> f64 {
    let a: BTreeSet<&String> = a.iter().collect();
    let b: BTreeSet<&String> = b.iter().collect();
    let union = a.union(&b).count();
    if union == 0 {
        return 0.0;
    }
    a.intersection(&b).count() as f64 / union as f64
}

/// The known place `fp` resembles most, if any reaches [`MATCH_JACCARD`] (lowest id on a tie).
pub fn best_match<'a>(places: &'a [Place], fp: &[String]) -> Option<&'a Place> {
    let mut best: Option<(&Place, f64)> = None;
    for p in places {
        let j = jaccard(&p.members, fp);
        if j >= MATCH_JACCARD && best.is_none_or(|(_, bj)| j > bj) {
            best = Some((p, j));
        }
    }
    best.map(|(p, _)| p)
}

/// New member list after a match: this scan's strongest first, then older members, capped.
fn merged_members(fp: &[String], old: &[String]) -> Vec<String> {
    let mut out: Vec<String> = fp.to_vec();
    for m in old {
        if !out.contains(m) {
            out.push(m.clone());
        }
    }
    out.truncate(MAX_MEMBERS);
    out
}

/// Access points (multi-radio group id when known, else BSSID hash) worth remembering.
fn wifi_ids(wifi: &[WifiObservation]) -> Vec<String> {
    let ids: BTreeSet<String> = wifi
        .iter()
        .filter(|o| o.rssi >= MIN_RSSI)
        .filter_map(|o| o.group_id.as_ref().or(o.bssid_hash.as_ref()))
        .cloned()
        .collect();
    ids.into_iter().collect()
}

/// Only tracker-signature devices are remembered by place. The scanner leaves `tracker` unset
/// for near-owner Find My adverts, so Apple is included only when separated.
fn ble_ids(ble: &[BleObservation]) -> Vec<String> {
    let ids: BTreeSet<String> = ble
        .iter()
        .filter(|b| b.tracker.is_some())
        .map(|b| b.peripheral_hash.clone())
        .collect();
    ids.into_iter().collect()
}

fn sightings_for(held: &Held, place_id: i64) -> Vec<PlaceSighting> {
    let mk = |kind, id: &String| PlaceSighting {
        kind,
        id_hash: id.clone(),
        place_id,
        first_seen: held.at,
        last_seen: held.at,
        scans: 1,
    };
    held.wifi
        .iter()
        .map(|i| mk(SightingKind::Wifi, i))
        .chain(held.ble.iter().map(|i| mk(SightingKind::Ble, i)))
        .collect()
}

/// Drop every access point that appears in two or more places from all member sets and
/// remember it as mobile.
fn remove_mobile(store: &mut Store, state: &mut DwellState) -> StoreResult<()> {
    let places = store.list_places()?;
    let mut count: BTreeMap<&String, usize> = BTreeMap::new();
    for p in &places {
        for m in p.members.iter().collect::<BTreeSet<_>>() {
            *count.entry(m).or_default() += 1;
        }
    }
    let newly: BTreeSet<String> = count
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .map(|(h, _)| h.clone())
        .collect();
    if newly.is_empty() {
        return Ok(());
    }
    for p in &places {
        if p.members.iter().any(|m| newly.contains(m)) {
            let kept: Vec<String> = p
                .members
                .iter()
                .filter(|m| !newly.contains(*m))
                .cloned()
                .collect();
            store.update_place_members(p.id, &kept, p.last_seen)?;
        }
    }
    for h in newly {
        if !state.mobile.contains(&h) {
            state.mobile.push(h);
        }
    }
    if state.mobile.len() > MAX_MOBILE {
        let drop = state.mobile.len() - MAX_MOBILE;
        state.mobile.drain(..drop);
    }
    Ok(())
}

fn reset_streak(state: &mut DwellState) {
    state.place_id = None;
    state.candidate.clear();
    state.streak = 0;
    state.held.clear();
}

fn save(store: &mut Store, state: &DwellState) -> StoreResult<()> {
    let json = serde_json::to_string(state)
        .map_err(|e| StoreError(format!("serialize place state: {e}")))?;
    store.set_place_state(&json)
}

/// Update place memory from one scan. Returns the known place the scan matched, if any
/// (whether or not the scan is yet part of a confirmed dwell).
pub fn update(
    store: &mut Store,
    scan: &ScanResult,
    settings: &Settings,
    now: Millis,
) -> StoreResult<Option<i64>> {
    let mut state: DwellState = store
        .place_state()?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mobile: BTreeSet<String> = state.mobile.iter().cloned().collect();
    let fp = fingerprint(&scan.wifi, &mobile);

    // A long silence (app closed, laptop asleep) ends the streak: the scans are not consecutive.
    let max_gap = Millis::from(settings.scan_interval_secs.max(1)) * 3_000;
    if state.last_scan != 0 && now - state.last_scan > max_gap {
        reset_streak(&mut state);
    }
    state.last_scan = now;

    if fp.len() < MIN_USABLE_APS {
        reset_streak(&mut state);
        save(store, &state)?;
        return Ok(None);
    }

    let places = store.list_places()?;
    if state
        .place_id
        .is_some_and(|id| !places.iter().any(|p| p.id == id))
    {
        reset_streak(&mut state); // forgotten while we were on it
    }
    let matched = best_match(&places, &fp).cloned();
    match &matched {
        Some(p) => {
            if state.place_id == Some(p.id) {
                state.streak += 1;
            } else {
                reset_streak(&mut state);
                state.place_id = Some(p.id);
                state.streak = 1;
            }
            store.update_place_members(p.id, &merged_members(&fp, &p.members), now)?;
        }
        None => {
            let continues = state.place_id.is_none()
                && !state.candidate.is_empty()
                && jaccard(&state.candidate, &fp) >= MATCH_JACCARD;
            if continues {
                state.streak += 1;
            } else {
                reset_streak(&mut state);
                state.streak = 1;
            }
            state.candidate = fp.clone();
        }
    }

    let this = Held {
        wifi: wifi_ids(&scan.wifi),
        ble: ble_ids(&scan.ble),
        at: now,
    };
    if state.streak < DWELL_SCANS {
        state.held.push(this);
        save(store, &state)?;
        return Ok(matched.map(|p| p.id));
    }

    // Dwell confirmed. An unmatched candidate becomes a place now.
    let place_id = match &matched {
        Some(p) => p.id,
        None => {
            let p = store.insert_place(None, &fp, now)?;
            state.place_id = Some(p.id);
            state.candidate.clear();
            p.id
        }
    };
    remove_mobile(store, &mut state)?;
    let mut batch: Vec<PlaceSighting> = Vec::new();
    for h in state.held.drain(..) {
        batch.extend(sightings_for(&h, place_id));
    }
    batch.extend(sightings_for(&this, place_id));
    store.add_place_sightings(&batch)?;
    save(store, &state)?;
    Ok(Some(place_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        hash_identifier, PermissionState, PermissionStatus, Salt, Security, TrackerKind,
    };

    const T0: Millis = 1_700_000_000_000;
    const MIN: Millis = 60_000;

    fn salt() -> Salt {
        Salt::from_bytes(vec![9; 32])
    }
    fn h(n: u32) -> String {
        hash_identifier(
            &salt(),
            &format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff),
        )
    }
    fn ap(n: u32, rssi: i32) -> WifiObservation {
        WifiObservation {
            ssid: Some("Net-A".into()),
            bssid_hash: Some(h(n)),
            rssi,
            channel: Some(6),
            security: Security::Wpa2Personal,
            seen_at: T0,
            vendor: None,
            group_id: None,
        }
    }
    fn tracker(id: &str) -> BleObservation {
        BleObservation {
            name: None,
            peripheral_hash: id.into(),
            rssi: Some(-60),
            tracker: Some(TrackerKind::Tile),
            owner_state: None,
            manufacturer_id: None,
            seen_at: T0,
        }
    }
    fn scan(wifi: Vec<WifiObservation>, ble: Vec<BleObservation>) -> ScanResult {
        ScanResult {
            scanned_at: T0,
            wifi,
            ble,
            errors: vec![],
            permissions: PermissionState {
                bluetooth: PermissionStatus::Granted,
                location: PermissionStatus::Granted,
            },
        }
    }
    fn aps(range: std::ops::Range<u32>) -> Vec<WifiObservation> {
        range.map(|n| ap(n, -60)).collect()
    }
    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        (d, s)
    }
    fn run(
        s: &mut Store,
        wifi: Vec<WifiObservation>,
        ble: Vec<BleObservation>,
        at: Millis,
    ) -> Option<i64> {
        update(s, &scan(wifi, ble), &Settings::default(), at).unwrap()
    }

    #[test]
    fn fingerprint_filters_weak_withheld_duplicates_and_caps() {
        let mut wifi = vec![ap(1, -60), ap(2, -80), ap(3, -81), ap(1, -50)];
        wifi.push(WifiObservation {
            bssid_hash: None,
            ..ap(4, -40)
        });
        let fp = fingerprint(&wifi, &BTreeSet::new());
        // -81 dropped, hash 1 deduped (strongest kept, so first), withheld skipped.
        assert_eq!(fp, vec![h(1), h(2)]);
        let many: Vec<_> = (0..60).map(|n| ap(n, -50 - n as i32 % 25)).collect();
        assert_eq!(fingerprint(&many, &BTreeSet::new()).len(), MAX_MEMBERS);
        let mobile: BTreeSet<String> = [h(1)].into();
        assert_eq!(fingerprint(&wifi, &mobile), vec![h(2)]);
    }

    #[test]
    fn jaccard_threshold_boundaries() {
        let a: Vec<String> = (0..10).map(h).collect();
        let b: Vec<String> = (7..17).map(h).collect(); // 3 shared / 17 union ~ 0.176
        assert!(jaccard(&a, &b) < MATCH_JACCARD);
        let c: Vec<String> = (5..15).map(h).collect(); // 5 / 15 = 0.33
        assert!(jaccard(&a, &c) >= MATCH_JACCARD);
        assert_eq!(jaccard(&[], &[]), 0.0);
        let place = |id, m: &[String]| Place {
            id,
            label: None,
            members: m.to_vec(),
            first_seen: T0,
            last_seen: T0,
        };
        let places = vec![place(1, &b), place(2, &a)];
        assert!(best_match(&places, &a).is_some_and(|p| p.id == 2));
        assert!(best_match(&places, &(100..110).map(h).collect::<Vec<_>>()).is_none());
    }

    #[test]
    fn too_few_usable_aps_means_unknown_place() {
        let (_d, mut s) = store();
        for i in 0..5 {
            // Two strong APs plus weak ones: only 2 usable.
            let mut w = aps(0..2);
            w.extend((10..20).map(|n| ap(n, -90)));
            assert_eq!(run(&mut s, w, vec![], T0 + i * MIN), None);
        }
        assert!(s.list_places().unwrap().is_empty());
        assert!(s.list_place_sightings().unwrap().is_empty());
    }

    #[test]
    fn dwell_needs_three_consecutive_scans_then_creates_one_place() {
        let (_d, mut s) = store();
        assert_eq!(run(&mut s, aps(0..8), vec![], T0), None);
        assert_eq!(run(&mut s, aps(0..8), vec![], T0 + MIN), None);
        assert!(
            s.list_places().unwrap().is_empty(),
            "no place before the third scan"
        );
        let id = run(&mut s, aps(0..8), vec![], T0 + 2 * MIN).expect("third scan confirms");
        assert_eq!(s.list_places().unwrap().len(), 1);
        // Pre-dwell scans are credited retroactively: 3 scans per AP.
        let sights = s.list_place_sightings().unwrap();
        assert_eq!(sights.len(), 8);
        assert!(sights.iter().all(|x| x.place_id == id && x.scans == 3));
        assert!(sights
            .iter()
            .all(|x| x.first_seen == T0 && x.last_seen == T0 + 2 * MIN));
        // The same place again matches rather than creating another.
        assert_eq!(run(&mut s, aps(2..10), vec![], T0 + 3 * MIN), Some(id));
        assert_eq!(s.list_places().unwrap().len(), 1);
    }

    #[test]
    fn transit_leaves_no_places_and_no_sightings() {
        let (_d, mut s) = store();
        // Each scan sees an entirely different set of APs, and a tracker rides along.
        for i in 0..12u32 {
            let w = aps(i * 20..i * 20 + 8);
            assert_eq!(
                run(&mut s, w, vec![tracker("dev-1")], T0 + i64::from(i) * MIN),
                None
            );
        }
        assert!(s.list_places().unwrap().is_empty());
        assert!(s.list_place_sightings().unwrap().is_empty());
    }

    #[test]
    fn a_gap_or_unknown_scan_breaks_the_streak() {
        let (_d, mut s) = store();
        run(&mut s, aps(0..8), vec![], T0);
        run(&mut s, aps(0..8), vec![], T0 + MIN);
        // A scan with no usable APs in between.
        run(&mut s, vec![], vec![], T0 + 2 * MIN);
        assert_eq!(run(&mut s, aps(0..8), vec![], T0 + 3 * MIN), None);
        // A long silence (> 3 scan intervals) also resets.
        run(&mut s, aps(0..8), vec![], T0 + 4 * MIN);
        assert_eq!(run(&mut s, aps(0..8), vec![], T0 + 60 * MIN), None);
        assert!(s.list_places().unwrap().is_empty());
    }

    #[test]
    fn two_distinct_places_and_only_trackers_are_recorded() {
        let (_d, mut s) = store();
        let other = BleObservation {
            tracker: None,
            peripheral_hash: "plain-1".into(),
            ..tracker("x")
        };
        let mut a = 0;
        for i in 0..3 {
            a = run(
                &mut s,
                aps(0..8),
                vec![tracker("dev-1"), other.clone()],
                T0 + i * MIN,
            )
            .unwrap_or(a);
        }
        let mut b = 0;
        for i in 0..3 {
            b = run(
                &mut s,
                aps(100..108),
                vec![tracker("dev-1")],
                T0 + (60 + i) * MIN,
            )
            .unwrap_or(b);
        }
        assert_ne!(a, b);
        assert_eq!(s.list_places().unwrap().len(), 2);
        let ble: Vec<_> = s
            .list_place_sightings()
            .unwrap()
            .into_iter()
            .filter(|x| x.kind == SightingKind::Ble)
            .collect();
        assert_eq!(
            ble.len(),
            2,
            "the tracker at both places, the plain device never"
        );
        assert!(ble.iter().all(|x| x.id_hash == "dev-1"));
    }

    #[test]
    fn mobile_ap_in_two_places_is_removed_from_members() {
        let (_d, mut s) = store();
        let with_mobile = |base: u32| {
            let mut w = aps(base..base + 8);
            w.push(ap(999, -50)); // the portable one, strongest everywhere
            w
        };
        for i in 0..3 {
            run(&mut s, with_mobile(0), vec![], T0 + i * MIN);
        }
        for i in 0..3 {
            run(&mut s, with_mobile(100), vec![], T0 + (60 + i) * MIN);
        }
        let places = s.list_places().unwrap();
        assert_eq!(
            places.len(),
            2,
            "the shared AP must not merge the two places"
        );
        assert!(places.iter().all(|p| !p.members.contains(&h(999))));
        // And it stays out when a later scan at place 1 matches and updates members.
        run(&mut s, with_mobile(0), vec![], T0 + 120 * MIN);
        assert!(s
            .list_places()
            .unwrap()
            .iter()
            .all(|p| !p.members.contains(&h(999))));
    }

    #[test]
    fn matching_updates_members_capped_and_strongest_first() {
        let (_d, mut s) = store();
        for i in 0..3 {
            run(&mut s, aps(0..30), vec![], T0 + i * MIN);
        }
        // 25 of the 30 plus 30 new ones: match is 25/(30+30) ~ 0.42.
        run(&mut s, aps(5..60), vec![], T0 + 3 * MIN);
        let p = &s.list_places().unwrap()[0];
        assert_eq!(p.members.len(), MAX_MEMBERS);
        assert_eq!(p.last_seen, T0 + 3 * MIN);
    }

    #[test]
    fn forgetting_a_place_mid_streak_does_not_resurrect_it() {
        let (_d, mut s) = store();
        for i in 0..3 {
            run(&mut s, aps(0..8), vec![], T0 + i * MIN);
        }
        let id = s.list_places().unwrap()[0].id;
        s.forget_place(id).unwrap();
        assert_eq!(run(&mut s, aps(0..8), vec![], T0 + 3 * MIN), None);
        assert!(s.list_places().unwrap().is_empty());
        assert!(s.list_place_sightings().unwrap().is_empty());
    }
}
