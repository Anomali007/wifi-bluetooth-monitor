//! Detection engine: pure functions over a [`History`]. OWNER: WP4.
//!
//! CONTRACT (frozen):
//! - [`evaluate`] is pure: no I/O, no clock, no randomness. `now` is passed in.
//! - Rules (each gated by `settings.alert_toggles`): EvilTwin, OpenLookalike,
//!   TrustedNetworkChanged, PersistentTracker, NewDevice. See the roadmap for definitions.
//!   v2 adds FollowedAcrossPlaces (`follow`), Watchlist (`watchlist`) and NewLanDevice (`lan`),
//!   which read the extra state in [`DetectContext`]. [`evaluate`] is the context-free form
//!   (empty context); the pipeline calls [`evaluate_with`].
//! - Returned alerts are deduplicated by `(kind, subject_hash)` within the call, with
//!   `first_seen`/`last_seen` taken from the history. `id` is a stable function of
//!   `(kind, subject_hash)`, and `dismissed` is always `false`; the store merges repeats
//!   across calls and owns dismissal.
//! - PersistentTracker alerts say "possible" and never claim certainty (IDs rotate).
//! - Subjects are hashes only; no raw identifier appears in `title` or `detail`.

mod follow;
mod lan;
mod watchlist;

use crate::model::{
    Alert, AlertKind, History, LanDevice, Millis, MineEntry, MineKind, NetworkInfo, Place,
    PlaceSighting, ScanSnapshot, Security, Settings, Severity, TrackerKind, TrustedNetwork,
    WatchlistEntry, WifiObservation,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// State beyond the scan history that the v2 rules read. Built by the pipeline from the store
/// (and the live LAN outcome); `Default` is "nothing known", under which v2 rules stay silent
/// and the v1 rules behave exactly as before.
#[derive(Debug, Clone, Default)]
pub struct DetectContext {
    pub mine: Vec<MineEntry>,
    pub watchlist: Vec<WatchlistEntry>,
    pub places: Vec<Place>,
    pub place_sightings: Vec<PlaceSighting>,
    pub lan_devices: Vec<LanDevice>,
    /// The joined network right now, if a LAN observation ran this cycle.
    pub current_network: Option<NetworkInfo>,
}

impl DetectContext {
    /// Whether `id_hash` is marked mine under any of `kinds`.
    pub fn is_mine(&self, kinds: &[MineKind], id_hash: &str) -> bool {
        self.mine
            .iter()
            .any(|m| m.id_hash == id_hash && kinds.contains(&m.kind))
    }
}

/// A tracker not seen for this long is no longer "following" the user.
const TRACKER_STALE_MS: Millis = 10 * 60 * 1000;
/// Consecutive missed scans tolerated inside a tracker-kind presence run (BLE scans are lossy).
const KIND_MAX_CONSECUTIVE_MISSES: usize = 1;
/// SSIDs shorter than this (after folding) must match exactly to count as a lookalike.
const MIN_FUZZY_LEN: usize = 4;

/// Evaluate every enabled rule over `history` as of `now` (Unix ms), with no v2 context.
pub fn evaluate(history: &History, settings: &Settings, now: Millis) -> Vec<Alert> {
    evaluate_with(history, settings, &DetectContext::default(), now)
}

/// [`evaluate`] plus the extra state the v2 rules read.
pub fn evaluate_with(
    history: &History,
    settings: &Settings,
    ctx: &DetectContext,
    now: Millis,
) -> Vec<Alert> {
    let mut out = Collector::default();
    let t = &settings.alert_toggles;
    if t.evil_twin {
        evil_twin(history, &mut out);
    }
    if t.open_lookalike {
        open_lookalike(history, settings, &mut out);
    }
    if t.trusted_network_changed {
        trusted_network_changed(history, settings, ctx, &mut out);
    }
    if t.persistent_tracker {
        persistent_tracker(history, settings, now, &mut out);
    }
    if t.new_device {
        new_device(history, &mut out);
    }
    if t.followed_across_places {
        follow::followed_across_places(history, settings, ctx, now, &mut out);
    }
    if t.watchlist {
        watchlist::watchlist(history, settings, ctx, now, &mut out);
    }
    if t.new_lan_device {
        lan::new_lan_device(history, settings, ctx, now, &mut out);
    }
    out.finish()
}

// ---------------------------------------------------------------------------
// Collection, ids, hashing
// ---------------------------------------------------------------------------

fn kind_tag(kind: AlertKind) -> &'static str {
    match kind {
        AlertKind::EvilTwin => "evilTwin",
        AlertKind::OpenLookalike => "openLookalike",
        AlertKind::TrustedNetworkChanged => "trustedNetworkChanged",
        AlertKind::PersistentTracker => "persistentTracker",
        AlertKind::NewDevice => "newDevice",
        AlertKind::FollowedAcrossPlaces => "followedAcrossPlaces",
        AlertKind::Watchlist => "watchlist",
        AlertKind::NewLanDevice => "newLanDevice",
    }
}

fn sha_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Unsalted subject key for things that are not device identifiers (network names, tracker
/// families). Namespaced so different subject types can never collide.
fn subject_key(namespace: &str, value: &str) -> String {
    sha_hex(&format!("{namespace}\u{1f}{value}"))
}

/// The `subject_hash` of the evil-twin and open-lookalike alerts about a network name. Lets a
/// caller find the alerts for a name without reading alert text.
pub fn ssid_subject_hash(ssid: &str) -> String {
    subject_key("ssid", &fold_ssid(ssid))
}

fn alert_id(kind: AlertKind, subject_hash: &str) -> String {
    sha_hex(&format!("{}\u{1f}{}", kind_tag(kind), subject_hash))
}

#[derive(Default)]
struct Collector {
    map: BTreeMap<(&'static str, String), Alert>,
}

impl Collector {
    /// Insert, or merge into the existing `(kind, subject)` alert: widen the seen range, keep the
    /// highest severity, and keep the text of the most recent sighting.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        kind: AlertKind,
        severity: Severity,
        title: String,
        detail: String,
        first_seen: Millis,
        last_seen: Millis,
        subject_hash: String,
    ) {
        let key = (kind_tag(kind), subject_hash.clone());
        match self.map.get_mut(&key) {
            Some(a) => {
                if last_seen >= a.last_seen {
                    a.title = title;
                    a.detail = detail;
                }
                a.first_seen = a.first_seen.min(first_seen);
                a.last_seen = a.last_seen.max(last_seen);
                a.severity = a.severity.max(severity);
            }
            None => {
                let id = alert_id(kind, &subject_hash);
                self.map.insert(
                    key,
                    Alert {
                        id,
                        kind,
                        severity,
                        title,
                        detail,
                        first_seen,
                        last_seen,
                        subject_hash,
                        dismissed: false,
                    },
                );
            }
        }
    }

    fn finish(self) -> Vec<Alert> {
        let mut v: Vec<Alert> = self.map.into_values().collect();
        v.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| kind_tag(a.kind).cmp(kind_tag(b.kind)))
                .then_with(|| a.subject_hash.cmp(&b.subject_hash))
        });
        v
    }
}

// ---------------------------------------------------------------------------
// SSID folding and edit distance
// ---------------------------------------------------------------------------

/// Fold an SSID for comparison: drop zero-width and control characters, collapse whitespace,
/// lowercase, map full-width ASCII, Cyrillic/Greek lookalikes and 0/1/| to Latin letters.
fn fold_ssid(s: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for c in s.chars() {
        if matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}') || c.is_control() {
            continue;
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        let c = match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        };
        for l in c.to_lowercase() {
            out.push(match l {
                'а' | 'α' => 'a',
                'в' => 'b',
                'с' | 'ϲ' => 'c',
                'е' | 'ε' => 'e',
                'н' => 'h',
                'і' | 'ι' => 'i',
                'ј' => 'j',
                'к' | 'κ' => 'k',
                'м' => 'm',
                'о' | 'ο' | '0' => 'o',
                'р' | 'ρ' => 'p',
                'ѕ' => 's',
                'т' | 'τ' => 't',
                'ν' => 'v',
                'х' | 'χ' => 'x',
                'у' | 'γ' => 'y',
                '1' | '|' => 'l',
                other => other,
            });
        }
    }
    out
}

/// Levenshtein distance over chars.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn is_lookalike(observed: &str, trusted: &str) -> bool {
    let (o, t) = (fold_ssid(observed), fold_ssid(trusted));
    if o.is_empty() || t.is_empty() {
        return false;
    }
    if o == t {
        return true;
    }
    o.chars().count().min(t.chars().count()) >= MIN_FUZZY_LEN && edit_distance(&o, &t) <= 1
}

// ---------------------------------------------------------------------------
// Wi-Fi rules
// ---------------------------------------------------------------------------

fn wifi_scans(history: &History) -> impl Iterator<Item = &ScanSnapshot> {
    history.scans.iter()
}

fn named(o: &WifiObservation) -> Option<&str> {
    o.ssid.as_deref().filter(|s| !s.trim().is_empty())
}

fn is_personal_class(s: Security) -> bool {
    matches!(
        s,
        Security::WpaPersonal | Security::Wpa2Personal | Security::Wpa3Personal
    )
}

fn is_enterprise_class(s: Security) -> bool {
    matches!(
        s,
        Security::WpaEnterprise | Security::Wpa2Enterprise | Security::Wpa3Enterprise
    )
}

fn evil_twin(history: &History, out: &mut Collector) {
    for scan in wifi_scans(history) {
        // ssid -> (distinct bssids, distinct known securities)
        let mut groups: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<SecKey>)> = BTreeMap::new();
        for o in &scan.wifi {
            let (Some(ssid), Some(b)) = (named(o), o.bssid_hash.as_deref()) else {
                continue;
            };
            let g = groups.entry(ssid).or_default();
            g.0.insert(b);
            if o.security != Security::Unknown {
                g.1.insert(SecKey(o.security));
            }
        }
        for (ssid, (bssids, secs)) in groups {
            if bssids.len() < 2 || secs.len() < 2 {
                continue;
            }
            let secs: Vec<Security> = secs.into_iter().map(|k| k.0).collect();
            let has_open = secs.iter().any(|s| s.is_open());
            let all_open_or_secured = has_open && secs.iter().any(|s| !s.is_open());
            let severity = if all_open_or_secured {
                Severity::High
            } else if secs.iter().all(|s| is_personal_class(*s))
                || secs.iter().all(|s| is_enterprise_class(*s))
            {
                // Only the WPA generation differs (e.g. WPA2/WPA3 across bands): common on
                // legitimate multi-AP setups.
                Severity::Low
            } else {
                Severity::Medium
            };
            out.add(
                AlertKind::EvilTwin,
                severity,
                format!("Possible evil twin: \"{ssid}\""),
                format!(
                    "{} access points advertise the network \"{ssid}\" with different security \
                     modes{}. A rogue access point can copy a real network's name; verify \
                     before connecting.",
                    bssids.len(),
                    if all_open_or_secured {
                        " (one is open while another is secured)"
                    } else {
                        ""
                    }
                ),
                scan.scanned_at,
                scan.scanned_at,
                subject_key("ssid", &fold_ssid(ssid)),
            );
        }
    }
}

/// `Security` has no `Ord`; wrap it for set membership with a stable order.
#[derive(PartialEq, Eq)]
struct SecKey(Security);
impl Ord for SecKey {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.0.strength(), self.0 as u8).cmp(&(o.0.strength(), o.0 as u8))
    }
}
impl PartialOrd for SecKey {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

fn trusted_for<'a>(settings: &'a Settings, ssid: &str) -> Option<&'a TrustedNetwork> {
    settings.trusted_networks.iter().find(|t| t.ssid == ssid)
}

fn open_lookalike(history: &History, settings: &Settings, out: &mut Collector) {
    if settings.trusted_networks.is_empty() {
        return;
    }
    for scan in wifi_scans(history) {
        for o in scan.wifi.iter().filter(|o| o.security.is_open()) {
            let Some(ssid) = named(o) else { continue };
            for t in &settings.trusted_networks {
                if !is_lookalike(ssid, &t.ssid) {
                    continue;
                }
                if ssid == t.ssid {
                    // The trusted network itself: fine if it is meant to be open, or if this is
                    // a known access point (a downgrade there is TrustedNetworkChanged's job).
                    let known = o
                        .bssid_hash
                        .as_ref()
                        .is_some_and(|b| t.known_bssid_hashes.contains(b));
                    if t.expected_security.is_open() || known {
                        continue;
                    }
                }
                out.add(
                    AlertKind::OpenLookalike,
                    Severity::High,
                    format!("Open network imitates \"{}\"", t.ssid),
                    format!(
                        "An open (unencrypted) network named \"{ssid}\" looks like your trusted \
                         network \"{}\". Do not connect to it.",
                        t.ssid
                    ),
                    scan.scanned_at,
                    scan.scanned_at,
                    subject_key("ssid", &fold_ssid(ssid)),
                );
            }
        }
    }
}

fn trusted_network_changed(
    history: &History,
    settings: &Settings,
    ctx: &DetectContext,
    out: &mut Collector,
) {
    if settings.trusted_networks.is_empty() {
        return;
    }
    for scan in wifi_scans(history) {
        for o in &scan.wifi {
            let Some(t) = named(o).and_then(|s| trusted_for(settings, s)) else {
                continue;
            };
            // An access point (or its whole radio group) marked mine counts as known, the same
            // as one listed on the trusted network itself: one concept, two ways to record it.
            let marked_mine = o
                .bssid_hash
                .as_deref()
                .is_some_and(|b| ctx.is_mine(&[MineKind::WifiAp], b))
                || o.group_id
                    .as_deref()
                    .is_some_and(|g| ctx.is_mine(&[MineKind::WifiGroup], g));
            let unknown_bssid = match o.bssid_hash.as_ref() {
                // With no known BSSIDs on file there is nothing to compare against.
                Some(b) => {
                    !marked_mine
                        && !t.known_bssid_hashes.is_empty()
                        && !t.known_bssid_hashes.contains(b)
                }
                None => false,
            };
            let downgrade = o.security != Security::Unknown
                && t.expected_security != Security::Unknown
                && o.security.strength() < t.expected_security.strength();
            if !unknown_bssid && !downgrade {
                continue;
            }
            let mut reasons = Vec::new();
            if unknown_bssid {
                reasons.push("an access point you have not marked as yours");
            }
            if downgrade {
                reasons.push("weaker security than you expect");
            }
            let subject = subject_key(
                "trusted",
                &format!(
                    "{}\u{1f}{}",
                    t.ssid,
                    o.bssid_hash.as_deref().unwrap_or("none")
                ),
            );
            out.add(
                AlertKind::TrustedNetworkChanged,
                if downgrade {
                    Severity::High
                } else {
                    Severity::Medium
                },
                format!("Trusted network \"{}\" changed", t.ssid),
                format!(
                    "\"{}\" is now offered by {}. This can be a new access point of your own \
                     or an impostor; check before relying on it.",
                    t.ssid,
                    reasons.join(" with ")
                ),
                scan.scanned_at,
                scan.scanned_at,
                subject,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// BLE rules
// ---------------------------------------------------------------------------

fn tracker_label(k: TrackerKind) -> &'static str {
    match k {
        TrackerKind::AppleFindMy => "Apple Find My",
        TrackerKind::Tile => "Tile",
        TrackerKind::SamsungSmartTag => "Samsung SmartTag",
        TrackerKind::Chipolo => "Chipolo",
        TrackerKind::Pebblebee => "Pebblebee",
        TrackerKind::GoogleFindMy => "Google Find My Device",
        TrackerKind::UnknownTracker => "unidentified",
    }
}

struct Run {
    count: usize,
    first: Millis,
    last: Millis,
}

/// Latest run of scans (`present[i]` true) that satisfies the thresholds, tolerating up to
/// `max_misses` consecutive absent scans inside a run.
fn qualifying_run(
    scans: &[ScanSnapshot],
    present: &[bool],
    max_misses: usize,
    min_scans: usize,
    min_span_ms: Millis,
) -> Option<(Run, usize, usize)> {
    let mut best: Option<(Run, usize, usize)> = None;
    let mut cur: Option<(usize, usize, usize)> = None; // (start idx, last present idx, count)
    let mut misses = 0usize;
    let close = |cur: &mut Option<(usize, usize, usize)>,
                 best: &mut Option<(Run, usize, usize)>| {
        if let Some((s, l, count)) = cur.take() {
            let run = Run {
                count,
                first: scans[s].scanned_at,
                last: scans[l].scanned_at,
            };
            if run.count >= min_scans && run.last - run.first >= min_span_ms {
                *best = Some((run, s, l));
            }
        }
    };
    for (i, &is_present) in present.iter().enumerate() {
        if is_present {
            misses = 0;
            cur = Some(match cur {
                Some((s, _, c)) => (s, i, c + 1),
                None => (i, i, 1),
            });
        } else {
            misses += 1;
            if misses > max_misses {
                close(&mut cur, &mut best);
            }
        }
    }
    close(&mut cur, &mut best);
    best
}

fn persistent_tracker(history: &History, settings: &Settings, now: Millis, out: &mut Collector) {
    let scans = &history.scans;
    let min_scans = settings.tracker_min_scans.max(1) as usize;
    let min_span = Millis::from(settings.tracker_min_minutes) * 60_000;

    // Per device: appearances across the window, continuity not required.
    let mut devices: BTreeMap<&str, TrackerKind> = BTreeMap::new();
    for s in scans {
        for b in s.ble.iter().filter(|b| b.tracker.is_some()) {
            devices
                .entry(b.peripheral_hash.as_str())
                .or_insert(b.tracker.unwrap());
        }
    }
    let mut device_alerted: BTreeSet<TrackerKindKey> = BTreeSet::new();
    for (hash, kind) in &devices {
        let present: Vec<bool> = scans
            .iter()
            .map(|s| s.ble.iter().any(|b| b.peripheral_hash == *hash))
            .collect();
        let Some((run, _, _)) = qualifying_run(scans, &present, usize::MAX, min_scans, min_span)
        else {
            continue;
        };
        if now - run.last > TRACKER_STALE_MS {
            continue;
        }
        device_alerted.insert(TrackerKindKey(*kind));
        let mins = (run.last - run.first) / 60_000;
        out.add(
            AlertKind::PersistentTracker,
            Severity::Medium,
            format!("Possible tracker nearby ({})", tracker_label(*kind)),
            format!(
                "A device matching a {} tracker signature appeared in {} scans over {} minutes. \
                 This is a best guess: it may be someone else's item or your own.",
                tracker_label(*kind),
                run.count,
                mins
            ),
            run.first,
            run.last,
            (*hash).to_string(),
        );
    }

    // Per tracker family: survives identifier rotation by requiring near-continuous
    // presence of the family instead. DULT draft 01 section 3.5: an accessory rotates its
    // address every 15 minutes near its owner and every 24 hours when separated; vendors
    // other than Apple may differ, so this stays a Low-severity best guess.
    let kinds: BTreeSet<TrackerKindKey> = devices
        .values()
        .copied()
        .filter(|k| *k != TrackerKind::UnknownTracker)
        .map(TrackerKindKey)
        .collect();
    for TrackerKindKey(kind) in kinds {
        let present: Vec<bool> = scans
            .iter()
            .map(|s| s.ble.iter().any(|b| b.tracker == Some(kind)))
            .collect();
        let Some((run, s, l)) = qualifying_run(
            scans,
            &present,
            KIND_MAX_CONSECUTIVE_MISSES,
            min_scans,
            min_span,
        ) else {
            continue;
        };
        if now - run.last > TRACKER_STALE_MS {
            continue;
        }
        let distinct: BTreeSet<&str> = scans[s..=l]
            .iter()
            .flat_map(|sc| sc.ble.iter())
            .filter(|b| b.tracker == Some(kind))
            .map(|b| b.peripheral_hash.as_str())
            .collect();
        // One stable device is already reported above; this rule is for rotating identifiers.
        if distinct.len() < 2 || device_alerted.contains(&TrackerKindKey(kind)) {
            continue;
        }
        let mins = (run.last - run.first) / 60_000;
        out.add(
            AlertKind::PersistentTracker,
            Severity::Low,
            format!("Possible rotating tracker nearby ({})", tracker_label(kind)),
            format!(
                "{} tracker signals were present in {} scans over {} minutes while their \
                 identifiers changed, which is how a separated tracker behaves. This is a best \
                 guess; crowded places can look the same.",
                tracker_label(kind),
                run.count,
                mins
            ),
            run.first,
            run.last,
            subject_key("trackerKind", tracker_label(kind)),
        );
    }
}

#[derive(PartialEq, Eq)]
struct TrackerKindKey(TrackerKind);
impl Clone for TrackerKindKey {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for TrackerKindKey {}
impl TrackerKindKey {
    fn rank(&self) -> u8 {
        self.0 as u8
    }
}
impl Ord for TrackerKindKey {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&o.rank())
    }
}
impl PartialOrd for TrackerKindKey {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

fn new_device(history: &History, out: &mut Collector) {
    // The first scan in the window is the baseline; only devices that appear later are new.
    let Some((first, rest)) = history.scans.split_first() else {
        return;
    };
    let mut known: BTreeSet<&str> = first
        .ble
        .iter()
        .map(|b| b.peripheral_hash.as_str())
        .collect();
    for scan in rest {
        for b in scan.ble.iter().filter(|b| b.tracker.is_none()) {
            if known.insert(b.peripheral_hash.as_str()) {
                out.add(
                    AlertKind::NewDevice,
                    Severity::Info,
                    "New Bluetooth device nearby".to_string(),
                    "A Bluetooth device that was not present earlier in this window has appeared."
                        .to_string(),
                    scan.scanned_at,
                    scan.scanned_at,
                    b.peripheral_hash.clone(),
                );
            }
        }
        // Trackers are not "new devices"; keep them out of the baseline too so that, if the
        // tracker classification later drops, they are not misreported.
        known.extend(rest_trackers(scan));
    }
}

fn rest_trackers(scan: &ScanSnapshot) -> impl Iterator<Item = &str> {
    scan.ble
        .iter()
        .filter(|b| b.tracker.is_some())
        .map(|b| b.peripheral_hash.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{hash_identifier, AlertToggles, BleObservation, Salt};

    const T0: Millis = 1_700_000_000_000;
    const MIN: Millis = 60_000;

    fn salt() -> Salt {
        Salt::from_bytes(vec![9; 32])
    }
    /// Synthetic locally administered BSSID, hashed like the real scanner does.
    fn bssid(n: u8) -> String {
        hash_identifier(&salt(), &format!("02:00:00:00:00:{n:02x}"))
    }
    fn dev(n: u8) -> String {
        hash_identifier(&salt(), &format!("synthetic-peripheral-{n}"))
    }
    fn ap(ssid: &str, b: u8, sec: Security) -> WifiObservation {
        WifiObservation {
            ssid: Some(ssid.to_string()),
            bssid_hash: Some(bssid(b)),
            rssi: -60,
            channel: Some(36),
            security: sec,
            seen_at: T0,
            vendor: None,
            group_id: None,
        }
    }
    fn ble(d: u8, tracker: Option<TrackerKind>) -> BleObservation {
        BleObservation {
            name: None,
            peripheral_hash: dev(d),
            rssi: Some(-70),
            tracker,
            owner_state: None,
            manufacturer_id: None,
            seen_at: T0,
        }
    }
    fn scan(i: i64, wifi: Vec<WifiObservation>, ble: Vec<BleObservation>) -> ScanSnapshot {
        ScanSnapshot {
            scanned_at: T0 + i * MIN,
            wifi,
            ble,
        }
    }
    fn hist(scans: Vec<ScanSnapshot>) -> History {
        History { scans }
    }
    fn trusted(ssid: &str, known: &[u8], sec: Security) -> TrustedNetwork {
        TrustedNetwork {
            ssid: ssid.to_string(),
            known_bssid_hashes: known.iter().map(|n| bssid(*n)).collect(),
            expected_security: sec,
        }
    }
    fn settings_with(trusted: Vec<TrustedNetwork>) -> Settings {
        Settings {
            trusted_networks: trusted,
            ..Settings::default()
        }
    }
    fn only_kind(alerts: &[Alert], kind: AlertKind) -> Vec<&Alert> {
        alerts.iter().filter(|a| a.kind == kind).collect()
    }
    fn at(i: i64) -> Millis {
        T0 + i * MIN
    }

    // ---- helpers ----------------------------------------------------------

    #[test]
    fn edit_distance_table() {
        let cases = [
            ("", "", 0),
            ("abc", "abc", 0),
            ("abc", "abd", 1),
            ("abc", "abcd", 1),
            ("abc", "ac", 1),
            ("kitten", "sitting", 3),
            ("abc", "xyz", 3),
        ];
        for (a, b, d) in cases {
            assert_eq!(edit_distance(a, b), d, "{a} vs {b}");
        }
    }

    #[test]
    fn lookalike_table() {
        // (observed, trusted, expected)
        let cases = [
            ("Net-A", "Net-A", true),
            ("net-a", "Net-A", true),
            ("  Net-A  ", "Net-A", true),
            ("Net -A", "Net-A", true), // distance 1
            ("Net-B", "Net-A", true),  // distance 1
            ("Net-AB", "Net-A", true),
            ("Net-ABC", "Net-A", false), // distance 2
            ("Cafe-Guest", "Cafe-Guest", true),
            ("Cаfe-Guest", "Cafe-Guest", true), // Cyrillic a
            ("Caf\u{200B}e-Guest", "Cafe-Guest", true), // zero width
            ("Ｃafe-Guest", "Cafe-Guest", true), // full-width C
            ("Cafe-Gue5t", "Cafe-Guest", true),
            ("Cafe-Guest2", "Cafe-Guest", true),
            ("Home-Lab", "Cafe-Guest", false),
            ("Ab", "Ac", false), // too short for fuzzy
            ("Ab", "Ab", true),
            ("", "Net-A", false),
        ];
        for (o, t, exp) in cases {
            assert_eq!(is_lookalike(o, t), exp, "{o:?} vs {t:?}");
        }
    }

    // ---- EvilTwin ---------------------------------------------------------

    #[test]
    fn evil_twin_table() {
        use Security::*;
        // (aps in one scan, expected severity or None)
        let cases: Vec<(Vec<WifiObservation>, Option<Severity>)> = vec![
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 2, Open)],
                Some(Severity::High),
            ),
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 2, Wpa3Personal)],
                Some(Severity::Low),
            ),
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 2, Wpa2Enterprise)],
                Some(Severity::Medium),
            ),
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 2, Wpa2Personal)],
                None,
            ),
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-B", 2, Open)],
                None,
            ),
            (vec![ap("Net-A", 1, Open)], None),
            // same BSSID twice with different security is not two access points
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 1, Open)],
                None,
            ),
            (
                vec![ap("Net-A", 1, Wpa2Personal), ap("Net-A", 2, Unknown)],
                None,
            ),
            (
                vec![
                    WifiObservation {
                        ssid: None,
                        ..ap("x", 1, Open)
                    },
                    WifiObservation {
                        ssid: None,
                        ..ap("x", 2, Wpa2Personal)
                    },
                ],
                None,
            ),
        ];
        for (i, (aps, exp)) in cases.into_iter().enumerate() {
            let a = evaluate(
                &hist(vec![scan(0, aps, vec![])]),
                &Settings::default(),
                at(0),
            );
            let got = only_kind(&a, AlertKind::EvilTwin);
            match exp {
                Some(sev) => {
                    assert_eq!(got.len(), 1, "case {i}");
                    assert_eq!(got[0].severity, sev, "case {i}");
                }
                None => assert!(got.is_empty(), "case {i}: {got:?}"),
            }
        }
    }

    // ---- OpenLookalike ----------------------------------------------------

    #[test]
    fn open_lookalike_table() {
        use Security::*;
        let tr = vec![trusted("Cafe-Guest", &[1], Wpa2Personal)];
        // (observed ap, fires)
        let cases: Vec<(WifiObservation, bool)> = vec![
            (ap("Cafe-Guest", 9, Open), true),  // exact name, unknown AP, open
            (ap("cafe-guest ", 9, Open), true), // case/space
            (ap("Cаfe-Guest", 9, Open), true),  // homoglyph
            (ap("Cafe-Guesst", 9, Open), true), // distance 1
            (ap("Cafe-Guest", 9, Wpa2Personal), false), // secured copy: not "open"
            (ap("Cafe-Gue", 9, Open), false),   // distance 2
            (ap("Totally-Other", 9, Open), false),
            (ap("Cafe-Guest", 1, Open), false), // known AP: downgrade rule's job
        ];
        for (i, (o, fires)) in cases.into_iter().enumerate() {
            let a = evaluate(
                &hist(vec![scan(0, vec![o], vec![])]),
                &settings_with(tr.clone()),
                at(0),
            );
            assert_eq!(
                only_kind(&a, AlertKind::OpenLookalike).len(),
                usize::from(fires),
                "case {i}"
            );
        }
    }

    #[test]
    fn open_lookalike_ignores_trusted_open_network_and_empty_trust_list() {
        let s_open = settings_with(vec![trusted("Cafe-Guest", &[], Security::Open)]);
        let h = hist(vec![scan(
            0,
            vec![ap("Cafe-Guest", 9, Security::Open)],
            vec![],
        )]);
        assert!(only_kind(&evaluate(&h, &s_open, at(0)), AlertKind::OpenLookalike).is_empty());
        assert!(evaluate(&h, &Settings::default(), at(0)).is_empty());
    }

    // ---- TrustedNetworkChanged -------------------------------------------

    #[test]
    fn trusted_changed_table() {
        use Security::*;
        let tr = vec![trusted("Net-A", &[1, 2], Wpa2Personal)];
        // (observed, expected severity or None)
        let cases: Vec<(WifiObservation, Option<Severity>)> = vec![
            (ap("Net-A", 1, Wpa2Personal), None),
            (ap("Net-A", 2, Wpa3Personal), None), // upgrade is fine
            (ap("Net-A", 7, Wpa2Personal), Some(Severity::Medium)), // unknown BSSID
            (ap("Net-A", 1, Open), Some(Severity::High)), // downgrade
            (ap("Net-A", 1, Wep), Some(Severity::High)),
            (ap("Net-A", 7, Open), Some(Severity::High)), // both
            (ap("Net-A", 1, Unknown), None),              // cannot compare
            (ap("Net-A", 1, Owe), Some(Severity::High)),  // encrypted but no password: weaker
            (ap("Net-B", 7, Open), None),                 // not trusted
        ];
        for (i, (o, exp)) in cases.into_iter().enumerate() {
            let a = evaluate(
                &hist(vec![scan(0, vec![o], vec![])]),
                &settings_with(tr.clone()),
                at(0),
            );
            let got = only_kind(&a, AlertKind::TrustedNetworkChanged);
            match exp {
                Some(sev) => {
                    assert_eq!(got.len(), 1, "case {i}");
                    assert_eq!(got[0].severity, sev, "case {i}");
                }
                None => assert!(got.is_empty(), "case {i}"),
            }
        }
    }

    #[test]
    fn trusted_without_known_bssids_only_checks_security() {
        let s = settings_with(vec![trusted("Net-A", &[], Security::Wpa2Personal)]);
        let ok = hist(vec![scan(
            0,
            vec![ap("Net-A", 7, Security::Wpa2Personal)],
            vec![],
        )]);
        let bad = hist(vec![scan(0, vec![ap("Net-A", 7, Security::Open)], vec![])]);
        assert!(evaluate(&ok, &s, at(0)).is_empty());
        assert_eq!(
            only_kind(&evaluate(&bad, &s, at(0)), AlertKind::TrustedNetworkChanged).len(),
            1
        );
    }

    #[test]
    fn wpa2_wpa3_transition_network_is_not_a_downgrade_against_trusted_wpa2() {
        // WP1 maps a WPA2/WPA3 transition network to Wpa3Personal. A trusted Wpa2Personal
        // network seen that way (known BSSID) must stay silent.
        let tr = vec![trusted("Net-A", &[1], Security::Wpa2Personal)];
        let h = hist(vec![scan(
            0,
            vec![ap("Net-A", 1, Security::Wpa3Personal)],
            vec![],
        )]);
        let a = evaluate(&h, &settings_with(tr), at(0));
        assert!(only_kind(&a, AlertKind::TrustedNetworkChanged).is_empty());
        assert!(only_kind(&a, AlertKind::EvilTwin).is_empty());
    }

    #[test]
    fn owe_is_never_treated_as_open() {
        // An OWE AP next to a secured AP with the same name is a security-mode mismatch,
        // but OWE must not be reported as an "open" network.
        let h = hist(vec![scan(
            0,
            vec![
                ap("Net-A", 1, Security::Owe),
                ap("Net-A", 2, Security::Wpa2Personal),
            ],
            vec![],
        )]);
        let a = evaluate(&h, &settings_with(vec![]), at(0));
        assert!(!a.iter().any(|x| x.detail.contains("one is open")));
        let h2 = hist(vec![scan(0, vec![ap("Net-A", 1, Security::Owe)], vec![])]);
        let s = settings_with(vec![trusted("Net-A", &[], Security::Wpa2Personal)]);
        assert!(only_kind(&evaluate(&h2, &s, at(0)), AlertKind::OpenLookalike).is_empty());
    }

    // ---- PersistentTracker -----------------------------------------------

    #[test]
    fn pebblebee_and_google_trackers_are_labelled() {
        for (kind, label) in [
            (TrackerKind::Pebblebee, "Pebblebee"),
            (TrackerKind::GoogleFindMy, "Google Find My Device"),
        ] {
            let a = evaluate(
                &tracker_hist(5, 5, kind, |_| 1),
                &Settings::default(),
                at(20),
            );
            let got = only_kind(&a, AlertKind::PersistentTracker);
            assert_eq!(got.len(), 1);
            assert!(got[0].title.contains(label) && got[0].title.contains("Possible"));
        }
    }

    fn tracker_hist(n_scans: i64, step: i64, kind: TrackerKind, id: impl Fn(i64) -> u8) -> History {
        hist(
            (0..n_scans)
                .map(|i| scan(i * step, vec![], vec![ble(id(i), Some(kind))]))
                .collect(),
        )
    }

    #[test]
    fn tracker_table() {
        use TrackerKind::*;
        // (history, now offset in scans, expect device alerts, expect kind alerts)
        let stable = |n, step| tracker_hist(n, step, Tile, |_| 1);
        // rotation every 15 scans-minutes: new id each 15 minutes, 1 scan/min
        let rotating = tracker_hist(25, 1, AppleFindMy, |i| (i / 15) as u8 + 1);
        let cases: Vec<(&str, History, Millis, usize, usize)> = vec![
            ("stable 5 scans / 20 min", stable(5, 5), at(20), 1, 0),
            ("stable 4 scans", stable(4, 10), at(30), 0, 0),
            ("stable 5 scans but only 4 min", stable(5, 1), at(4), 0, 0),
            (
                "stable 5 scans / 19 min",
                hist(
                    (0..5)
                        .map(|i| scan(i * 19 / 4, vec![], vec![ble(1, Some(Tile))]))
                        .collect(),
                ),
                at(19),
                0,
                0,
            ),
            (
                "stale: last seen 2 h ago",
                stable(5, 5),
                at(20) + 120 * MIN,
                0,
                0,
            ),
            ("rotating Find My", rotating.clone(), at(24), 0, 1),
            (
                "non-tracker never alerts",
                hist(
                    (0..10)
                        .map(|i| scan(i * 5, vec![], vec![ble(1, None)]))
                        .collect(),
                ),
                at(45),
                0,
                0,
            ),
            (
                "unknown tracker kind is not grouped",
                tracker_hist(25, 1, UnknownTracker, |i| (i / 15) as u8 + 1),
                at(24),
                0,
                0,
            ),
        ];
        for (name, h, now, dev_n, kind_n) in cases {
            let a = evaluate(&h, &Settings::default(), now);
            let trackers = only_kind(&a, AlertKind::PersistentTracker);
            let kind_alerts = trackers
                .iter()
                .filter(|x| x.severity == Severity::Low)
                .count();
            assert_eq!(trackers.len() - kind_alerts, dev_n, "{name}: device alerts");
            assert_eq!(kind_alerts, kind_n, "{name}: kind alerts");
        }
    }

    #[test]
    fn tracker_gap_breaks_kind_run_but_one_miss_is_tolerated() {
        use TrackerKind::AppleFindMy as K;
        // ids rotate each scan so no single device qualifies.
        // One miss tolerated: scans 0..=24 minus scan 10 (as an empty scan, not removed).
        let with_empty = |empty: &[i64]| {
            hist(
                (0..25)
                    .map(|i| {
                        let b = if empty.contains(&i) {
                            vec![]
                        } else {
                            vec![ble(i as u8, Some(K))]
                        };
                        scan(i, vec![], b)
                    })
                    .collect(),
            )
        };
        let one_miss = evaluate(&with_empty(&[10]), &Settings::default(), at(24));
        assert_eq!(only_kind(&one_miss, AlertKind::PersistentTracker).len(), 1);
        let two_miss = evaluate(&with_empty(&[10, 11]), &Settings::default(), at(24));
        assert!(only_kind(&two_miss, AlertKind::PersistentTracker).is_empty());
    }

    #[test]
    fn tracker_wording_is_hedged_and_thresholds_follow_settings() {
        let h = tracker_hist(3, 5, TrackerKind::Tile, |_| 1);
        let s = Settings {
            tracker_min_scans: 3,
            tracker_min_minutes: 10,
            ..Settings::default()
        };
        let a = evaluate(&h, &s, at(10));
        assert_eq!(a.len(), 1);
        let text = format!("{} {}", a[0].title, a[0].detail).to_lowercase();
        assert!(text.contains("possible") && text.contains("best guess"));
        assert_eq!(a[0].subject_hash, dev(1));
        assert_eq!((a[0].first_seen, a[0].last_seen), (at(0), at(10)));
    }

    // ---- NewDevice --------------------------------------------------------

    #[test]
    fn new_device_table() {
        let mut s = Settings::default();
        s.alert_toggles.new_device = true;
        // (history, expected count)
        let cases: Vec<(&str, History, usize)> = vec![
            (
                "single scan is baseline",
                hist(vec![scan(0, vec![], vec![ble(1, None)])]),
                0,
            ),
            (
                "device appears later",
                hist(vec![
                    scan(0, vec![], vec![ble(1, None)]),
                    scan(1, vec![], vec![ble(1, None), ble(2, None)]),
                ]),
                1,
            ),
            (
                "device seen twice is one alert",
                hist(vec![
                    scan(0, vec![], vec![ble(1, None)]),
                    scan(1, vec![], vec![ble(2, None)]),
                    scan(2, vec![], vec![ble(2, None)]),
                ]),
                1,
            ),
            (
                "trackers are not new devices",
                hist(vec![
                    scan(0, vec![], vec![ble(1, None)]),
                    scan(1, vec![], vec![ble(2, Some(TrackerKind::Tile))]),
                ]),
                0,
            ),
            ("empty history", hist(vec![]), 0),
        ];
        for (name, h, n) in cases {
            let a = evaluate(&h, &s, at(10));
            assert_eq!(only_kind(&a, AlertKind::NewDevice).len(), n, "{name}");
        }
    }

    // ---- toggles, dedupe, ids, privacy -----------------------------------

    fn busy_history() -> (History, Settings) {
        use Security::*;
        let mut s = settings_with(vec![trusted("Cafe-Guest", &[1], Wpa2Personal)]);
        s.alert_toggles = AlertToggles {
            new_device: true,
            ..AlertToggles::default()
        };
        let wifi = vec![
            ap("Net-A", 1, Wpa2Personal),
            ap("Net-A", 2, Open),
            ap("Cafe-Guest", 9, Open),
            ap("Cafe-Guest", 1, Open),
        ];
        let scans = (0..6)
            .map(|i| {
                let mut b = vec![ble(1, Some(TrackerKind::Tile))];
                if i > 0 {
                    b.push(ble(2, None));
                }
                scan(i * 5, wifi.clone(), b)
            })
            .collect();
        (hist(scans), s)
    }

    #[test]
    fn all_rules_fire_on_busy_history() {
        let (h, s) = busy_history();
        let a = evaluate(&h, &s, at(25));
        for k in [
            AlertKind::EvilTwin,
            AlertKind::OpenLookalike,
            AlertKind::TrustedNetworkChanged,
            AlertKind::PersistentTracker,
            AlertKind::NewDevice,
        ] {
            assert!(!only_kind(&a, k).is_empty(), "{k:?} missing");
        }
    }

    #[test]
    fn toggle_off_silences_each_rule() {
        let (h, s) = busy_history();
        type Off = fn(&mut AlertToggles);
        let kinds: [(AlertKind, Off); 5] = [
            (AlertKind::EvilTwin, |t| t.evil_twin = false),
            (AlertKind::OpenLookalike, |t| t.open_lookalike = false),
            (AlertKind::TrustedNetworkChanged, |t| {
                t.trusted_network_changed = false
            }),
            (AlertKind::PersistentTracker, |t| {
                t.persistent_tracker = false
            }),
            (AlertKind::NewDevice, |t| t.new_device = false),
        ];
        for (kind, off) in kinds {
            let mut s2 = s.clone();
            off(&mut s2.alert_toggles);
            let a = evaluate(&h, &s2, at(25));
            assert!(only_kind(&a, kind).is_empty(), "{kind:?} still fired");
            // the others are unaffected
            assert!(a.len() >= 4, "{kind:?}: other rules went quiet");
        }
        let mut all_off = s.clone();
        all_off.alert_toggles = AlertToggles {
            evil_twin: false,
            open_lookalike: false,
            trusted_network_changed: false,
            persistent_tracker: false,
            new_device: false,
            followed_across_places: false,
            watchlist: false,
            new_lan_device: false,
        };
        assert!(evaluate(&h, &all_off, at(25)).is_empty());
    }

    // ---- v2 context --------------------------------------------------------

    fn mine_entry(kind: MineKind, id_hash: String) -> MineEntry {
        MineEntry {
            kind,
            id_hash,
            label: None,
            added_at: T0,
        }
    }

    #[test]
    fn v2_rules_are_silent_stubs_and_empty_context_equals_evaluate() {
        let (h, s) = busy_history();
        assert_eq!(
            evaluate(&h, &s, at(25)),
            evaluate_with(&h, &s, &DetectContext::default(), at(25))
        );
        // Even a populated context yields nothing until the work packages land.
        let ctx = DetectContext {
            mine: vec![mine_entry(MineKind::Lan, "aa".into())],
            watchlist: vec![WatchlistEntry {
                id: 1,
                kind: crate::model::WatchKind::Ssid,
                pattern: "Net-A".into(),
                match_mode: crate::model::WatchMatch::Contains,
                added_at: T0,
            }],
            current_network: Some(NetworkInfo::default()),
            ..DetectContext::default()
        };
        let a = evaluate_with(&h, &s, &ctx, at(25));
        for k in [AlertKind::FollowedAcrossPlaces, AlertKind::NewLanDevice] {
            assert!(only_kind(&a, k).is_empty(), "{k:?} fired from a stub");
        }
    }

    #[test]
    fn mine_access_point_counts_as_known_for_trusted_network_changed() {
        // Net-A trusts access point 1 only; access point 2 is the unfamiliar one.
        let s = settings_with(vec![trusted("Net-A", &[1], Security::Wpa2Personal)]);
        let h = hist(vec![scan(
            0,
            vec![ap("Net-A", 2, Security::Wpa2Personal)],
            vec![],
        )]);
        let fires = |ctx: &DetectContext| {
            !only_kind(
                &evaluate_with(&h, &s, ctx, at(1)),
                AlertKind::TrustedNetworkChanged,
            )
            .is_empty()
        };
        assert!(
            fires(&DetectContext::default()),
            "negative control: unknown AP alerts"
        );
        let mine = |kind, id: String| DetectContext {
            mine: vec![mine_entry(kind, id)],
            ..DetectContext::default()
        };
        assert!(
            !fires(&mine(MineKind::WifiAp, bssid(2))),
            "marked mine => known"
        );
        // Wrong kind or wrong hash must not silence it.
        assert!(fires(&mine(MineKind::Ble, bssid(2))));
        assert!(fires(&mine(MineKind::WifiAp, bssid(3))));
        // A radio group marked mine covers an observation that carries that group id.
        let mut grouped = ap("Net-A", 2, Security::Wpa2Personal);
        grouped.group_id = Some("group-1".into());
        let hg = hist(vec![scan(0, vec![grouped], vec![])]);
        let ctx = mine(MineKind::WifiGroup, "group-1".into());
        assert!(evaluate_with(&hg, &s, &ctx, at(1))
            .iter()
            .all(|a| a.kind != AlertKind::TrustedNetworkChanged));
    }

    #[test]
    fn new_device_is_off_by_default() {
        let (h, _) = busy_history();
        let a = evaluate(&h, &Settings::default(), at(25));
        assert!(only_kind(&a, AlertKind::NewDevice).is_empty());
    }

    #[test]
    fn dedupes_by_kind_and_subject_across_scans_and_widens_range() {
        let (h, s) = busy_history();
        let a = evaluate(&h, &s, at(25));
        let mut keys = BTreeSet::new();
        for x in &a {
            assert!(
                keys.insert((kind_tag(x.kind), x.subject_hash.clone())),
                "duplicate {x:?}"
            );
            assert!(!x.dismissed);
        }
        // Six scans produce one EvilTwin alert whose range spans all of them.
        let twin = only_kind(&a, AlertKind::EvilTwin);
        assert_eq!(twin.len(), 1);
        assert_eq!((twin[0].first_seen, twin[0].last_seen), (at(0), at(25)));
    }

    #[test]
    fn ids_are_stable_unique_and_deterministic() {
        let (h, s) = busy_history();
        let a = evaluate(&h, &s, at(25));
        let b = evaluate(&h, &s, at(25));
        assert_eq!(a, b);
        let ids: BTreeSet<&str> = a.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids.len(), a.len());
        assert_eq!(a[0].id, alert_id(a[0].kind, &a[0].subject_hash));
        // Same subject, different kind: different id.
        assert_ne!(
            alert_id(AlertKind::EvilTwin, "x"),
            alert_id(AlertKind::NewDevice, "x")
        );
    }

    #[test]
    fn output_is_sorted_most_severe_first() {
        let (h, s) = busy_history();
        let a = evaluate(&h, &s, at(25));
        assert!(a.windows(2).all(|w| w[0].severity >= w[1].severity));
    }

    #[test]
    fn alert_text_carries_no_device_identifier() {
        let (h, s) = busy_history();
        let a = evaluate(&h, &s, at(25));
        let hashes: Vec<String> = (0..20u8).map(bssid).chain((0..5u8).map(dev)).collect();
        for x in &a {
            let text = format!("{} {}", x.title, x.detail);
            assert!(!text.contains("02:00:00"), "raw bssid in {text}");
            for hsh in &hashes {
                assert!(!text.contains(hsh.as_str()), "hash in text");
            }
        }
    }

    #[test]
    fn empty_history_and_default_settings_yield_nothing() {
        assert!(evaluate(&History::default(), &Settings::default(), 0).is_empty());
    }
}
