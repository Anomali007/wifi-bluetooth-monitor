//! Shared data contract. FROZEN after Phase 0 (extended once by the v2 Foundation pass for
//! places, Mine, watchlist and LAN devices): only the integrator may change it, and every
//! change must be mirrored in `lib/types.ts`.
//!
//! Conventions
//! - All structs and enums serialise as camelCase JSON (`#[serde(rename_all = "camelCase")]`),
//!   so the TypeScript mirror is mechanical. Enums become string unions.
//! - Every timestamp is an `i64` of Unix milliseconds (see [`Millis`]).
//! - Identifiers of other people's devices (BSSIDs, BLE peripheral UUIDs) never leave
//!   the scanning module in the clear: they are hashed with [`hash_identifier`] and the
//!   per-install [`Salt`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Unix time in milliseconds.
pub type Millis = i64;

/// Frontend event: payload is a [`ScanResult`], emitted after every completed scan.
pub const EVENT_SCAN: &str = "wbm://scan";
/// Frontend event: payload is an [`Alert`], emitted once when an alert is first created.
pub const EVENT_ALERT: &str = "wbm://alert";

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Per-install random secret mixed into every identifier hash.
///
/// Generated and persisted by the `store` module (32 random bytes, file mode 0600).
/// The `Debug` impl is redacted so the salt cannot reach a log by accident, and the type
/// deliberately does not implement `Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt(Vec<u8>);

impl Salt {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Salt(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salt(<redacted>)")
    }
}

/// The ONE way to turn a raw identifier into the string stored and shown anywhere.
///
/// `SHA-256(salt || normalised(raw))` as lowercase hex (64 chars). Normalisation is
/// trim + ASCII lowercase, so `"AA:BB"` and `" aa:bb "` hash identically.
/// `wifi::scan` and `ble::scan` call this on BSSIDs and peripheral UUIDs respectively
/// before returning, so raw identifiers never leave those modules.
pub fn hash_identifier(salt: &Salt, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(raw.trim().to_ascii_lowercase().as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// Wi-Fi security mode, as far as CoreWLAN reports it. Ordered weakest to strongest by
/// [`Security::strength`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Security {
    Open,
    Wep,
    WpaPersonal,
    Wpa2Personal,
    Wpa3Personal,
    WpaEnterprise,
    Wpa2Enterprise,
    Wpa3Enterprise,
    /// Opportunistic Wireless Encryption (and OWE transition): encrypted, no password.
    /// Not "open" for alerting purposes.
    Owe,
    Unknown,
}

impl Security {
    /// Coarse strength rank used to detect downgrades: Open 0 < Owe/Wep 1 < Wpa 2 < Wpa2 3 < Wpa3 4.
    /// Personal and Enterprise of the same generation rank equal. `Unknown` ranks 0 but must
    /// be treated as "cannot compare" by detection rules.
    pub fn strength(self) -> u8 {
        match self {
            Security::Open | Security::Unknown => 0,
            Security::Wep | Security::Owe => 1,
            Security::WpaPersonal | Security::WpaEnterprise => 2,
            Security::Wpa2Personal | Security::Wpa2Enterprise => 3,
            Security::Wpa3Personal | Security::Wpa3Enterprise => 4,
        }
    }
    pub fn is_open(self) -> bool {
        self == Security::Open
    }
}

/// One access point seen in one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiObservation {
    /// `None` when macOS withholds it (no Location authorisation) or the network is hidden.
    pub ssid: Option<String>,
    /// `hash_identifier(salt, bssid)`. `None` when the BSSID was withheld.
    pub bssid_hash: Option<String>,
    /// Signal strength in dBm.
    pub rssi: i32,
    pub channel: Option<u32>,
    pub security: Security,
    pub seen_at: Millis,
    /// Short vendor name from the BSSID's OUI, computed from the raw BSSID before hashing.
    /// "Private address" for a locally administered BSSID. `None` when unknown or withheld
    /// (and for rows stored before this field existed).
    #[serde(default)]
    pub vendor: Option<String>,
    /// Multi-radio group: a salted hash shared by the BSSIDs of one physical device in one scan
    /// (see `vendor::radio_group`). `None` when the BSSID was withheld or for older rows.
    #[serde(default)]
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrackerKind {
    AppleFindMy,
    Tile,
    SamsungSmartTag,
    Chipolo,
    Pebblebee,
    GoogleFindMy,
    UnknownTracker,
}

/// Whether a Find My style advertisement says its owner is nearby.
///
/// DULT draft section 3.8 (near-owner bit) and AirGuard `AppleFindMy.getConnectionState`.
/// Only `Separated` adverts may raise a tracker alert; a `NearOwner` advert is an owner's own
/// accessory (or an Apple device acting as one) and is expected to be near its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OwnerState {
    Separated,
    NearOwner,
}

/// One BLE peripheral seen in one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BleObservation {
    /// Advertised local name, if any.
    pub name: Option<String>,
    /// `hash_identifier(salt, peripheral_uuid)`. CoreBluetooth exposes per-host UUIDs, not MACs.
    pub peripheral_hash: String,
    /// Signal strength in dBm, if reported.
    pub rssi: Option<i16>,
    /// `Some` only when the advertisement matches a known tracker signature AND, for Find My
    /// style adverts, is in the separated state. Nearby-owner Find My adverts are `None` here.
    pub tracker: Option<TrackerKind>,
    /// Find My style adverts only: separated vs near-owner. `None` for everything else
    /// (and for rows stored before this field existed).
    #[serde(default)]
    pub owner_state: Option<OwnerState>,
    /// First manufacturer-data company identifier, if any (e.g. 0x004C Apple).
    pub manufacturer_id: Option<u16>,
    pub seen_at: Millis,
}

// ---------------------------------------------------------------------------
// Permissions and errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionStatus {
    Granted,
    Denied,
    NotDetermined,
    Restricted,
    Unknown,
}

/// Permissions this app depends on. Location gates SSID/BSSID visibility; Bluetooth gates BLE scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionState {
    pub bluetooth: PermissionStatus,
    pub location: PermissionStatus,
}

impl PermissionState {
    pub const UNKNOWN: PermissionState = PermissionState {
        bluetooth: PermissionStatus::Unknown,
        location: PermissionStatus::Unknown,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanSource {
    Wifi,
    Ble,
    Store,
    Detect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanErrorCode {
    PermissionDenied,
    Unavailable,
    Timeout,
    Failed,
}

/// A scan-time failure that is reported to the UI instead of printed or swallowed.
/// `message` must never contain a raw identifier or a scan result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanError {
    pub source: ScanSource,
    pub code: ScanErrorCode,
    pub message: String,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}/{:?}: {}", self.source, self.code, self.message)
    }
}

impl std::error::Error for ScanError {}

// ---------------------------------------------------------------------------
// Scan results and history
// ---------------------------------------------------------------------------

/// Everything one scan cycle produced. Also the payload of [`EVENT_SCAN`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// When the cycle started. All observations in this result share this scan.
    pub scanned_at: Millis,
    pub wifi: Vec<WifiObservation>,
    pub ble: Vec<BleObservation>,
    pub errors: Vec<ScanError>,
    pub permissions: PermissionState,
}

/// One stored scan cycle, as returned by `Store::get_history`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub scanned_at: Millis,
    pub wifi: Vec<WifiObservation>,
    pub ble: Vec<BleObservation>,
}

/// A window of recent scans: what `detect::evaluate` consumes and `get_history` returns.
/// `scans` is sorted ascending by `scanned_at`; the last element is the newest scan.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct History {
    pub scans: Vec<ScanSnapshot>,
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertKind {
    EvilTwin,
    OpenLookalike,
    TrustedNetworkChanged,
    PersistentTracker,
    NewDevice,
    /// A tracker-signature device or an access point seen at two or more distinct places.
    FollowedAcrossPlaces,
    /// A visible SSID or vendor matches a watchlist entry.
    Watchlist,
    /// A device not seen before on a network whose access point is marked mine.
    NewLanDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// One finding. Alerts are deduplicated by `(kind, subject_hash)`; a repeat sighting
/// updates `last_seen` on the existing alert rather than creating a new one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    /// Stable id derived from `(kind, subject_hash)`; assigned by `detect`.
    pub id: String,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub first_seen: Millis,
    pub last_seen: Millis,
    /// Hash identifying what the alert is about (an SSID hash, a BSSID hash, a device hash
    /// or a tracker-kind key). Never a raw identifier.
    pub subject_hash: String,
    /// Set by the user via `dismiss_alert`; owned by `store`, always `false` coming from `detect`.
    pub dismissed: bool,
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// A network the user trusts. Compared by SSID; BSSIDs are stored hashed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedNetwork {
    pub ssid: String,
    /// Hashed BSSIDs known to belong to this network.
    pub known_bssid_hashes: Vec<String>,
    /// Security mode the network is expected to use; a weaker one is a downgrade.
    pub expected_security: Security,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AlertToggles {
    pub evil_twin: bool,
    pub open_lookalike: bool,
    pub trusted_network_changed: bool,
    pub persistent_tracker: bool,
    pub new_device: bool,
    pub followed_across_places: bool,
    pub watchlist: bool,
    pub new_lan_device: bool,
}

impl Default for AlertToggles {
    fn default() -> Self {
        AlertToggles {
            evil_twin: true,
            open_lookalike: true,
            trusted_network_changed: true,
            persistent_tracker: true,
            new_device: false, // noisy; opt-in
            followed_across_places: true,
            watchlist: true,      // does nothing until the watchlist has entries
            new_lan_device: true, // only fires on networks whose access point is marked mine
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub trusted_networks: Vec<TrustedNetwork>,
    /// Seconds between scan cycles. Default 60.
    pub scan_interval_secs: u32,
    /// Seconds each BLE scan listens. Default 10.
    pub ble_scan_secs: u32,
    /// How long history is kept before it is purged. Default 24.
    pub retention_hours: u32,
    /// Show a system notification for each new alert. Default true.
    pub notify: bool,
    pub alert_toggles: AlertToggles,
    /// PersistentTracker threshold: minimum number of scans a tracker must appear in. Default 5.
    pub tracker_min_scans: u32,
    /// PersistentTracker threshold: minimum minutes spanned by those sightings. Default 20.
    pub tracker_min_minutes: u32,
    /// How long places, place sightings and LAN devices are kept, in days. Default 14.
    /// Separate from `retention_hours`; anything marked mine never expires.
    pub place_retention_days: u32,
    /// Opt-in LAN sweep: one zero-byte UDP datagram per host, only while the joined access point
    /// is marked mine. The one deliberate exception to listen-only. Default false.
    pub lan_active_sweep: bool,
    /// Opt-in background item: two launchd jobs (Apple's `arp -an` and `ndp -an`, once a minute)
    /// whose output the app reads, because macOS 27 hides the neighbor tables from apps. The
    /// app spawns nothing. Default false.
    pub lan_neighbor_helper: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            trusted_networks: Vec::new(),
            scan_interval_secs: 60,
            ble_scan_secs: 10,
            retention_hours: 24,
            notify: true,
            alert_toggles: AlertToggles::default(),
            tracker_min_scans: 5,
            tracker_min_minutes: 20,
            place_retention_days: 14,
            lan_active_sweep: false,
            lan_neighbor_helper: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Places, Mine, watchlist, LAN (v2)
// ---------------------------------------------------------------------------

/// A place is a Wi-Fi fingerprint (no GPS): the set of strongest access-point hashes seen
/// there. `label` is typed by the user ("Home"); `None` shows as "Place N" in the UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Place {
    pub id: i64,
    pub label: Option<String>,
    /// Member BSSID hashes (capped at the ~40 strongest by the places module).
    pub members: Vec<String>,
    pub first_seen: Millis,
    pub last_seen: Millis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SightingKind {
    Wifi,
    Ble,
    Lan,
}

/// A device or access point seen during a dwell at a place. `id_hash` is the access-point
/// group id when known (else the BSSID hash), a BLE peripheral hash or a LAN MAC hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceSighting {
    pub kind: SightingKind,
    pub id_hash: String,
    pub place_id: i64,
    pub first_seen: Millis,
    pub last_seen: Millis,
    /// Number of scans it was seen in during dwells at this place.
    pub scans: u32,
}

/// What a Mine entry refers to. `WifiAp` is the single-BSSID form of the old "access point
/// marked as yours" concept; `WifiGroup` covers every radio of one physical access point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MineKind {
    WifiAp,
    WifiGroup,
    Ble,
    Lan,
}

/// Something the user marked as theirs. Stored by hash, never expires until unmarked, and is
/// excluded from FollowedAcrossPlaces, NewDevice, Watchlist and NewLanDevice alerts. Mine
/// `WifiAp`/`WifiGroup` entries also count as known access points for TrustedNetworkChanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MineEntry {
    pub kind: MineKind,
    pub id_hash: String,
    pub label: Option<String>,
    /// The network name that went with a `WifiAp`/`WifiGroup` mark when it was made. The sweep
    /// gate requires the joined network to carry the same name, because a cloned BSSID (or any
    /// BSSID in the same radio group) shares the hash but not necessarily the name. `None` for
    /// other kinds and for marks made before this field existed (those do not allow a sweep).
    #[serde(default)]
    pub ssid: Option<String>,
    pub added_at: Millis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WatchKind {
    Ssid,
    Vendor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WatchMatch {
    Exact,
    Contains,
}

/// One watchlist rule. Matching is case-insensitive; SSID entries also match look-alikes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchlistEntry {
    pub id: i64,
    pub kind: WatchKind,
    pub pattern: String,
    #[serde(rename = "match")]
    pub match_mode: WatchMatch,
    pub added_at: Millis,
}

/// A device seen on the local network. The MAC is hashed; IPs are shown live and never stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanDevice {
    /// Salted hash identifying the joined network (access point group or BSSID).
    pub network_key: String,
    pub mac_hash: String,
    pub vendor: Option<String>,
    /// mDNS hostname, if the device announced one.
    pub hostname: Option<String>,
    /// mDNS service types the device announced, e.g. `_http._tcp`.
    #[serde(default)]
    pub services: Vec<String>,
    pub first_seen: Millis,
    pub last_seen: Millis,
    /// Live only: filled from the current ARP table, never persisted.
    #[serde(default)]
    pub ip: Option<String>,
    /// Filled when listing: whether the MAC hash is in Mine.
    #[serde(default)]
    pub mine: bool,
    /// How the device was learned: from the neighbor tables, from its mDNS announcements, or
    /// both (merged across scans when stored). `None` only for rows from before v4.
    #[serde(default)]
    pub source: Option<LanSource>,
    /// Filled when listing, never persisted: the label of a Mine device whose mDNS hostname
    /// this device also announced. Only a hint to confirm by hand; it never makes a device Mine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub possibly_same_as: Option<String>,
}

/// Where a LAN device came from. A device only ever heard announcing has no hardware address
/// here, so its key is a namespaced hash of its hostname instead of a MAC hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LanSource {
    /// In the IPv6 neighbor table (or the IPv4 ARP table): has a hardware address.
    Neighbor,
    /// Heard announcing itself over mDNS, with no hardware address matched.
    Announced,
    /// Both: an mDNS host joined to a neighbor entry.
    Both,
}

impl LanSource {
    /// Stored text form.
    pub fn as_str(self) -> &'static str {
        match self {
            LanSource::Neighbor => "neighbor",
            LanSource::Announced => "announced",
            LanSource::Both => "both",
        }
    }

    pub fn parse(s: &str) -> Option<LanSource> {
        match s {
            "neighbor" => Some(LanSource::Neighbor),
            "announced" => Some(LanSource::Announced),
            "both" => Some(LanSource::Both),
            _ => None,
        }
    }
}

/// How the LAN was last observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LanMode {
    /// ARP table + receive-only mDNS.
    Passive,
    /// Passive plus the opt-in zero-byte UDP sweep.
    Sweep,
}

/// The network the Mac is joined to right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NetworkInfo {
    /// Same value as `LanDevice::network_key`; `None` when not on Wi-Fi or BSSID withheld.
    pub network_key: Option<String>,
    pub ssid: Option<String>,
    pub bssid_hash: Option<String>,
    pub group_id: Option<String>,
    /// Interface subnet in CIDR form, e.g. `192.0.2.0/24`.
    pub subnet: Option<String>,
    /// The joined access point (or its radio group) is in Mine.
    pub is_mine: bool,
    /// `lan_active_sweep` is on AND `is_mine`: a sweep may run.
    pub sweep_enabled: bool,
    pub mode: LanMode,
    pub last_sweep_at: Option<Millis>,
    /// Why no neighbor table could be read (Apple's `arp`/`ndp` unavailable), so the page can
    /// say it is showing announced devices only. `None` when neighbors were readable.
    pub neighbor_note: Option<String>,
    /// Why a sweep will not run although the setting is on and the access point is Mine (a mark
    /// without a saved network name, a hidden name, a different name). `None` otherwise.
    pub sweep_note: Option<String>,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        NetworkInfo {
            network_key: None,
            ssid: None,
            bssid_hash: None,
            group_id: None,
            subnet: None,
            is_mine: false,
            sweep_enabled: false,
            mode: LanMode::Passive,
            last_sweep_at: None,
            neighbor_note: None,
            sweep_note: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + fmt::Debug>(v: &T) {
        let s = serde_json::to_string(v).unwrap();
        let back: T = serde_json::from_str(&s).unwrap();
        assert_eq!(&back, v);
    }

    fn salt(b: u8) -> Salt {
        Salt::from_bytes(vec![b; 32])
    }

    #[test]
    fn hash_is_deterministic_and_salt_sensitive() {
        let a = hash_identifier(&salt(1), "02:00:00:aa:bb:cc");
        assert_eq!(a, hash_identifier(&salt(1), "02:00:00:aa:bb:cc"));
        assert_ne!(a, hash_identifier(&salt(2), "02:00:00:aa:bb:cc"));
        assert_ne!(a, hash_identifier(&salt(1), "02:00:00:aa:bb:cd"));
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_normalises_case_and_whitespace() {
        assert_eq!(
            hash_identifier(&salt(1), "02:00:00:AA:BB:CC"),
            hash_identifier(&salt(1), " 02:00:00:aa:bb:cc ")
        );
    }

    #[test]
    fn salt_debug_is_redacted() {
        assert!(!format!("{:?}", salt(7)).contains('7'));
    }

    #[test]
    fn model_serde_roundtrip_and_camel_case() {
        let w = WifiObservation {
            ssid: Some("Net-A".into()),
            bssid_hash: Some("ab".repeat(32)),
            rssi: -60,
            channel: Some(36),
            security: Security::Wpa2Personal,
            seen_at: 1_700_000_000_000,
            vendor: Some("Vendor-A".into()),
            group_id: Some("ef".repeat(32)),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["bssidHash"], json!("ab".repeat(32)));
        assert_eq!(v["security"], json!("wpa2Personal"));
        assert_eq!(v["seenAt"], json!(1_700_000_000_000_i64));
        roundtrip(&w);

        let b = BleObservation {
            name: None,
            peripheral_hash: "cd".repeat(32),
            rssi: Some(-71),
            tracker: Some(TrackerKind::AppleFindMy),
            owner_state: Some(OwnerState::Separated),
            manufacturer_id: Some(0x004C),
            seen_at: 5,
        };
        assert_eq!(
            serde_json::to_value(&b).unwrap()["tracker"],
            json!("appleFindMy")
        );
        roundtrip(&b);

        let scan = ScanResult {
            scanned_at: 5,
            wifi: vec![w.clone()],
            ble: vec![b.clone()],
            errors: vec![ScanError {
                source: ScanSource::Ble,
                code: ScanErrorCode::PermissionDenied,
                message: "Bluetooth permission denied".into(),
            }],
            permissions: PermissionState::UNKNOWN,
        };
        roundtrip(&scan);
        roundtrip(&History {
            scans: vec![ScanSnapshot {
                scanned_at: 5,
                wifi: vec![w],
                ble: vec![b],
            }],
        });
        roundtrip(&Alert {
            id: "x".into(),
            kind: AlertKind::EvilTwin,
            severity: Severity::High,
            title: "t".into(),
            detail: "d".into(),
            first_seen: 1,
            last_seen: 2,
            subject_hash: "s".into(),
            dismissed: false,
        });
        roundtrip(&Settings::default());
    }

    #[test]
    fn v2_types_roundtrip_and_camel_case() {
        let place = Place {
            id: 3,
            label: Some("Place-A".into()),
            members: vec!["ab".repeat(32)],
            first_seen: 1,
            last_seen: 2,
        };
        roundtrip(&place);
        roundtrip(&PlaceSighting {
            kind: SightingKind::Ble,
            id_hash: "cd".repeat(32),
            place_id: 3,
            first_seen: 1,
            last_seen: 2,
            scans: 4,
        });
        let mine = MineEntry {
            kind: MineKind::WifiGroup,
            id_hash: "ef".repeat(32),
            label: None,
            ssid: None,
            added_at: 9,
        };
        assert_eq!(
            serde_json::to_value(&mine).unwrap()["kind"],
            json!("wifiGroup")
        );
        roundtrip(&mine);
        let w = WatchlistEntry {
            id: 1,
            kind: WatchKind::Vendor,
            pattern: "Vendor-A".into(),
            match_mode: WatchMatch::Contains,
            added_at: 9,
        };
        // The Rust field is `match_mode`; on the wire it is `match`.
        assert_eq!(
            serde_json::to_value(&w).unwrap()["match"],
            json!("contains")
        );
        roundtrip(&w);
        let dev = LanDevice {
            network_key: "aa".repeat(32),
            mac_hash: "bb".repeat(32),
            vendor: Some("Vendor-A".into()),
            hostname: Some("device-1.local".into()),
            services: vec!["_http._tcp".into()],
            first_seen: 1,
            last_seen: 2,
            ip: Some("192.0.2.10".into()),
            mine: false,
            source: Some(LanSource::Both),
            possibly_same_as: None,
        };
        roundtrip(&dev);
        roundtrip(&NetworkInfo::default());
        assert_eq!(
            serde_json::to_value(AlertKind::NewLanDevice).unwrap(),
            json!("newLanDevice")
        );
    }

    #[test]
    fn older_json_without_v2_fields_still_loads() {
        let w: WifiObservation = serde_json::from_str(
            r#"{"ssid":null,"bssidHash":null,"rssi":-60,"channel":null,"security":"open","seenAt":1}"#,
        )
        .unwrap();
        assert_eq!((w.vendor, w.group_id), (None, None));
        let t: AlertToggles = serde_json::from_str(r#"{"evilTwin":false}"#).unwrap();
        assert!(!t.evil_twin && t.followed_across_places && t.watchlist && t.new_lan_device);
    }

    #[test]
    fn settings_defaults_and_partial_json() {
        let s = Settings::default();
        assert_eq!(
            (s.scan_interval_secs, s.retention_hours, s.ble_scan_secs),
            (60, 24, 10)
        );
        assert!(s.notify && !s.alert_toggles.new_device && s.alert_toggles.evil_twin);
        // Missing fields fall back to defaults so older stored settings keep loading.
        let partial: Settings = serde_json::from_str(r#"{"retentionHours": 6}"#).unwrap();
        assert_eq!(partial.retention_hours, 6);
        assert_eq!(partial.scan_interval_secs, 60);
        assert_eq!(partial.place_retention_days, 14);
        assert!(!partial.lan_active_sweep);
    }

    #[test]
    fn security_strength_orders_downgrades() {
        assert!(Security::Wpa3Personal.strength() > Security::Wpa2Personal.strength());
        assert!(Security::Wpa2Personal.strength() > Security::Open.strength());
        assert!(Security::Open.is_open() && !Security::Wep.is_open());
        // OWE is encrypted: stronger than open, never counted as open.
        assert!(Security::Owe.strength() > Security::Open.strength());
        assert!(!Security::Owe.is_open());
    }

    #[test]
    fn event_names_are_valid_for_tauri() {
        for n in [EVENT_SCAN, EVENT_ALERT] {
            assert!(n
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-/:_".contains(c)));
        }
    }
}
