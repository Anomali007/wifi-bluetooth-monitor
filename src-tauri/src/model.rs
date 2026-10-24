//! Shared data contract. FROZEN after Phase 0: only the integrator may change it,
//! and every change must be mirrored in `lib/types.ts`.
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
    /// `Some` only when the advertisement matches a known tracker signature.
    pub tracker: Option<TrackerKind>,
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
}

impl Default for AlertToggles {
    fn default() -> Self {
        AlertToggles {
            evil_twin: true,
            open_lookalike: true,
            trusted_network_changed: true,
            persistent_tracker: true,
            new_device: false, // noisy; opt-in
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
