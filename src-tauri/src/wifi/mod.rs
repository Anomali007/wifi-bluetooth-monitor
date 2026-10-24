//! Wi-Fi scanning via CoreWLAN (`objc2-core-wlan`). OWNER: WP1.
//!
//! CONTRACT (frozen):
//! - Receive-only. Never associate to, join or probe a network.
//! - [`scan`] returns one [`WifiObservation`] per access point, all stamped with the
//!   current time. The BSSID is hashed with [`hash_identifier`] and the supplied salt
//!   INSIDE this module; a raw BSSID must never be returned, logged or stored.
//! - SSID/BSSID are nil unless Location is authorised. In that case return the
//!   observations with `ssid`/`bssid_hash` = `None` AND/OR a `ScanError` with code
//!   `PermissionDenied`; never silently return an empty list as if nothing was nearby.
//! - [`location_permission`] and [`request_location_permission`] wrap `CLLocationManager`.
//! - Do not print results. Errors are returned, not logged with scan content.
//!
//! `tokio-wifiscanner` is gone: it shells out to `airport`, which macOS no longer ships.

use crate::model::{PermissionStatus, Salt, ScanError, WifiObservation};

/// Scan for nearby access points once.
pub async fn scan(_salt: &Salt) -> Result<Vec<WifiObservation>, ScanError> {
    // STUB (WP1 replaces).
    Ok(Vec::new())
}

/// Current Location authorisation, which gates SSID/BSSID visibility.
pub fn location_permission() -> PermissionStatus {
    // STUB (WP1 replaces).
    PermissionStatus::Unknown
}

/// Ask macOS to show the Location prompt (`requestWhenInUseAuthorization`). Idempotent.
pub fn request_location_permission() {
    // STUB (WP1 replaces).
}
