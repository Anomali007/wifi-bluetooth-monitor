//! BLE scanning (btleplug) and tracker classification. OWNER: WP2.
//!
//! CONTRACT (frozen):
//! - Receive-only passive scan. Never connect to, pair with or read GATT from a peripheral.
//! - [`scan`] listens for `window`, then returns one [`BleObservation`] per distinct
//!   peripheral. CoreBluetooth exposes per-host UUIDs rather than MACs; the UUID is hashed
//!   with [`hash_identifier`] and the supplied salt INSIDE this module and the raw UUID is
//!   never returned, logged or stored.
//! - `tracker` is `Some` only when the advertisement matches a documented tracker
//!   signature (cite the primary source for every constant). An ordinary Apple device
//!   (phone, AirPods) must NOT classify as a tracker.
//! - A missing/denied Bluetooth adapter is returned as a `ScanError`, not an empty `Ok`.
//! - [`bluetooth_permission`] reports the CoreBluetooth authorisation state.

use crate::model::{BleObservation, PermissionStatus, Salt, ScanError};
use std::time::Duration;

/// Listen for BLE advertisements for `window` and return what was heard.
pub async fn scan(_salt: &Salt, _window: Duration) -> Result<Vec<BleObservation>, ScanError> {
    // STUB (WP2 replaces).
    Ok(Vec::new())
}

/// Current Bluetooth authorisation.
pub fn bluetooth_permission() -> PermissionStatus {
    // STUB (WP2 replaces).
    PermissionStatus::Unknown
}
