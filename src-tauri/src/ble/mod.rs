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

pub mod classify;

use crate::model::{
    hash_identifier, BleObservation, Millis, PermissionStatus, Salt, ScanError, ScanErrorCode,
    ScanSource,
};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn err(code: ScanErrorCode, message: impl Into<String>) -> ScanError {
    ScanError {
        source: ScanSource::Ble,
        code,
        message: message.into(),
    }
}

fn now_millis() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as Millis)
        .unwrap_or(0)
}

/// Listen for BLE advertisements for `window` and return what was heard.
///
/// Receive-only: starts a scan, reads advertisement properties, stops the scan. It never
/// connects, discovers services, reads GATT or pairs.
pub async fn scan(salt: &Salt, window: Duration) -> Result<Vec<BleObservation>, ScanError> {
    match bluetooth_permission() {
        PermissionStatus::Denied | PermissionStatus::Restricted => {
            return Err(err(
                ScanErrorCode::PermissionDenied,
                "Bluetooth access is not allowed",
            ));
        }
        _ => {}
    }
    // CoreBluetooth never answers while authorisation is pending or the radio is off, so every
    // await that depends on it is bounded.
    let setup = Duration::from_secs(5);
    let adapter = tokio::time::timeout(setup, async {
        let manager = Manager::new()
            .await
            .map_err(|_| err(ScanErrorCode::Unavailable, "Bluetooth manager unavailable"))?;
        let adapters = manager
            .adapters()
            .await
            .map_err(|_| err(ScanErrorCode::Unavailable, "no Bluetooth adapter"))?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| err(ScanErrorCode::Unavailable, "no Bluetooth adapter"))?;
        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|_| err(ScanErrorCode::Failed, "could not start BLE scan"))?;
        Ok::<_, ScanError>(adapter)
    })
    .await
    .map_err(|_| {
        err(
            ScanErrorCode::Timeout,
            "Bluetooth did not respond (permission pending or radio off)",
        )
    })??;
    tokio::time::sleep(window).await;
    let peripherals = tokio::time::timeout(setup, adapter.peripherals()).await;
    // Always stop, even if reading peripherals failed.
    let _ = tokio::time::timeout(setup, adapter.stop_scan()).await;
    let peripherals = peripherals
        .map_err(|_| err(ScanErrorCode::Timeout, "reading BLE results timed out"))?
        .map_err(|_| err(ScanErrorCode::Failed, "could not read BLE results"))?;

    let seen_at = now_millis();
    let mut out: HashMap<String, BleObservation> = HashMap::new();
    for p in peripherals {
        let Ok(Some(props)) = p.properties().await else {
            continue;
        };
        let service_uuids: Vec<u128> = props.services.iter().map(|u| u.as_u128()).collect();
        let service_data: HashMap<u128, Vec<u8>> = props
            .service_data
            .iter()
            .map(|(u, d)| (u.as_u128(), d.clone()))
            .collect();
        let class = classify::classify(&props.manufacturer_data, &service_uuids, &service_data);
        // Lowest company id for a stable choice when several are present.
        let manufacturer_id = props.manufacturer_data.keys().copied().min();
        // Raw peripheral UUID is hashed here and never leaves this function.
        let peripheral_hash = hash_identifier(salt, &p.id().to_string());
        out.insert(
            peripheral_hash.clone(),
            BleObservation {
                name: props.local_name.or(props.advertisement_name),
                peripheral_hash,
                rssi: props.rssi,
                tracker: class.tracker,
                owner_state: class.owner_state,
                manufacturer_id,
                seen_at,
            },
        );
    }
    Ok(out.into_values().collect())
}

/// Map `CBManagerAuthorization` (CoreBluetooth) to [`PermissionStatus`].
/// Values per Apple docs: 0 notDetermined, 1 restricted, 2 denied, 3 allowedAlways.
pub fn map_cb_authorization(raw: isize) -> PermissionStatus {
    match raw {
        0 => PermissionStatus::NotDetermined,
        1 => PermissionStatus::Restricted,
        2 => PermissionStatus::Denied,
        3 => PermissionStatus::Granted,
        _ => PermissionStatus::Unknown,
    }
}

/// Current Bluetooth authorisation (class method `+[CBManager authorization]`, no prompt).
#[cfg(target_os = "macos")]
pub fn bluetooth_permission() -> PermissionStatus {
    use objc2::msg_send;
    use objc2::runtime::AnyClass;
    match AnyClass::get(c"CBManager") {
        Some(cls) => {
            // SAFETY: `+authorization` takes no arguments and returns NSInteger.
            let raw: isize = unsafe { msg_send![cls, authorization] };
            map_cb_authorization(raw)
        }
        None => PermissionStatus::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn bluetooth_permission() -> PermissionStatus {
    PermissionStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cb_authorization_mapping() {
        assert_eq!(map_cb_authorization(0), PermissionStatus::NotDetermined);
        assert_eq!(map_cb_authorization(1), PermissionStatus::Restricted);
        assert_eq!(map_cb_authorization(2), PermissionStatus::Denied);
        assert_eq!(map_cb_authorization(3), PermissionStatus::Granted);
        assert_eq!(map_cb_authorization(9), PermissionStatus::Unknown);
    }

    /// Live receive-only scan. Prints ONLY counts. Run:
    /// `cargo test -- --ignored ble_live --nocapture`
    #[tokio::test]
    #[ignore]
    async fn ble_live() {
        let salt = Salt::from_bytes(vec![7u8; 32]);
        let obs = scan(&salt, Duration::from_secs(10)).await.expect("scan");
        let mut by_kind: HashMap<String, usize> = HashMap::new();
        for o in &obs {
            if let Some(k) = o.tracker {
                *by_kind.entry(format!("{k:?}")).or_default() += 1;
            }
        }
        let trackers: usize = by_kind.values().sum();
        println!(
            "BLE_LIVE devices={} trackers={} by_kind={:?}",
            obs.len(),
            trackers,
            by_kind
        );
    }
}
