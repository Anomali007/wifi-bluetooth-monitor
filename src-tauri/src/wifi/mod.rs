//! Wi-Fi scanning via CoreWLAN (`objc2-core-wlan`). OWNER: WP1.
//!
//! CONTRACT (frozen):
//! - Receive-only. Never associate to, join or probe a network. Only the undirected
//!   `scanForNetworksWithName:nil` is used (never a directed/hidden-SSID probe).
//! - [`scan`] returns one [`WifiObservation`] per access point, all stamped with the
//!   current time. The BSSID is hashed with `hash_identifier` and the supplied salt
//!   INSIDE this module; a raw BSSID is never returned, logged or stored.
//! - SSID/BSSID are nil unless Location is authorised: the observations come back with
//!   `ssid`/`bssid_hash` = `None`. If the scan is empty while Location is denied or
//!   restricted, a `PermissionDenied` error is returned instead of an empty list.
//! - [`location_permission`] and [`request_location_permission`] wrap `CLLocationManager`.
//! - Nothing here prints. Errors carry no scan content.
//!
//! `tokio-wifiscanner` is gone: it shells out to `airport`, which macOS no longer ships.

mod location;
mod mapping;

use crate::model::{
    Millis, PermissionStatus, Salt, ScanError, ScanErrorCode, ScanSource, WifiObservation,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A CoreWLAN scan blocks for a few seconds; give up after this long.
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

fn err(code: ScanErrorCode, message: &str) -> ScanError {
    ScanError {
        source: ScanSource::Wifi,
        code,
        message: message.to_string(),
    }
}

fn now_millis() -> Millis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as Millis)
        .unwrap_or(0)
}

/// Scan for nearby access points once.
pub async fn scan(salt: &Salt) -> Result<Vec<WifiObservation>, ScanError> {
    let salt_copy = Salt::from_bytes(salt.as_bytes().to_vec());
    let job = tokio::task::spawn_blocking(move || scan_blocking(&salt_copy));
    match tokio::time::timeout(SCAN_TIMEOUT, job).await {
        Err(_) => Err(err(ScanErrorCode::Timeout, "Wi-Fi scan timed out")),
        Ok(Err(_)) => Err(err(ScanErrorCode::Failed, "Wi-Fi scan task failed")),
        Ok(Ok(result)) => result,
    }
}

#[cfg(target_os = "macos")]
fn scan_blocking(salt: &Salt) -> Result<Vec<WifiObservation>, ScanError> {
    use mapping::{cw_security::ALL as ALL_SECURITY, RawNetwork};
    use objc2_core_wlan::{CWSecurity, CWWiFiClient};

    // SAFETY: CoreWLAN calls on objects created and used within this thread. The scan is
    // the receive-only `scanForNetworksWithName:nil` (no directed probe, no association).
    let raws: Vec<RawNetwork> = unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let Some(interface) = client.interface() else {
            return Err(err(ScanErrorCode::Unavailable, "no Wi-Fi interface"));
        };
        let networks = interface
            .scanForNetworksWithName_error(None)
            .map_err(|_| err(ScanErrorCode::Failed, "CoreWLAN scan failed"))?;
        networks
            .iter()
            .map(|n| RawNetwork {
                ssid: n.ssid().map(|s| s.to_string()),
                bssid: n.bssid().map(|s| s.to_string()),
                rssi: n.rssiValue() as i64,
                channel: n.wlanChannel().map(|c| c.channelNumber() as i64),
                supported_security: ALL_SECURITY
                    .iter()
                    .copied()
                    .filter(|v| n.supportsSecurity(CWSecurity(*v)))
                    .collect(),
            })
            .collect()
    };

    let now = now_millis();
    let observations: Vec<WifiObservation> = raws
        .iter()
        .map(|r| mapping::map_network(r, salt, now))
        .collect();

    if observations.is_empty()
        && matches!(
            location_permission(),
            PermissionStatus::Denied | PermissionStatus::Restricted
        )
    {
        return Err(err(
            ScanErrorCode::PermissionDenied,
            "Location access is required for Wi-Fi scan results",
        ));
    }
    Ok(observations)
}

#[cfg(not(target_os = "macos"))]
fn scan_blocking(_salt: &Salt) -> Result<Vec<WifiObservation>, ScanError> {
    Err(err(
        ScanErrorCode::Unavailable,
        "Wi-Fi scanning requires macOS",
    ))
}

/// Current Location authorisation, which gates SSID/BSSID visibility.
pub fn location_permission() -> PermissionStatus {
    location::status()
}

/// Ask macOS to show the Location prompt (`requestWhenInUseAuthorization`). Idempotent.
///
/// Must run on the main thread; elsewhere it is a no-op (the integrator should call it from
/// Tauri `setup` or via `run_on_main_thread`). Does nothing unless the status is
/// `NotDetermined`, and only prompts for a bundled app that has a usage description.
pub fn request_location_permission() {
    if location_permission() != PermissionStatus::NotDetermined {
        return;
    }
    if !location::request() {
        log::warn!("request_location_permission must be called on the main thread");
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Run with `cargo test -- --ignored wifi_live --nocapture`. Prints counts only.
    #[test]
    #[ignore]
    fn wifi_live() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let salt = Salt::from_bytes(vec![7; 16]);
        let status = location_permission();
        let result = rt.block_on(scan(&salt));
        match result {
            Ok(obs) => {
                let with_ssid = obs.iter().filter(|o| o.ssid.is_some()).count();
                println!(
                    "wifi_live: networks={} with_ssid={} authorization={:?}",
                    obs.len(),
                    with_ssid,
                    status
                );
            }
            Err(e) => println!(
                "wifi_live: error code={:?} authorization={:?}",
                e.code, status
            ),
        }
    }
}
