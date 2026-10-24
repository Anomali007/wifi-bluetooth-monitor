//! Tauri command surface. FROZEN signatures; OWNER: integrator (Phase 2).
//!
//! Phase 0 bodies are stubs that return empty/default values so the app launches.
//! Errors cross the IPC boundary as `String` (the `Display` of the underlying error).
//! JS argument names are camelCase (`includeDismissed`).
//!
//! Push events (see `model`): `EVENT_SCAN` (`wbm://scan`) carries a `ScanResult` after each scan cycle,
//! `EVENT_ALERT` (`wbm://alert`) carries an `Alert` when one is first created.
//!
//! `get_permissions` additionally lets the UI trigger the Location prompt via the wifi module.

use crate::model::{Alert, History, Millis, PermissionState, ScanResult, Settings};

/// Run one scan cycle now (Wi-Fi + BLE), store it, evaluate alerts, return the result.
#[tauri::command]
pub async fn scan_now() -> Result<ScanResult, String> {
    // STUB (integrator replaces).
    Ok(ScanResult {
        scanned_at: 0,
        wifi: Vec::new(),
        ble: Vec::new(),
        errors: Vec::new(),
        permissions: PermissionState::UNKNOWN,
    })
}

/// Stored scans with `scanned_at >= since` (Unix ms); `None` = the whole retention window.
#[tauri::command]
pub async fn get_history(since: Option<Millis>) -> Result<History, String> {
    let _ = since;
    Ok(History::default())
}

/// Stored alerts, newest first. Dismissed alerts are hidden unless `include_dismissed`.
#[tauri::command]
pub async fn get_alerts(include_dismissed: Option<bool>) -> Result<Vec<Alert>, String> {
    let _ = include_dismissed;
    Ok(Vec::new())
}

/// Mark an alert as dismissed.
#[tauri::command]
pub async fn dismiss_alert(id: String) -> Result<(), String> {
    let _ = id;
    Ok(())
}

#[tauri::command]
pub async fn get_settings() -> Result<Settings, String> {
    Ok(Settings::default())
}

/// Persist settings; returns what was stored (the scan loop picks up the new interval).
#[tauri::command]
pub async fn set_settings(settings: Settings) -> Result<Settings, String> {
    Ok(settings)
}

/// Current Bluetooth + Location authorisation.
#[tauri::command]
pub async fn get_permissions() -> Result<PermissionState, String> {
    Ok(PermissionState::UNKNOWN)
}
