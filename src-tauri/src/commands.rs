//! Tauri command surface and the background scan loop.
//!
//! Errors cross the IPC boundary as `String`. JS argument names are camelCase
//! (`includeDismissed`).
//!
//! Push events (see `model`): `EVENT_SCAN` (`wbm://scan`) carries a `ScanResult` after every
//! scan cycle, `EVENT_ALERT` (`wbm://alert`) carries an `Alert` when one is first created.
//!
//! Logging here is counts only, and only in debug builds. Scan data is never printed.

use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;

use crate::model::{
    Alert, History, Millis, PermissionState, ScanResult, Settings, EVENT_ALERT, EVENT_SCAN,
};
use crate::pipeline;
use crate::store::Store;
use crate::{ble, wifi};

/// Managed state: the store behind a mutex (its SQLite connection is not `Sync`) and an async
/// lock that serialises scan cycles so `scan_now` and the background loop never overlap.
pub struct AppState {
    pub store: Mutex<Store>,
    pub cycle: tokio::sync::Mutex<()>,
}

impl AppState {
    pub fn new(store: Store) -> Self {
        AppState {
            store: Mutex::new(store),
            cycle: tokio::sync::Mutex::new(()),
        }
    }
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> String {
    "store lock poisoned".to_string()
}

fn permissions() -> PermissionState {
    PermissionState {
        bluetooth: ble::bluetooth_permission(),
        location: wifi::location_permission(),
    }
}

/// One full cycle: scan Wi-Fi and BLE concurrently, store, detect, emit, notify.
pub async fn run_cycle(app: &AppHandle) -> Result<ScanResult, String> {
    let state = app.state::<AppState>();
    let _cycle = state.cycle.lock().await;

    let (salt, settings) = {
        let store = state.store.lock().map_err(lock_err)?;
        (
            store.salt().clone(),
            store.get_settings().map_err(|e| e.to_string())?,
        )
    };

    let scanned_at = pipeline::now_ms();
    let window = Duration::from_secs(u64::from(settings.ble_scan_secs.clamp(1, 60)));
    let (wifi_res, ble_res) = tokio::join!(wifi::scan(&salt), ble::scan(&salt, window));
    let result = pipeline::assemble(scanned_at, wifi_res, ble_res, permissions());

    let new_alerts = {
        let mut store = state.store.lock().map_err(lock_err)?;
        pipeline::ingest(&mut store, &result, pipeline::now_ms()).map_err(|e| e.to_string())?
    };

    if cfg!(debug_assertions) {
        log::info!(
            "scan: {} wifi, {} ble, {} errors, {} new alerts",
            result.wifi.len(),
            result.ble.len(),
            result.errors.len(),
            new_alerts.len()
        );
    }

    let _ = app.emit(EVENT_SCAN, &result);
    for alert in &new_alerts {
        let _ = app.emit(EVENT_ALERT, alert);
        if settings.notify {
            let (title, body) = pipeline::notification_text(alert);
            let _ = app.notification().builder().title(title).body(body).show();
        }
    }
    Ok(result)
}

/// Background loop. The interval is re-read from the store every cycle, so a settings change
/// takes effect on the next one.
pub fn spawn_scan_loop(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            if let Err(e) = run_cycle(&app).await {
                if cfg!(debug_assertions) {
                    log::warn!("scan cycle failed: {e}");
                }
            }
            let secs = {
                let state = app.state::<AppState>();
                let guard = state.store.lock();
                guard
                    .ok()
                    .and_then(|s| s.get_settings().ok())
                    .map(|s| s.scan_interval_secs)
                    .unwrap_or(60)
            };
            tokio::time::sleep(Duration::from_secs(u64::from(secs.max(5)))).await;
        }
    });
}

/// Run one scan cycle now (Wi-Fi + BLE), store it, evaluate alerts, return the result.
#[tauri::command]
pub async fn scan_now(app: AppHandle) -> Result<ScanResult, String> {
    run_cycle(&app).await
}

/// Stored scans with `scanned_at >= since` (Unix ms); `None` = the whole retention window.
#[tauri::command]
pub async fn get_history(
    state: State<'_, AppState>,
    since: Option<Millis>,
) -> Result<History, String> {
    let store = state.store.lock().map_err(lock_err)?;
    let since = match since {
        Some(s) => s,
        None => {
            let hours = store
                .get_settings()
                .map_err(|e| e.to_string())?
                .retention_hours;
            pipeline::now_ms() - Millis::from(hours) * 3_600_000
        }
    };
    store.get_history(since).map_err(|e| e.to_string())
}

/// Stored alerts, newest first. Dismissed alerts are hidden unless `include_dismissed`.
#[tauri::command]
pub async fn get_alerts(
    state: State<'_, AppState>,
    include_dismissed: Option<bool>,
) -> Result<Vec<Alert>, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .get_alerts(include_dismissed.unwrap_or(false))
        .map_err(|e| e.to_string())
}

/// Mark an alert as dismissed.
#[tauri::command]
pub async fn dismiss_alert(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store.dismiss_alert(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store.get_settings().map_err(|e| e.to_string())
}

/// Persist settings; returns what was stored (the scan loop picks them up next cycle).
#[tauri::command]
pub async fn set_settings(
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Settings, String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store.set_settings(&settings).map_err(|e| e.to_string())?;
    store.get_settings().map_err(|e| e.to_string())
}

/// Current Bluetooth + Location authorisation.
#[tauri::command]
pub async fn get_permissions() -> Result<PermissionState, String> {
    Ok(permissions())
}
