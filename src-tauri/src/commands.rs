//! Tauri command surface and the background scan loop.
//!
//! Errors cross the IPC boundary as `String`. JS argument names are camelCase
//! (`includeDismissed`).
//!
//! v2 commands (places, Mine, watchlist, LAN) are thin wrappers over `Store` CRUD and `lan`;
//! rule logic lives elsewhere.
//!
//! Push events (see `model`): `EVENT_SCAN` (`wbm://scan`) carries a `ScanResult` after every
//! scan cycle, `EVENT_ALERT` (`wbm://alert`) carries an `Alert` when one is first created.
//!
//! Logging here is counts only, and only in debug builds. Scan data is never printed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;

use crate::lan::{self, LanInputs, LanScanOutcome, LanState};
use crate::model::PermissionState;
use crate::model::{
    Alert, History, LanDevice, Millis, MineEntry, MineKind, NetworkInfo, Place, ScanResult,
    Settings, WatchKind, WatchMatch, WatchlistEntry, EVENT_ALERT, EVENT_SCAN,
};
use crate::pipeline;
use crate::store::Store;
use crate::{ble, wifi};

/// Managed state: the store behind a mutex (its SQLite connection is not `Sync`) and an async
/// lock that serialises scan cycles so `scan_now` and the background loop never overlap.
pub struct AppState {
    pub store: Mutex<Store>,
    pub cycle: tokio::sync::Mutex<()>,
    /// Sweep cadence state, shared with the blocking LAN thread.
    pub lan: Arc<Mutex<LanState>>,
}

impl AppState {
    pub fn new(store: Store) -> Self {
        AppState {
            store: Mutex::new(store),
            cycle: tokio::sync::Mutex::new(()),
            lan: Arc::new(Mutex::new(LanState::default())),
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

/// Observe the LAN on a blocking thread. A failure becomes `None` (counts only in debug logs):
/// the LAN is an extra, never a reason to lose a Wi-Fi/BLE cycle.
async fn run_lan(app: &AppHandle, force_sweep: bool) -> Option<LanScanOutcome> {
    let state = app.state::<AppState>();
    let (salt, settings, mine) = {
        let store = state.store.lock().ok()?;
        (
            store.salt().clone(),
            store.get_settings().ok()?,
            store.list_mine().ok()?,
        )
    };
    let inputs = LanInputs {
        salt,
        settings,
        mine,
        force_sweep,
        // A running sweep re-reads the setting and Mine from the store and stops if they change.
        live: Some(lan::LiveInputs::new({
            let app = app.clone();
            move || {
                let state = app.state::<AppState>();
                let store = state.store.lock().ok()?;
                Some((
                    store.get_settings().ok()?.lan_active_sweep,
                    store.list_mine().ok()?,
                ))
            }
        })),
    };
    let lan_state = Arc::clone(&state.lan);
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let mut guard = lan_state.lock().ok()?;
        lan::scan(&inputs, &mut guard).ok()
    })
    .await;
    joined.ok().flatten()
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

    let lan_outcome = run_lan(app, false).await;

    let new_alerts = {
        let mut store = state.store.lock().map_err(lock_err)?;
        pipeline::ingest_with(
            &mut store,
            &result,
            lan_outcome.as_ref(),
            pipeline::now_ms(),
        )
        .map_err(|e| e.to_string())?
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
    }
    if settings.notify {
        for n in pipeline::plan_notifications(&new_alerts) {
            let _ = app
                .notification()
                .builder()
                .title(n.title)
                .body(n.body)
                .show();
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
    let was = store
        .get_settings()
        .map(|s| s.lan_neighbor_helper)
        .unwrap_or(false);
    store.set_settings(&settings).map_err(|e| e.to_string())?;
    let saved = store.get_settings().map_err(|e| e.to_string())?;
    if saved.lan_neighbor_helper != was {
        lan::helper::apply(saved.lan_neighbor_helper);
    }
    Ok(saved)
}

/// State of the opt-in background item (off / enabled / needs approval in Login Items).
#[tauri::command]
pub async fn get_helper_status() -> Result<lan::helper::HelperStatus, String> {
    Ok(lan::helper::status())
}

/// Open System Settings at Login Items, where the background item is approved.
#[tauri::command]
pub async fn open_login_items() -> Result<(), String> {
    lan::helper::open_login_items();
    Ok(())
}

/// Current Bluetooth + Location authorisation.
#[tauri::command]
pub async fn get_permissions() -> Result<PermissionState, String> {
    Ok(permissions())
}

// ---------------------------------------------------------------------------
// v2: places, Mine, watchlist, LAN
// ---------------------------------------------------------------------------

/// All remembered places, oldest first.
#[tauri::command]
pub async fn list_places(state: State<'_, AppState>) -> Result<Vec<Place>, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store.list_places().map_err(|e| e.to_string())
}

/// Set (or clear, with `None`/blank) a place's label; returns the place.
#[tauri::command]
pub async fn rename_place(
    state: State<'_, AppState>,
    id: i64,
    label: Option<String>,
) -> Result<Place, String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store
        .rename_place(id, label.as_deref())
        .map_err(|e| e.to_string())?;
    store
        .list_places()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "no such place".to_string())
}

/// Forget a place and everything recorded there.
#[tauri::command]
pub async fn forget_place(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store.forget_place(id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_mine(state: State<'_, AppState>) -> Result<Vec<MineEntry>, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store.list_mine().map_err(|e| e.to_string())
}

/// Mark an access point, radio group, BLE device or LAN device as mine (by hash).
#[tauri::command]
pub async fn add_mine(
    state: State<'_, AppState>,
    kind: MineKind,
    id_hash: String,
    label: Option<String>,
    ssid: Option<String>,
) -> Result<MineEntry, String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    let entry = MineEntry {
        kind,
        id_hash,
        label: label
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty()),
        // Only access-point marks carry a name; an empty one counts as none.
        ssid: ssid
            .filter(|_| matches!(kind, MineKind::WifiAp | MineKind::WifiGroup))
            .filter(|n| !n.is_empty()),
        added_at: pipeline::now_ms(),
    };
    store.mark_mine(&entry).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_mine(
    state: State<'_, AppState>,
    kind: MineKind,
    id_hash: String,
) -> Result<(), String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store.remove_mine(kind, &id_hash).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_watchlist(state: State<'_, AppState>) -> Result<Vec<WatchlistEntry>, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store.list_watchlist().map_err(|e| e.to_string())
}

/// JS argument is `matchMode`.
#[tauri::command]
pub async fn add_watchlist(
    state: State<'_, AppState>,
    kind: WatchKind,
    pattern: String,
    match_mode: WatchMatch,
) -> Result<WatchlistEntry, String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store
        .add_watchlist(kind, &pattern, match_mode, pipeline::now_ms())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn remove_watchlist(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let mut store = state.store.lock().map_err(lock_err)?;
    store.remove_watchlist(id).map_err(|e| e.to_string())
}

/// Stored LAN devices, all networks or one `network_key`, newest first. IPs are not stored.
#[tauri::command]
pub async fn list_lan_devices(
    state: State<'_, AppState>,
    network_key: Option<String>,
) -> Result<Vec<LanDevice>, String> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .list_lan_devices(network_key.as_deref())
        .map_err(|e| e.to_string())
}

/// The joined network and whether a sweep is currently allowed on it.
#[tauri::command]
pub async fn get_current_network(state: State<'_, AppState>) -> Result<NetworkInfo, String> {
    let (salt, settings, mine) = {
        let store = state.store.lock().map_err(lock_err)?;
        (
            store.salt().clone(),
            store.get_settings().map_err(|e| e.to_string())?,
            store.list_mine().map_err(|e| e.to_string())?,
        )
    };
    let inputs = LanInputs {
        salt,
        settings,
        mine,
        force_sweep: false,
        live: None,
    };
    // try_lock: a sweep holds this lock for ~12 s and the Network page polls this command, so
    // never queue behind it; a default state only loses the "last sweep" timestamp.
    let snapshot = match state.lan.try_lock() {
        Ok(guard) => guard.clone(),
        Err(_) => LanState::default(),
    };
    Ok(lan::current_network(&inputs, &snapshot))
}

/// "Sweep now": observe the LAN immediately (the sweep gate still applies), record it, and
/// return the stored devices for the joined network.
#[tauri::command]
pub async fn sweep_now(app: AppHandle) -> Result<Vec<LanDevice>, String> {
    let state = app.state::<AppState>();
    let (salt, settings, mine) = {
        let store = state.store.lock().map_err(lock_err)?;
        (
            store.salt().clone(),
            store.get_settings().map_err(|e| e.to_string())?,
            store.list_mine().map_err(|e| e.to_string())?,
        )
    };
    let inputs = LanInputs {
        salt,
        settings,
        mine,
        force_sweep: true,
        live: None,
    };
    let lan_state = Arc::clone(&state.lan);
    let refusal = tauri::async_runtime::spawn_blocking(move || {
        let guard = lan_state
            .lock()
            .map_err(|_| "lan lock poisoned".to_string())?;
        Ok::<_, String>(lan::sweep_refusal(&inputs, &guard))
    })
    .await
    .map_err(|e| e.to_string())??;
    if let Some(msg) = refusal {
        return Err(msg.to_string());
    }
    let _cycle = state.cycle.lock().await;
    let Some(outcome) = run_lan(&app, true).await else {
        return Ok(Vec::new());
    };
    let mut store = state.store.lock().map_err(lock_err)?;
    lan::record(&mut store, &outcome, pipeline::now_ms()).map_err(|e| e.to_string())?;
    store
        .list_lan_devices(outcome.network.network_key.as_deref())
        .map_err(|e| e.to_string())
}
