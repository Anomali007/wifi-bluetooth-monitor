//! Wi-Fi + Bluetooth Monitor backend.
//!
//! Listen-only: every scan API used here is receive-only. Nothing in this crate
//! transmits, probes, connects to or pairs with a discovered device, with one gated
//! exception: the opt-in network sweep in `lan/sweep.rs` (see `lan/gate.rs`).
//!
//! Module map (file ownership is defined in the build roadmap):
//! - [`model`]    shared, frozen types and the identifier-hashing helper
//! - [`wifi`]     CoreWLAN scan -> `WifiObservation`
//! - [`ble`]      btleplug scan + tracker classification -> `BleObservation`
//! - [`detect`]   pure detection rules over a `History`
//! - [`store`]    SQLite persistence, retention purge, per-install salt
//! - [`vendor`]   OUI vendor lookup and multi-radio grouping (raw address in, plain/hashed out)
//! - [`places`]   Wi-Fi-fingerprint place memory and dwell tracking
//! - [`lan`]      local-network discovery (ARP, receive-only mDNS, opt-in sweep)
//! - [`pipeline`] one scan cycle without Tauri: assemble -> store -> detect -> upsert
//! - [`commands`] the Tauri command surface and the background scan loop

pub mod ble;
pub mod commands;
pub mod detect;
pub mod lan;
pub mod model;
pub mod pipeline;
pub mod places;
pub mod store;
pub mod vendor;
pub mod wifi;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri::Manager;
    use tauri_plugin_notification::NotificationExt;
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            commands::scan_now,
            commands::get_history,
            commands::get_alerts,
            commands::dismiss_alert,
            commands::get_settings,
            commands::set_settings,
            commands::get_permissions,
            commands::list_places,
            commands::rename_place,
            commands::forget_place,
            commands::list_mine,
            commands::add_mine,
            commands::remove_mine,
            commands::list_watchlist,
            commands::add_watchlist,
            commands::remove_watchlist,
            commands::list_lan_devices,
            commands::get_current_network,
            commands::sweep_now,
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            let dir = app.path().app_data_dir()?;
            let store = store::Store::open(&dir)?;
            let notify = store.get_settings().map(|s| s.notify).unwrap_or(true);
            app.manage(commands::AppState::new(store));

            // `setup` runs on the main thread, which CoreLocation requires for the prompt.
            wifi::request_location_permission();
            if notify {
                let _ = app.notification().request_permission();
            }

            commands::spawn_scan_loop(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
