//! Wi-Fi + Bluetooth Monitor backend.
//!
//! Listen-only: every scan API used here is receive-only. Nothing in this crate
//! transmits, probes, connects to or pairs with a discovered device.
//!
//! Module map (file ownership is defined in the build roadmap):
//! - [`model`]    shared, frozen types and the identifier-hashing helper
//! - [`wifi`]     CoreWLAN scan -> `WifiObservation`
//! - [`ble`]      btleplug scan + tracker classification -> `BleObservation`
//! - [`detect`]   pure detection rules over a `History`
//! - [`store`]    SQLite persistence, retention purge, per-install salt
//! - [`commands`] the Tauri command surface

pub mod ble;
pub mod commands;
pub mod detect;
pub mod model;
pub mod store;
pub mod wifi;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
