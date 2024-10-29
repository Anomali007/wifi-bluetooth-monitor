// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// fn main() {
//   app_lib::run();
// }

use btleplug::api::{Central, Manager as _, Peripheral, ScanFilter};
use btleplug::platform::Manager as BtleplugManager;
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use tauri::Manager;
use tokio_wifiscanner::scan as wifi_scan;

#[derive(Serialize)]
struct NetworkDevice {
    name: String,
    identifier: String, // Hashed BSSID or MAC address
    signal_strength: Option<i32>,
    timestamp: String,
    device_type: String, // "Wi-Fi" or "Bluetooth"
}

fn anonymize_identifier(identifier: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(identifier);
    format!("{:x}", hasher.finalize())
}

#[tauri::command]
async fn scan_networks() -> Result<Vec<NetworkDevice>, String> {
    let salt = "your_secret_salt"; // Replace with a secure method to store the salt
    let mut devices = Vec::new();

    // Wi-Fi scanning
    match wifi_scan().await {
        Ok(wifi_networks) => {
            for network in wifi_networks {
                devices.push(NetworkDevice {
                    name: network.ssid,
                    identifier: anonymize_identifier(&network.mac, salt),
                    signal_strength: Some(network.signal_level),
                    timestamp: Utc::now().to_rfc3339(),
                    device_type: "Wi-Fi".to_string(),
                });
            }
        }
        Err(e) => {
            println!("Error scanning Wi-Fi networks: {:?}", e);
            // Handle the error as needed
        }
    }

    // Bluetooth scanning
    match scan_bluetooth_devices(salt).await {
        Ok(bluetooth_devices) => {
            devices.extend(bluetooth_devices);
        }
        Err(e) => {
            println!("Error scanning Bluetooth devices: {:?}", e);
            // Handle the error as needed
        }
    }

    Ok(devices)
}

async fn scan_bluetooth_devices(salt: &str) -> Result<Vec<NetworkDevice>, Box<dyn Error>> {
    let manager = BtleplugManager::new().await?;
    let adapters = manager.adapters().await?;
    let mut devices = Vec::new();

    for adapter in adapters {
        println!(
            "Starting scan on adapter: {}",
            adapter.adapter_info().await?
        );
        adapter.start_scan(ScanFilter::default()).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await; // Scan for 10 seconds

        let peripherals = adapter.peripherals().await?;
        for peripheral in peripherals {
            let properties = peripheral.properties().await?;
            if let Some(props) = properties {
                devices.push(NetworkDevice {
                    name: props
                        .local_name
                        .unwrap_or_else(|| "Unknown Device".to_string()),
                    identifier: anonymize_identifier(&props.address.to_string(), salt),
                    signal_strength: props.rssi,
                    timestamp: Utc::now().to_rfc3339(),
                    device_type: "Bluetooth".to_string(),
                });
            }
        }
        adapter.stop_scan().await?;
    }

    Ok(devices)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![scan_networks])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
