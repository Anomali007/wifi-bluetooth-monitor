//! `CLLocationManager` authorisation. macOS withholds SSID/BSSID from CoreWLAN scan results
//! unless the app has Location authorisation.

use super::mapping::map_authorization;
use crate::model::PermissionStatus;

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use objc2::rc::Retained;
    use objc2::MainThreadMarker;
    use objc2_core_location::CLLocationManager;
    use std::sync::Mutex;

    /// The manager must outlive the prompt, so keep it. `CLLocationManager` is only touched
    /// from the main thread (request) or read-only (status), guarded by the mutex.
    struct Held(Retained<CLLocationManager>);
    // SAFETY: access is serialised by the Mutex and the only mutating call
    // (`requestWhenInUseAuthorization`) is made on the main thread.
    unsafe impl Send for Held {}

    static MANAGER: Mutex<Option<Held>> = Mutex::new(None);

    pub fn status() -> PermissionStatus {
        // SAFETY: `authorizationStatus` is a plain getter; the instance is created and used here.
        let raw = unsafe { CLLocationManager::new().authorizationStatus() };
        map_authorization(raw.0)
    }

    pub fn request() -> bool {
        let Some(mtm) = MainThreadMarker::new() else {
            return false;
        };
        let _ = mtm;
        let Ok(mut guard) = MANAGER.lock() else {
            return false;
        };
        let held = guard.get_or_insert_with(|| Held(unsafe { CLLocationManager::new() }));
        // SAFETY: main thread, manager retained in the static.
        unsafe { held.0.requestWhenInUseAuthorization() };
        true
    }
}

/// Current Location authorisation.
#[cfg(target_os = "macos")]
pub fn status() -> PermissionStatus {
    imp::status()
}

/// Ask for WhenInUse authorisation. Returns `false` (and does nothing) when not called on
/// the main thread. Only shows a prompt while the status is `NotDetermined`, and only for
/// a bundled app with `NSLocationWhenInUseUsageDescription` in its Info.plist.
#[cfg(target_os = "macos")]
pub fn request() -> bool {
    imp::request()
}

#[cfg(not(target_os = "macos"))]
pub fn status() -> PermissionStatus {
    let _ = map_authorization;
    PermissionStatus::Unknown
}

#[cfg(not(target_os = "macos"))]
pub fn request() -> bool {
    false
}
