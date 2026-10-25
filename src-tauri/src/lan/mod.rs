//! Local-network discovery: ARP table, receive-only mDNS, opt-in sweep. OWNER: WP-D.
//!
//! CONTRACT (frozen signatures; logic is a stub until WP-D):
//! - Passive (always): read the ARP table via `sysctl`, listen on mDNS (never send).
//! - Active sweep: only when `settings.lan_active_sweep` AND the joined access point is in
//!   Mine, or when `force_sweep` is set by the user's "Sweep now" (the same gate still applies).
//!   One zero-byte UDP datagram per host to port 9, rate-limited. No TCP, no port scans.
//! - [`scan`] is blocking; callers run it on a blocking thread. [`record`] persists the
//!   outcome (devices by MAC hash, never an IP).

use crate::model::{LanDevice, Millis, MineEntry, NetworkInfo, Salt, ScanError, Settings};
use crate::store::{Store, StoreResult};

/// Everything [`scan`] needs, so the signature can stay frozen while the inputs grow.
#[derive(Debug, Clone)]
pub struct LanInputs {
    pub salt: Salt,
    pub settings: Settings,
    pub mine: Vec<MineEntry>,
    /// The user pressed "Sweep now". Still subject to the sweep gate.
    pub force_sweep: bool,
}

/// State kept between cycles (sweep cadence). Lives in `AppState`.
#[derive(Debug, Clone, Default)]
pub struct LanState {
    pub last_sweep_at: Option<Millis>,
}

/// What one LAN observation produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LanScanOutcome {
    pub network: NetworkInfo,
    pub devices: Vec<LanDevice>,
}

/// Observe the joined network. Stub: returns an empty outcome.
pub fn scan(_inputs: &LanInputs, _state: &mut LanState) -> Result<LanScanOutcome, ScanError> {
    Ok(LanScanOutcome::default())
}

/// The currently joined network without touching the LAN. Stub: no network.
pub fn current_network(_inputs: &LanInputs, _state: &LanState) -> NetworkInfo {
    NetworkInfo::default()
}

/// Persist an outcome's devices. Stub: stores nothing.
pub fn record(_store: &mut Store, _outcome: &LanScanOutcome, _now: Millis) -> StoreResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> LanInputs {
        LanInputs {
            salt: Salt::from_bytes(vec![1; 32]),
            settings: Settings::default(),
            mine: vec![],
            force_sweep: false,
        }
    }

    #[test]
    fn stub_scan_is_empty_and_passive() {
        let out = scan(&inputs(), &mut LanState::default()).unwrap();
        assert!(out.devices.is_empty());
        assert!(!out.network.sweep_enabled);
        assert_eq!(
            out.network,
            current_network(&inputs(), &LanState::default())
        );
    }
}
