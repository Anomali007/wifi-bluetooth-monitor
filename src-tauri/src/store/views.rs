//! Read-only views over the store that both the agent tools and the app's proposal approval
//! use, so the two can never disagree about what "seen recently" or "alert active" means.

use super::{Store, StoreResult};
use crate::detect::ssid_subject_hash;
use crate::model::{AlertKind, Millis, MineKind, ScanSnapshot};
use std::collections::{HashMap, HashSet};

/// An alert counts as active for a name while it was last seen this recently: three scan
/// intervals, and never less than ten minutes.
fn active_window_ms(scan_interval_secs: u32) -> Millis {
    (i64::from(scan_interval_secs) * 3_000).max(600_000)
}

impl Store {
    /// The newest stored scan, if any.
    pub fn latest_scan(&self) -> StoreResult<Option<ScanSnapshot>> {
        let Some(at) = self.latest_scan_at()? else {
            return Ok(None);
        };
        Ok(self.get_history(at)?.scans.into_iter().last())
    }

    /// Hashes of `kind` the monitor has stored, so a typo cannot mark nothing and a made-up
    /// value is refused.
    pub fn known_hashes(&self, kind: MineKind, now: Millis) -> StoreResult<HashSet<String>> {
        let mut out = HashSet::new();
        match kind {
            MineKind::Lan => {
                out.extend(self.list_lan_devices(None)?.into_iter().map(|d| d.mac_hash))
            }
            _ => {
                let hours = i64::from(self.get_settings()?.retention_hours);
                let history = self.get_history(now - hours * 3_600_000)?;
                for s in &history.scans {
                    match kind {
                        MineKind::WifiAp => {
                            out.extend(s.wifi.iter().filter_map(|o| o.bssid_hash.clone()))
                        }
                        MineKind::WifiGroup => {
                            out.extend(s.wifi.iter().filter_map(|o| o.group_id.clone()))
                        }
                        _ => out.extend(s.ble.iter().map(|o| o.peripheral_hash.clone())),
                    }
                }
                if matches!(kind, MineKind::WifiAp | MineKind::WifiGroup) {
                    for p in self.list_places()? {
                        out.extend(p.members);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Network names seen in the latest scan or on the trusted list, keyed by the subject hash
    /// that evil-twin and open-lookalike alerts about them carry. Lets a caller name an alert's
    /// subject without reading alert text.
    pub fn ssid_subject_names(&self) -> StoreResult<HashMap<String, String>> {
        let mut names: Vec<String> = self
            .latest_scan()?
            .map(|s| s.wifi.into_iter().filter_map(|o| o.ssid).collect())
            .unwrap_or_default();
        names.extend(
            self.get_settings()?
                .trusted_networks
                .into_iter()
                .map(|t| t.ssid),
        );
        Ok(names
            .into_iter()
            .map(|n| (ssid_subject_hash(&n), n))
            .collect())
    }

    /// An active (not dismissed, recently seen) evil-twin or open-lookalike alert whose subject
    /// is this network name, found by the alert's subject hash, never by its text.
    pub fn active_ssid_alert(&self, ssid: &str, now: Millis) -> StoreResult<Option<AlertKind>> {
        let subject = ssid_subject_hash(ssid);
        let since = now - active_window_ms(self.get_settings()?.scan_interval_secs);
        Ok(self
            .get_alerts(false)?
            .into_iter()
            .find(|a| {
                matches!(a.kind, AlertKind::EvilTwin | AlertKind::OpenLookalike)
                    && a.subject_hash == subject
                    && a.last_seen >= since
            })
            .map(|a| a.kind))
    }
}
