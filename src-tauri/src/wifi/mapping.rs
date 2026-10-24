//! Pure mapping from plain CoreWLAN values to [`WifiObservation`]. No Objective-C here, so
//! it is unit-testable with synthetic inputs.

use crate::model::{hash_identifier, Millis, PermissionStatus, Salt, Security, WifiObservation};

/// Raw `CWSecurity` values (Apple `CoreWLANTypes.h`, `kCWSecurity*`).
pub(super) mod cw_security {
    pub const NONE: isize = 0;
    pub const WEP: isize = 1;
    pub const WPA_PERSONAL: isize = 2;
    pub const WPA_PERSONAL_MIXED: isize = 3;
    pub const WPA2_PERSONAL: isize = 4;
    pub const PERSONAL: isize = 5;
    pub const DYNAMIC_WEP: isize = 6;
    pub const WPA_ENTERPRISE: isize = 7;
    pub const WPA_ENTERPRISE_MIXED: isize = 8;
    pub const WPA2_ENTERPRISE: isize = 9;
    pub const ENTERPRISE: isize = 10;
    pub const WPA3_PERSONAL: isize = 11;
    pub const WPA3_ENTERPRISE: isize = 12;
    pub const WPA3_TRANSITION: isize = 13;
    pub const OWE: isize = 14;
    pub const OWE_TRANSITION: isize = 15;
    /// Every raw value worth probing with `supportsSecurity:`.
    pub const ALL: [isize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
}

/// One network as CoreWLAN reports it, reduced to plain Rust values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawNetwork {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub rssi: i64,
    pub channel: Option<i64>,
    /// Raw `CWSecurity` values for which `supportsSecurity:` returned true.
    pub supported_security: Vec<isize>,
}

/// Collapse the set of supported `CWSecurity` values to one [`Security`], choosing the
/// strongest mode the network advertises (a WPA2/WPA3 transition network reports WPA3).
///
/// `Open` only when `None` is supported and nothing stronger is. OWE (encrypted, no
/// password) maps to `Owe`, which is never treated as open.
pub(super) fn map_security(supported: &[isize]) -> Security {
    use cw_security::*;
    let has = |v: isize| supported.contains(&v);
    if has(WPA3_ENTERPRISE) {
        Security::Wpa3Enterprise
    } else if has(WPA3_PERSONAL) || has(WPA3_TRANSITION) {
        Security::Wpa3Personal
    } else if has(WPA2_ENTERPRISE) || has(ENTERPRISE) {
        Security::Wpa2Enterprise
    } else if has(WPA_ENTERPRISE) || has(WPA_ENTERPRISE_MIXED) {
        Security::WpaEnterprise
    } else if has(WPA2_PERSONAL) || has(PERSONAL) {
        Security::Wpa2Personal
    } else if has(WPA_PERSONAL) || has(WPA_PERSONAL_MIXED) {
        Security::WpaPersonal
    } else if has(WEP) || has(DYNAMIC_WEP) {
        Security::Wep
    } else if has(OWE) || has(OWE_TRANSITION) {
        Security::Owe
    } else if has(NONE) {
        Security::Open
    } else {
        Security::Unknown
    }
}

/// A nil or empty string becomes `None`, never `""`.
fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Map one raw network to an observation. The BSSID is hashed here; the raw value is dropped.
pub(super) fn map_network(raw: &RawNetwork, salt: &Salt, seen_at: Millis) -> WifiObservation {
    WifiObservation {
        ssid: raw.ssid.as_ref().filter(|s| !s.is_empty()).cloned(),
        bssid_hash: non_empty(&raw.bssid).map(|b| hash_identifier(salt, b)),
        rssi: raw.rssi.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
        channel: raw
            .channel
            .and_then(|c| u32::try_from(c).ok())
            .filter(|c| *c > 0),
        security: map_security(&raw.supported_security),
        seen_at,
    }
}

/// Map `CLAuthorizationStatus` raw values: 0 notDetermined, 1 restricted, 2 denied,
/// 3 authorizedAlways, 4 authorizedWhenInUse.
pub(super) fn map_authorization(raw: i32) -> PermissionStatus {
    match raw {
        0 => PermissionStatus::NotDetermined,
        1 => PermissionStatus::Restricted,
        2 => PermissionStatus::Denied,
        3 | 4 => PermissionStatus::Granted,
        _ => PermissionStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::cw_security::*;
    use super::*;

    fn salt(b: u8) -> Salt {
        Salt::from_bytes(vec![b; 16])
    }

    fn raw(ssid: Option<&str>, bssid: Option<&str>, sec: &[isize]) -> RawNetwork {
        RawNetwork {
            ssid: ssid.map(String::from),
            bssid: bssid.map(String::from),
            rssi: -55,
            channel: Some(6),
            supported_security: sec.to_vec(),
        }
    }

    #[test]
    fn security_each_mode() {
        let cases: [(&[isize], Security); 12] = [
            (&[NONE], Security::Open),
            (&[WEP], Security::Wep),
            (&[DYNAMIC_WEP], Security::Wep),
            (&[WPA_PERSONAL], Security::WpaPersonal),
            (&[WPA_PERSONAL_MIXED, WPA_PERSONAL], Security::WpaPersonal),
            (&[WPA2_PERSONAL], Security::Wpa2Personal),
            (&[WPA3_PERSONAL], Security::Wpa3Personal),
            (&[WPA_ENTERPRISE], Security::WpaEnterprise),
            (&[WPA2_ENTERPRISE], Security::Wpa2Enterprise),
            (&[WPA3_ENTERPRISE], Security::Wpa3Enterprise),
            (&[OWE], Security::Owe),
            (&[], Security::Unknown),
        ];
        for (input, want) in cases {
            assert_eq!(map_security(input), want, "input {input:?}");
        }
    }

    #[test]
    fn security_picks_strongest_of_transition() {
        assert_eq!(
            map_security(&[WPA2_PERSONAL, WPA3_PERSONAL, WPA3_TRANSITION]),
            Security::Wpa3Personal
        );
        assert_eq!(
            map_security(&[WPA2_PERSONAL, WPA2_ENTERPRISE]),
            Security::Wpa2Enterprise
        );
        // `None` alongside OWE transition must not read as open.
        assert_eq!(map_security(&[NONE, OWE_TRANSITION]), Security::Owe);
    }

    #[test]
    fn nil_ssid_and_bssid_become_none() {
        let o = map_network(&raw(None, None, &[WPA2_PERSONAL]), &salt(1), 10);
        assert_eq!(o.ssid, None);
        assert_eq!(o.bssid_hash, None);
        assert_eq!(o.seen_at, 10);
    }

    #[test]
    fn empty_strings_are_never_kept() {
        let o = map_network(&raw(Some(""), Some("  "), &[NONE]), &salt(1), 0);
        assert_eq!(o.ssid, None);
        assert_eq!(o.bssid_hash, None);
    }

    #[test]
    fn hidden_network_has_hash_but_no_ssid() {
        let o = map_network(
            &raw(None, Some("02:00:00:aa:bb:01"), &[WPA2_PERSONAL]),
            &salt(1),
            0,
        );
        assert_eq!(o.ssid, None);
        assert_eq!(o.bssid_hash.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn visible_network_maps_all_fields() {
        let o = map_network(
            &raw(Some("Net-A"), Some("02:00:00:aa:bb:02"), &[WPA3_PERSONAL]),
            &salt(1),
            99,
        );
        assert_eq!(o.ssid.as_deref(), Some("Net-A"));
        assert_eq!(o.rssi, -55);
        assert_eq!(o.channel, Some(6));
        assert_eq!(o.security, Security::Wpa3Personal);
    }

    #[test]
    fn channel_mapping() {
        let mut r = raw(Some("Net-A"), None, &[NONE]);
        for (input, want) in [
            (Some(1), Some(1)),
            (Some(149), Some(149)),
            (Some(0), None),
            (Some(-3), None),
            (None, None),
        ] {
            r.channel = input;
            assert_eq!(map_network(&r, &salt(1), 0).channel, want);
        }
    }

    #[test]
    fn bssid_hash_is_deterministic_salted_and_case_insensitive() {
        let a = map_network(&raw(None, Some("02:00:00:AA:BB:03"), &[NONE]), &salt(1), 0).bssid_hash;
        let b = map_network(&raw(None, Some("02:00:00:aa:bb:03"), &[NONE]), &salt(1), 5).bssid_hash;
        let c = map_network(&raw(None, Some("02:00:00:aa:bb:03"), &[NONE]), &salt(2), 0).bssid_hash;
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(!a.unwrap().contains("02:00"));
    }

    #[test]
    fn authorization_mapping() {
        assert_eq!(map_authorization(0), PermissionStatus::NotDetermined);
        assert_eq!(map_authorization(1), PermissionStatus::Restricted);
        assert_eq!(map_authorization(2), PermissionStatus::Denied);
        assert_eq!(map_authorization(3), PermissionStatus::Granted);
        assert_eq!(map_authorization(4), PermissionStatus::Granted);
        assert_eq!(map_authorization(99), PermissionStatus::Unknown);
    }
}
