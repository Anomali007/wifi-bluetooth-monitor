//! Pure tracker classification over a BLE advertisement. No I/O, no btleplug types.
//!
//! Every constant below is cited to a primary source. Reference implementation:
//! Seemoo Lab AirGuard, <https://github.com/seemoo-lab/AirGuard>, read at commit
//! `d515c534be7aac370de33e7bae0136a7b995e0cf`; paths are under
//! `app/src/main/java/de/seemoo/at_tracking_detection/database/models/device/`.
//! Standard: IETF `draft-detecting-unwanted-location-trackers-01` (DULT, Dec 2023),
//! <https://www.ietf.org/archive/id/draft-detecting-unwanted-location-trackers-01.txt>.
//!
//! Scope and honesty notes:
//! - Classification says "this advertisement matches a documented tracker signature".
//!   It does not say the device is following anyone.
//! - Apple type 0x12 is the Find My (offline finding) advertisement used by AirTags,
//!   third-party Find My accessories, and also by ordinary iPhones/Macs/AirPods. AirGuard's
//!   `AppleDevice` filter matches any 0x4C payload whose first byte is 0x12. So 0x12 alone
//!   proves nothing; see the Find My rule on [`classify`].
//! - Only SEPARATED Find My adverts count as trackers (AirGuard `getConnectionState`, DULT
//!   near-owner bit). Nearby-owner adverts are reported via `owner_state` and never alert.
//!   Not field-verified with a real AirTag: the byte rules come from AirGuard source and the
//!   DULT draft, and are tested on synthetic bytes only.
//! - Pebblebee and Google Find My Device Network (FMDN) map to their own `TrackerKind`s.
//!   A DULT advertisement from a non-Apple network maps to `UnknownTracker`.
//! - NOT included because no primary source was verified: Tile 0xFEEC, Google FMDN frame
//!   type 0x41 (AirGuard's FEAA filter carries 0x40 with an all-zero mask, which does not
//!   constrain; we require 0x40), Samsung "Find My Mobile" phones/tablets.

use crate::model::{OwnerState, TrackerKind};
use std::collections::HashMap;

/// Bluetooth Base UUID: `0000xxxx-0000-1000-8000-00805F9B34FB`.
const BASE_UUID: u128 = 0x0000_0000_0000_1000_8000_0080_5F9B_34FB;

/// Expand a 16-bit assigned number to a full 128-bit UUID value.
pub const fn uuid16(short: u16) -> u128 {
    BASE_UUID | ((short as u128) << 96)
}

/// Apple company identifier.
pub const COMPANY_APPLE: u16 = 0x004C;
/// Apple manufacturer-data message type for Find My (offline finding).
/// AirGuard `types/AppleDevice.kt` `bluetoothFilter` (data `0x12 0x19`, mask `0xFF 0x00`:
/// only the first byte is compared) and `types/AirTag.kt` (same prefix + status byte).
pub const APPLE_TYPE_FIND_MY: u8 = 0x12;

/// Tile. AirGuard `types/Tile.kt`: `offlineFindingServiceUUID` = 0xFEED, filter on service
/// data prefix `02 00` mask `FF FF`. `DeviceManager.kt calculateDeviceType` also treats a
/// bare 0xFEED service UUID as Tile.
pub const SVC_TILE: u128 = uuid16(0xFEED);
pub const TILE_SERVICE_DATA_PREFIX: [u8; 2] = [0x02, 0x00];

/// Samsung SmartTag. AirGuard `types/SamsungTracker.kt`: service 0xFD5A; filter on service
/// data first byte `0x10` with mask `0xF8`.
pub const SVC_SAMSUNG_TAG: u128 = uuid16(0xFD5A);
pub const SAMSUNG_STATE_MASK: u8 = 0xF8;
pub const SAMSUNG_STATE_VALUE: u8 = 0x10;

/// Chipolo. AirGuard `types/Chipolo.kt`: `offlineFindingServiceUUID` = 0xFE33 (filter is
/// the service UUID alone).
pub const SVC_CHIPOLO: u128 = uuid16(0xFE33);

/// Pebblebee. AirGuard `types/PebbleBee.kt`: `offlineFindingServiceUUID` = 0xFA25.
pub const SVC_PEBBLEBEE: u128 = uuid16(0xFA25);

/// Google Find My Device Network. AirGuard `types/GoogleFindMyNetwork.kt`:
/// `offlineFindingServiceUUID` = 0xFEAA, service data first byte 0x40.
pub const SVC_GOOGLE_FMDN: u128 = uuid16(0xFEAA);
pub const GOOGLE_FMDN_FRAME_TYPE: u8 = 0x40;

/// DULT location-enabled advertisement. Draft section 3.6 / Table 1: service data TLV with
/// 16-bit UUID 0xFCB2. Service data: byte 0 = Network ID (section 3.7), byte 1 LSB =
/// near-owner bit (section 3.8, 1 = near owner, 0 = separated).
pub const SVC_DULT: u128 = uuid16(0xFCB2);
/// DULT temporary Network ID registry, section 10.1.1 Table 22: 0x01 Apple, 0x02 Google.
pub const DULT_NETWORK_APPLE: u8 = 0x01;

/// Result of classifying one advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Classification {
    /// `Some` only for an alertable tracker signature. A Find My style advert whose owner is
    /// nearby, or one that is not an AirTag / Find My accessory, is `None` here.
    pub tracker: Option<TrackerKind>,
    /// Set for Find My style adverts (Apple type 0x12 or DULT) so the UI can say why a
    /// 0x004C device is not flagged.
    pub owner_state: Option<OwnerState>,
}

/// Apple status byte (payload byte 2) device-type bits. AirGuard
/// `DeviceManager.kt` `calculateDeviceType` (lines 79-88): `(status & 0x30) >> 4` matched
/// against each class's `statusByteDeviceType`: 0 `AppleDevice.kt`, 1 `AirTag.kt`,
/// 2 `AppleFindMy.kt`, 3 `AirPods.kt`.
const APPLE_STATUS_TYPE_MASK: u8 = 0x30;
const APPLE_STATUS_TYPE_AIRTAG: u8 = 1;
const APPLE_STATUS_TYPE_FIND_MY: u8 = 2;

/// Apple Find My "separated" marker: payload byte 1 (the TLV length) is `0x19`. AirGuard
/// `types/AppleFindMy.kt` `getConnectionState` (lines 531-540): `mfg[1] == 0x19` is
/// `OVERMATURE_OFFLINE` (separated), any other value is `CONNECTED` (owner recently nearby);
/// `DeviceManager.kt` line 27 `unsafeConnectionState` = {OVERMATURE_OFFLINE, UNKNOWN} are the
/// only states AirGuard records as a possible tracker. The offline-finding filters in
/// `AirTag.kt` / `AppleFindMy.kt` (`bluetoothFilter`) also anchor on `0x12 0x19`.
const APPLE_SEPARATED_LEN: u8 = 0x19;

/// Classify one advertisement.
///
/// Order: DULT (standard) first, then Apple Find My, then vendor legacy service ids.
///
/// Find My rule (the false-positive fix): an Apple type 0x12 advert is only a tracker when it
/// is SEPARATED (length byte 0x19) and its status byte says AirTag or Find My accessory.
/// iPhones/Macs/AirPods and owner-nearby accessories also broadcast 0x12, and flagging them
/// produced ~28 false trackers in 3 minutes in a home with no AirTag. Deliberately more
/// conservative than AirGuard, which also tracks separated generic Apple devices and AirPods
/// but with longer thresholds; this app does not.
pub fn classify(
    manufacturer_data: &HashMap<u16, Vec<u8>>,
    service_uuids: &[u128],
    service_data: &HashMap<u128, Vec<u8>>,
) -> Classification {
    let mut owner_state = None;

    // 1. DULT standard advertisement: byte 0 network id, byte 1 LSB near-owner bit
    //    (draft section 3.8, Table 3: 1 = near owner, 0 = separated). Both bytes are REQUIRED
    //    by Table 1, so a shorter payload is not trusted.
    if let Some(d) = service_data.get(&SVC_DULT) {
        if d.len() >= 2 {
            if d[1] & 1 == 1 {
                return Classification {
                    tracker: None,
                    owner_state: Some(OwnerState::NearOwner),
                };
            }
            return Classification {
                tracker: Some(if d[0] == DULT_NETWORK_APPLE {
                    TrackerKind::AppleFindMy
                } else {
                    TrackerKind::UnknownTracker
                }),
                owner_state: Some(OwnerState::Separated),
            };
        }
    }

    // 2. Apple Find My: company 0x004C, first payload byte 0x12, status byte present
    //    (AirGuard `DeviceManager.calculateDeviceType` requires size >= 3).
    if let Some(p) = manufacturer_data.get(&COMPANY_APPLE) {
        if p.len() >= 3 && p[0] == APPLE_TYPE_FIND_MY {
            let separated = p[1] == APPLE_SEPARATED_LEN;
            owner_state = Some(if separated {
                OwnerState::Separated
            } else {
                OwnerState::NearOwner
            });
            let status_type = (p[2] & APPLE_STATUS_TYPE_MASK) >> 4;
            let accessory =
                status_type == APPLE_STATUS_TYPE_AIRTAG || status_type == APPLE_STATUS_TYPE_FIND_MY;
            if separated && accessory {
                return Classification {
                    tracker: Some(TrackerKind::AppleFindMy),
                    owner_state,
                };
            }
        }
    }

    let has_svc = |u: u128| service_uuids.contains(&u) || service_data.contains_key(&u);

    // 3. Vendor legacy ids.
    if let Some(d) = service_data.get(&SVC_TILE) {
        if d.starts_with(&TILE_SERVICE_DATA_PREFIX) {
            return vendor(owner_state, TrackerKind::Tile);
        }
    }
    if service_uuids.contains(&SVC_TILE) {
        return vendor(owner_state, TrackerKind::Tile);
    }

    if let Some(d) = service_data.get(&SVC_SAMSUNG_TAG) {
        if d.first()
            .is_some_and(|b| b & SAMSUNG_STATE_MASK == SAMSUNG_STATE_VALUE)
        {
            return vendor(owner_state, TrackerKind::SamsungSmartTag);
        }
    }
    if service_uuids.contains(&SVC_SAMSUNG_TAG) {
        return vendor(owner_state, TrackerKind::SamsungSmartTag);
    }

    if has_svc(SVC_CHIPOLO) {
        return vendor(owner_state, TrackerKind::Chipolo);
    }
    if has_svc(SVC_PEBBLEBEE) {
        return vendor(owner_state, TrackerKind::Pebblebee);
    }
    if let Some(d) = service_data.get(&SVC_GOOGLE_FMDN) {
        if d.first() == Some(&GOOGLE_FMDN_FRAME_TYPE) {
            return vendor(owner_state, TrackerKind::GoogleFindMy);
        }
    }
    Classification {
        tracker: None,
        owner_state,
    }
}

fn vendor(owner_state: Option<OwnerState>, kind: TrackerKind) -> Classification {
    Classification {
        tracker: Some(kind),
        owner_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mfg(id: u16, bytes: &[u8]) -> HashMap<u16, Vec<u8>> {
        HashMap::from([(id, bytes.to_vec())])
    }
    fn sd(u: u128, bytes: &[u8]) -> HashMap<u128, Vec<u8>> {
        HashMap::from([(u, bytes.to_vec())])
    }
    fn none_m() -> HashMap<u16, Vec<u8>> {
        HashMap::new()
    }
    fn tr(
        m: &HashMap<u16, Vec<u8>>,
        u: &[u128],
        s: &HashMap<u128, Vec<u8>>,
    ) -> Option<TrackerKind> {
        classify(m, u, s).tracker
    }
    fn none_s() -> HashMap<u128, Vec<u8>> {
        HashMap::new()
    }

    #[test]
    fn uuid16_expands_to_base() {
        assert_eq!(uuid16(0xFEED), 0x0000FEED_0000_1000_8000_00805F9B34FB);
    }

    /// Synthetic Apple 0x12 payload: type, length byte, status byte, then filler.
    fn apple12(len_byte: u8, status: u8) -> Vec<u8> {
        let mut p = vec![0x12, len_byte, status];
        p.extend([0xAA; 22]);
        p
    }

    #[test]
    fn separated_airtag_and_find_my_accessory_are_trackers() {
        // status 0x10 -> device type 1 (AirTag), 0x20 -> 2 (Find My accessory); low bits
        // (battery, flags) must not matter.
        for status in [0x10u8, 0x14, 0x50, 0x20, 0x24, 0xA0] {
            let c = classify(&mfg(0x004C, &apple12(0x19, status)), &[], &none_s());
            assert_eq!(c.tracker, Some(TrackerKind::AppleFindMy), "{status:#x}");
            assert_eq!(c.owner_state, Some(OwnerState::Separated));
        }
    }

    #[test]
    fn nearby_owner_find_my_is_not_a_tracker() {
        // Length byte != 0x19 (AirGuard: CONNECTED). Same status bytes as above.
        for len in [0x02u8, 0x00, 0x18, 0x1A, 0xFF] {
            for status in [0x10u8, 0x20] {
                let c = classify(&mfg(0x004C, &apple12(len, status)), &[], &none_s());
                assert_eq!(c.tracker, None, "len {len:#x} status {status:#x}");
                assert_eq!(c.owner_state, Some(OwnerState::NearOwner));
            }
        }
        let short = [0x12u8, 0x02, 0x00, 0x01];
        assert_eq!(tr(&mfg(0x004C, &short), &[], &none_s()), None);
    }

    #[test]
    fn separated_iphone_mac_and_airpods_status_types_are_not_trackers() {
        // 0x00 -> type 0 (generic Apple device), 0x30 -> 3 (AirPods).
        for status in [0x00u8, 0x04, 0x30, 0x34, 0x3F] {
            let c = classify(&mfg(0x004C, &apple12(0x19, status)), &[], &none_s());
            assert_eq!(c.tracker, None, "{status:#x}");
        }
    }

    #[test]
    fn dult_near_owner_bit_decides() {
        let near = sd(SVC_DULT, &[0x01, 0x01]);
        let c = classify(&none_m(), &[], &near);
        assert_eq!(c.tracker, None);
        assert_eq!(c.owner_state, Some(OwnerState::NearOwner));
        // Reserved bits do not matter, only the LSB.
        assert_eq!(
            tr(&none_m(), &[], &sd(SVC_DULT, &[0x01, 0xFE])),
            Some(TrackerKind::AppleFindMy)
        );
        // Single byte: bit missing, not trusted.
        assert_eq!(tr(&none_m(), &[], &sd(SVC_DULT, &[0x01])), None);
    }

    #[test]
    fn positive_dult_apple_network() {
        let s = sd(SVC_DULT, &[0x01, 0x00]); // near-owner bit 0 = separated
        assert_eq!(tr(&none_m(), &[], &s), Some(TrackerKind::AppleFindMy));
    }

    #[test]
    fn positive_dult_other_network_is_unknown_tracker() {
        let s = sd(SVC_DULT, &[0x02, 0x00]);
        assert_eq!(tr(&none_m(), &[], &s), Some(TrackerKind::UnknownTracker));
    }

    #[test]
    fn positive_tile_service_data() {
        let s = sd(SVC_TILE, &[0x02, 0x00, 0x11, 0x22]);
        assert_eq!(tr(&none_m(), &[], &s), Some(TrackerKind::Tile));
    }

    #[test]
    fn positive_tile_service_uuid_only() {
        assert_eq!(
            tr(&none_m(), &[SVC_TILE], &none_s()),
            Some(TrackerKind::Tile)
        );
    }

    #[test]
    fn positive_samsung_smarttag() {
        // 0x10..=0x17 all match mask 0xF8 -> 0x10
        for b in [0x10u8, 0x13, 0x17] {
            let s = sd(SVC_SAMSUNG_TAG, &[b, 0x01, 0x02]);
            assert_eq!(
                tr(&none_m(), &[], &s),
                Some(TrackerKind::SamsungSmartTag),
                "{b:#x}"
            );
        }
        assert_eq!(
            tr(&none_m(), &[SVC_SAMSUNG_TAG], &none_s()),
            Some(TrackerKind::SamsungSmartTag)
        );
    }

    #[test]
    fn positive_chipolo() {
        assert_eq!(
            tr(&none_m(), &[SVC_CHIPOLO], &none_s()),
            Some(TrackerKind::Chipolo)
        );
        let s = sd(SVC_CHIPOLO, &[0x00, 0x01]);
        assert_eq!(tr(&none_m(), &[], &s), Some(TrackerKind::Chipolo));
    }

    #[test]
    fn positive_pebblebee_and_google_have_their_own_kinds() {
        assert_eq!(
            tr(&none_m(), &[SVC_PEBBLEBEE], &none_s()),
            Some(TrackerKind::Pebblebee)
        );
        let s = sd(SVC_GOOGLE_FMDN, &[0x40, 0x01]);
        assert_eq!(tr(&none_m(), &[], &s), Some(TrackerKind::GoogleFindMy));
    }

    // ---- negatives ----

    #[test]
    fn negative_apple_non_tracker_message_types() {
        // 0x10 Nearby Info, 0x0C Handoff, 0x07 Proximity Pairing (AirPods), 0x05 AirDrop,
        // 0x09 AirPlay target, 0x0F Nearby Action, 0x16 Nearby Action v2.
        for t in [0x10u8, 0x0C, 0x07, 0x05, 0x09, 0x0F, 0x16] {
            let p = [t, 0x19, 0x10, 0x02, 0x03, 0x04, 0x05];
            assert_eq!(tr(&mfg(0x004C, &p), &[], &none_s()), None, "type {t:#x}");
        }
    }

    #[test]
    fn negative_type_12_in_other_company_or_too_short() {
        let p = [0x12, 0x19, 0x10, 0x00];
        assert_eq!(tr(&mfg(0x0006, &p), &[], &none_s()), None); // not Apple
        assert_eq!(tr(&mfg(0x004C, &[0x12, 0x19]), &[], &none_s()), None); // no status byte
        assert_eq!(tr(&mfg(0x004C, &[]), &[], &none_s()), None);
    }

    #[test]
    fn negative_eddystone_and_samsung_non_tag_and_tile_wrong_prefix() {
        // Eddystone-URL frame (0x10) on FEAA is not Google FMDN (0x40).
        let e = sd(SVC_GOOGLE_FMDN, &[0x10, 0x00, 0x03]);
        assert_eq!(tr(&none_m(), &[], &e), None);
        // Samsung service data whose state nibble does not match 0x10/0xF8.
        let s = sd(SVC_SAMSUNG_TAG, &[0x20, 0x00]);
        assert_eq!(tr(&none_m(), &[], &s), None);
        // Tile service data without 02 00 prefix and no uuid listing.
        let t = sd(SVC_TILE, &[0x01, 0x00]);
        assert_eq!(tr(&none_m(), &[], &t), None);
    }

    #[test]
    fn negative_empty_and_generic() {
        assert_eq!(tr(&none_m(), &[], &none_s()), None);
        // Heart-rate service 0x180D, a random company id.
        assert_eq!(
            tr(&mfg(0x0059, &[1, 2, 3]), &[uuid16(0x180D)], &none_s()),
            None
        );
        // Empty DULT service data does not classify.
        assert_eq!(tr(&none_m(), &[], &sd(SVC_DULT, &[])), None);
    }
}
