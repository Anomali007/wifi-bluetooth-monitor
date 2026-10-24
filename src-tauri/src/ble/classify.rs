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
//!   third-party Find My accessories and some AirPods/iPhones in lost mode. AirGuard's
//!   `AppleDevice` filter matches any 0x4C payload whose first byte is 0x12.
//! - Pebblebee and Google Find My Device Network (FMDN) map to their own `TrackerKind`s.
//!   A DULT advertisement from a non-Apple network maps to `UnknownTracker`.
//! - NOT included because no primary source was verified: Tile 0xFEEC, Google FMDN frame
//!   type 0x41 (AirGuard's FEAA filter carries 0x40 with an all-zero mask, which does not
//!   constrain; we require 0x40), Samsung "Find My Mobile" phones/tablets.

use crate::model::TrackerKind;
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

/// Classify one advertisement. `None` means "no tracker signature matched".
///
/// Order: DULT (standard) first, then Apple Find My, then vendor legacy service ids.
pub fn classify(
    manufacturer_data: &HashMap<u16, Vec<u8>>,
    service_uuids: &[u128],
    service_data: &HashMap<u128, Vec<u8>>,
) -> Option<TrackerKind> {
    // 1. DULT standard advertisement.
    if let Some(d) = service_data.get(&SVC_DULT) {
        if let Some(&network) = d.first() {
            return Some(if network == DULT_NETWORK_APPLE {
                TrackerKind::AppleFindMy
            } else {
                TrackerKind::UnknownTracker
            });
        }
    }

    // 2. Apple Find My: company 0x004C, first payload byte 0x12, and a status byte present
    //    (AirGuard `DeviceManager.calculateDeviceType` requires size >= 3).
    if let Some(p) = manufacturer_data.get(&COMPANY_APPLE) {
        if p.len() >= 3 && p[0] == APPLE_TYPE_FIND_MY {
            return Some(TrackerKind::AppleFindMy);
        }
    }

    let has_svc = |u: u128| service_uuids.contains(&u) || service_data.contains_key(&u);

    // 3. Vendor legacy ids.
    if let Some(d) = service_data.get(&SVC_TILE) {
        if d.starts_with(&TILE_SERVICE_DATA_PREFIX) {
            return Some(TrackerKind::Tile);
        }
    }
    if service_uuids.contains(&SVC_TILE) {
        return Some(TrackerKind::Tile);
    }

    if let Some(d) = service_data.get(&SVC_SAMSUNG_TAG) {
        if d.first()
            .is_some_and(|b| b & SAMSUNG_STATE_MASK == SAMSUNG_STATE_VALUE)
        {
            return Some(TrackerKind::SamsungSmartTag);
        }
    }
    if service_uuids.contains(&SVC_SAMSUNG_TAG) {
        return Some(TrackerKind::SamsungSmartTag);
    }

    if has_svc(SVC_CHIPOLO) {
        return Some(TrackerKind::Chipolo);
    }
    if has_svc(SVC_PEBBLEBEE) {
        return Some(TrackerKind::Pebblebee);
    }
    if let Some(d) = service_data.get(&SVC_GOOGLE_FMDN) {
        if d.first() == Some(&GOOGLE_FMDN_FRAME_TYPE) {
            return Some(TrackerKind::GoogleFindMy);
        }
    }
    None
}

/// Apple Find My "separated from owner" state. AirGuard `types/AppleFindMy.kt`
/// `getConnectionState`: payload byte 1 (the TLV length) == 0x19 means offline/separated,
/// anything else means the owner device was recently connected. Not used by the contract
/// today; exposed for the detector to refine severity later.
pub fn apple_find_my_separated(payload: &[u8]) -> Option<bool> {
    if payload.len() > 2 && payload[0] == APPLE_TYPE_FIND_MY {
        Some(payload[1] == 0x19)
    } else {
        None
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
    fn none_s() -> HashMap<u128, Vec<u8>> {
        HashMap::new()
    }

    #[test]
    fn uuid16_expands_to_base() {
        assert_eq!(uuid16(0xFEED), 0x0000FEED_0000_1000_8000_00805F9B34FB);
    }

    #[test]
    fn positive_apple_find_my_offline() {
        let mut p = vec![0x12, 0x19, 0x10];
        p.extend([0xAA; 24]);
        assert_eq!(
            classify(&mfg(0x004C, &p), &[], &none_s()),
            Some(TrackerKind::AppleFindMy)
        );
        assert_eq!(apple_find_my_separated(&p), Some(true));
    }

    #[test]
    fn positive_apple_find_my_owner_nearby_len() {
        let p = [0x12, 0x02, 0x00, 0x01];
        assert_eq!(
            classify(&mfg(0x004C, &p), &[], &none_s()),
            Some(TrackerKind::AppleFindMy)
        );
        assert_eq!(apple_find_my_separated(&p), Some(false));
    }

    #[test]
    fn positive_dult_apple_network() {
        let s = sd(SVC_DULT, &[0x01, 0x00]);
        assert_eq!(classify(&none_m(), &[], &s), Some(TrackerKind::AppleFindMy));
    }

    #[test]
    fn positive_dult_other_network_is_unknown_tracker() {
        let s = sd(SVC_DULT, &[0x02, 0x01]);
        assert_eq!(
            classify(&none_m(), &[], &s),
            Some(TrackerKind::UnknownTracker)
        );
    }

    #[test]
    fn positive_tile_service_data() {
        let s = sd(SVC_TILE, &[0x02, 0x00, 0x11, 0x22]);
        assert_eq!(classify(&none_m(), &[], &s), Some(TrackerKind::Tile));
    }

    #[test]
    fn positive_tile_service_uuid_only() {
        assert_eq!(
            classify(&none_m(), &[SVC_TILE], &none_s()),
            Some(TrackerKind::Tile)
        );
    }

    #[test]
    fn positive_samsung_smarttag() {
        // 0x10..=0x17 all match mask 0xF8 -> 0x10
        for b in [0x10u8, 0x13, 0x17] {
            let s = sd(SVC_SAMSUNG_TAG, &[b, 0x01, 0x02]);
            assert_eq!(
                classify(&none_m(), &[], &s),
                Some(TrackerKind::SamsungSmartTag),
                "{b:#x}"
            );
        }
        assert_eq!(
            classify(&none_m(), &[SVC_SAMSUNG_TAG], &none_s()),
            Some(TrackerKind::SamsungSmartTag)
        );
    }

    #[test]
    fn positive_chipolo() {
        assert_eq!(
            classify(&none_m(), &[SVC_CHIPOLO], &none_s()),
            Some(TrackerKind::Chipolo)
        );
        let s = sd(SVC_CHIPOLO, &[0x00, 0x01]);
        assert_eq!(classify(&none_m(), &[], &s), Some(TrackerKind::Chipolo));
    }

    #[test]
    fn positive_pebblebee_and_google_have_their_own_kinds() {
        assert_eq!(
            classify(&none_m(), &[SVC_PEBBLEBEE], &none_s()),
            Some(TrackerKind::Pebblebee)
        );
        let s = sd(SVC_GOOGLE_FMDN, &[0x40, 0x01]);
        assert_eq!(
            classify(&none_m(), &[], &s),
            Some(TrackerKind::GoogleFindMy)
        );
    }

    // ---- negatives ----

    #[test]
    fn negative_apple_non_tracker_message_types() {
        // 0x10 Nearby Info, 0x0C Handoff, 0x07 Proximity Pairing (AirPods), 0x05 AirDrop,
        // 0x09 AirPlay target, 0x0F Nearby Action, 0x16 Nearby Action v2.
        for t in [0x10u8, 0x0C, 0x07, 0x05, 0x09, 0x0F, 0x16] {
            let p = [t, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
            assert_eq!(
                classify(&mfg(0x004C, &p), &[], &none_s()),
                None,
                "type {t:#x}"
            );
        }
    }

    #[test]
    fn negative_type_12_in_other_company_or_too_short() {
        let p = [0x12, 0x19, 0x10, 0x00];
        assert_eq!(classify(&mfg(0x0006, &p), &[], &none_s()), None); // not Apple
        assert_eq!(classify(&mfg(0x004C, &[0x12, 0x19]), &[], &none_s()), None); // no status byte
        assert_eq!(classify(&mfg(0x004C, &[]), &[], &none_s()), None);
    }

    #[test]
    fn negative_eddystone_and_samsung_non_tag_and_tile_wrong_prefix() {
        // Eddystone-URL frame (0x10) on FEAA is not Google FMDN (0x40).
        let e = sd(SVC_GOOGLE_FMDN, &[0x10, 0x00, 0x03]);
        assert_eq!(classify(&none_m(), &[], &e), None);
        // Samsung service data whose state nibble does not match 0x10/0xF8.
        let s = sd(SVC_SAMSUNG_TAG, &[0x20, 0x00]);
        assert_eq!(classify(&none_m(), &[], &s), None);
        // Tile service data without 02 00 prefix and no uuid listing.
        let t = sd(SVC_TILE, &[0x01, 0x00]);
        assert_eq!(classify(&none_m(), &[], &t), None);
    }

    #[test]
    fn negative_empty_and_generic() {
        assert_eq!(classify(&none_m(), &[], &none_s()), None);
        // Heart-rate service 0x180D, a random company id.
        assert_eq!(
            classify(&mfg(0x0059, &[1, 2, 3]), &[uuid16(0x180D)], &none_s()),
            None
        );
        // Empty DULT service data does not classify.
        assert_eq!(classify(&none_m(), &[], &sd(SVC_DULT, &[])), None);
    }
}
