//! OUI vendor lookup and multi-radio grouping. OWNER: WP-C.
//!
//! CONTRACT (frozen signatures; logic is a stub until WP-C):
//! - Both functions take the RAW address, because they run in `wifi::mapping` before the
//!   BSSID is hashed. Nothing here stores or logs a raw address.
//! - [`vendor_for`]: short vendor name from the IEEE MA-L prefix; a locally administered
//!   address (bit 0x02 of the first byte) is "Private address"; `None` when unknown.
//! - [`radio_group`]: BSSIDs with the same first 5 bytes and the same high nibble of the last
//!   byte are one physical device. The key is those 5 bytes plus `last & 0xF0`.
//! - [`group_id`]: the salted hash of that key, stored as `WifiObservation::group_id`.

use crate::model::Salt;

/// Short vendor name for a raw MAC/BSSID, or `None` when it cannot be parsed or is unknown.
pub fn vendor_for(_raw_mac: &str) -> Option<String> {
    None
}

/// Multi-radio group key for a raw BSSID: first 5 bytes + `last & 0xF0`. `None` when unparsable.
pub fn radio_group(_raw_bssid: &str) -> Option<[u8; 6]> {
    None
}

/// Salted hash of [`radio_group`], or `None` when the BSSID is unparsable.
pub fn group_id(_salt: &Salt, _raw_bssid: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_return_nothing_until_wp_c() {
        let salt = Salt::from_bytes(vec![1; 32]);
        assert_eq!(vendor_for("02:00:00:00:00:01"), None);
        assert_eq!(radio_group("02:00:00:00:00:01"), None);
        assert_eq!(group_id(&salt, "02:00:00:00:00:01"), None);
    }
}
