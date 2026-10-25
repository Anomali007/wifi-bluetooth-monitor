//! Place memory: Wi-Fi fingerprints, dwell tracking and place sightings. OWNER: WP-AB.
//!
//! CONTRACT (frozen signature; logic is a stub until WP-AB):
//! - [`update`] runs once per scan, after the scan is stored and before detection. It matches
//!   the scan to a known place (or creates one), tracks dwell, and writes `places` /
//!   `place_sightings` through the `Store` CRUD methods. Returns the matched place id, if any.
//! - It reads only hashed identifiers already in the `ScanResult`.

use crate::model::{Millis, ScanResult, Settings};
use crate::store::{Store, StoreResult};

/// Update place memory from one scan. Stub: records nothing.
pub fn update(
    _store: &mut Store,
    _scan: &ScanResult,
    _settings: &Settings,
    _now: Millis,
) -> StoreResult<Option<i64>> {
    Ok(None)
}
