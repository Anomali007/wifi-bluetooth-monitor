//! FollowedAcrossPlaces rule. OWNER: WP-AB.
//!
//! Stub: returns no alerts until WP-AB. Contract: reads `ctx.places` / `ctx.place_sightings`
//! (hashed ids only), skips anything in `ctx.mine`, says "possible", and never reports
//! coordinates, only place labels.

use super::{Collector, DetectContext};
use crate::model::{History, Millis, Settings};

pub(super) fn followed_across_places(
    _history: &History,
    _settings: &Settings,
    _ctx: &DetectContext,
    _now: Millis,
    _out: &mut Collector,
) {
}
