//! Watchlist rule. OWNER: WP-C.
//!
//! Stub: returns no alerts until WP-C. Contract: matches `ctx.watchlist` entries against the
//! SSID and vendor of Wi-Fi observations (case-insensitive; SSID entries also match
//! look-alikes), skips anything in `ctx.mine`.

use super::{Collector, DetectContext};
use crate::model::{History, Millis, Settings};

pub(super) fn watchlist(
    _history: &History,
    _settings: &Settings,
    _ctx: &DetectContext,
    _now: Millis,
    _out: &mut Collector,
) {
}
