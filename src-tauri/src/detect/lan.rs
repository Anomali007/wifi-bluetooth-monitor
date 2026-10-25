//! NewLanDevice rule. OWNER: WP-D.
//!
//! Stub: returns no alerts until WP-D. Contract: fires only when `ctx.current_network` is a
//! network whose access point is marked mine and a device in `ctx.lan_devices` for that
//! network key is new; skips devices in `ctx.mine`.

use super::{Collector, DetectContext};
use crate::model::{History, Millis, Settings};

pub(super) fn new_lan_device(
    _history: &History,
    _settings: &Settings,
    _ctx: &DetectContext,
    _now: Millis,
    _out: &mut Collector,
) {
}
