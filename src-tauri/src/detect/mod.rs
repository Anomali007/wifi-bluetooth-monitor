//! Detection engine: pure functions over a [`History`]. OWNER: WP4.
//!
//! CONTRACT (frozen):
//! - [`evaluate`] is pure: no I/O, no clock, no randomness. `now` is passed in.
//! - Rules (each gated by `settings.alert_toggles`): EvilTwin, OpenLookalike,
//!   TrustedNetworkChanged, PersistentTracker, NewDevice. See the roadmap for definitions.
//! - Returned alerts are deduplicated by `(kind, subject_hash)` within the call, with
//!   `first_seen`/`last_seen` taken from the history. `id` is a stable function of
//!   `(kind, subject_hash)`, and `dismissed` is always `false`; the store merges repeats
//!   across calls and owns dismissal.
//! - PersistentTracker alerts say "possible" and never claim certainty (IDs rotate).
//! - Subjects are hashes only; no raw identifier appears in `title` or `detail`.

use crate::model::{Alert, History, Millis, Settings};

/// Evaluate every enabled rule over `history` as of `now` (Unix ms).
pub fn evaluate(_history: &History, _settings: &Settings, _now: Millis) -> Vec<Alert> {
    // STUB (WP4 replaces).
    Vec::new()
}
