//! Settings are one JSON blob, and two writers share it: the app (the settings page edits a
//! draft and saves the WHOLE object) and agent tools (`wbm trusted add`). A blind overwrite
//! lets whichever saves last erase the other's change.
//!
//! Every save bumps `Settings::revision`, and the last few saved versions are kept in `meta`.
//! A save that carries the current revision is a plain overwrite. A save that is behind is
//! merged three ways: the version the client loaded (its base), what is stored now, and what
//! the client wants. A field the client did not change keeps the stored value; a trusted
//! network is added or removed only if the client itself added or removed it.

use super::{err, from_json, to_json, Store, StoreResult};
use crate::model::{Settings, TrustedNetwork};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;

const HISTORY_KEY: &str = "settings_history";
const HISTORY_LEN: usize = 16;

fn load_settings(conn: &Connection) -> StoreResult<Settings> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = 'settings'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match raw {
        Some(s) => from_json(&s),
        None => Ok(Settings::default()),
    }
}

fn load_history(conn: &Connection) -> StoreResult<Vec<Settings>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [HISTORY_KEY],
            |r| r.get(0),
        )
        .optional()?;
    // A damaged history only costs the ability to merge: the save then keeps both sides.
    Ok(raw
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default())
}

/// Remember `current` (the version being replaced) and `next`, write `next`, bump nothing else.
fn commit(
    tx: &Transaction<'_>,
    mut history: Vec<Settings>,
    current: &Settings,
    mut next: Settings,
) -> StoreResult<()> {
    next.revision = current.revision + 1;
    if !history.iter().any(|h| h.revision == current.revision) {
        history.push(current.clone());
    }
    history.push(next.clone());
    if history.len() > HISTORY_LEN {
        let drop = history.len() - HISTORY_LEN;
        history.drain(..drop);
    }
    tx.execute(
        "INSERT INTO settings (key, value) VALUES ('settings', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [to_json(&next)?],
    )?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![HISTORY_KEY, to_json(&history)?],
    )?;
    Ok(())
}

impl Store {
    pub(super) fn save_settings(&mut self, incoming: &Settings) -> StoreResult<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_settings(&tx)?;
        let history = load_history(&tx)?;
        let next = if incoming.revision == current.revision {
            incoming.clone()
        } else {
            let base = history.iter().find(|h| h.revision == incoming.revision);
            merge_settings(base, &current, incoming)?
        };
        commit(&tx, history, &current, next)?;
        tx.commit()?;
        Ok(())
    }

    /// Read-modify-write the stored settings in one `BEGIN IMMEDIATE` transaction. The change
    /// sees the newest stored value, so concurrent writers serialise instead of overwriting.
    pub(super) fn edit_stored_settings<R>(
        &mut self,
        change: impl FnOnce(&mut Settings) -> R,
    ) -> StoreResult<R> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_settings(&tx)?;
        let history = load_history(&tx)?;
        let mut next = current.clone();
        let out = change(&mut next);
        commit(&tx, history, &current, next)?;
        tx.commit()?;
        Ok(out)
    }
}

fn to_value(s: &Settings) -> StoreResult<Value> {
    serde_json::to_value(s).map_err(|e| err("serialize settings", e))
}

/// Three-way merge. `base` is the version the client loaded, when still remembered.
pub(super) fn merge_settings(
    base: Option<&Settings>,
    current: &Settings,
    incoming: &Settings,
) -> StoreResult<Settings> {
    let (cur, inc) = (to_value(current)?, to_value(incoming)?);
    let base_v = base.map(to_value).transpose()?;
    let (Value::Object(mut out), Value::Object(inc)) = (cur, inc) else {
        return Err(err("merge settings", "not an object"));
    };
    for (key, wanted) in &inc {
        if key == "revision" || key == "trustedNetworks" {
            continue;
        }
        let client_changed = match base_v.as_ref().and_then(|b| b.get(key)) {
            Some(was) => was != wanted,
            None => true, // base unknown: the client's explicit value wins
        };
        if client_changed {
            out.insert(key.clone(), wanted.clone());
        }
    }
    let mut merged: Settings =
        serde_json::from_value(Value::Object(out)).map_err(|e| err("merge settings", e))?;
    merged.trusted_networks = merge_trusted(
        base.map(|b| b.trusted_networks.as_slice()),
        &current.trusted_networks,
        &incoming.trusted_networks,
    );
    Ok(merged)
}

/// Keep what is stored, then apply only the client's own additions, changes and removals.
/// Without a base nothing can be called a removal, so nothing is removed.
fn merge_trusted(
    base: Option<&[TrustedNetwork]>,
    current: &[TrustedNetwork],
    incoming: &[TrustedNetwork],
) -> Vec<TrustedNetwork> {
    let mut out: Vec<TrustedNetwork> = current.to_vec();
    if let Some(base) = base {
        out.retain(|c| {
            let client_removed =
                base.iter().any(|b| b.ssid == c.ssid) && !incoming.iter().any(|i| i.ssid == c.ssid);
            !client_removed
        });
    }
    for i in incoming {
        let unchanged_by_client = base.is_some_and(|b| b.iter().any(|x| x == i));
        match out.iter().position(|c| c.ssid == i.ssid) {
            Some(at) => {
                if !unchanged_by_client {
                    out[at] = i.clone();
                }
            }
            None => {
                // Not stored now. It is the client's addition unless the client merely kept
                // an entry that someone else removed since.
                if !unchanged_by_client {
                    out.push(i.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Security;

    fn tn(ssid: &str) -> TrustedNetwork {
        TrustedNetwork {
            ssid: ssid.into(),
            known_bssid_hashes: vec![],
            expected_security: Security::Wpa2Personal,
        }
    }

    fn with(list: &[&str]) -> Settings {
        Settings {
            trusted_networks: list.iter().map(|s| tn(s)).collect(),
            ..Settings::default()
        }
    }

    fn names(s: &Settings) -> Vec<&str> {
        s.trusted_networks.iter().map(|t| t.ssid.as_str()).collect()
    }

    #[test]
    fn merge_applies_only_the_clients_own_trusted_changes() {
        let base = with(&["Net-A", "Net-B"]);
        let current = with(&["Net-A", "Net-B", "Net-C"]); // someone added C
        let incoming = with(&["Net-A", "Net-D"]); // client removed B, added D
        let m = merge_settings(Some(&base), &current, &incoming).unwrap();
        assert_eq!(names(&m), ["Net-A", "Net-C", "Net-D"]);
    }

    #[test]
    fn merge_without_a_base_never_removes() {
        let current = with(&["Net-A", "Net-B"]);
        let incoming = with(&["Net-A", "Net-D"]);
        let m = merge_settings(None, &current, &incoming).unwrap();
        assert_eq!(names(&m), ["Net-A", "Net-B", "Net-D"]);
    }

    #[test]
    fn merge_keeps_stored_scalars_the_client_did_not_touch() {
        let base = Settings {
            scan_interval_secs: 60,
            notify: true,
            ..Settings::default()
        };
        let current = Settings {
            scan_interval_secs: 60,
            notify: false,
            ..Settings::default()
        };
        let incoming = Settings {
            scan_interval_secs: 90,
            notify: true,
            ..Settings::default()
        };
        let m = merge_settings(Some(&base), &current, &incoming).unwrap();
        assert_eq!(m.scan_interval_secs, 90, "the client changed this");
        assert!(
            !m.notify,
            "the client left this alone; the stored value stands"
        );
    }

    #[test]
    fn a_client_edit_to_an_existing_trusted_entry_wins() {
        let base = with(&["Net-A"]);
        let mut edited = with(&["Net-A"]);
        edited.trusted_networks[0].expected_security = Security::Wpa3Personal;
        let current = with(&["Net-A", "Net-C"]);
        let m = merge_settings(Some(&base), &current, &edited).unwrap();
        assert_eq!(
            m.trusted_networks[0].expected_security,
            Security::Wpa3Personal
        );
        assert_eq!(names(&m), ["Net-A", "Net-C"]);
    }

    #[test]
    fn history_is_bounded_and_revisions_strictly_increase() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let mut last = s.get_settings().unwrap().revision;
        for _ in 0..(HISTORY_LEN + 5) {
            s.update_trusted_networks(|l| l.push(tn("Net-A"))).unwrap();
            let r = s.get_settings().unwrap().revision;
            assert_eq!(r, last + 1);
            last = r;
        }
        let h = load_history(&s.conn).unwrap();
        assert_eq!(h.len(), HISTORY_LEN);
        assert_eq!(h.last().unwrap().revision, last);
    }

    #[test]
    fn a_damaged_history_costs_only_the_merge_never_the_data() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut s = Store::open(dir.path()).unwrap();
        let draft = s.get_settings().unwrap();
        s.update_trusted_networks(|l| l.push(tn("Net-A"))).unwrap();
        s.conn
            .execute(
                "UPDATE meta SET value = 'not json' WHERE key = ?1",
                [HISTORY_KEY],
            )
            .unwrap();
        let mut stale = draft;
        stale.notify = false;
        s.set_settings(&stale).unwrap();
        let now = s.get_settings().unwrap();
        assert_eq!(names(&now), ["Net-A"], "the stored network survives");
        assert!(!now.notify);
    }
}
