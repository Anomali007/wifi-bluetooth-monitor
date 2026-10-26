//! Rule-specific `Store` queries for places and the follow rule. OWNER: WP-AB.
//!
//! Dwell bookkeeping lives in the existing `meta` table (one JSON value under
//! [`PLACE_STATE_KEY`]) so the schema stays as the Foundation froze it.

use super::{err, Store, StoreResult};
use crate::model::PlaceSighting;
use rusqlite::{params, OptionalExtension};

const PLACE_STATE_KEY: &str = "places_state";

impl Store {
    /// The places module's persisted dwell state (opaque JSON), if any.
    pub fn place_state(&self) -> StoreResult<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [PLACE_STATE_KEY],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn set_place_state(&mut self, json: &str) -> StoreResult<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![PLACE_STATE_KEY, json],
        )?;
        Ok(())
    }

    /// Add sightings, widening `first_seen`/`last_seen` and ADDING `scans` on conflict (the
    /// frozen `upsert_place_sighting` takes the larger count, which cannot accumulate).
    pub fn add_place_sightings(&mut self, batch: &[PlaceSighting]) -> StoreResult<()> {
        let tx = self.conn.transaction()?;
        {
            let mut w = tx.prepare(
                "INSERT INTO place_sightings (kind, id_hash, place_id, first_seen, last_seen, scans)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(kind, id_hash, place_id) DO UPDATE SET
                     first_seen = MIN(first_seen, excluded.first_seen),
                     last_seen = MAX(last_seen, excluded.last_seen),
                     scans = scans + excluded.scans",
            )?;
            for s in batch {
                let kind = serde_json::to_string(&s.kind).map_err(|e| err("serialize", e))?;
                w.execute(params![
                    kind,
                    s.id_hash,
                    s.place_id,
                    s.first_seen,
                    s.last_seen,
                    s.scans
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}
