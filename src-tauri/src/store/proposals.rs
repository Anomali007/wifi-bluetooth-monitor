//! Agent proposals and the agent audit log.
//!
//! An agent (the `wbm` CLI or MCP server) can never apply an edit that could hide an alert.
//! It writes a row to `agent_proposals` and stops; a person approves or rejects it in the app.
//! Nothing here applies a proposal: applying lives in `crate::proposals`, which only the app's
//! Tauri commands call (`tests/agent_listen_only.rs` keeps `agent/` away from it).
//!
//! `agent_audit` records every change an agent made, directly or through an approved proposal,
//! with `added_by = agent`, and carries what is needed to undo it.

use super::{Store, StoreResult};
use crate::model::Millis;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A pending proposal expires after this long.
pub const PROPOSAL_TTL_MS: Millis = 24 * 60 * 60 * 1000;
/// At most this many proposals wait at once; more are refused until some are decided.
pub const MAX_PENDING_PROPOSALS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Pending => "pending",
            ProposalStatus::Approved => "approved",
            ProposalStatus::Rejected => "rejected",
            ProposalStatus::Expired => "expired",
        }
    }
    fn parse(s: &str) -> ProposalStatus {
        match s {
            "approved" => ProposalStatus::Approved,
            "rejected" => ProposalStatus::Rejected,
            "expired" => ProposalStatus::Expired,
            _ => ProposalStatus::Pending,
        }
    }
}

/// Who made a Mine entry. Only a person's (`User`, or `Approved` by a click) count for
/// detection and for the sweep gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddedBy {
    /// Created by a person in the app.
    User,
    /// Proposed by an agent, then approved by a person in the app.
    Approved,
    /// Written by an agent with no human click. Kept for display; never trusted.
    Agent,
}

impl AddedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            AddedBy::User => "user",
            AddedBy::Approved => "approved",
            AddedBy::Agent => "agent",
        }
    }
    /// Unknown text reads as `Agent`: the least trusted reading.
    pub fn parse(s: &str) -> AddedBy {
        match s {
            "user" => AddedBy::User,
            "approved" => AddedBy::Approved,
            _ => AddedBy::Agent,
        }
    }
    pub fn is_human_confirmed(self) -> bool {
        self != AddedBy::Agent
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub id: i64,
    pub tool: String,
    pub args: Value,
    pub created_at: Millis,
    pub status: ProposalStatus,
    pub decided_at: Option<Millis>,
}

/// What [`Store::create_proposal`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewProposal {
    Created(i64),
    /// An identical proposal was already pending; this is its id.
    Existing(i64),
    /// [`MAX_PENDING_PROPOSALS`] are already waiting.
    TooMany,
}

/// One applied agent change, as recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub id: i64,
    pub at: Millis,
    pub tool: String,
    /// `direct` (applied by the tool) or `proposal` (a person approved it).
    pub via: String,
    /// Always `agent`: the change originated from an agent, whoever clicked.
    pub added_by: String,
    pub proposal_id: Option<i64>,
    /// App-written one-liner.
    pub summary: String,
    /// How to reverse it (interpreted by `crate::proposals::undo`).
    pub undo: Value,
    pub undone: bool,
}

#[derive(Debug, Clone)]
pub struct NewAudit<'a> {
    pub at: Millis,
    pub tool: &'a str,
    pub via: &'a str,
    pub proposal_id: Option<i64>,
    pub summary: &'a str,
    pub undo: &'a Value,
}

fn row_to_proposal(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<(i64, String, String, Millis, String, Option<Millis>)> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    ))
}

fn build(row: (i64, String, String, Millis, String, Option<Millis>)) -> Proposal {
    Proposal {
        id: row.0,
        tool: row.1,
        args: serde_json::from_str(&row.2).unwrap_or(Value::Null),
        created_at: row.3,
        status: ProposalStatus::parse(&row.4),
        decided_at: row.5,
    }
}

const PROPOSAL_COLS: &str = "id, tool, args, created_at, status, decided_at";

impl Store {
    /// Record a proposal. Identical pending proposals (same tool and arguments) are one;
    /// stale pending ones are expired first; at most [`MAX_PENDING_PROPOSALS`] wait at once.
    pub fn create_proposal(
        &mut self,
        tool: &str,
        args: &Value,
        now: Millis,
    ) -> StoreResult<NewProposal> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, now)?;
        // `Value` objects are key-sorted, so equal arguments serialise equally.
        let canon = serde_json::to_string(args).unwrap_or_default();
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM agent_proposals WHERE status = 'pending' AND tool = ?1 AND args = ?2",
                params![tool, canon],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            return Ok(NewProposal::Existing(id));
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM agent_proposals WHERE status = 'pending'",
            [],
            |r| r.get(0),
        )?;
        if pending as usize >= MAX_PENDING_PROPOSALS {
            return Ok(NewProposal::TooMany);
        }
        tx.execute(
            "INSERT INTO agent_proposals (tool, args, created_at, status) VALUES (?1, ?2, ?3, 'pending')",
            params![tool, canon, now],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(NewProposal::Created(id))
    }

    /// Mark every pending proposal older than the TTL expired. Returns how many.
    pub fn expire_proposals(&mut self, now: Millis) -> StoreResult<usize> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = expire(&tx, now)?;
        tx.commit()?;
        Ok(n)
    }

    /// Pending proposals (after expiring stale ones), oldest first.
    pub fn list_pending_proposals(&mut self, now: Millis) -> StoreResult<Vec<Proposal>> {
        self.expire_proposals(now)?;
        let mut q = self.conn.prepare(&format!(
            "SELECT {PROPOSAL_COLS} FROM agent_proposals WHERE status = 'pending' ORDER BY id"
        ))?;
        let rows = q.query_map([], row_to_proposal)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(build(r?));
        }
        Ok(out)
    }

    pub fn get_proposal(&self, id: i64) -> StoreResult<Option<Proposal>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {PROPOSAL_COLS} FROM agent_proposals WHERE id = ?1"),
                [id],
                row_to_proposal,
            )
            .optional()?
            .map(build))
    }

    /// Decide a PENDING proposal. Returns false when it was not pending (already decided or
    /// expired), so a double click or a second window cannot apply it twice.
    pub fn decide_proposal(
        &mut self,
        id: i64,
        status: ProposalStatus,
        now: Millis,
    ) -> StoreResult<bool> {
        let n = self.conn.execute(
            "UPDATE agent_proposals SET status = ?1, decided_at = ?2 WHERE id = ?3 AND status = 'pending'",
            params![status.as_str(), now, id],
        )?;
        Ok(n == 1)
    }

    /// Append to the audit log. Returns the entry id.
    pub fn record_audit(&mut self, e: &NewAudit<'_>) -> StoreResult<i64> {
        self.conn.execute(
            "INSERT INTO agent_audit (at, tool, via, added_by, proposal_id, summary, undo)
             VALUES (?1, ?2, ?3, 'agent', ?4, ?5, ?6)",
            params![
                e.at,
                e.tool,
                e.via,
                e.proposal_id,
                e.summary,
                serde_json::to_string(e.undo).unwrap_or_default()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Newest first.
    pub fn list_audit(&self, limit: usize) -> StoreResult<Vec<AuditEntry>> {
        let mut q = self.conn.prepare(
            "SELECT id, at, tool, via, added_by, proposal_id, summary, undo, undone
             FROM agent_audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = q.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], audit_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_audit(&self, id: i64) -> StoreResult<Option<AuditEntry>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, at, tool, via, added_by, proposal_id, summary, undo, undone
                 FROM agent_audit WHERE id = ?1",
                [id],
                audit_row,
            )
            .optional()?)
    }

    /// Returns false when already undone.
    pub fn mark_audit_undone(&mut self, id: i64) -> StoreResult<bool> {
        let n = self.conn.execute(
            "UPDATE agent_audit SET undone = 1 WHERE id = ?1 AND undone = 0",
            [id],
        )?;
        Ok(n == 1)
    }
}

fn audit_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    let undo: String = r.get(7)?;
    Ok(AuditEntry {
        id: r.get(0)?,
        at: r.get(1)?,
        tool: r.get(2)?,
        via: r.get(3)?,
        added_by: r.get(4)?,
        proposal_id: r.get(5)?,
        summary: r.get(6)?,
        undo: serde_json::from_str(&undo).unwrap_or(Value::Null),
        undone: r.get::<_, i64>(8)? != 0,
    })
}

fn expire(tx: &rusqlite::Transaction<'_>, now: Millis) -> StoreResult<usize> {
    Ok(tx.execute(
        "UPDATE agent_proposals SET status = 'expired', decided_at = ?1
         WHERE status = 'pending' AND created_at <= ?2",
        params![now, now - PROPOSAL_TTL_MS],
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open() -> (tempfile::TempDir, Store) {
        let d = tempfile::TempDir::new().unwrap();
        let s = Store::open(d.path()).unwrap();
        (d, s)
    }

    #[test]
    fn identical_pending_proposals_are_one() {
        let (_d, mut s) = open();
        let a = s
            .create_proposal("trusted_add", &json!({"ssid": "Net-A"}), 1_000)
            .unwrap();
        let b = s
            .create_proposal("trusted_add", &json!({"ssid": "Net-A"}), 2_000)
            .unwrap();
        let c = s
            .create_proposal("trusted_add", &json!({"ssid": "Net-B"}), 2_000)
            .unwrap();
        let (NewProposal::Created(ida), NewProposal::Existing(idb)) = (a, b) else {
            panic!("{a:?} {b:?}")
        };
        assert_eq!(ida, idb);
        assert!(matches!(c, NewProposal::Created(_)));
        assert_eq!(s.list_pending_proposals(3_000).unwrap().len(), 2);
    }

    #[test]
    fn pending_is_capped_and_a_decision_frees_a_slot() {
        let (_d, mut s) = open();
        for i in 0..MAX_PENDING_PROPOSALS {
            let r = s
                .create_proposal("trusted_add", &json!({"ssid": format!("N{i}")}), 1_000)
                .unwrap();
            assert!(matches!(r, NewProposal::Created(_)), "{i}");
        }
        assert_eq!(
            s.create_proposal("trusted_add", &json!({"ssid": "over"}), 1_000)
                .unwrap(),
            NewProposal::TooMany
        );
        // A repeat of one already waiting is still just that one.
        assert!(matches!(
            s.create_proposal("trusted_add", &json!({"ssid": "N0"}), 1_000)
                .unwrap(),
            NewProposal::Existing(_)
        ));
        let first = s.list_pending_proposals(1_000).unwrap()[0].id;
        assert!(s
            .decide_proposal(first, ProposalStatus::Rejected, 1_500)
            .unwrap());
        assert!(matches!(
            s.create_proposal("trusted_add", &json!({"ssid": "over"}), 1_600)
                .unwrap(),
            NewProposal::Created(_)
        ));
    }

    #[test]
    fn proposals_expire_after_24_hours_and_cannot_be_decided_afterwards() {
        let (_d, mut s) = open();
        let NewProposal::Created(id) = s
            .create_proposal("mine_add", &json!({"kind": "ble"}), 1_000)
            .unwrap()
        else {
            panic!()
        };
        let just_before = 1_000 + PROPOSAL_TTL_MS - 1;
        assert_eq!(s.list_pending_proposals(just_before).unwrap().len(), 1);
        let after = 1_000 + PROPOSAL_TTL_MS;
        assert!(s.list_pending_proposals(after).unwrap().is_empty());
        assert_eq!(
            s.get_proposal(id).unwrap().unwrap().status,
            ProposalStatus::Expired
        );
        assert!(!s
            .decide_proposal(id, ProposalStatus::Approved, after)
            .unwrap());
        // An expired identical proposal does not block a fresh one.
        assert!(matches!(
            s.create_proposal("mine_add", &json!({"kind": "ble"}), after)
                .unwrap(),
            NewProposal::Created(_)
        ));
    }

    #[test]
    fn a_proposal_is_decided_once() {
        let (_d, mut s) = open();
        let NewProposal::Created(id) = s
            .create_proposal("dismiss_alert", &json!({"id": "x"}), 1)
            .unwrap()
        else {
            panic!()
        };
        assert!(s.decide_proposal(id, ProposalStatus::Approved, 2).unwrap());
        assert!(!s.decide_proposal(id, ProposalStatus::Rejected, 3).unwrap());
        let p = s.get_proposal(id).unwrap().unwrap();
        assert_eq!(
            (p.status, p.decided_at),
            (ProposalStatus::Approved, Some(2))
        );
    }

    #[test]
    fn audit_round_trips_and_undo_is_once() {
        let (_d, mut s) = open();
        let undo = json!({"op": "watchlistRemove", "id": 3});
        let id = s
            .record_audit(&NewAudit {
                at: 5,
                tool: "watchlist_add",
                via: "direct",
                proposal_id: None,
                summary: "s",
                undo: &undo,
            })
            .unwrap();
        let e = s.get_audit(id).unwrap().unwrap();
        assert_eq!(
            (e.added_by.as_str(), e.via.as_str(), e.undone),
            ("agent", "direct", false)
        );
        assert_eq!(e.undo, undo);
        assert!(s.mark_audit_undone(id).unwrap());
        assert!(!s.mark_audit_undone(id).unwrap());
        assert_eq!(s.list_audit(10).unwrap().len(), 1);
    }

    #[test]
    fn an_agent_written_mine_row_is_invisible_to_detection_and_the_gate() {
        use crate::lan::gate::ap_is_mine;
        use crate::model::{MineEntry, MineKind};
        let (_d, mut s) = open();
        let ap = "a".repeat(64);
        let e = |h: &str, at| MineEntry {
            kind: MineKind::WifiAp,
            id_hash: h.into(),
            label: None,
            added_at: at,
        };
        s.add_mine_as(&e(&ap, 1), AddedBy::Agent).unwrap();
        assert!(
            !ap_is_mine(&s.list_mine().unwrap(), Some(&ap), None),
            "agent rows never arm the gate"
        );
        assert_eq!(
            s.list_mine_with_source().unwrap().len(),
            1,
            "but it is still listed for display"
        );
        // A person marking the same thing makes it theirs; an approved one counts as well.
        s.add_mine(&e(&ap, 2)).unwrap();
        assert!(ap_is_mine(&s.list_mine().unwrap(), Some(&ap), None));
        let other = "b".repeat(64);
        s.add_mine_as(&e(&other, 3), AddedBy::Approved).unwrap();
        assert!(ap_is_mine(&s.list_mine().unwrap(), Some(&other), None));
        // An agent re-adding cannot demote or promote.
        s.add_mine_as(&e(&other, 4), AddedBy::Agent).unwrap();
        assert!(ap_is_mine(&s.list_mine().unwrap(), Some(&other), None));
    }
}
