//! What an agent asked for, described from the app's own data, and applying it once a person
//! approves.
//!
//! This module is the ONLY place an agent's proposal turns into a change, and only the Tauri
//! commands `decide_agent_proposal` and `undo_agent_change` call it. The `wbm` CLI and MCP
//! server cannot (`tests/agent_listen_only.rs` keeps `agent/` from naming this module).
//!
//! Descriptions are built from stored data and plain templates. The only agent-supplied text
//! that appears is a name (a network name, a label, a rule pattern), shown inside quotation
//! marks and stripped of control characters: it reads as data, never as an instruction.
//! Approval re-validates against CURRENT data, so a proposal that was fine when made can be
//! refused when approved.

use crate::agent::cli::fmt_time;
use crate::detect::is_lookalike;
use crate::labels::{
    alert_kind_label, clean, codepoints_if_not_ascii, mine_kind_label, quote, security_label,
    severity_label, strip_unsafe, tracker_label,
};
use crate::model::{
    AlertKind, Millis, MineEntry, MineKind, Security, TrustedNetwork, WatchKind, WatchMatch,
    WatchlistEntry,
};
use crate::store::{
    AddedBy, AuditEntry, NewAudit, Proposal, ProposalStatus, Store, StoreResult, PROPOSAL_TTL_MS,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// One pending request as the Settings page shows it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalView {
    pub id: i64,
    pub tool: String,
    pub created_at: Millis,
    pub expires_at: Millis,
    /// One sentence from the app's own data. Agent-supplied names appear only in quotes.
    pub summary: String,
    /// Things worth a second look, each from the app's own data.
    pub warnings: Vec<String>,
    /// Set when approving would be refused right now, with the reason.
    pub blocked: Option<String>,
    /// Digest of what this request describes (hashes, modes, subject, label). Approve must
    /// carry it back; if the situation changed since it was read, approval is refused and the
    /// request must be read again.
    pub digest: String,
}

/// One applied agent change as the Settings page shows it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub id: i64,
    pub at: Millis,
    pub tool: String,
    /// `direct` or `proposal`.
    pub via: String,
    /// Always `agent`.
    pub added_by: String,
    pub proposal_id: Option<i64>,
    pub summary: String,
    pub undone: bool,
}

impl From<AuditEntry> for AuditView {
    fn from(e: AuditEntry) -> Self {
        AuditView {
            id: e.id,
            at: e.at,
            tool: e.tool,
            via: e.via,
            added_by: e.added_by,
            proposal_id: e.proposal_id,
            summary: e.summary,
            undone: e.undone,
        }
    }
}

/// The result of a decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    /// `approved` or `rejected`.
    pub status: String,
    /// Approved, and something actually changed (false: it was already so).
    pub changed: bool,
    pub message: String,
}

type Res<T> = Result<T, String>;

fn db<T>(r: StoreResult<T>) -> Res<T> {
    r.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Describing
// ---------------------------------------------------------------------------

fn arg_str(args: &Value, k: &str) -> Option<String> {
    args.get(k).and_then(Value::as_str).map(str::to_string)
}

fn mine_args(args: &Value) -> Option<(MineKind, String)> {
    let kind: MineKind = serde_json::from_value(args.get("kind")?.clone()).ok()?;
    Some((kind, arg_str(args, "idHash")?))
}

fn join_labels(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a} and {b}"),
        _ => format!(
            "{}, and {}",
            items[..items.len() - 1].join(", "),
            items[items.len() - 1]
        ),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Last six characters of a hash, so two devices that share a name can be told apart on screen.
fn tail(hash: &str) -> String {
    let n = hash.chars().count();
    format!(
        "\u{2026}{}",
        hash.chars().skip(n.saturating_sub(6)).collect::<String>()
    )
}

/// Everything known about trusting a name, from the latest scan only.
struct TrustCheck {
    /// Distinct access points (hash, signal) in the latest scan.
    aps: Vec<(String, i32)>,
    modes: Vec<Security>,
    groups: BTreeSet<String>,
    already: bool,
    alert: Option<AlertKind>,
    /// Why approval would be refused, if it would.
    problem: Option<String>,
}

impl TrustCheck {
    fn hashes(&self) -> Vec<String> {
        self.aps.iter().map(|(h, _)| h.clone()).collect()
    }
}

fn trust_check(store: &Store, ssid: &str, now: Millis) -> StoreResult<TrustCheck> {
    let already = store
        .get_settings()?
        .trusted_networks
        .iter()
        .any(|t| t.ssid == ssid);
    let alert = store.active_ssid_alert(ssid, now)?;
    let rows: Vec<_> = store
        .latest_scan()?
        .map(|s| s.wifi)
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.ssid.as_deref() == Some(ssid))
        .collect();
    let mut modes: Vec<Security> = Vec::new();
    for o in &rows {
        if !modes.contains(&o.security) {
            modes.push(o.security);
        }
    }
    modes.sort_by_key(|m| m.strength());
    let mut aps: Vec<(String, i32)> = Vec::new();
    for o in &rows {
        if let Some(h) = &o.bssid_hash {
            if !aps.iter().any(|(x, _)| x == h) {
                aps.push((h.clone(), o.rssi));
            }
        }
    }
    // One physical device (all its radios) shares a group; a row without one stands alone.
    let groups: BTreeSet<String> = rows
        .iter()
        .enumerate()
        .map(|(i, o)| {
            o.group_id
                .clone()
                .or_else(|| o.bssid_hash.clone())
                .unwrap_or_else(|| format!("row-{i}"))
        })
        .collect();
    let problem = if already {
        None
    } else if rows.is_empty() {
        Some("This name is not in the latest scan, so there is nothing current to trust.".into())
    } else if aps.is_empty() {
        Some("The access points' identities are withheld (check Location access), so none can be recorded.".into())
    } else if modes.contains(&Security::Unknown) {
        Some("The security mode of this network is unknown, so there is nothing meaningful to record. Check it, then use Trust on the Networks page.".into())
    } else if modes.len() > 1 {
        Some(format!(
            "This name appears with {} security modes in the latest scan ({}). That is what an evil twin looks like. Check it, then use Trust on the Networks page.",
            modes.len(),
            join_labels(&modes.iter().map(|m| security_label(*m).to_string()).collect::<Vec<_>>())
        ))
    } else if groups.len() > 1 {
        Some(format!(
            "This name comes from {} different devices in the latest scan. Check that they are all yours, then use Trust on the Networks page.",
            groups.len()
        ))
    } else {
        alert.map(|kind| {
            format!(
                "An {} alert for this name is active. Resolve it before trusting the name.",
                alert_kind_label(kind)
            )
        })
    };
    Ok(TrustCheck {
        aps,
        modes,
        groups,
        already,
        alert,
        problem,
    })
}

/// Name of the subject SSID of an alert, found by matching its subject hash against names seen
/// in the latest scan and the trusted list (never by reading alert text).
pub fn alert_subject_ssid(store: &Store, kind: AlertKind, subject_hash: &str) -> Option<String> {
    if !matches!(kind, AlertKind::EvilTwin | AlertKind::OpenLookalike) {
        return None;
    }
    store.ssid_subject_names().ok()?.remove(subject_hash)
}

/// The Wi-Fi access point the Mac is joined to, from the app's last status snapshot.
fn joined_ap(store: &Store) -> (Option<String>, Option<String>) {
    let Some(raw) = store.app_status().ok().flatten() else {
        return (None, None);
    };
    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let n = &v["network"];
    (
        n["bssidHash"].as_str().map(str::to_string),
        n["groupId"].as_str().map(str::to_string),
    )
}

struct Described {
    summary: String,
    warnings: Vec<String>,
    blocked: Option<String>,
    /// Everything the sentence depends on that matters for the decision (hashes, modes,
    /// subject, label), WITHOUT values that move on every scan (signal). Its digest is what
    /// Approve must carry, so approving something that changed after it was read is refused.
    state: String,
}

impl Described {
    fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.state.as_bytes());
        h.update(b"\x1f");
        h.update(self.warnings.join("\x1e").as_bytes());
        h.update(b"\x1f");
        h.update(self.blocked.as_deref().unwrap_or("").as_bytes());
        hex::encode(&h.finalize()[..12])
    }
}

/// Warnings about the look of a network name: invisible or non-ASCII characters (with their
/// code points), and a name that resembles another trusted or nearby name without being it.
fn name_warnings(store: &Store, ssid: &str, warnings: &mut Vec<String>) -> StoreResult<()> {
    if let Some(cps) = codepoints_if_not_ascii(ssid) {
        warnings.push(format!(
            "\u{26A0} this name contains non-ASCII characters ({cps}); check it is the network you mean, not a look-alike alphabet."
        ));
    }
    let similar: Vec<String> = store
        .known_ssids()?
        .into_iter()
        .filter(|other| other != ssid && is_lookalike(ssid, other))
        .collect();
    if let Some(first) = similar.first() {
        warnings.push(format!(
            "\u{26A0} this name looks like {} (a trusted or nearby network) but is not the same name.",
            quote(first)
        ));
    }
    Ok(())
}

fn describe(store: &Store, tool: &str, args: &Value, now: Millis) -> StoreResult<Described> {
    let mut warnings = Vec::new();
    let mut blocked = None;
    let mut state = String::new();
    let summary = match tool {
        "trusted_add" => {
            let ssid = arg_str(args, "ssid").unwrap_or_default();
            let c = trust_check(store, &ssid, now)?;
            blocked = c.problem.clone();
            let mut hashes = c.hashes();
            hashes.sort();
            state = format!(
                "trusted_add|{ssid}|{:?}|{hashes:?}|{:?}|{:?}|{}",
                c.modes.iter().map(|m| m.strength()).collect::<Vec<_>>(),
                c.groups,
                c.alert,
                c.already
            );
            if strip_unsafe(&ssid) != ssid {
                warnings.push(
                    "\u{26A0} this name contains hidden characters, left out of the quotation below."
                        .into(),
                );
                blocked = Some("The name contains hidden characters, so what you see is not exactly what would be trusted.".into());
            }
            if let Some(kind) = c.alert {
                warnings.push(format!(
                    "\u{26A0} an {} alert for this name is active.",
                    alert_kind_label(kind)
                ));
            }
            name_warnings(store, &ssid, &mut warnings)?;
            if c.modes.contains(&Security::Open) {
                warnings.push(
                    "\u{26A0} this network is open (not encrypted); trusting it records that as normal."
                        .into(),
                );
            }
            if c.already {
                format!(
                    "Trust network {}: already trusted, nothing would change.",
                    quote(&ssid)
                )
            } else if c.aps.is_empty() {
                format!(
                    "Trust network {}: not seen in the latest scan.",
                    quote(&ssid)
                )
            } else {
                let labels: Vec<String> = c
                    .modes
                    .iter()
                    .map(|m| security_label(*m).to_string())
                    .collect();
                let listed: Vec<String> = c
                    .aps
                    .iter()
                    .take(6)
                    .map(|(h, rssi)| format!("{} at {rssi} dBm", tail(h)))
                    .collect();
                let more = if c.aps.len() > 6 {
                    format!(", and {} more", c.aps.len() - 6)
                } else {
                    String::new()
                };
                format!(
                    "Trust network {}: {} seen ({}{more}), {}.",
                    quote(&ssid),
                    plural(c.aps.len(), "access point", "access points"),
                    listed.join(", "),
                    join_labels(&labels)
                )
            }
        }
        "trusted_remove" => {
            let ssid = arg_str(args, "ssid").unwrap_or_default();
            match store
                .get_settings()?
                .trusted_networks
                .into_iter()
                .find(|t| t.ssid == ssid)
            {
                Some(t) => {
                    state = format!(
                        "trusted_remove|{}",
                        serde_json::to_string(&t).unwrap_or_default()
                    );
                    warnings.push(
                        "\u{26A0} evil-twin and downgrade alerts for this name will stop.".into(),
                    );
                    format!(
                        "Stop trusting {}: {} known, expected {}.",
                        quote(&ssid),
                        plural(t.known_bssid_hashes.len(), "access point", "access points"),
                        security_label(t.expected_security)
                    )
                }
                None => {
                    blocked = Some("That network is no longer in the trusted list.".into());
                    state = format!("trusted_remove|absent|{ssid}");
                    format!("Stop trusting {}: not currently trusted.", quote(&ssid))
                }
            }
        }
        "mine_add" => match mine_args(args) {
            None => {
                blocked = Some("This request is malformed.".into());
                "Mark a device as yours.".into()
            }
            Some((kind, hash)) => {
                let label = arg_str(args, "label")
                    .map(|l| clean(&l, 64))
                    .filter(|l| !l.trim().is_empty());
                describe_mine_add(
                    store,
                    kind,
                    &hash,
                    label.as_deref(),
                    now,
                    &mut warnings,
                    &mut blocked,
                    &mut state,
                )?
            }
        },
        "mine_remove" => match mine_args(args) {
            None => {
                blocked = Some("This request is malformed.".into());
                "Remove a device from Mine.".into()
            }
            Some((kind, hash)) => {
                let row = store
                    .list_mine_with_source()?
                    .into_iter()
                    .find(|(m, _)| m.kind == kind && m.id_hash == hash);
                match row {
                    Some((m, by)) => {
                        state = format!(
                            "mine_remove|{kind:?}|{hash}|{:?}|{:?}|{}",
                            m.label,
                            m.ssid,
                            by.as_str()
                        );
                        warnings.push(match kind {
                            MineKind::Lan => "\u{26A0} without the mark, a device that announces this one's hostname can take over its history, and the new-device alert for it stops being a surprise.".to_string(),
                            _ => "\u{26A0} alerts that the mark silences will come back, and anything that relied on the mark (such as the opt-in sweep) stops.".to_string(),
                        });
                        format!(
                            "Remove this {} ({}){} from Mine.",
                            mine_kind_label(kind),
                            tail(&hash),
                            m.label
                                .as_deref()
                                .map(|l| format!(", labelled {}", quote(l)))
                                .unwrap_or_default()
                        )
                    }
                    None => {
                        blocked = Some("That entry is no longer in Mine.".into());
                        state = format!("mine_remove|absent|{hash}");
                        format!("Remove a {} that is not in Mine.", mine_kind_label(kind))
                    }
                }
            }
        },
        "dismiss_alert" => {
            let id = arg_str(args, "id").unwrap_or_default();
            match store.get_alerts(true)?.into_iter().find(|a| a.id == id) {
                Some(a) => {
                    let subject = alert_subject_ssid(store, a.kind, &a.subject_hash);
                    let latest = store.latest_scan_at()?.unwrap_or(0);
                    state = format!(
                        "dismiss_alert|{id}|{:?}|{}|{}",
                        a.kind, a.subject_hash, a.dismissed
                    );
                    if a.last_seen >= latest {
                        warnings.push(
                            "\u{26A0} this finding is present in the latest scan. A dismissed alert stays dismissed while the finding continues."
                                .into(),
                        );
                    }
                    if a.dismissed {
                        blocked = Some("That alert is already dismissed.".into());
                    }
                    let about = subject
                        .map(|s| format!(" about {}", quote(&s)))
                        .unwrap_or_default();
                    format!(
                        "Dismiss the {} alert ({} severity, subject {}, first seen {}, last seen {}){about}.",
                        alert_kind_label(a.kind),
                        severity_label(a.severity),
                        tail(&a.subject_hash),
                        fmt_time(a.first_seen),
                        fmt_time(a.last_seen)
                    )
                }
                None => {
                    blocked = Some("That alert no longer exists.".into());
                    state = format!("dismiss_alert|absent|{id}");
                    "Dismiss an alert that no longer exists.".into()
                }
            }
        }
        "watchlist_remove" => {
            let id = args.get("id").and_then(Value::as_i64).unwrap_or(-1);
            match store.list_watchlist()?.into_iter().find(|w| w.id == id) {
                Some(w) => {
                    state = format!(
                        "watchlist_remove|{}",
                        serde_json::to_string(&w).unwrap_or_default()
                    );
                    warnings.push(
                        "\u{26A0} watchlist alerts for matching networks or vendors will stop."
                            .into(),
                    );
                    format!(
                        "Remove the watchlist rule: {} {} {}.",
                        match w.kind {
                            WatchKind::Ssid => "network name",
                            WatchKind::Vendor => "vendor",
                        },
                        match w.match_mode {
                            WatchMatch::Exact => "is",
                            WatchMatch::Contains => "contains",
                        },
                        quote(&w.pattern)
                    )
                }
                None => {
                    blocked = Some("That rule no longer exists.".into());
                    state = format!("watchlist_remove|absent|{id}");
                    "Remove a watchlist rule that no longer exists.".into()
                }
            }
        }
        other => {
            blocked = Some("This kind of request is not recognised.".into());
            state = format!("unknown|{other}");
            format!("Unrecognised request {}.", quote(other))
        }
    };
    Ok(Described {
        summary,
        warnings,
        blocked,
        state,
    })
}

#[allow(clippy::too_many_arguments)]
fn describe_mine_add(
    store: &Store,
    kind: MineKind,
    hash: &str,
    label: Option<&str>,
    now: Millis,
    warnings: &mut Vec<String>,
    blocked: &mut Option<String>,
    state: &mut String,
) -> StoreResult<String> {
    if !store.known_hashes(kind, now)?.contains(hash) {
        *blocked = Some("The monitor has not seen that device recently.".into());
    }
    let latest = store.latest_scan()?;
    let label_clause = label
        .map(|l| format!(", with the label {}", quote(l)))
        .unwrap_or_default();
    let what = match kind {
        MineKind::WifiAp | MineKind::WifiGroup => {
            let o = latest.as_ref().and_then(|s| {
                s.wifi.iter().find(|o| match kind {
                    MineKind::WifiAp => o.bssid_hash.as_deref() == Some(hash),
                    _ => o.group_id.as_deref() == Some(hash),
                })
            });
            let (jb, jg) = joined_ap(store);
            let joined = match kind {
                MineKind::WifiAp => jb.as_deref() == Some(hash),
                _ => jg.as_deref() == Some(hash),
            };
            *state = format!(
                "mine_add|{kind:?}|{hash}|{:?}|{:?}|{joined}|{label:?}",
                o.map(|o| o.ssid.clone()),
                o.map(|o| o.vendor.clone())
            );
            if joined {
                warnings.push(format!(
                    "\u{26A0} this is the Wi-Fi network this Mac is joined to. Marking it as yours is what lets the opt-in LAN sweep run on it (the sweep is {} in Settings).",
                    if store.get_settings()?.lan_active_sweep { "ON" } else { "off" }
                ));
            }
            match o {
                Some(o) => {
                    if let Some(ssid) = o.ssid.as_deref() {
                        if let Some(a) = store.active_ssid_alert(ssid, now)? {
                            warnings.push(format!(
                                "\u{26A0} an {} alert for this network name is active.",
                                alert_kind_label(a)
                            ));
                        }
                        name_warnings(store, ssid, warnings)?;
                    }
                    let name = o
                        .ssid
                        .as_deref()
                        .map_or("a hidden network".to_string(), quote);
                    format!(
                        "{} named {} ({}, {} dBm, {})",
                        mine_kind_label(kind),
                        name,
                        clean(o.vendor.as_deref().unwrap_or("unknown vendor"), 40),
                        o.rssi,
                        tail(hash)
                    )
                }
                None => format!(
                    "{} that is not in the latest scan ({})",
                    mine_kind_label(kind),
                    tail(hash)
                ),
            }
        }
        MineKind::Ble => {
            let o = latest
                .as_ref()
                .and_then(|s| s.ble.iter().find(|o| o.peripheral_hash == hash));
            *state = format!(
                "mine_add|ble|{hash}|{:?}|{:?}|{label:?}",
                o.map(|o| o.name.clone()),
                o.map(|o| o.tracker)
            );
            match o {
                Some(o) => {
                    let mut facts = Vec::new();
                    if let Some(t) = o.tracker {
                        warnings.push(format!(
                            "\u{26A0} this device has a {} tracker signature. Marking it as yours silences possible-tracker alerts for it.",
                            tracker_label(t)
                        ));
                        facts.push(format!("{} tracker signature", tracker_label(t)));
                    }
                    if let Some(r) = o.rssi {
                        facts.push(format!("{r} dBm"));
                    }
                    facts.push(tail(hash));
                    format!(
                        "{} {} ({})",
                        mine_kind_label(kind),
                        o.name.as_deref().map_or("with no name".to_string(), quote),
                        facts.join(", ")
                    )
                }
                None => format!(
                    "{} that is not in the latest scan ({})",
                    mine_kind_label(kind),
                    tail(hash)
                ),
            }
        }
        MineKind::Lan => {
            let d = store
                .list_lan_devices(None)?
                .into_iter()
                .find(|d| d.mac_hash == hash);
            *state = format!(
                "mine_add|lan|{hash}|{:?}|{:?}|{label:?}",
                d.as_ref().map(|d| d.hostname.clone()),
                d.as_ref().map(|d| d.vendor.clone())
            );
            match d {
                Some(d) => format!(
                    "{} {} ({}, {})",
                    mine_kind_label(kind),
                    d.hostname
                        .as_deref()
                        .map_or("with no hostname".to_string(), quote),
                    clean(d.vendor.as_deref().unwrap_or("unknown vendor"), 40),
                    tail(hash)
                ),
                None => format!(
                    "{} that is not remembered ({})",
                    mine_kind_label(kind),
                    tail(hash)
                ),
            }
        }
    };
    Ok(format!("Mark this {what} as yours{label_clause}."))
}

/// Pending requests, described. Stale ones are expired first.
pub fn list_pending(store: &mut Store, now: Millis) -> Res<Vec<ProposalView>> {
    let pending = db(store.list_pending_proposals(now))?;
    let mut out = Vec::new();
    for p in pending {
        let d = db(describe(store, &p.tool, &p.args, now))?;
        out.push(ProposalView {
            id: p.id,
            tool: p.tool,
            created_at: p.created_at,
            expires_at: p.created_at + PROPOSAL_TTL_MS,
            digest: d.digest(),
            summary: d.summary,
            warnings: d.warnings,
            blocked: d.blocked,
        });
    }
    Ok(out)
}

/// How many requests wait (for the Dashboard).
pub fn pending_count(store: &mut Store, now: Millis) -> Res<usize> {
    Ok(db(store.list_pending_proposals(now))?.len())
}

/// A page of the audit log for the UI.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    /// Direct changes not yet undone come first (so later entries can never bury them), then
    /// the rest newest first.
    pub entries: Vec<AuditView>,
    /// All entries in the log; `total - entries.len()` are not shown.
    pub total: usize,
    /// How many of `entries` are pinned (direct and not undone).
    pub pinned: usize,
}

pub fn list_audit_page(store: &Store, limit: usize) -> Res<AuditPage> {
    let entries = db(store.list_audit_pinned_first(limit))?;
    let (total, pinned_all) = db(store.count_audit())?;
    Ok(AuditPage {
        pinned: pinned_all.min(entries.len()),
        entries: entries.into_iter().map(AuditView::from).collect(),
        total,
    })
}

/// The digest of a pending request as it reads right now (what the UI carries back).
pub fn current_digest(store: &mut Store, id: i64, now: Millis) -> Res<String> {
    db(store.expire_proposals(now))?;
    let p = db(store.get_proposal(id))?.ok_or("That request no longer exists.")?;
    Ok(db(describe(store, &p.tool, &p.args, now))?.digest())
}

/// Recent applied agent changes, newest first.
pub fn list_audit(store: &Store, limit: usize) -> Res<Vec<AuditView>> {
    Ok(db(store.list_audit(limit))?
        .into_iter()
        .map(AuditView::from)
        .collect())
}

// ---------------------------------------------------------------------------
// Deciding
// ---------------------------------------------------------------------------

struct Applied {
    changed: bool,
    summary: String,
    undo: Value,
}

/// Approve or reject a pending request. Approval re-validates against current data and
/// applies it; a refusal leaves the request pending so the reason can be read (and Reject
/// chosen). A request is decided exactly once.
pub fn decide(
    store: &mut Store,
    id: i64,
    approve: bool,
    digest: Option<&str>,
    now: Millis,
) -> Res<Decision> {
    db(store.expire_proposals(now))?;
    let p = db(store.get_proposal(id))?.ok_or("That request no longer exists.")?;
    if p.status != ProposalStatus::Pending {
        return Err(format!("That request was already {}.", p.status.as_str()));
    }
    if !approve {
        if !db(store.decide_proposal(id, ProposalStatus::Rejected, now))? {
            return Err("That request was already decided.".into());
        }
        return Ok(Decision {
            status: "rejected".into(),
            changed: false,
            message: "Rejected. Nothing changed.".into(),
        });
    }
    // Approve only what was read: recompute what the request describes now and compare with
    // the digest the person saw. A difference means the situation changed in between.
    let current = db(describe(store, &p.tool, &p.args, now))?.digest();
    if digest != Some(current.as_str()) {
        return Err("This request changed since you read it (or was approved without being shown). It has been re-read; check it and approve again.".into());
    }
    let applied = apply(store, &p, now)?;
    if !db(store.decide_proposal(id, ProposalStatus::Approved, now))? {
        return Err("That request was already decided.".into());
    }
    if applied.changed {
        db(store.record_audit(&NewAudit {
            at: now,
            tool: &p.tool,
            via: "proposal",
            proposal_id: Some(id),
            summary: &applied.summary,
            undo: &applied.undo,
        }))?;
    }
    Ok(Decision {
        status: "approved".into(),
        changed: applied.changed,
        message: if applied.changed {
            "Approved and applied.".into()
        } else {
            "Approved. It was already so; nothing changed.".into()
        },
    })
}

fn apply(store: &mut Store, p: &Proposal, now: Millis) -> Res<Applied> {
    let d = db(describe(store, &p.tool, &p.args, now))?;
    if let Some(why) = d.blocked {
        return Err(why);
    }
    let summary = d.summary;
    match p.tool.as_str() {
        "trusted_add" => {
            let ssid = arg_str(&p.args, "ssid").ok_or("malformed request")?;
            let c = db(trust_check(store, &ssid, now))?;
            if c.already {
                return Ok(Applied {
                    changed: false,
                    summary,
                    undo: Value::Null,
                });
            }
            // Strongest security in the LATEST scan; refusal above guarantees a single mode.
            let expected = c
                .modes
                .iter()
                .copied()
                .max_by_key(|m| m.strength())
                .ok_or("no security mode seen")?;
            let entry = TrustedNetwork {
                ssid: ssid.clone(),
                known_bssid_hashes: c.hashes(),
                expected_security: expected,
            };
            let added = db(store.update_trusted_networks(|list| {
                if list.iter().any(|t| t.ssid == ssid) {
                    false
                } else {
                    list.push(entry.clone());
                    true
                }
            }))?;
            Ok(Applied {
                changed: added,
                summary,
                undo: json!({"op": "trustedRemove", "entry": entry}),
            })
        }
        "trusted_remove" => {
            let ssid = arg_str(&p.args, "ssid").ok_or("malformed request")?;
            let removed = db(store.update_trusted_networks(|list| {
                let at = list.iter().position(|t| t.ssid == ssid)?;
                Some(list.remove(at))
            }))?;
            match removed {
                Some(entry) => Ok(Applied {
                    changed: true,
                    summary,
                    undo: json!({"op": "trustedRestore", "entry": entry}),
                }),
                None => Ok(Applied {
                    changed: false,
                    summary,
                    undo: Value::Null,
                }),
            }
        }
        "mine_add" => {
            let (kind, id_hash) = mine_args(&p.args).ok_or("malformed request")?;
            let existing = db(store.list_mine_with_source())?
                .into_iter()
                .any(|(m, _)| m.kind == kind && m.id_hash == id_hash);
            if existing {
                return Ok(Applied {
                    changed: false,
                    summary,
                    undo: Value::Null,
                });
            }
            let label = arg_str(&p.args, "label")
                .map(|l| clean(&l, 64))
                .filter(|l| !l.trim().is_empty());
            // An access-point mark carries the network name from the LATEST scan, as the app's
            // own Mine button does; the sweep gate requires it to match the joined network. If
            // the name is hidden there is none to store, and the mark then fails closed for the
            // sweep with SsidMismatch (it still silences alerts); mark it again in the app with
            // Location access on.
            let ssid = match kind {
                MineKind::WifiAp | MineKind::WifiGroup => db(store.latest_scan())?.and_then(|s| {
                    s.wifi
                        .into_iter()
                        .find(|o| match kind {
                            MineKind::WifiAp => o.bssid_hash.as_deref() == Some(id_hash.as_str()),
                            _ => o.group_id.as_deref() == Some(id_hash.as_str()),
                        })
                        .and_then(|o| o.ssid)
                }),
                _ => None,
            };
            let entry = MineEntry {
                kind,
                id_hash: id_hash.clone(),
                label,
                ssid,
                added_at: now,
            };
            // A person clicked Approve: the entry counts as user-confirmed.
            db(store.add_mine_as(&entry, AddedBy::Approved))?;
            Ok(Applied {
                changed: true,
                summary,
                undo: json!({"op": "mineRemove", "kind": kind, "idHash": id_hash}),
            })
        }
        "mine_remove" => {
            let (kind, id_hash) = mine_args(&p.args).ok_or("malformed request")?;
            let row = db(store.list_mine_with_source())?
                .into_iter()
                .find(|(m, _)| m.kind == kind && m.id_hash == id_hash);
            let Some((entry, by)) = row else {
                return Ok(Applied {
                    changed: false,
                    summary,
                    undo: Value::Null,
                });
            };
            db(store.remove_mine(kind, &id_hash))?;
            Ok(Applied {
                changed: true,
                summary,
                undo: json!({"op": "mineRestore", "entry": entry, "addedBy": by.as_str()}),
            })
        }
        "dismiss_alert" => {
            let id = arg_str(&p.args, "id").ok_or("malformed request")?;
            db(store.dismiss_alert(&id))?;
            Ok(Applied {
                changed: true,
                summary,
                undo: json!({"op": "undismiss", "id": id}),
            })
        }
        "watchlist_remove" => {
            let id = p
                .args
                .get("id")
                .and_then(Value::as_i64)
                .ok_or("malformed request")?;
            let entry = db(store.list_watchlist())?
                .into_iter()
                .find(|w| w.id == id)
                .ok_or("That rule no longer exists.")?;
            db(store.remove_watchlist(id))?;
            Ok(Applied {
                changed: true,
                summary,
                undo: json!({"op": "watchlistRestore", "entry": entry}),
            })
        }
        other => Err(format!("unrecognised request {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------

/// Reverse one audited agent change. Refuses when the thing has been changed since, so an undo
/// never overwrites a person's later edit.
pub fn undo(store: &mut Store, audit_id: i64) -> Res<()> {
    let e = db(store.get_audit(audit_id))?.ok_or("That entry no longer exists.")?;
    if e.undone {
        return Err("That change was already undone.".into());
    }
    let op = e.undo["op"].as_str().unwrap_or("").to_string();
    match op.as_str() {
        "trustedRemove" => {
            let entry: TrustedNetwork =
                serde_json::from_value(e.undo["entry"].clone()).map_err(|_| "unreadable undo")?;
            let done =
                db(
                    store.update_trusted_networks(|l| match l.iter().position(|t| *t == entry) {
                        Some(at) => {
                            l.remove(at);
                            true
                        }
                        None => false,
                    }),
                )?;
            if !done {
                return Err(
                    "That network was edited since; change it in the trusted list instead.".into(),
                );
            }
        }
        "trustedRestore" => {
            let entry: TrustedNetwork =
                serde_json::from_value(e.undo["entry"].clone()).map_err(|_| "unreadable undo")?;
            let done = db(store.update_trusted_networks(|l| {
                if l.iter().any(|t| t.ssid == entry.ssid) {
                    false
                } else {
                    l.push(entry.clone());
                    true
                }
            }))?;
            if !done {
                return Err("That network is trusted again already.".into());
            }
        }
        "mineRemove" => {
            let kind: MineKind =
                serde_json::from_value(e.undo["kind"].clone()).map_err(|_| "unreadable undo")?;
            let hash = e.undo["idHash"]
                .as_str()
                .ok_or("unreadable undo")?
                .to_string();
            let row = db(store.list_mine_with_source())?
                .into_iter()
                .find(|(m, _)| m.kind == kind && m.id_hash == hash);
            match row {
                Some((_, AddedBy::Approved)) | Some((_, AddedBy::Agent)) => {
                    db(store.remove_mine(kind, &hash))?;
                }
                Some((_, AddedBy::User)) => {
                    return Err(
                        "You marked this yourself since; remove it from Mine if you want it gone."
                            .into(),
                    )
                }
                None => return Err("It is no longer in Mine.".into()),
            }
        }
        "mineRestore" => {
            let entry: MineEntry =
                serde_json::from_value(e.undo["entry"].clone()).map_err(|_| "unreadable undo")?;
            let by = AddedBy::parse(e.undo["addedBy"].as_str().unwrap_or("user"));
            let present = db(store.list_mine_with_source())?
                .into_iter()
                .any(|(m, _)| m.kind == entry.kind && m.id_hash == entry.id_hash);
            if present {
                return Err("It is in Mine again already.".into());
            }
            db(store.add_mine_as(&entry, by))?;
        }
        "undismiss" => {
            let id = e.undo["id"].as_str().ok_or("unreadable undo")?.to_string();
            db(store.undismiss_alert(&id))?;
        }
        "watchlistRemove" => {
            // By id, or by content when the rule was removed and restored since (new id).
            let w: WatchlistEntry =
                serde_json::from_value(e.undo["entry"].clone()).map_err(|_| "unreadable undo")?;
            let rules = db(store.list_watchlist())?;
            let found = rules
                .iter()
                .find(|r| r.id == w.id && r.pattern == w.pattern)
                .or_else(|| {
                    rules.iter().find(|r| {
                        r.kind == w.kind && r.match_mode == w.match_mode && r.pattern == w.pattern
                    })
                });
            let id = found.map(|r| r.id).ok_or("That rule is already gone.")?;
            db(store.remove_watchlist(id))?;
        }
        "watchlistRestore" => {
            let w: WatchlistEntry =
                serde_json::from_value(e.undo["entry"].clone()).map_err(|_| "unreadable undo")?;
            db(store.add_watchlist(w.kind, &w.pattern, w.match_mode, w.added_at))?;
        }
        _ => return Err("This change cannot be undone automatically.".into()),
    }
    if !db(store.mark_audit_undone(audit_id))? {
        return Err("That change was already undone.".into());
    }
    Ok(())
}
