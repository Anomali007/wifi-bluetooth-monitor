//! Bypass-check fixes: direct edits are atomic (no check-then-act race), the approval digest
//! covers every field `apply` reads (one test per proposal kind), and the invisible-character
//! filter has no gaps. Synthetic data only.

mod common;

use app_lib::agent::tools;
use app_lib::agent::{AgentError, Ctx};
use app_lib::model::*;
use app_lib::proposals;
use app_lib::store::{AddedBy, DirectMineRemove, Store};
use common::*;
use serde_json::{json, Value};

fn ctx_db(db: std::path::PathBuf) -> Ctx {
    let mut c = Ctx::new(db).with_edits(true);
    c.pid_alive = |_| true;
    c
}
fn call(f: &Fixture, n: &str, a: Value) -> Result<Value, AgentError> {
    tools::call(&ctx_db(f.db.clone()), n, &a)
}
fn app(f: &Fixture) -> Store {
    Store::open(f.dir.path()).unwrap()
}
fn now() -> Millis {
    app_lib::pipeline::now_ms()
}
fn pid(v: Value) -> i64 {
    v["proposalId"]
        .as_i64()
        .unwrap_or_else(|| panic!("not a proposal: {v}"))
}
fn view(f: &Fixture, id: i64) -> proposals::ProposalView {
    proposals::list_pending(&mut app(f), now())
        .unwrap()
        .into_iter()
        .find(|x| x.id == id)
        .unwrap()
}

// ---- 1. atomic direct edits and proposal creation --------------------------------------

#[test]
fn parallel_watchlist_adds_cannot_exceed_the_cap_or_the_hourly_limit() {
    let f = bare();
    {
        let mut s = app(&f);
        for i in 0..44 {
            s.add_watchlist(
                WatchKind::Ssid,
                &format!("seed{i}"),
                WatchMatch::Contains,
                1,
            )
            .unwrap();
        }
    }
    let hs: Vec<_> = (0..40)
        .map(|i| {
            let db = f.db.clone();
            std::thread::spawn(move || {
                tools::call(
                    &ctx_db(db),
                    "watchlist_add",
                    &json!({"kind": "ssid", "pattern": format!("p{i}")}),
                )
            })
        })
        .collect();
    let res: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let okc = res.iter().filter(|r| r.is_ok()).count();
    let rules = app(&f).list_watchlist().unwrap().len();
    let (_, pinned) = app(&f).count_audit().unwrap();
    assert!(rules <= 50, "{rules} rules (cap 50)");
    assert_eq!(okc, rules - 44, "every success is exactly one new rule");
    assert_eq!(pinned, okc, "and exactly one audit row");
    assert!(okc <= 6, "{okc} succeeded with 44 seeded");
    // Every refusal says why.
    for r in res.iter().filter_map(|r| r.as_ref().err()) {
        assert!(matches!(r, AgentError::Failed(_)), "{r:?}");
    }
    // The hourly limit under the same race, with an empty list.
    let g = bare();
    let hs: Vec<_> = (0..40)
        .map(|i| {
            let db = g.db.clone();
            std::thread::spawn(move || {
                tools::call(
                    &ctx_db(db),
                    "watchlist_add",
                    &json!({"kind": "ssid", "pattern": format!("q{i}")}),
                )
            })
        })
        .collect();
    let okc = hs
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|r| r.is_ok())
        .count();
    assert_eq!(okc, 10, "exactly the limit");
    assert_eq!(app(&g).count_audit().unwrap().0, 10);
    assert_eq!(app(&g).list_watchlist().unwrap().len(), 10);
}

#[test]
fn parallel_agent_row_removals_respect_the_limit_and_never_touch_a_persons_row() {
    let f = bare();
    let mut s = app(&f);
    let hash = |i: usize| format!("{i:064x}");
    for i in 0..30 {
        s.add_mine_as(
            &MineEntry {
                kind: MineKind::Ble,
                id_hash: hash(i),
                label: None,
                ssid: None,
                added_at: 1,
            },
            AddedBy::Agent,
        )
        .unwrap();
    }
    s.add_mine(&MineEntry {
        kind: MineKind::Ble,
        id_hash: hash(99),
        label: None,
        ssid: None,
        added_at: 1,
    })
    .unwrap();
    drop(s);
    let hs: Vec<_> = (0..31)
        .map(|i| {
            let db = f.db.clone();
            let id = if i == 30 { hash(99) } else { hash(i) };
            std::thread::spawn(move || {
                tools::call(
                    &ctx_db(db),
                    "mine_remove",
                    &json!({"kind": "ble", "idHash": id}),
                )
            })
        })
        .collect();
    let res: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let removed = res
        .iter()
        .filter(|r| matches!(r, Ok(v) if v["removed"] == true))
        .count();
    assert_eq!(removed, 10, "the hourly limit holds under a race");
    assert_eq!(
        app(&f).count_audit().unwrap().0,
        10,
        "one audit row per removal"
    );
    let left = app(&f).list_mine_with_source().unwrap();
    assert_eq!(left.len(), 30 + 1 - 10);
    assert!(
        left.iter()
            .any(|(m, by)| m.id_hash == hash(99) && *by == AddedBy::User),
        "the person's row survives"
    );
}

#[test]
fn the_direct_mine_delete_is_guarded_by_added_by_in_the_statement_itself() {
    let f = bare();
    let h1 = "a".repeat(64);
    app(&f)
        .add_mine(&MineEntry {
            kind: MineKind::Lan,
            id_hash: h1.clone(),
            label: None,
            ssid: None,
            added_at: 1,
        })
        .unwrap();
    let mut agent = Store::open_db_file(&f.db, app_lib::store::OpenMode::Edit).unwrap();
    let r = agent
        .agent_remove_mine(MineKind::Lan, &h1, now(), |_| "x".into(), 10)
        .unwrap();
    assert_eq!(r, DirectMineRemove::NotAgent);
    assert_eq!(app(&f).list_mine().unwrap().len(), 1);
    assert_eq!(
        app(&f).count_audit().unwrap().0,
        0,
        "nothing audited, nothing changed"
    );
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/store/proposals.rs"
    ))
    .unwrap();
    assert!(
        src.contains("AND added_by = 'agent'"),
        "the DELETE carries the guard"
    );
}

#[test]
fn parallel_proposals_cannot_exceed_the_per_tool_cap() {
    let f = bare();
    let at = now() - 5_000;
    push_scan(
        &f,
        at,
        (0..40)
            .map(|i| {
                wifi_in_group(
                    &format!("Net-{i}"),
                    &format!("02:00:00:00:{i:02x}:01"),
                    &format!("d{i}"),
                    Security::Wpa2Personal,
                    at,
                )
            })
            .collect(),
    );
    let hs: Vec<_> = (0..40)
        .map(|i| {
            let db = f.db.clone();
            std::thread::spawn(move || {
                tools::call(
                    &ctx_db(db),
                    "trusted_add",
                    &json!({"ssid": format!("Net-{i}")}),
                )
            })
        })
        .collect();
    let okc = hs
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|r| r.is_ok())
        .count();
    assert_eq!(okc, app_lib::store::MAX_PENDING_PER_TOOL);
    assert_eq!(
        proposals::list_pending(&mut app(&f), now()).unwrap().len(),
        okc
    );
}

// ---- 2. the digest covers everything apply reads ---------------------------------------

/// Read the request, change the world, try to approve what was read: it must be refused and
/// the digest must have moved.
fn assert_refused_after(
    f: &Fixture,
    id: i64,
    change: impl FnOnce(&Fixture),
    nothing_applied: impl Fn(&Fixture) -> bool,
) {
    let before = view(f, id);
    change(f);
    let after = view(f, id);
    assert_ne!(
        before.digest, after.digest,
        "the digest did not move:\n{}\n{}",
        before.summary, after.summary
    );
    let e = proposals::decide(&mut app(f), id, true, Some(&before.digest), now()).unwrap_err();
    assert!(e.contains("changed since you read it"), "{e}");
    assert!(nothing_applied(f), "something was applied anyway");
}

#[test]
fn digest_trusted_add_covers_the_exact_security_mode_not_just_its_strength() {
    for (a, b) in [
        (Security::Wpa2Personal, Security::Wpa2Enterprise),
        (Security::Wep, Security::Owe),
        (Security::WpaPersonal, Security::WpaEnterprise),
        (Security::Wpa3Personal, Security::Wpa3Enterprise),
    ] {
        let f = bare();
        let t = now();
        push_scan(
            &f,
            t - 2000,
            vec![wifi_in_group(
                "Net-D",
                "02:00:00:00:00:aa",
                "g1",
                a,
                t - 2000,
            )],
        );
        let id = pid(call(&f, "trusted_add", json!({"ssid": "Net-D"})).unwrap());
        assert_refused_after(
            &f,
            id,
            |f| {
                push_scan(
                    f,
                    t - 1000,
                    vec![wifi_in_group(
                        "Net-D",
                        "02:00:00:00:00:aa",
                        "g1",
                        b,
                        t - 1000,
                    )],
                )
            },
            |f| app(f).get_settings().unwrap().trusted_networks.is_empty(),
        );
    }
}

#[test]
fn digest_trusted_add_covers_hashes_groups_and_an_alert_appearing() {
    let t = now();
    for case in 0..3 {
        let f = bare();
        push_scan(
            &f,
            t - 2000,
            vec![wifi_in_group(
                "Net-C",
                "02:00:00:00:00:aa",
                "g1",
                Security::Wpa2Personal,
                t - 2000,
            )],
        );
        let id = pid(call(&f, "trusted_add", json!({"ssid": "Net-C"})).unwrap());
        assert_refused_after(
            &f,
            id,
            |f| match case {
                0 => push_scan(
                    f,
                    t - 1000,
                    vec![wifi_in_group(
                        "Net-C",
                        "02:00:00:00:00:bb",
                        "g1",
                        Security::Wpa2Personal,
                        t - 1000,
                    )],
                ), // other BSSID, same group
                1 => push_scan(
                    f,
                    t - 1000,
                    vec![
                        wifi_in_group(
                            "Net-C",
                            "02:00:00:00:00:aa",
                            "g1",
                            Security::Wpa2Personal,
                            t - 1000,
                        ),
                        wifi_in_group(
                            "Net-C",
                            "02:00:00:00:00:cc",
                            "g1",
                            Security::Wpa2Personal,
                            t - 1000,
                        ), // one more radio
                    ],
                ),
                _ => push_name_alert(f, AlertKind::OpenLookalike, "Net-C", now() - 1000),
            },
            |f| app(f).get_settings().unwrap().trusted_networks.is_empty(),
        );
    }
}

#[test]
fn digest_dismiss_alert_covers_severity_and_dismissal() {
    let mk = |sev| Alert {
        id: "trk".into(),
        kind: AlertKind::PersistentTracker,
        severity: sev,
        title: "Possible tracker".into(),
        detail: "d".into(),
        first_seen: now() - 1000,
        last_seen: now(),
        subject_hash: h("t"),
        dismissed: false,
    };
    let f = fixture();
    app(&f).upsert_alerts(&[mk(Severity::Low)]).unwrap();
    let id = pid(call(&f, "dismiss_alert", json!({"id": "trk"})).unwrap());
    assert_refused_after(
        &f,
        id,
        |f| {
            app(f).upsert_alerts(&[mk(Severity::High)]).unwrap();
        },
        |f| {
            app(f)
                .get_alerts(false)
                .unwrap()
                .iter()
                .any(|a| a.id == "trk")
        },
    );
    // And a person dismissing it first.
    let g = fixture();
    app(&g).upsert_alerts(&[mk(Severity::Low)]).unwrap();
    let id = pid(call(&g, "dismiss_alert", json!({"id": "trk"})).unwrap());
    assert_refused_after(&g, id, |g| app(g).dismiss_alert("trk").unwrap(), |_| true);
}

#[test]
fn digest_mine_add_covers_the_name_stored_and_an_existing_row() {
    let t = now();
    let mac = "02:00:00:00:00:cc";
    let f = bare();
    push_scan(
        &f,
        t - 2000,
        vec![wifi(
            Some("Net-D"),
            mac,
            -40,
            Security::Wpa2Personal,
            t - 2000,
        )],
    );
    let id = pid(call(
        &f,
        "mine_add",
        json!({"kind": "wifiAp", "idHash": h(mac), "label": "Mine"}),
    )
    .unwrap());
    assert_refused_after(
        &f,
        id,
        |f| {
            push_scan(
                f,
                t - 1000,
                vec![wifi(
                    Some("Net-E"),
                    mac,
                    -40,
                    Security::Wpa2Personal,
                    t - 1000,
                )],
            )
        },
        |f| app(f).list_mine().unwrap().is_empty(),
    );
    let g = bare();
    push_scan(
        &g,
        t - 2000,
        vec![wifi(
            Some("Net-D"),
            mac,
            -40,
            Security::Wpa2Personal,
            t - 2000,
        )],
    );
    let id = pid(call(&g, "mine_add", json!({"kind": "wifiAp", "idHash": h(mac)})).unwrap());
    // A person marks it themselves in between: the pending request no longer means the same.
    assert_refused_after(
        &g,
        id,
        |g| {
            app(g)
                .add_mine(&MineEntry {
                    kind: MineKind::WifiAp,
                    id_hash: h(mac),
                    label: Some("Mine".into()),
                    ssid: Some("Net-D".into()),
                    added_at: 1,
                })
                .unwrap();
        },
        |_| true,
    );
}

#[test]
fn digest_mine_remove_covers_label_ssid_and_provenance() {
    for case in 0..3 {
        let f = bare();
        let hash = "b".repeat(64);
        app(&f)
            .add_mine(&MineEntry {
                kind: MineKind::WifiAp,
                id_hash: hash.clone(),
                label: Some("Old".into()),
                ssid: Some("Net-D".into()),
                added_at: 1,
            })
            .unwrap();
        let id = pid(call(&f, "mine_remove", json!({"kind": "wifiAp", "idHash": hash})).unwrap());
        let hh = hash.clone();
        assert_refused_after(
            &f,
            id,
            move |f| match case {
                0 => app(f)
                    .add_mine(&MineEntry {
                        kind: MineKind::WifiAp,
                        id_hash: hh,
                        label: Some("New label".into()),
                        ssid: None,
                        added_at: 9,
                    })
                    .unwrap(),
                1 => app(f)
                    .add_mine(&MineEntry {
                        kind: MineKind::WifiAp,
                        id_hash: hh,
                        label: Some("Old".into()),
                        ssid: Some("Net-Z".into()),
                        added_at: 9,
                    })
                    .unwrap(),
                _ => app(f)
                    .add_mine_as(
                        &MineEntry {
                            kind: MineKind::WifiAp,
                            id_hash: hh,
                            label: Some("Old".into()),
                            ssid: Some("Net-D".into()),
                            added_at: 9,
                        },
                        AddedBy::Approved,
                    )
                    .unwrap(),
            },
            |f| app(f).list_mine().unwrap().len() == 1,
        );
    }
}

#[test]
fn digest_trusted_remove_and_watchlist_remove_cover_the_entry() {
    let f = bare();
    app(&f)
        .update_trusted_networks(|l| {
            l.push(TrustedNetwork {
                ssid: "Net-A".into(),
                known_bssid_hashes: vec![h("x")],
                expected_security: Security::Wpa2Personal,
            })
        })
        .unwrap();
    let id = pid(call(&f, "trusted_remove", json!({"ssid": "Net-A"})).unwrap());
    assert_refused_after(
        &f,
        id,
        |f| {
            app(f)
                .update_trusted_networks(|l| l[0].expected_security = Security::Wpa3Personal)
                .unwrap();
        },
        |f| app(f).get_settings().unwrap().trusted_networks.len() == 1,
    );
    let g = bare();
    let w = pid({
        call(
            &g,
            "watchlist_add",
            json!({"kind": "ssid", "pattern": "zz"}),
        )
        .unwrap();
        let wid = app(&g).list_watchlist().unwrap()[0].id;
        call(&g, "watchlist_remove", json!({"id": wid})).unwrap()
    });
    // The rule is removed and re-added with the same text: a different row (id, added_at).
    assert_refused_after(
        &g,
        w,
        |g| {
            let id = app(g).list_watchlist().unwrap()[0].id;
            app(g).remove_watchlist(id).unwrap();
            app(g)
                .add_watchlist(WatchKind::Ssid, "zz", WatchMatch::Contains, 5)
                .unwrap();
        },
        |g| app(g).list_watchlist().unwrap().len() == 1,
    );
}

// ---- 3. invisible characters ------------------------------------------------------------

#[test]
fn the_reviewers_missing_characters_are_filtered_end_to_end() {
    for c in [
        '\u{0890}',
        '\u{0891}',
        '\u{2065}',
        '\u{FFF0}',
        '\u{FFF8}',
        '\u{E0080}',
        '\u{E0FFF}',
        '\u{E0100}',
    ] {
        assert!(app_lib::labels::is_unsafe_char(c), "U+{:04X}", c as u32);
        let f = bare();
        let t = now();
        let evil = format!("Corp-WiFi{c}");
        push_scan(
            &f,
            t - 1000,
            vec![wifi_in_group(
                &evil,
                "02:00:00:00:00:aa",
                "g1",
                Security::Wpa2Personal,
                t - 1000,
            )],
        );
        assert!(
            call(&f, "trusted_add", json!({"ssid": evil})).is_err(),
            "tool accepted U+{:04X}",
            c as u32
        );
        let id = match app(&f)
            .create_proposal("trusted_add", &json!({"ssid": evil}), now())
            .unwrap()
        {
            app_lib::store::NewProposal::Created(i) | app_lib::store::NewProposal::Existing(i) => i,
            o => panic!("{o:?}"),
        };
        assert!(
            view(&f, id).blocked.is_some(),
            "approval not blocked for U+{:04X}",
            c as u32
        );
    }
}
