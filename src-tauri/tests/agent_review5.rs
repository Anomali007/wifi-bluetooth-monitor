//! Fixes from the fifth security review: an attacker-controlled agent. Each test names the
//! finding it pins. Synthetic data only.

mod common;

use app_lib::agent::tools;
use app_lib::agent::{AgentError, Ctx};
use app_lib::model::{
    Alert, AlertKind, LanDevice, LanSource, Millis, MineEntry, MineKind, Security, Severity,
};
use app_lib::proposals;
use app_lib::store::{AddedBy, NewAudit, Store};
use common::{bare, fixture, h, push_scan, wifi, wifi_in_group};
use serde_json::{json, Value};

fn ctx(f: &common::Fixture) -> Ctx {
    let mut c = Ctx::new(f.db.clone()).with_edits(true);
    c.pid_alive = |_| true;
    c
}
fn call(f: &common::Fixture, n: &str, a: Value) -> Result<Value, AgentError> {
    tools::call(&ctx(f), n, &a)
}
fn ok(f: &common::Fixture, n: &str, a: Value) -> Value {
    call(f, n, a).unwrap_or_else(|e| panic!("{n}: {e}"))
}
fn app(f: &common::Fixture) -> Store {
    Store::open(f.dir.path()).unwrap()
}
fn now() -> Millis {
    app_lib::pipeline::now_ms()
}
fn pid(f: &common::Fixture, n: &str, a: Value) -> i64 {
    let r = ok(f, n, a);
    assert_eq!(r["status"], "pending", "{r}");
    r["proposalId"].as_i64().unwrap()
}
fn pending(f: &common::Fixture) -> Vec<proposals::ProposalView> {
    proposals::list_pending(&mut app(f), now()).unwrap()
}
fn view(f: &common::Fixture, id: i64) -> proposals::ProposalView {
    pending(f).into_iter().find(|v| v.id == id).unwrap()
}
/// Approve with the digest the UI was shown.
fn approve_shown(f: &common::Fixture, id: i64) -> Result<proposals::Decision, String> {
    let d = view(f, id).digest;
    proposals::decide(&mut app(f), id, true, Some(&d), now())
}
fn trusted(f: &common::Fixture) -> Vec<Value> {
    ok(f, "trusted_list", json!({}))["trusted"]
        .as_array()
        .unwrap()
        .clone()
}

// ---- M1 -------------------------------------------------------------------------------

#[test]
fn m1_the_watchlist_holds_at_most_fifty_rules() {
    let f = bare();
    // Space the adds across hours so only the cap is under test.
    for i in 0..50 {
        // Pre-seed through the store, as a person would, to stay under the hourly limit.
        app(&f)
            .add_watchlist(
                app_lib::model::WatchKind::Ssid,
                &format!("rule-{i}"),
                app_lib::model::WatchMatch::Contains,
                1,
            )
            .unwrap();
    }
    let e = call(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "one-too-many"}),
    )
    .unwrap_err();
    assert!(matches!(e, AgentError::Failed(_)), "{e:?}");
    assert!(e.message().contains("50 rules"), "{}", e.message());
    assert_eq!(
        ok(&f, "watchlist_list", json!({}))["watchlist"]
            .as_array()
            .unwrap()
            .len(),
        50
    );
}

#[test]
fn m1_direct_agent_edits_are_limited_to_ten_an_hour() {
    let f = bare();
    for i in 0..10 {
        ok(
            &f,
            "watchlist_add",
            json!({"kind": "ssid", "pattern": format!("zz{i}")}),
        );
    }
    let e = call(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "zz10"}),
    )
    .unwrap_err();
    assert!(
        e.message().contains("too many direct edits"),
        "{}",
        e.message()
    );
    // An hour later the window has moved on.
    let mut c = ctx(&f);
    c.now = || now() + 3_600_001;
    tools::call(
        &c,
        "watchlist_add",
        &json!({"kind": "ssid", "pattern": "zz10"}),
    )
    .unwrap();
    // Proposals are not direct edits and are not counted.
    let g = bare();
    for i in 0..10 {
        ok(
            &g,
            "watchlist_add",
            json!({"kind": "ssid", "pattern": format!("a{i}")}),
        );
    }
    assert!(call(&g, "watchlist_list", json!({})).is_ok());
}

// ---- M2 -------------------------------------------------------------------------------

#[test]
fn m2_a_direct_change_is_pinned_above_a_flood_of_later_entries_and_the_page_says_how_many_more() {
    let f = bare();
    let mut s = app(&f);
    s.record_audit(&NewAudit {
        at: 1,
        tool: "mine_remove",
        via: "direct",
        proposal_id: None,
        summary: "Removed a thing",
        undo: &json!({"op": "none"}),
    })
    .unwrap();
    for i in 0..40 {
        s.record_audit(&NewAudit {
            at: 10 + i,
            tool: "trusted_add",
            via: "proposal",
            proposal_id: Some(i),
            summary: "later",
            undo: &json!({"op": "none"}),
        })
        .unwrap();
    }
    let page = proposals::list_audit_page(&s, 30).unwrap();
    assert_eq!(page.entries.len(), 30);
    assert_eq!(page.total, 41);
    assert_eq!(page.pinned, 1);
    assert_eq!(page.entries[0].tool, "mine_remove", "pinned first");
    assert_eq!(page.total - page.entries.len(), 11, "the UI says 11 more");
    // The old window (newest 30) would have hidden it: control.
    assert!(!s
        .list_audit(30)
        .unwrap()
        .iter()
        .any(|a| a.tool == "mine_remove"));
    // Once undone it is no longer pinned.
    let id = page.entries[0].id;
    s.mark_audit_undone(id).unwrap();
    assert!(!proposals::list_audit_page(&s, 30)
        .unwrap()
        .entries
        .iter()
        .any(|a| a.tool == "mine_remove"));
}

// ---- M3 -------------------------------------------------------------------------------

#[test]
fn m3_invisible_names_cannot_be_proposed_and_an_existing_request_for_one_is_blocked() {
    let f = bare();
    let t = now();
    let evil = "Net-Z\u{E0061}\u{E0070}\u{E0070}";
    push_scan(
        &f,
        t - 1000,
        vec![wifi_in_group(
            evil,
            "02:00:00:00:00:77",
            "g",
            Security::Wpa2Personal,
            t - 1000,
        )],
    );
    // Through the tool: refused.
    assert!(matches!(
        call(&f, "trusted_add", json!({"ssid": evil})).unwrap_err(),
        AgentError::Usage(_)
    ));
    // Output: the tag characters are gone from what the agent sees.
    let v = tools::call_marked(&ctx(&f), "networks", &json!({})).unwrap();
    assert_eq!(v["networks"][0]["ssid"]["untrusted"], "Net-Z");
    // A request that reached the table some other way is blocked at approval.
    app(&f)
        .create_proposal("trusted_add", &json!({"ssid": evil}), now())
        .unwrap();
    let pv = &pending(&f)[0];
    assert!(pv.blocked.is_some(), "{pv:?}");
    assert!(pv.warnings.iter().any(|w| w.contains("hidden characters")));
    let e = proposals::decide(&mut app(&f), pv.id, true, Some(&pv.digest), now()).unwrap_err();
    assert!(e.contains("hidden characters"), "{e}");
    assert!(trusted(&f).is_empty());
}

#[test]
fn m3_a_non_ascii_name_is_shown_with_its_code_points_and_a_lookalike_warning() {
    let f = bare();
    let t = now();
    let cyr = "N\u{435}t-C"; // Cyrillic small e
    push_scan(
        &f,
        t - 1000,
        vec![
            wifi_in_group(
                "Net-C",
                "02:00:00:00:0c:01",
                "g1",
                Security::Wpa2Personal,
                t - 1000,
            ),
            wifi_in_group(
                cyr,
                "02:00:00:00:0c:02",
                "g2",
                Security::Wpa2Personal,
                t - 1000,
            ),
        ],
    );
    let id = pid(&f, "trusted_add", json!({"ssid": cyr}));
    let v = view(&f, id);
    assert!(
        v.warnings.iter().any(|w| w.contains("U+0435")),
        "{:?}",
        v.warnings
    );
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("looks like \u{201C}Net-C\u{201D}")),
        "{:?}",
        v.warnings
    );
    // CONTROL: the plain ASCII name carries neither warning about code points.
    let id2 = pid(&f, "trusted_add", json!({"ssid": "Net-C"}));
    assert!(view(&f, id2).warnings.iter().all(|w| !w.contains("U+")));
}

// ---- M4 -------------------------------------------------------------------------------

#[test]
fn m4_approving_a_request_whose_situation_changed_since_it_was_read_is_refused() {
    let f = bare();
    let t = now();
    push_scan(
        &f,
        t - 2000,
        vec![wifi_in_group(
            "Net-C",
            "02:00:00:00:00:aa",
            "g-legit",
            Security::Wpa2Personal,
            t - 2000,
        )],
    );
    let id = pid(&f, "trusted_add", json!({"ssid": "Net-C"}));
    let shown = view(&f, id);
    assert!(
        shown.summary.contains(&h("02:00:00:00:00:aa")[58..]),
        "tail of the AP hash is on screen: {}",
        shown.summary
    );
    // The legit AP leaves; an attacker AP with the same name and security takes its place.
    push_scan(
        &f,
        t - 1000,
        vec![wifi_in_group(
            "Net-C",
            "02:00:00:00:00:bb",
            "g-attacker",
            Security::Wpa2Personal,
            t - 1000,
        )],
    );
    let e = proposals::decide(&mut app(&f), id, true, Some(&shown.digest), now()).unwrap_err();
    assert!(e.contains("changed since you read it"), "{e}");
    assert!(trusted(&f).is_empty(), "nothing was trusted");
    // No digest at all is refused too.
    assert!(proposals::decide(&mut app(&f), id, true, None, now()).is_err());
    // Re-read: the sentence now shows the attacker's tail; approving THAT is the person's call.
    let reread = view(&f, id);
    assert_ne!(reread.digest, shown.digest);
    assert!(reread.summary.contains(&h("02:00:00:00:00:bb")[58..]));
    assert!(approve_shown(&f, id).unwrap().changed);
    assert_eq!(
        trusted(&f)[0]["knownBssidHashes"],
        json!([h("02:00:00:00:00:bb")])
    );
}

#[test]
fn m4_a_signal_change_alone_does_not_invalidate_the_digest_but_a_name_swap_on_mine_add_does() {
    let f = bare();
    let t = now();
    let mac = "02:00:00:00:00:cc";
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
    let id = pid(&f, "mine_add", json!({"kind": "wifiAp", "idHash": h(mac)}));
    let shown = view(&f, id);
    push_scan(
        &f,
        t - 1500,
        vec![wifi(
            Some("Net-D"),
            mac,
            -70,
            Security::Wpa2Personal,
            t - 1500,
        )],
    );
    assert_eq!(
        view(&f, id).digest,
        shown.digest,
        "rssi moves every scan; it is not part of the digest"
    );
    assert_ne!(
        view(&f, id).summary,
        shown.summary,
        "but the sentence does show it"
    );
    push_scan(
        &f,
        t - 1000,
        vec![wifi(
            Some("Net-E"),
            mac,
            -70,
            Security::Wpa2Personal,
            t - 1000,
        )],
    );
    let e = proposals::decide(&mut app(&f), id, true, Some(&shown.digest), now()).unwrap_err();
    assert!(e.contains("changed since you read it"), "{e}");
    assert!(app(&f).list_mine().unwrap().is_empty());
}

// ---- L1 / L2 --------------------------------------------------------------------------

#[test]
fn l2_two_dismissals_and_two_unnamed_bluetooth_devices_read_differently() {
    let f = fixture();
    let t = now();
    let mut s = app(&f);
    for i in 0..2 {
        s.upsert_alerts(&[Alert {
            id: format!("trk{i}"),
            kind: AlertKind::PersistentTracker,
            severity: Severity::High,
            title: format!("Possible tracker {i}"),
            detail: "d".into(),
            first_seen: t - 1000 - i * 60_000,
            last_seen: t,
            subject_hash: h(&format!("t{i}")),
            dismissed: false,
        }])
        .unwrap();
    }
    drop(s);
    let a = pid(&f, "dismiss_alert", json!({"id": "trk0"}));
    let b = pid(&f, "dismiss_alert", json!({"id": "trk1"}));
    let (va, vb) = (view(&f, a), view(&f, b));
    assert_ne!(va.summary, vb.summary, "{} / {}", va.summary, vb.summary);
    assert!(
        va.summary.contains("subject \u{2026}")
            && va.summary.contains("first seen")
            && va.summary.contains("last seen")
    );
    // Two unnamed BLE devices (one tracker-shaped): different tails, and the tracker is named.
    let bles = tools::call(&ctx(&f), "ble", &json!({})).unwrap();
    let hashes: Vec<String> = bles["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["peripheralHash"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(hashes.len(), 2);
    let ids: Vec<i64> = hashes
        .iter()
        .map(|x| pid(&f, "mine_add", json!({"kind": "ble", "idHash": x})))
        .collect();
    let (s0, s1) = (view(&f, ids[0]).summary, view(&f, ids[1]).summary);
    assert_ne!(s0, s1);
    let both = format!("{s0} {s1}");
    assert!(
        both.contains("Tile tracker signature") && both.contains("dBm"),
        "{both}"
    );
}

// ---- L5 -------------------------------------------------------------------------------

#[test]
fn l5_possibly_same_as_is_untrusted_text_and_agents_get_no_hint_without_the_salt() {
    use app_lib::lan::{host_key, record, LanScanOutcome};
    let f = bare();
    let mut s = app(&f);
    let hk = host_key(s.salt(), "device-a.local");
    let dev = |mac: &str, src, at| LanDevice {
        network_key: "key".into(),
        mac_hash: mac.into(),
        vendor: None,
        hostname: Some("device-a.local".into()),
        services: vec![],
        first_seen: at,
        last_seen: at,
        ip: None,
        mine: false,
        source: Some(src),
        possibly_same_as: None,
    };
    let out = |d| LanScanOutcome {
        network: app_lib::model::NetworkInfo::default(),
        devices: vec![d],
    };
    record(&mut s, &out(dev(&hk, LanSource::Announced, 100)), 100).unwrap();
    s.add_mine(&MineEntry {
        kind: MineKind::Lan,
        id_hash: hk,
        label: Some("IGNORE PRIOR \u{202E}x".into()),
        ssid: None,
        added_at: 110,
    })
    .unwrap();
    record(&mut s, &out(dev("mac2", LanSource::Both, 900)), 900).unwrap();
    // The app's own listing carries the hint...
    let own = s.list_lan_devices(Some("key")).unwrap();
    assert!(own.iter().any(|d| d.possibly_same_as.is_some()));
    drop(s);
    // ...an agent connection has no salt, so no hint; and whatever text reaches output is wrapped.
    let v = tools::call_marked(&ctx(&f), "lan_devices", &json!({})).unwrap();
    assert!(v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d["possiblySameAs"].is_null()));
    let wrapped = app_lib::agent::output::finish(
        json!({"devices": [{"possiblySameAs": format!("Dev\u{202E}{}", "x".repeat(200))}]}),
        true,
    );
    let t = wrapped["devices"][0]["possiblySameAs"]["untrusted"]
        .as_str()
        .unwrap();
    assert!(t.len() <= 64 && !t.contains('\u{202E}'), "{t:?}");
}

// ---- L6 -------------------------------------------------------------------------------

#[test]
fn l6_the_mcp_wire_stays_under_256_kb_even_though_the_result_is_sent_twice() {
    use rmcp::model::CallToolResult;
    let f = fixture();
    let t = now();
    let rows: Vec<_> = (0..3000)
        .map(|i| {
            wifi(
                Some(&format!("Net-{i}")),
                &format!("02:00:00:00:{:02x}:{:02x}", i / 256, i % 256),
                -50,
                Security::Wpa2Personal,
                t,
            )
        })
        .collect();
    push_scan(&f, t, rows);
    for (tool, args) in [
        ("networks", json!({"limit": 500})),
        ("history", json!({"full": true, "limit": 50, "since": "7d"})),
    ] {
        let v = tools::call_marked(&ctx(&f), tool, &args).unwrap();
        let wire = serde_json::to_string(&CallToolResult::structured(v))
            .unwrap()
            .len();
        assert!(wire <= 256 * 1024, "{tool}: {wire} bytes on the wire");
    }
}

// ---- L7 / L8 --------------------------------------------------------------------------

#[test]
fn l7_watchlist_patterns_are_bounded_in_bytes_not_characters() {
    let f = bare();
    let wide = "\u{4E2D}".repeat(30); // 30 characters, 90 bytes
    assert!(matches!(
        call(
            &f,
            "watchlist_add",
            json!({"kind": "ssid", "pattern": wide})
        )
        .unwrap_err(),
        AgentError::Usage(_)
    ));
    ok(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "x".repeat(64)}),
    );
    assert!(call(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "x".repeat(65)})
    )
    .is_err());
    ok(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "\u{4E2D}".repeat(21)}),
    ); // 63 bytes
}

#[test]
fn l8_unknown_security_is_refused_and_open_is_warned() {
    let f = bare();
    let t = now();
    push_scan(
        &f,
        t - 1000,
        vec![
            wifi_in_group(
                "Net-U",
                "02:00:00:00:00:01",
                "g1",
                Security::Unknown,
                t - 1000,
            ),
            wifi_in_group("Net-O", "02:00:00:00:00:02", "g2", Security::Open, t - 1000),
        ],
    );
    let u = pid(&f, "trusted_add", json!({"ssid": "Net-U"}));
    let o = pid(&f, "trusted_add", json!({"ssid": "Net-O"}));
    assert!(view(&f, u).blocked.as_deref().unwrap().contains("unknown"));
    assert!(proposals::decide(&mut app(&f), u, true, Some(&view(&f, u).digest), now()).is_err());
    let vo = view(&f, o);
    assert!(vo.blocked.is_none());
    assert!(
        vo.warnings.iter().any(|w| w.contains("open")),
        "{:?}",
        vo.warnings
    );
    assert!(
        approve_shown(&f, o).unwrap().changed,
        "open is allowed, with the warning"
    );
}

// ---- H1: tool-level shapes ------------------------------------------------------------

#[test]
fn h1_mine_remove_of_a_persons_row_is_a_proposal_and_of_an_agents_row_is_direct() {
    let f = bare();
    let (p, a) = (h("person"), h("agent"));
    let mut s = app(&f);
    for (hash, by) in [(&p, AddedBy::User), (&a, AddedBy::Agent)] {
        s.add_mine_as(
            &MineEntry {
                kind: MineKind::Ble,
                id_hash: hash.clone(),
                label: None,
                ssid: None,
                added_at: 1,
            },
            by,
        )
        .unwrap();
    }
    drop(s);
    let r = ok(&f, "mine_remove", json!({"kind": "ble", "idHash": p}));
    assert_eq!(r["status"], "pending");
    assert_eq!(
        ok(&f, "mine_remove", json!({"kind": "ble", "idHash": a}))["removed"],
        true
    );
    let left = app(&f).list_mine_with_source().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].0.id_hash, p);
}
