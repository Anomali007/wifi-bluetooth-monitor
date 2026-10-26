//! The agent tool table and the MCP server, against synthetic temp databases.
//!
//! Boundaries under test: read tools never write; edit tools exist only with edits on; the five
//! edits that could hide an alert are proposals that change nothing until a person approves
//! them in the app (here: `app_lib::proposals::decide`, the function the Tauri command calls);
//! the two direct edits only add alerts and are audited; there is no sweep tool and no settings
//! tool, and calling one fails. Every guard has a negative control.

mod common;

use app_lib::agent::mcp::{serve_rw, tool_definitions};
use app_lib::agent::status::{self, AppStatus};
use app_lib::agent::tools::{self, Access};
use app_lib::agent::{AgentError, Ctx};
use app_lib::lan::helper::HelperStatus;
use app_lib::model::{PermissionState, PermissionStatus, ScanResult, Settings};
use app_lib::proposals;
use app_lib::store::{OpenMode, Store};
use common::{fixture, h};
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const EXPECTED_TOOLS: [&str; 17] = [
    "status",
    "alerts",
    "dismiss_alert",
    "networks",
    "ble",
    "lan_devices",
    "places",
    "history",
    "mine_list",
    "mine_add",
    "mine_remove",
    "trusted_list",
    "trusted_add",
    "trusted_remove",
    "watchlist_list",
    "watchlist_add",
    "watchlist_remove",
];

const READ_TOOLS: [&str; 10] = [
    "status",
    "alerts",
    "networks",
    "ble",
    "lan_devices",
    "places",
    "history",
    "mine_list",
    "trusted_list",
    "watchlist_list",
];

/// Names that would let an agent transmit or change configuration.
const FORBIDDEN_WORDS: [&str; 8] = [
    "sweep",
    "scan",
    "setting",
    "config",
    "interval",
    "toggle",
    "retention",
    "helper",
];

/// The context with edits ON (`wbm --edits`). Read-only contexts are built explicitly.
fn ctx(f: &common::Fixture) -> Ctx {
    let mut c = Ctx::new(f.db.clone()).with_edits(true);
    c.pid_alive = |_| true;
    c
}

fn read_ctx(f: &common::Fixture) -> Ctx {
    ctx(f).with_edits(false)
}

fn call(f: &common::Fixture, name: &str, args: Value) -> Result<Value, AgentError> {
    tools::call(&ctx(f), name, &args)
}

/// The running app's handle on the same file.
fn app(f: &common::Fixture) -> Store {
    Store::open(f.dir.path()).unwrap()
}

/// A person clicks Approve (or Reject) in the app: the Rust function the Tauri command calls.
fn decide(f: &common::Fixture, id: i64, approve: bool) -> Result<proposals::Decision, String> {
    proposals::decide(&mut app(f), id, approve, app_lib::pipeline::now_ms())
}

/// Propose through the tool and return the proposal id, asserting nothing was applied.
fn propose(f: &common::Fixture, name: &str, args: Value) -> i64 {
    let r = ok(f, name, args);
    assert_eq!(r["status"], "pending", "{name}: {r}");
    r["proposalId"].as_i64().unwrap()
}

fn ok(f: &common::Fixture, name: &str, args: Value) -> Value {
    call(f, name, args).unwrap_or_else(|e| panic!("{name} failed: {e}"))
}

/// A names list passes if it has no forbidden word. Used on the real list AND on a poisoned one.
fn contaminated(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| FORBIDDEN_WORDS.iter().any(|w| n.contains(w)))
        .cloned()
        .collect()
}

#[test]
fn the_table_is_exactly_the_documented_seventeen() {
    let names: Vec<&str> = tools::specs().iter().map(|s| s.name).collect();
    assert_eq!(names, EXPECTED_TOOLS);
    for s in tools::specs() {
        assert!(
            s.description.len() > 60,
            "{} needs a real description",
            s.name
        );
        let schema = (s.schema)();
        assert_eq!(schema["type"], "object", "{}", s.name);
        assert_eq!(schema["additionalProperties"], false, "{}", s.name);
        assert_eq!(s.read_only(), READ_TOOLS.contains(&s.name), "{}", s.name);
    }
}

#[test]
fn no_tool_can_sweep_scan_or_change_a_setting() {
    let f = fixture();
    let names: Vec<String> = tool_definitions(&ctx(&f))
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(names.len(), 17, "FLOOR: the list was actually read");
    assert_eq!(contaminated(&names), Vec::<String>::new());
    // NEGATIVE CONTROL: the checker flags each dangerous name when it is present.
    for bad in [
        "sweep_now",
        "scan_now",
        "set_settings",
        "lan_active_sweep",
        "set_retention",
    ] {
        let mut poisoned = names.clone();
        poisoned.push(bad.to_string());
        assert_eq!(contaminated(&poisoned), vec![bad.to_string()], "{bad}");
    }
    // No tool takes a settings-shaped argument either.
    for s in tools::specs() {
        let props = (s.schema)()["properties"].clone();
        for k in props.as_object().unwrap().keys() {
            assert!(
                contaminated(&[k.to_lowercase()]).is_empty(),
                "{} has argument {k}",
                s.name
            );
        }
    }
}

#[test]
fn calling_a_forbidden_tool_fails_and_changes_nothing() {
    let f = fixture();
    let before = dump(&f);
    for bad in [
        "sweep_now",
        "scan_now",
        "set_settings",
        "set_setting",
        "get_settings",
        "lan_active_sweep",
        "update_settings",
        "open_login_items",
    ] {
        let e = call(&f, bad, json!({})).unwrap_err();
        assert!(matches!(e, AgentError::Usage(_)), "{bad}: {e:?}");
    }
    // A real tool given a settings key is refused too.
    let e = call(
        &f,
        "trusted_add",
        json!({"ssid": "Net-A", "lanActiveSweep": true}),
    )
    .unwrap_err();
    assert!(matches!(e, AgentError::Usage(_)), "{e:?}");
    assert_eq!(dump(&f), before);
}

/// Every table that holds user data, as text, for before/after comparison.
fn dump(f: &common::Fixture) -> Vec<String> {
    let c = Connection::open(&f.db).unwrap();
    let mut out = Vec::new();
    for (table, order) in [
        ("alerts", "id"),
        ("mine", "kind, id_hash"),
        ("watchlist", "id"),
        ("settings", "key"),
        ("lan_devices", "mac_hash"),
        ("wifi_sightings", "id"),
        ("ble_sightings", "id"),
        ("scans", "scanned_at"),
        ("places", "id"),
        ("agent_proposals", "id"),
        ("agent_audit", "id"),
    ] {
        let mut q = c
            .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
            .unwrap();
        let n = q.column_count();
        let rows = q
            .query_map([], |r| {
                Ok((0..n)
                    .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap();
        out.push(format!("{table}:"));
        out.extend(rows.map(Result::unwrap));
    }
    out
}

#[test]
fn a_read_connection_is_refused_every_write_by_sqlite_itself() {
    let f = fixture();
    let mut ro = Store::open_db_file(&f.db, OpenMode::Read).unwrap();
    assert!(ro.set_app_status("{}").is_err());
    assert!(ro.dismiss_alert("alert-1").is_err());
    // A change that really changes something (a no-op writes nothing, so it cannot fail).
    assert!(ro
        .update_trusted_networks(|l| l.push(app_lib::model::TrustedNetwork {
            ssid: "Net-Z".into(),
            known_bssid_hashes: vec![],
            expected_security: app_lib::model::Security::Open,
        }))
        .is_err());
    assert!(ro
        .create_proposal("trusted_add", &json!({"ssid": "Net-A"}), 1)
        .is_err());
    // NEGATIVE CONTROL: the same calls succeed on an edit connection.
    let mut rw = Store::open_db_file(&f.db, OpenMode::Edit).unwrap();
    rw.set_app_status("{}").unwrap();
    rw.dismiss_alert("alert-1").unwrap();
}

#[test]
fn read_tools_never_write() {
    let f = fixture();
    let before = dump(&f);
    assert!(before.len() > 10, "FLOOR: the dump saw data");
    let mut ran = 0;
    for name in READ_TOOLS {
        ok(&f, name, json!({}));
        ran += 1;
    }
    ok(&f, "history", json!({"full": true, "since": "1d"}));
    ok(
        &f,
        "alerts",
        json!({"includeDismissed": true, "since": "1d"}),
    );
    ok(&f, "ble", json!({"trackersOnly": true}));
    ran += 3;
    assert!(ran >= 13);
    assert_eq!(dump(&f), before, "a read tool changed the database");
    // NEGATIVE CONTROL: the dump does see a real edit.
    ok(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "Net-Z"}),
    );
    assert_ne!(dump(&f), before);
}

#[test]
fn reads_return_the_documented_shapes() {
    let f = fixture();
    let nets = ok(&f, "networks", json!({}));
    let rows = nets["networks"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["rssi"], -40, "strongest first");
    let mut keys: Vec<&str> = rows[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "bssidHash",
            "channel",
            "groupId",
            "mine",
            "rssi",
            "security",
            "ssid",
            "trusted",
            "vendor"
        ]
    );
    assert_eq!(rows[0]["bssidHash"], h("02:00:00:00:00:01"));
    assert!(
        rows.iter().any(|r| r["ssid"].is_null()),
        "hidden network keeps ssid null"
    );

    let ble = ok(&f, "ble", json!({}));
    assert_eq!(ble["devices"].as_array().unwrap().len(), 2);
    let trackers = ok(&f, "ble", json!({"trackersOnly": true}));
    assert_eq!(trackers["devices"].as_array().unwrap().len(), 1);
    assert_eq!(trackers["devices"][0]["tracker"], "tile");

    let alerts = ok(&f, "alerts", json!({}));
    assert_eq!(alerts["alerts"][0]["id"], "alert-1");
    assert_eq!(alerts["alerts"][0]["kind"], "evilTwin");
    assert_eq!(alerts["total"], 1);

    let lan = ok(&f, "lan_devices", json!({}));
    assert_eq!(lan["devices"][0]["vendor"], "Vendor-A");
    assert!(lan["devices"][0]["ip"].is_null(), "IPs are never stored");

    let hist = ok(&f, "history", json!({"since": "1d"}));
    assert_eq!(hist["scans"].as_array().unwrap().len(), 2);
    assert_eq!(hist["scans"][0]["wifiCount"], 4);
    assert!(
        hist["scans"][0].get("wifi").is_none(),
        "counts only by default"
    );
    let full = ok(
        &f,
        "history",
        json!({"since": "1d", "full": true, "limit": 1}),
    );
    assert_eq!(full["scans"].as_array().unwrap().len(), 1);
    assert_eq!(full["truncated"], true);
    assert_eq!(full["scans"][0]["wifi"].as_array().unwrap().len(), 4);
}

#[test]
fn alerts_since_filters_and_dismiss_is_a_proposal_a_person_approves() {
    let f = fixture();
    assert_eq!(ok(&f, "alerts", json!({"since": "10s"}))["total"], 0);
    assert_eq!(ok(&f, "alerts", json!({"since": "1h"}))["total"], 1);
    let before = dump(&f);
    let id = propose(&f, "dismiss_alert", json!({"id": "alert-1"}));
    assert_eq!(
        ok(&f, "alerts", json!({}))["total"],
        1,
        "still active: only a proposal exists"
    );
    assert_ne!(dump(&f), before, "the proposal row is the only change");
    assert_eq!(
        Store::open_db_file(&f.db, OpenMode::Read)
            .unwrap()
            .get_alerts(false)
            .unwrap()
            .len(),
        1
    );
    let d = decide(&f, id, true).unwrap();
    assert!(d.changed);
    assert_eq!(ok(&f, "alerts", json!({}))["total"], 0);
    assert_eq!(
        ok(&f, "alerts", json!({"includeDismissed": true}))["total"],
        1
    );
    // Proposing it again: the alert is already dismissed.
    assert!(matches!(
        call(&f, "dismiss_alert", json!({"id": "alert-1"})).unwrap_err(),
        AgentError::Usage(_)
    ));
    let e = call(&f, "dismiss_alert", json!({"id": "nope"})).unwrap_err();
    assert!(matches!(e, AgentError::NotFound(_)), "{e:?}");
}

#[test]
fn mine_add_refuses_raw_identifiers_and_unseen_hashes() {
    let f = fixture();
    let before = dump(&f);
    for raw in [
        "02:00:00:00:00:01",
        "Net-A",
        "",
        &"A".repeat(64),
        &"ab".repeat(31),
    ] {
        let e = call(&f, "mine_add", json!({"kind": "wifiAp", "idHash": raw})).unwrap_err();
        assert!(matches!(e, AgentError::Usage(_)), "{raw:?}: {e:?}");
    }
    let unseen = "ab".repeat(32);
    let e = call(&f, "mine_add", json!({"kind": "wifiAp", "idHash": unseen})).unwrap_err();
    assert!(matches!(e, AgentError::NotFound(_)), "{e:?}");
    let e = call(
        &f,
        "mine_add",
        json!({"kind": "wifiAp", "idHash": h("02:00:00:00:00:01"), "label": "bad\nlabel"}),
    )
    .unwrap_err();
    assert!(matches!(e, AgentError::Usage(_)));
    assert_eq!(dump(&f), before, "refused calls must not write");
}

#[test]
fn mine_add_is_a_proposal_and_mine_remove_applies_directly_for_every_kind() {
    let f = fixture();
    let nets = ok(&f, "networks", json!({}));
    let ap = nets["networks"][0]["bssidHash"]
        .as_str()
        .unwrap()
        .to_string();
    let group = nets["networks"][0]["groupId"].as_str().unwrap().to_string();
    let ble = ok(&f, "ble", json!({}))["devices"][0]["peripheralHash"]
        .as_str()
        .unwrap()
        .to_string();
    let lan = ok(&f, "lan_devices", json!({}))["devices"][0]["macHash"]
        .as_str()
        .unwrap()
        .to_string();
    let kinds = [
        ("wifiAp", &ap),
        ("wifiGroup", &group),
        ("ble", &ble),
        ("lan", &lan),
    ];
    let mut ids = Vec::new();
    for (kind, hash) in kinds {
        ids.push(propose(
            &f,
            "mine_add",
            json!({"kind": kind, "idHash": hash, "label": "Mine-A"}),
        ));
    }
    assert!(
        ok(&f, "mine_list", json!({}))["mine"]
            .as_array()
            .unwrap()
            .is_empty(),
        "nothing is mine until a person approves"
    );
    assert_eq!(ok(&f, "networks", json!({}))["networks"][0]["mine"], false);
    for id in ids {
        assert!(decide(&f, id, true).unwrap().changed);
    }
    let mine = ok(&f, "mine_list", json!({}));
    assert_eq!(mine["mine"].as_array().unwrap().len(), 4);
    assert!(mine["mine"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["label"] == "Mine-A" && m["addedBy"] == "approved"));
    // The read tools now say so.
    assert_eq!(ok(&f, "networks", json!({}))["networks"][0]["mine"], true);
    assert_eq!(ok(&f, "lan_devices", json!({}))["devices"][0]["mine"], true);
    for (kind, hash) in kinds {
        assert_eq!(
            ok(&f, "mine_remove", json!({"kind": kind, "idHash": hash}))["removed"],
            true
        );
        assert_eq!(
            ok(&f, "mine_remove", json!({"kind": kind, "idHash": hash}))["removed"],
            false
        );
    }
    assert!(ok(&f, "mine_list", json!({}))["mine"]
        .as_array()
        .unwrap()
        .is_empty());
    // Four approved additions and four direct removals, all attributed to the agent.
    let audit = app(&f).list_audit(50).unwrap();
    assert_eq!(audit.len(), 8);
    assert!(audit.iter().all(|a| a.added_by == "agent"));
    assert_eq!(audit.iter().filter(|a| a.via == "proposal").count(), 4);
    assert_eq!(audit.iter().filter(|a| a.via == "direct").count(), 4);
}

#[test]
fn edits_change_nothing_but_their_own_table() {
    let f = fixture();
    // Give the app some non-default settings first, as a user would.
    {
        let mut app = Store::open(f.dir.path()).unwrap();
        let mut s = app.get_settings().unwrap();
        s.lan_active_sweep = true;
        s.lan_neighbor_helper = true;
        s.scan_interval_secs = 45;
        s.retention_hours = 48;
        s.notify = false;
        app.set_settings(&s).unwrap();
    }
    let settings_before = Store::open_db_file(&f.db, OpenMode::Edit)
        .unwrap()
        .get_settings()
        .unwrap();

    // Net-B is a single open access point in the fixture, so it can be trusted on approval.
    let t = propose(&f, "trusted_add", json!({"ssid": "Net-B"}));
    ok(
        &f,
        "watchlist_add",
        json!({"kind": "vendor", "pattern": "Vendor-A"}),
    );
    let d = propose(&f, "dismiss_alert", json!({"id": "alert-1"}));
    let ap = ok(&f, "networks", json!({}))["networks"][0]["bssidHash"]
        .as_str()
        .unwrap()
        .to_string();
    let m = propose(&f, "mine_add", json!({"kind": "wifiAp", "idHash": ap}));
    for id in [t, d, m] {
        decide(&f, id, true).unwrap();
    }
    let r = propose(&f, "trusted_remove", json!({"ssid": "Net-B"}));
    decide(&f, r, true).unwrap();

    let after = Store::open_db_file(&f.db, OpenMode::Edit)
        .unwrap()
        .get_settings()
        .unwrap();
    let mut expect: Settings = settings_before.clone();
    expect.revision = after.revision;
    assert_eq!(after, expect, "an edit changed a setting");
    assert!(
        after.revision > settings_before.revision,
        "the trust add and remove did commit"
    );
    assert!(after.lan_active_sweep && after.lan_neighbor_helper);
    assert_eq!(
        (
            after.scan_interval_secs,
            after.retention_hours,
            after.notify
        ),
        (45, 48, false)
    );
    // NEGATIVE CONTROL: the comparison does catch a changed setting.
    let mut tampered = after.clone();
    tampered.lan_active_sweep = false;
    assert_ne!(tampered, expect);
}

#[test]
fn watchlist_add_dedupes_validates_and_removes() {
    let f = fixture();
    let a = ok(
        &f,
        "watchlist_add",
        json!({"kind": "ssid", "pattern": "  Net-Z  ", "match": "exact"}),
    );
    assert_eq!(a["added"], true);
    assert_eq!(a["watch"]["pattern"], "Net-Z");
    assert_eq!(a["watch"]["match"], "exact");
    let id = a["watch"]["id"].as_i64().unwrap();
    assert_eq!(
        ok(
            &f,
            "watchlist_add",
            json!({"kind": "ssid", "pattern": "net-z", "match": "exact"})
        )["added"],
        false
    );
    assert_eq!(
        ok(&f, "watchlist_list", json!({}))["watchlist"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for bad in [
        json!({"kind": "ssid", "pattern": ""}),
        json!({"kind": "ssid", "pattern": "x".repeat(65)}),
        json!({"kind": "mac", "pattern": "x"}),
        json!({"kind": "ssid", "pattern": "a", "match": "regex"}),
    ] {
        assert!(matches!(
            call(&f, "watchlist_add", bad).unwrap_err(),
            AgentError::Usage(_)
        ));
    }
    // Removing a rule is a proposal.
    let p = propose(&f, "watchlist_remove", json!({"id": id}));
    assert_eq!(
        ok(&f, "watchlist_list", json!({}))["watchlist"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    decide(&f, p, true).unwrap();
    assert!(ok(&f, "watchlist_list", json!({}))["watchlist"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(matches!(
        call(&f, "watchlist_remove", json!({"id": id})).unwrap_err(),
        AgentError::NotFound(_)
    ));
}

#[test]
fn argument_validation() {
    let f = fixture();
    for (tool, args) in [
        ("alerts", json!({"since": "yesterday"})),
        ("alerts", json!({"limit": 0})),
        ("alerts", json!({"limit": 5000})),
        ("alerts", json!({"includeDismissed": "yes"})),
        ("status", json!({"verbose": true})),
        ("status", json!("x")),
        ("dismiss_alert", json!({})),
        ("history", json!({"since": "-1h"})),
    ] {
        assert!(
            matches!(
                call(&f, tool, args.clone()).unwrap_err(),
                AgentError::Usage(_)
            ),
            "{tool} {args}"
        );
    }
}

#[test]
fn status_reports_the_app_snapshot_with_its_age() {
    let f = fixture();
    // No snapshot yet.
    let s = ok(&f, "status", json!({}));
    assert_eq!(s["freshness"], "noSnapshot");
    assert!(s["appRunning"].is_null());
    assert_eq!(s["counts"]["alertsActive"], 1);
    assert_eq!(s["counts"]["lanDevices"], 1);

    // The app publishes after a scan.
    let scan = ScanResult {
        scanned_at: f.now - 5_000,
        wifi: vec![],
        ble: vec![],
        errors: vec![],
        permissions: PermissionState {
            bluetooth: PermissionStatus::Denied,
            location: PermissionStatus::Granted,
        },
    };
    let net = app_lib::model::NetworkInfo {
        ssid: Some("Net-A".into()),
        bssid_hash: Some(h("02:00:00:00:00:01")),
        group_id: Some(h("group-1")),
        is_mine: true,
        ..Default::default()
    };
    let snap: AppStatus = status::build(
        &scan,
        Some(&net),
        HelperStatus::NeedsApproval,
        60,
        2,
        std::process::id(),
        "0.1.0",
        f.now - 5_000,
    );
    let mut store = Store::open_db_file(&f.db, OpenMode::Edit).unwrap();
    status::publish(&mut store, &snap).unwrap();

    let mut c = ctx(&f);
    c.now = || app_lib::pipeline::now_ms();
    let live = tools::call(&c, "status", &json!({})).unwrap();
    assert_eq!(live["freshness"], "live");
    assert_eq!(live["appRunning"], true);
    assert!(live["snapshotAgeSecs"].as_i64().unwrap() < 30);
    assert_eq!(live["snapshot"]["permissions"]["bluetooth"], "denied");
    assert_eq!(live["snapshot"]["helper"], "needsApproval");
    assert_eq!(live["snapshot"]["network"]["ssid"], "Net-A");
    assert_eq!(live["snapshot"]["network"]["isMine"], true);
    assert_eq!(live["snapshot"]["scan"]["newAlerts"], 2);

    // The app quits: the same snapshot says so plainly.
    c.pid_alive = |_| false;
    let gone = tools::call(&c, "status", &json!({})).unwrap();
    assert_eq!(gone["freshness"], "appNotRunning");
    assert_eq!(gone["appRunning"], false);
    assert!(gone["message"].as_str().unwrap().contains("not running"));

    // Running but silent for an hour: stale.
    c.pid_alive = |_| true;
    c.now = || app_lib::pipeline::now_ms() + 3_600_000;
    let stale = tools::call(&c, "status", &json!({})).unwrap();
    assert_eq!(stale["freshness"], "stale");
    assert!(stale["message"].as_str().unwrap().contains("last scan"));
}

#[test]
fn the_apps_scan_pipeline_publishes_the_snapshot_wbm_status_reads() {
    use app_lib::model::{NetworkInfo, Security};
    use app_lib::pipeline::{ingest_and_publish, now_ms};
    let f = fixture();
    let mut app = Store::open(f.dir.path()).unwrap();
    let at = now_ms();
    let scan = ScanResult {
        scanned_at: at,
        wifi: vec![common::wifi(
            Some("Net-A"),
            "02:00:00:00:00:01",
            -45,
            Security::Wpa2Personal,
            at,
        )],
        ble: vec![common::ble(Some("Device-A"), "synthetic-ble-1", None, at)],
        errors: vec![],
        permissions: PermissionState {
            bluetooth: PermissionStatus::Granted,
            location: PermissionStatus::Restricted,
        },
    };
    let joined = NetworkInfo {
        ssid: Some("Net-A".into()),
        bssid_hash: Some(h("02:00:00:00:00:01")),
        ..NetworkInfo::default()
    };
    let outcome = app_lib::lan::LanScanOutcome {
        network: joined,
        devices: vec![],
    };
    ingest_and_publish(
        &mut app,
        &scan,
        Some(&outcome),
        HelperStatus::Enabled,
        std::process::id(),
        at,
    )
    .unwrap();

    let s = ok(&f, "status", json!({}));
    assert_eq!(s["freshness"], "live");
    assert_eq!(s["snapshot"]["permissions"]["location"], "restricted");
    assert_eq!(s["snapshot"]["helper"], "enabled");
    assert_eq!(s["snapshot"]["network"]["ssid"], "Net-A");
    assert_eq!(s["snapshot"]["scan"]["wifi"], 1);
    assert_eq!(s["snapshot"]["scan"]["ble"], 1);
    assert_eq!(s["snapshot"]["pid"], std::process::id());
    assert_eq!(s["snapshot"]["lastScanAt"], at);
}

#[test]
fn access_classes_match_the_edit_allowlist() {
    let edits: Vec<&str> = tools::specs()
        .iter()
        .filter(|s| !s.read_only())
        .map(|s| s.name)
        .collect();
    assert_eq!(
        edits,
        [
            "dismiss_alert",
            "mine_add",
            "mine_remove",
            "trusted_add",
            "trusted_remove",
            "watchlist_add",
            "watchlist_remove"
        ]
    );
    for s in tools::specs() {
        match s.name {
            // The edits that could hide an alert are proposals.
            "dismiss_alert" | "mine_add" | "trusted_add" | "trusted_remove"
            | "watchlist_remove" => assert_eq!(s.access, Access::Propose, "{}", s.name),
            // The edits that can only add alerts apply directly.
            "watchlist_add" => assert_eq!(s.access, Access::Add),
            "mine_remove" => assert_eq!(s.access, Access::Remove),
            _ => assert_eq!(s.access, Access::Read),
        }
    }
    // NEGATIVE CONTROL: dropping the classes to their old meaning would be caught.
    assert_ne!(Access::Propose.mode(), Access::Add.mode());
}

#[test]
fn without_edits_the_edit_tools_are_neither_listed_nor_callable() {
    let f = fixture();
    let c = read_ctx(&f);
    let names: Vec<&str> = tools::available(&c).map(|s| s.name).collect();
    assert_eq!(names, READ_TOOLS);
    let with: Vec<&str> = tools::available(&ctx(&f)).map(|s| s.name).collect();
    assert_eq!(
        with, EXPECTED_TOOLS,
        "NEGATIVE CONTROL: edits on lists all seventeen"
    );
    let before = dump(&f);
    for spec in tools::specs().iter().filter(|s| !s.read_only()) {
        let e = tools::call(&c, spec.name, &json!({})).unwrap_err();
        assert!(matches!(e, AgentError::Usage(_)), "{}: {e:?}", spec.name);
        assert!(e.message().contains("--edits"), "{}", e.message());
        // Even with valid arguments.
        let e = tools::call_marked(
            &c,
            spec.name,
            &json!({"kind": "ssid", "pattern": "x", "ssid": "Net-A", "id": "alert-1", "idHash": h("02:00:00:00:00:01")}),
        );
        assert!(e.is_err(), "{}", spec.name);
    }
    assert_eq!(dump(&f), before);
}

// ---------------------------------------------------------------------------
// MCP over an in-memory pipe, speaking raw JSON-RPC lines
// ---------------------------------------------------------------------------

struct Client {
    w: tokio::io::DuplexStream,
    r: BufReader<tokio::io::DuplexStream>,
    next: i64,
}

impl Client {
    async fn send(&mut self, v: Value) {
        self.w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
        self.w.flush().await.unwrap();
    }
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.r.read_line(&mut line),
            )
            .await
            .expect("server answered in time")
            .unwrap();
            assert!(n > 0, "server closed the stream");
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }
}

async fn start(f: &common::Fixture) -> Client {
    start_with(f, ctx(f)).await
}

async fn start_with(_f: &common::Fixture, c: Ctx) -> Client {
    let (cw, sr) = tokio::io::duplex(1 << 20);
    let (sw, cr) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve_rw(c, sr, sw));
    let mut c = Client {
        w: cw,
        r: BufReader::new(cr),
        next: 0,
    };
    let init = c
        .request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
        )
        .await;
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "wbm");
    c.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    c
}

#[tokio::test]
async fn mcp_lists_ten_read_tools_by_default_and_all_seventeen_with_edits() {
    let f = fixture();
    // Default server: reads only.
    let mut r = start_with(&f, read_ctx(&f)).await;
    let list = r.request("tools/list", json!({})).await;
    let names: Vec<String> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, READ_TOOLS);
    // An edit tool is a protocol error on the read-only server, and changes nothing.
    let before = dump(&f);
    for edit in [
        "watchlist_add",
        "trusted_add",
        "dismiss_alert",
        "mine_remove",
    ] {
        let resp = r
            .request("tools/call", json!({"name": edit, "arguments": {"kind": "ssid", "pattern": "Net-Z", "ssid": "Net-B", "id": "alert-1"}}))
            .await;
        assert!(resp.get("error").is_some(), "{edit}: {resp}");
    }
    assert_eq!(dump(&f), before);
    let info = r.request("tools/list", json!({})).await;
    assert!(info.get("result").is_some());

    let mut c = start(&f).await;
    let list = c.request("tools/list", json!({})).await;
    let tools_v = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools_v.len(), 17);
    let names: Vec<String> = tools_v
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, EXPECTED_TOOLS);
    assert!(contaminated(&names).is_empty());
    for t in tools_v {
        let name = t["name"].as_str().unwrap();
        assert!(t["description"].as_str().unwrap().len() > 60, "{name}");
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
        let ro = t["annotations"]["readOnlyHint"].as_bool();
        assert_eq!(ro, Some(READ_TOOLS.contains(&name)), "{name} readOnlyHint");
        assert_eq!(t["annotations"]["openWorldHint"], false, "{name}");
    }
    let by = |n: &str| tools_v.iter().find(|t| t["name"] == n).unwrap().clone();
    // Every proposal tool is flagged destructive; the direct add is not; the direct
    // removal is.
    for n in [
        "trusted_add",
        "trusted_remove",
        "mine_add",
        "dismiss_alert",
        "watchlist_remove",
    ] {
        assert_eq!(by(n)["annotations"]["destructiveHint"], true, "{n}");
        assert_eq!(by(n)["annotations"]["readOnlyHint"], false, "{n}");
    }
    assert_eq!(by("watchlist_add")["annotations"]["destructiveHint"], false);
    assert_eq!(by("watchlist_add")["annotations"]["readOnlyHint"], false);
    assert_eq!(by("mine_remove")["annotations"]["readOnlyHint"], false);
}

#[tokio::test]
async fn mcp_status_call_returns_structured_content() {
    let f = fixture();
    let mut c = start(&f).await;
    let r = c
        .request("tools/call", json!({"name": "status", "arguments": {}}))
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert_eq!(
        r["result"]["structuredContent"]["counts"]["alertsActive"],
        1
    );
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap()["freshness"],
        "noSnapshot"
    );
}

#[tokio::test]
async fn mcp_rejects_sweep_and_settings_tools_and_changes_nothing() {
    let f = fixture();
    let before = dump(&f);
    let mut c = start(&f).await;
    for bad in [
        "sweep_now",
        "scan_now",
        "set_settings",
        "get_settings",
        "lan_active_sweep",
        "set_lan_active_sweep",
        "open_login_items",
    ] {
        let r = c
            .request(
                "tools/call",
                json!({"name": bad, "arguments": {"lanActiveSweep": true}}),
            )
            .await;
        assert!(
            r.get("error").is_some(),
            "{bad} must be a JSON-RPC error: {r}"
        );
        assert!(r.get("result").is_none(), "{bad} returned a result");
    }
    // A real edit tool given a settings argument is a tool-level usage error.
    let r = c
        .request(
            "tools/call",
            json!({"name": "trusted_add", "arguments": {"ssid": "Net-A", "lanActiveSweep": true}}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert_eq!(r["result"]["structuredContent"]["error"]["code"], "usage");
    assert_eq!(dump(&f), before);
    // NEGATIVE CONTROL: the harness does see an allowed edit.
    let r = c
        .request(
            "tools/call",
            json!({"name": "watchlist_add", "arguments": {"kind": "ssid", "pattern": "Net-Z"}}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert_ne!(dump(&f), before);
}

#[tokio::test]
async fn mcp_tool_errors_are_flagged_not_thrown() {
    let f = fixture();
    let mut c = start(&f).await;
    let r = c
        .request(
            "tools/call",
            json!({"name": "dismiss_alert", "arguments": {"id": "missing"}}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "notFound"
    );
    // A missing database is also a tool error, and the server stays up.
    let (cw, sr) = tokio::io::duplex(1 << 16);
    let (sw, cr) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve_rw(
        Ctx::new(f.dir.path().join("absent.sqlite3")),
        sr,
        sw,
    ));
    let mut c2 = Client {
        w: cw,
        r: BufReader::new(cr),
        next: 0,
    };
    c2.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})).await;
    c2.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    let r = c2
        .request("tools/call", json!({"name": "status", "arguments": {}}))
        .await;
    assert_eq!(
        r["result"]["structuredContent"]["error"]["code"],
        "noDatabase"
    );
    assert!(
        !f.dir.path().join("absent.sqlite3").exists(),
        "a read must not create the file"
    );
}
