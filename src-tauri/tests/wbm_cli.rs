//! The real `wbm` binary, run as a child process against synthetic temp databases: exit codes,
//! `--json` shapes, human output, and an end-to-end MCP session over its stdio.

mod common;

use common::{fixture, h};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

fn wbm(db: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wbm"))
        .arg("--db")
        .arg(db)
        .args(args)
        .env_remove("HOME") // nothing may fall back to the real store
        .output()
        .expect("run wbm")
}

fn json_of(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&o.stdout)))
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

#[test]
fn exit_codes() {
    let f = fixture();
    // 0 ok
    assert_eq!(wbm(&f.db, &["status"]).status.code(), Some(0));
    // 2 bad usage, in several shapes
    for bad in [
        &["nope"][..],
        &["alerts", "--since"],
        &["alerts", "--bogus"],
        &["mine", "add", "ble"],
        &[],
    ] {
        assert_eq!(wbm(&f.db, bad).status.code(), Some(2), "{bad:?}");
    }
    // 3 no database, and it must not be created
    let missing = f.dir.path().join("nope/store.sqlite3");
    let o = wbm(&missing, &["status", "--json"]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(json_of(&o)["error"]["code"], "noDatabase");
    assert!(!missing.exists() && !missing.parent().unwrap().exists());
    // 4 a file that is not a store
    let junk = f.dir.path().join("junk.sqlite3");
    std::fs::write(&junk, b"this is not sqlite at all, just text padding.....").unwrap();
    assert_eq!(wbm(&junk, &["status"]).status.code(), Some(4));
    // 5 not found (edits on, so the call reaches the lookup)
    assert_eq!(
        wbm(&f.db, &["--edits", "alert", "dismiss", "nope"])
            .status
            .code(),
        Some(5)
    );
    // An edit command without --edits is bad usage and says how to allow it.
    let o = wbm(&f.db, &["alert", "dismiss", "alert-1"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--edits"));
    // Human errors go to stderr, nothing on stdout.
    let o = wbm(&missing, &["status"]);
    assert!(o.stdout.is_empty() && !o.stderr.is_empty());
}

#[test]
fn json_output_is_stable_and_parseable_for_every_read_command() {
    let f = fixture();
    let cases: [(&[&str], &str); 10] = [
        (&["status"], "freshness"),
        (&["alerts"], "alerts"),
        (&["networks"], "networks"),
        (&["ble"], "devices"),
        (&["devices"], "devices"),
        (&["places"], "places"),
        (&["history", "--since", "1d"], "scans"),
        (&["mine", "list"], "mine"),
        (&["trusted", "list"], "trusted"),
        (&["watchlist", "list"], "watchlist"),
    ];
    let mut ran = 0;
    for (args, key) in cases {
        let mut a = args.to_vec();
        a.push("--json");
        let o = wbm(&f.db, &a);
        assert_eq!(o.status.code(), Some(0), "{args:?}");
        assert!(json_of(&o).get(key).is_some(), "{args:?} lacks {key}");
        ran += 1;
    }
    assert_eq!(ran, 10);
    // --json may come first or last.
    let o = Command::new(env!("CARGO_BIN_EXE_wbm"))
        .args(["--json", "--db"])
        .arg(&f.db)
        .arg("alerts")
        .output()
        .unwrap();
    assert_eq!(json_of(&o)["total"], 1);
}

#[test]
fn json_marks_broadcast_text_as_untrusted_and_the_table_prints_it_plain() {
    let f = fixture();
    let j = json_of(&wbm(&f.db, &["networks", "--json"]));
    assert_eq!(j["networks"][0]["ssid"], json!({"untrusted": "Net-A"}));
    assert!(j["networks"][0]["rssi"].is_number() && j["networks"][0]["bssidHash"].is_string());
    let a = json_of(&wbm(&f.db, &["alerts", "--json"]));
    assert!(a["alerts"][0]["title"]["untrusted"].is_string());
    assert_eq!(a["alerts"][0]["kind"], "evilTwin");
    // Human tables are not wrapped.
    let t = text(&wbm(&f.db, &["networks"]));
    assert!(t.contains("Net-A") && !t.contains("untrusted"), "{t}");
}

#[test]
fn human_output_is_a_short_table() {
    let f = fixture();
    let o = wbm(&f.db, &["networks"]);
    let t = text(&o);
    assert!(
        t.contains("ssid") && t.contains("Net-A") && t.contains("Net-B"),
        "{t}"
    );
    assert!(t.lines().count() < 12, "short");
    // Hashes are shortened to 12 characters in tables, full in JSON.
    assert!(t.contains(&h("02:00:00:00:00:01")[..12]));
    assert!(!t.contains(&h("02:00:00:00:00:01")));
    let st = text(&wbm(&f.db, &["status"]));
    assert!(
        st.contains("App: noSnapshot") && st.contains("Stored: 1 alerts"),
        "{st}"
    );
    assert!(text(&wbm(&f.db, &["alerts"])).contains("evilTwin"));
}

/// Run with --edits.
fn wbme(db: &std::path::Path, args: &[&str]) -> Output {
    let mut a = vec!["--edits"];
    a.extend_from_slice(args);
    wbm(db, &a)
}

#[test]
fn edits_through_the_cli_need_edits_and_proposals_wait_for_the_app() {
    let f = fixture();
    // Every edit subcommand is refused without --edits and writes nothing.
    let ap = h("02:00:00:00:00:03");
    let refused: [&[&str]; 7] = [
        &["trusted", "add", "Net-B"],
        &["trusted", "remove", "Net-B"],
        &["mine", "add", "wifiAp", &ap],
        &["mine", "remove", "wifiAp", &ap],
        &["alert", "dismiss", "alert-1"],
        &["watchlist", "add", "ssid", "Net-Z"],
        &["watchlist", "remove", "1"],
    ];
    for args in refused {
        let o = wbm(&f.db, args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty());
    }
    assert!(
        json_of(&wbm(&f.db, &["trusted", "list", "--json"]))["trusted"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // With --edits, a trust request is a pending proposal.
    let o = wbme(&f.db, &["trusted", "add", "Net-B"]);
    assert_eq!(o.status.code(), Some(0));
    let t = text(&o);
    assert!(
        t.contains("Nothing has changed") && t.contains("Agent requests"),
        "{t}"
    );
    let j = json_of(&wbme(&f.db, &["trusted", "add", "Net-B", "--json"]));
    assert_eq!(j["status"], "pending");
    assert!(j["proposalId"].as_i64().unwrap() > 0);
    assert!(
        json_of(&wbm(&f.db, &["trusted", "list", "--json"]))["trusted"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // --security is gone.
    assert_eq!(
        wbme(&f.db, &["trusted", "add", "Net-B", "--security", "open"])
            .status
            .code(),
        Some(2)
    );

    // The direct edits apply at once.
    assert_eq!(
        wbme(
            &f.db,
            &["watchlist", "add", "vendor", "Vendor-A", "--match", "exact"]
        )
        .status
        .code(),
        Some(0)
    );
    let w = json_of(&wbm(&f.db, &["watchlist", "list", "--json"]));
    assert_eq!(w["watchlist"][0]["match"], "exact");
    let id = w["watchlist"][0]["id"].to_string();
    // Removing it is a proposal.
    assert_eq!(
        wbme(&f.db, &["watchlist", "remove", &id]).status.code(),
        Some(0)
    );
    assert_eq!(
        json_of(&wbm(&f.db, &["watchlist", "list", "--json"]))["watchlist"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let o = wbme(&f.db, &["mine", "add", "wifiAp", &ap, "--label", "Shed"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(json_of(&wbm(&f.db, &["mine", "list", "--json"]))["mine"]
        .as_array()
        .unwrap()
        .is_empty());
    // A raw MAC is refused with the usage code.
    assert_eq!(
        wbme(&f.db, &["mine", "add", "wifiAp", "02:00:00:00:00:03"])
            .status
            .code(),
        Some(2)
    );
    // mine remove of something absent is fine; alert dismiss is a proposal.
    assert_eq!(
        wbme(&f.db, &["mine", "remove", "wifiAp", &ap])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        wbme(&f.db, &["alert", "dismiss", "alert-1"]).status.code(),
        Some(0)
    );
    assert_eq!(
        json_of(&wbm(&f.db, &["alerts", "--json"]))["total"],
        1,
        "not dismissed"
    );
    // Four distinct proposals are waiting (trust, watchlist removal, mine add, dismissal).
    let store = app_lib::store::Store::open(f.dir.path()).unwrap();
    assert_eq!(store.get_alerts(false).unwrap().len(), 1);
}

#[test]
fn there_is_no_command_for_sweeping_scanning_or_settings() {
    let f = fixture();
    for bad in [
        &["sweep"][..],
        &["scan"],
        &["settings"],
        &["settings", "set", "lanActiveSweep", "true"],
        &["set", "lanActiveSweep"],
        &["sweep", "now"],
        &["config"],
    ] {
        assert_eq!(wbm(&f.db, bad).status.code(), Some(2), "{bad:?}");
    }
    let help = text(&wbm(&f.db, &["help"]));
    assert!(help.contains("never scans, never sweeps"), "{help}");
    let tools = text(&wbm(&f.db, &["tools"]));
    assert_eq!(tools.lines().count(), 10, "reads only without --edits");
    let all = text(&wbme(&f.db, &["tools"]));
    assert_eq!(all.lines().count(), 17);
    assert!(all.contains("proposal") && all.contains("direct"));
    assert!(!all.contains("sweep_now") && !all.contains("set_settings"));
}

/// One MCP session over the real binary's stdio; returns (tool count, trusted_add result).
fn mcp_session(db: &std::path::Path, edits: bool) -> (usize, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wbm"));
    cmd.arg("--db").arg(db).arg("mcp");
    if edits {
        cmd.arg("--edits");
    }
    let mut child = cmd
        .env_remove("HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut send = |v: Value| {
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    };
    let mut recv = |id: i64| -> Value {
        loop {
            let mut line = String::new();
            assert!(out.read_line(&mut line).unwrap() > 0, "server closed");
            let v: Value = serde_json::from_str(line.trim()).expect("stdout carries only JSON-RPC");
            if v["id"] == json!(id) {
                return v;
            }
        }
    };
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}}}),
    );
    assert_eq!(recv(1)["result"]["serverInfo"]["name"], "wbm");
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}));
    let n = recv(2)["result"]["tools"].as_array().unwrap().len();
    send(
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "status", "arguments": {}}}),
    );
    let r = recv(3);
    assert_eq!(r["result"]["isError"], false);
    assert!(r["result"]["structuredContent"]["counts"].is_object());
    send(
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sweep_now", "arguments": {}}}),
    );
    assert!(recv(4).get("error").is_some());
    send(
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "trusted_add", "arguments": {"ssid": "Net-B"}}}),
    );
    let t = recv(5);
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "clean exit when the client closes stdin: {status:?}"
    );
    (n, t)
}

#[test]
fn mcp_end_to_end_over_the_real_binary_stdio() {
    let f = fixture();
    // Default: the ten read tools; trusted_add is not served.
    let (n, t) = mcp_session(&f.db, false);
    assert_eq!(n, 10);
    assert!(t.get("error").is_some(), "{t}");
    // --edits: all seventeen; trusted_add returns a pending proposal and changes nothing.
    let (n, t) = mcp_session(&f.db, true);
    assert_eq!(n, 17);
    assert_eq!(t["result"]["structuredContent"]["status"], "pending", "{t}");
    assert!(
        json_of(&wbm(&f.db, &["trusted", "list", "--json"]))["trusted"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
