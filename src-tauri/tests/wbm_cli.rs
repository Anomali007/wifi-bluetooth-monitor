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
    // 5 not found
    assert_eq!(
        wbm(&f.db, &["alert", "dismiss", "nope"]).status.code(),
        Some(5)
    );
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

#[test]
fn edits_through_the_cli_land_in_the_database() {
    let f = fixture();
    assert_eq!(
        wbm(&f.db, &["trusted", "add", "Net-A"]).status.code(),
        Some(0)
    );
    let t = json_of(&wbm(&f.db, &["trusted", "list", "--json"]));
    assert_eq!(t["trusted"][0]["ssid"], "Net-A");
    let again = text(&wbm(&f.db, &["trusted", "add", "Net-A"]));
    assert!(again.contains("Already trusted"));

    assert_eq!(
        wbm(
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
    assert_eq!(
        wbm(&f.db, &["watchlist", "remove", &id]).status.code(),
        Some(0)
    );

    let ap = h("02:00:00:00:00:03");
    assert_eq!(
        wbm(&f.db, &["mine", "add", "wifiAp", &ap, "--label", "Shed"])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        json_of(&wbm(&f.db, &["mine", "list", "--json"]))["mine"][0]["label"],
        "Shed"
    );
    // A raw MAC is refused with the usage code.
    assert_eq!(
        wbm(&f.db, &["mine", "add", "wifiAp", "02:00:00:00:00:03"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        wbm(&f.db, &["mine", "remove", "wifiAp", &ap]).status.code(),
        Some(0)
    );

    assert_eq!(
        wbm(&f.db, &["alert", "dismiss", "alert-1"]).status.code(),
        Some(0)
    );
    assert_eq!(json_of(&wbm(&f.db, &["alerts", "--json"]))["total"], 0);
    assert_eq!(
        wbm(&f.db, &["trusted", "remove", "Net-A"]).status.code(),
        Some(0)
    );
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
    assert_eq!(tools.lines().count(), 17);
    assert!(!tools.contains("sweep_now") && !tools.contains("set_settings"));
}

#[test]
fn mcp_end_to_end_over_the_real_binary_stdio() {
    let f = fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_wbm"))
        .arg("--db")
        .arg(&f.db)
        .arg("mcp")
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
    assert_eq!(n, 17);
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
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "clean exit when the client closes stdin: {status:?}"
    );
}
