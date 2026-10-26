//! Structural guarantees for the agent tools (`wbm` CLI and MCP server), checked against their
//! own source, in the same style as `lan_listen_only.rs` (which also covers `src/bin/wbm.rs`
//! through its crate-wide "no process" and "no TCP" scans): no socket, no process, no route to
//! a scanner, the sweep, or the settings writer. Text checks, so each has a negative control.

use std::fs;
use std::path::PathBuf;

/// Anything that opens or names a socket. `wbm` talks to SQLite and its own stdio, nothing else.
const SOCKET_TOKENS: &[&str] = &[
    "UdpSocket",
    "TcpStream",
    "TcpListener",
    "UnixStream",
    "UnixListener",
    "UnixDatagram",
    "std::net",
    "tokio::net",
    "socket2",
    "SocketAddr",
    "::bind(",
    ".accept(",
    "libc::socket",
    "libc::sendto",
    "send_to",
    ".send(",
    "sendmsg",
    ".connect(",
    "connect(",
];

/// Starting a process by any route.
const SPAWN_TOKENS: &[&str] = &[
    "Command",
    "process::Child",
    "tokio::process",
    "posix_spawn",
    "libc::system",
    "libc::popen",
    "libc::fork",
    "libc::vfork",
    "libc::exec",
    "NSTask",
    "launchctl",
];

/// Reaching a scanner, the sweep, the helper registration, or the app's settings writer.
const FORBIDDEN_CALLS: &[&str] = &[
    "wifi::scan",
    "ble::scan",
    "lan::scan",
    "lan::sweep",
    "run_sweep",
    "sweep_now",
    "NetSink",
    "helper::apply",
    "helper::register",
    "helper::unregister",
    "helper::reconcile",
    "open_login_items",
    "set_settings",
    "request_location_permission",
    "lan_active_sweep",
    "lan_neighbor_helper",
    "commands::",
];

fn production_code(src: &str) -> String {
    src.split("#[cfg(test)]")
        .next()
        .unwrap_or("")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn hits(code: &str, tokens: &[&str]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| code.contains(*t))
        .map(|t| t.to_string())
        .collect()
}

/// The bin, the `agent` module, and the two store files only the agent paths use.
fn agent_files() -> Vec<(String, String)> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![src.join("agent"), src.join("bin")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
            }
        }
    }
    for f in ["store/agent_queries.rs", "store/settings_sync.rs"] {
        let p = src.join(f);
        out.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
    }
    out
}

#[test]
fn agent_tools_open_no_socket_and_spawn_no_process() {
    let files = agent_files();
    // FLOOR: cli, mcp, status, tools, mod, the bin, and the two store files.
    assert!(files.len() >= 8, "found only {} agent files", files.len());
    for must in [
        "bin/wbm.rs",
        "agent/mcp.rs",
        "agent/cli.rs",
        "agent/tools.rs",
        "agent/status.rs",
    ] {
        assert!(
            files.iter().any(|(n, _)| n.ends_with(must)),
            "missing {must}"
        );
    }
    let mut checked = 0;
    for (name, src) in &files {
        let code = production_code(src);
        assert!(
            hits(&code, SOCKET_TOKENS).is_empty(),
            "{name} uses a socket: {:?}",
            hits(&code, SOCKET_TOKENS)
        );
        assert!(
            hits(&code, SPAWN_TOKENS).is_empty(),
            "{name} starts a process: {:?}",
            hits(&code, SPAWN_TOKENS)
        );
        checked += 1;
    }
    assert!(checked >= 8);
}

#[test]
fn agent_tools_cannot_reach_a_scanner_a_sweep_or_the_settings_writer() {
    let files = agent_files();
    assert!(files.len() >= 8);
    let mut checked = 0;
    for (name, src) in &files {
        // The two store files are the store's own settings writer; they are checked below.
        if name.ends_with("settings_sync.rs") || name.ends_with("agent_queries.rs") {
            continue;
        }
        let bad = hits(&production_code(src), FORBIDDEN_CALLS);
        assert!(bad.is_empty(), "{name} reaches {bad:?}");
        checked += 1;
    }
    assert!(checked >= 6, "checked only {checked}");
    // The only settings write an agent can make is the trusted-list editor.
    let q = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store/agent_queries.rs"),
    )
    .unwrap();
    let q = production_code(&q);
    assert!(q.contains("edit_stored_settings(|s| change(&mut s.trusted_networks))"));
    assert_eq!(q.matches("edit_stored_settings(").count(), 1);
    assert!(!q.contains("set_settings"));
    // And nothing in `agent/` reaches the generic settings editor.
    for (name, src) in files.iter().filter(|(n, _)| n.contains("/agent/")) {
        assert!(
            !production_code(src).contains("edit_stored_settings"),
            "{name}"
        );
    }
}

#[test]
fn scanners_can_fail_negative_control() {
    for (list, label) in [
        (SOCKET_TOKENS, "socket"),
        (SPAWN_TOKENS, "spawn"),
        (FORBIDDEN_CALLS, "forbidden"),
    ] {
        for t in list {
            let sample = production_code(&format!("fn f() {{ x {t}; }}"));
            assert!(
                hits(&sample, list).contains(&t.to_string()),
                "{label}: missed {t}"
            );
        }
    }
    let quiet = "// UdpSocket Command set_settings\nfn f() {}\n#[cfg(test)]\nmod t { use std::process::Command; }";
    let code = production_code(quiet);
    assert!(hits(&code, SOCKET_TOKENS).is_empty());
    assert!(hits(&code, SPAWN_TOKENS).is_empty());
    assert!(hits(&code, FORBIDDEN_CALLS).is_empty());
    // A file that really did call a scanner would be caught by the same path.
    assert!(!hits(
        &production_code("fn f() { crate::wifi::scan(&salt); }"),
        FORBIDDEN_CALLS
    )
    .is_empty());
}

#[test]
fn the_mcp_dependency_has_no_network_or_child_process_features() {
    let toml =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let line = toml
        .lines()
        .find(|l| l.starts_with("rmcp ="))
        .expect("rmcp dependency");
    assert!(line.contains("default-features = false"), "{line}");
    let banned = [
        "transport-io",
        "child-process",
        "streamable-http",
        "reqwest",
        "auth",
        "server-side-http",
        "unix-socket",
    ];
    for b in banned {
        assert!(!line.contains(b), "rmcp feature {b}: {line}");
    }
    // NEGATIVE CONTROL: the same check flags a risky feature set.
    let risky = r#"rmcp = { version = "3", features = ["transport-child-process"] }"#;
    assert!(banned.iter().any(|b| risky.contains(b)));
}
