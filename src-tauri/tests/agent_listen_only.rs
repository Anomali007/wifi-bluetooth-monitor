//! Structural guarantees for the agent tools (`wbm` CLI and MCP server), checked against their
//! own source, in the same style as `lan_listen_only.rs` (which also covers `src/bin/wbm.rs`
//! through its crate-wide "no process" and "no TCP" scans): no socket, no process, no signal,
//! no file write, no route to a scanner, the sweep, the settings writer or the proposal
//! decision, and a closed list of the `Store` methods `agent/` may call. These are text checks,
//! so each one has a negative control that proves it can fail.

use std::collections::BTreeSet;
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

/// Signalling a process by any route other than the one allowed `kill(pid, 0)` existence check
/// (see `only_status_may_call_kill_and_only_with_signal_zero`).
const SIGNAL_TOKENS: &[&str] = &[
    "libc::signal",
    "libc::sigaction",
    "libc::raise",
    "libc::killpg",
    "libc::pthread_kill",
    "libc::abort",
    "libc::SIGKILL",
    "libc::SIGTERM",
    "libc::SIGHUP",
    "libc::SIGINT",
    "libc::SIGSTOP",
    "libc::SIGUSR",
    "nix::sys::signal",
    "std::process::abort",
];

/// Writing, creating, moving or deleting a file. The only thing `wbm` writes is the SQLite
/// store, and it does that through `Store`, never through the filesystem API.
const FS_WRITE_TOKENS: &[&str] = &[
    "fs::write",
    "File::create",
    "File::options",
    "OpenOptions",
    "fs::remove_",
    "fs::rename",
    "fs::copy",
    "fs::create_dir",
    "fs::set_permissions",
    "fs::hard_link",
    "fs::symlink",
    "os::unix::fs",
    "libc::open",
    "libc::unlink",
    "libc::rename",
    "libc::write",
    "libc::chmod",
    "libc::mkdir",
];

/// Reaching a scanner, the sweep, the helper registration, the app's settings writer, the
/// database driver directly, or the code that turns a proposal into a change.
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
    "proposals::",
    "decide_proposal",
    "edit_stored_settings",
    "update_trusted_networks",
    "rusqlite",
];

// ---------------------------------------------------------------------------
// Reading source
// ---------------------------------------------------------------------------

/// Replace comments with spaces (keeping string and character literals), so a token in a
/// comment never counts and a token after a comment still does.
fn blank_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match (c, next) {
            ('/', Some('/')) => {
                while i < b.len() && b[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        out.push(if b[i] == '\n' { '\n' } else { ' ' });
                        i += 1;
                    }
                }
            }
            ('\'', _) => {
                // A character literal ('"', '{', '\n') is copied whole; a lifetime is not.
                let len = if b.get(i + 2) == Some(&'\'') {
                    3
                } else if b.get(i + 1) == Some(&'\\') && b.get(i + 3) == Some(&'\'') {
                    4
                } else {
                    1
                };
                out.extend(&b[i..i + len]);
                i += len;
            }
            ('"', _) => {
                // A string literal: copy to its closing quote, honouring escapes.
                out.push(c);
                i += 1;
                while i < b.len() {
                    out.push(b[i]);
                    if b[i] == '\\' && i + 1 < b.len() {
                        out.push(b[i + 1]);
                        i += 2;
                        continue;
                    }
                    i += 1;
                    if b[i - 1] == '"' {
                        break;
                    }
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Skip over literals while looking for the `}` that closes the block opened at `open` (the
/// index of a `{`). Returns the index just past it.
fn end_of_block(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '\'' => {
                // A character literal ('{', '\n') but not a lifetime ('a).
                if chars.get(i + 2) == Some(&'\'') {
                    i += 2;
                } else if chars.get(i + 1) == Some(&'\\') && chars.get(i + 3) == Some(&'\'') {
                    i += 3;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Cut off a `#[cfg(test)] mod ... { ... }` ONLY when it is the last item of the file. A test
/// attribute anywhere else (on a function, on a module followed by more code) hides nothing:
/// everything after it is still scanned.
fn strip_trailing_test_mod(code: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let Some(at) = code.rfind(ATTR) else {
        return code.to_string();
    };
    let after = &code[at + ATTR.len()..];
    let rest = after.trim_start();
    if !(rest.starts_with("mod ") || rest.starts_with("pub mod ")) {
        return code.to_string();
    }
    let chars: Vec<char> = after.chars().collect();
    let Some(open) = chars.iter().position(|c| *c == '{') else {
        return code.to_string();
    };
    // Between `mod` and `{` there must be only the module's name (`mod x;` declares a file).
    let header: String = chars[..open].iter().collect();
    if header.contains(';') {
        return code.to_string();
    }
    match end_of_block(&chars, open) {
        Some(end) if chars[end..].iter().all(|c| c.is_whitespace()) => code[..at].to_string(),
        _ => code.to_string(),
    }
}

fn production_code(src: &str) -> String {
    strip_trailing_test_mod(&blank_comments(src))
}

fn hits(code: &str, tokens: &[&str]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| code.contains(*t))
        .map(|t| t.to_string())
        .collect()
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The bin, the `agent` module, and the store files the agent paths use.
fn agent_files() -> Vec<(String, String)> {
    let src = src_dir();
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
    for f in [
        "store/agent_queries.rs",
        "store/settings_sync.rs",
        "store/proposals.rs",
        "store/views.rs",
    ] {
        let p = src.join(f);
        out.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
    }
    out
}

fn is_store_file(name: &str) -> bool {
    name.contains("/store/")
}

// ---------------------------------------------------------------------------
// The scans
// ---------------------------------------------------------------------------

#[test]
fn agent_tools_open_no_socket_spawn_no_process_send_no_signal_and_write_no_file() {
    let files = agent_files();
    // FLOOR: cli, mcp, status, tools, output, mod, the bin, and the four store files.
    assert!(files.len() >= 11, "found only {} agent files", files.len());
    for must in [
        "bin/wbm.rs",
        "agent/mcp.rs",
        "agent/cli.rs",
        "agent/tools.rs",
        "agent/status.rs",
        "agent/output.rs",
        "store/proposals.rs",
    ] {
        assert!(
            files.iter().any(|(n, _)| n.ends_with(must)),
            "missing {must}"
        );
    }
    let mut checked = 0;
    for (name, src) in &files {
        let code = production_code(src);
        for (list, what) in [
            (SOCKET_TOKENS, "uses a socket"),
            (SPAWN_TOKENS, "starts a process"),
            (SIGNAL_TOKENS, "sends a signal"),
            (FS_WRITE_TOKENS, "writes a file"),
        ] {
            assert!(
                hits(&code, list).is_empty(),
                "{name} {what}: {:?}",
                hits(&code, list)
            );
        }
        checked += 1;
    }
    assert!(checked >= 11);
}

#[test]
fn agent_tools_cannot_reach_a_scanner_a_sweep_the_settings_writer_or_a_proposal_decision() {
    let files = agent_files();
    assert!(files.len() >= 11);
    let mut checked = 0;
    for (name, src) in &files {
        // The store files are the store's own writers; they are checked below.
        if is_store_file(name) {
            continue;
        }
        let bad = hits(&production_code(src), FORBIDDEN_CALLS);
        assert!(bad.is_empty(), "{name} reaches {bad:?}");
        checked += 1;
    }
    assert!(checked >= 7, "checked only {checked}");
    // The settings writer lives in one store function, used by the app's proposal approval.
    let q = production_code(&fs::read_to_string(src_dir().join("store/agent_queries.rs")).unwrap());
    assert!(q.contains("edit_stored_settings(|s| change(&mut s.trusted_networks))"));
    assert_eq!(q.matches("edit_stored_settings(").count(), 1);
    assert!(!q.contains("set_settings"));
    // The proposal store records and lists; it never touches settings itself.
    let p = production_code(&fs::read_to_string(src_dir().join("store/proposals.rs")).unwrap());
    assert!(!p.contains("edit_stored_settings") && !p.contains("update_trusted_networks"));
}

#[test]
fn only_status_may_call_kill_and_only_with_signal_zero() {
    let mut saw_the_existence_check = false;
    for (name, src) in agent_files() {
        let code = production_code(&src);
        let bad = kill_calls_that_send_a_signal(&code);
        if name.ends_with("agent/status.rs") {
            saw_the_existence_check = code.contains("libc::kill(");
        } else {
            assert!(!code.contains("kill("), "{name} calls kill");
        }
        assert!(bad.is_empty(), "{name} sends a real signal: {bad:?}");
    }
    assert!(
        saw_the_existence_check,
        "FLOOR: status.rs's kill(pid, 0) was not found"
    );
}

/// Every `kill(` call whose last argument is not the literal `0`.
fn kill_calls_that_send_a_signal(code: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let mut from = 0;
    while let Some(i) = code[from..].find("kill(") {
        let start = from + i;
        let args_start = start + "kill(".len();
        let mut depth = 1;
        let mut end = code.len();
        for (k, c) in code[args_start..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = args_start + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let args = code[args_start..end].trim();
        let last = args.rsplit(',').next().unwrap_or("").trim();
        if last != "0" {
            bad.push(code[start..end].to_string());
        }
        from = args_start;
    }
    bad
}

// ---------------------------------------------------------------------------
// The closed list of Store methods agent/ may call
// ---------------------------------------------------------------------------

/// Every `Store` method `agent/` and `bin/` may call. Anything else on `Store` (scans, purge,
/// settings writes, proposal decisions, ...) is forbidden by omission.
const ALLOWED_STORE_METHODS: &[&str] = &[
    // opening
    "open_db_file",
    // reads
    "app_status",
    "counts",
    "latest_scan_at",
    "get_alerts",
    "get_alerts_limited",
    "get_history_newest",
    "get_settings",
    "known_hashes",
    "latest_scan",
    "list_lan_devices_limited",
    "list_mine",
    "list_mine_with_source",
    "list_places",
    "list_watchlist",
    "ssid_subject_names",
    // the proposal inbox and the audit log
    "create_proposal",
    "count_direct_edits_since",
    "record_audit",
    // the two direct edits (they can only add alerts)
    "add_watchlist",
    "remove_mine",
];

/// Allowed in `agent/status.rs` only: the app's own status publisher (`status::publish`, which
/// the scan pipeline calls). No tool, command or server file may call it.
const STATUS_ONLY_STORE_METHODS: &[&str] = &["set_app_status"];

fn allowed_for(file: &str) -> Vec<&'static str> {
    let mut a: Vec<&'static str> = ALLOWED_STORE_METHODS.to_vec();
    if file.ends_with("agent/status.rs") {
        a.extend_from_slice(STATUS_ONLY_STORE_METHODS);
    }
    a
}

/// Names of every method defined on `Store` (any visibility): a `fn` indented four spaces in
/// a store file, outside a test module.
fn store_method_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let dir = src_dir().join("store");
    for entry in fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|e| e == "rs") {
            names.extend(methods_in(&production_code(
                &fs::read_to_string(&p).unwrap(),
            )));
        }
    }
    names
}

fn methods_in(code: &str) -> Vec<String> {
    // Only inside `impl Store { ... }`: other impls (AddedBy::as_str, ...) are not the store.
    let mut in_store_impl = false;
    let mut out = Vec::new();
    for l in code.lines() {
        if l.starts_with("impl Store {") {
            in_store_impl = true;
            continue;
        }
        if in_store_impl && l.starts_with('}') {
            in_store_impl = false;
            continue;
        }
        if !in_store_impl {
            continue;
        }
        let Some(rest) = l.strip_prefix("    ") else {
            continue;
        };
        if rest.starts_with(' ') {
            continue;
        }
        let rest = rest
            .strip_prefix("pub(super) ")
            .or_else(|| rest.strip_prefix("pub(crate) "))
            .or_else(|| rest.strip_prefix("pub "))
            .unwrap_or(rest);
        let Some(rest) = rest.strip_prefix("fn ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.push(name);
        }
    }
    out
}

/// Store methods (by name) that `code` calls as `.name(` or `Store::name(` and that are not
/// in `allowed`.
fn disallowed_store_calls(
    code: &str,
    store_methods: &BTreeSet<String>,
    allowed: &[&str],
) -> Vec<String> {
    store_methods
        .iter()
        .filter(|m| !allowed.contains(&m.as_str()))
        .filter(|m| code.contains(&format!(".{m}(")) || code.contains(&format!("Store::{m}(")))
        .cloned()
        .collect()
}

#[test]
fn agent_code_calls_only_allowlisted_store_methods() {
    let methods = store_method_names();
    // FLOOR: the scan actually found the store's methods.
    assert!(
        methods.len() >= 50,
        "found only {} store methods",
        methods.len()
    );
    for must in [
        "set_settings",
        "insert_scan",
        "purge",
        "decide_proposal",
        "add_mine_as",
        "dismiss_alert",
        "update_trusted_networks",
        "set_app_status",
        "migrate",
        "open",
    ] {
        assert!(methods.contains(must), "store method scan missed {must}");
    }
    // The allowlist names real methods (a stale entry would hide a rename).
    for a in ALLOWED_STORE_METHODS {
        assert!(
            methods.contains(*a),
            "allowlisted {a} is not a Store method"
        );
    }
    let files = agent_files();
    let scanned: Vec<_> = files
        .iter()
        .filter(|(n, _)| n.contains("/agent/") || n.ends_with("bin/wbm.rs"))
        .collect();
    let mut checked = 0;
    let mut used = BTreeSet::new();
    for (name, src) in &scanned {
        let code = production_code(src);
        let bad = disallowed_store_calls(&code, &methods, &allowed_for(name));
        assert!(
            bad.is_empty(),
            "{name} calls Store methods outside the allowlist: {bad:?}"
        );
        used.extend(
            ALLOWED_STORE_METHODS
                .iter()
                .filter(|m| {
                    code.contains(&format!(".{m}(")) || code.contains(&format!("Store::{m}("))
                })
                .copied(),
        );
        checked += 1;
    }
    assert!(checked >= 7, "checked only {checked}");
    // The allowlist is not vacuous: the agent really calls most of it.
    assert!(used.len() >= 14, "agent code uses only {used:?}");
}

#[test]
fn the_store_method_allowlist_can_fail_negative_control() {
    let methods = store_method_names();
    for forbidden in [
        "set_settings",
        "insert_scan",
        "purge",
        "purge_places",
        "decide_proposal",
        "add_mine_as",
        "add_mine",
        "dismiss_alert",
        "undismiss_alert",
        "update_trusted_networks",
        "set_app_status",
        "migrate",
        "remove_watchlist",
        "upsert_alerts",
        "expire_proposals",
        "mark_audit_undone",
        "forget_place",
        "upsert_lan_device",
    ] {
        let method_call = format!("fn f(s: &mut Store) {{ s.{forbidden}(1); }}");
        assert_eq!(
            disallowed_store_calls(&method_call, &methods, ALLOWED_STORE_METHODS),
            vec![forbidden.to_string()],
            "missed .{forbidden}("
        );
    }
    // The status publisher's write is allowed in status.rs and nowhere else.
    let publish = "fn f(s: &mut Store) { s.set_app_status(j); }";
    assert!(
        disallowed_store_calls(publish, &methods, &allowed_for("src/agent/status.rs")).is_empty()
    );
    assert_eq!(
        disallowed_store_calls(publish, &methods, &allowed_for("src/agent/tools.rs")),
        vec!["set_app_status".to_string()]
    );
    // The static form too: Store::open creates and migrates a database.
    assert_eq!(
        disallowed_store_calls("let s = Store::open(dir);", &methods, ALLOWED_STORE_METHODS),
        vec!["open".to_string()]
    );
    // And allowed calls pass.
    assert!(disallowed_store_calls(
        "s.list_mine(); s.create_proposal(a, b, c); Store::open_db_file(p, m);",
        &methods,
        ALLOWED_STORE_METHODS
    )
    .is_empty());
}

// ---------------------------------------------------------------------------
// Negative controls for the scanners themselves
// ---------------------------------------------------------------------------

#[test]
fn scanners_can_fail_negative_control() {
    for (list, label) in [
        (SOCKET_TOKENS, "socket"),
        (SPAWN_TOKENS, "spawn"),
        (SIGNAL_TOKENS, "signal"),
        (FS_WRITE_TOKENS, "fs write"),
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
    let quiet = "// UdpSocket Command set_settings\n/* libc::kill(1, 9) fs::write */\nfn f() {}\n#[cfg(test)]\nmod t { use std::process::Command; fn g() { std::fs::write(a, b); } }";
    let code = production_code(quiet);
    for list in [
        SOCKET_TOKENS,
        SPAWN_TOKENS,
        SIGNAL_TOKENS,
        FS_WRITE_TOKENS,
        FORBIDDEN_CALLS,
    ] {
        assert!(hits(&code, list).is_empty(), "{:?}", hits(&code, list));
    }
    // A file that really did call a scanner would be caught by the same path.
    assert!(!hits(
        &production_code("fn f() { crate::wifi::scan(&salt); }"),
        FORBIDDEN_CALLS
    )
    .is_empty());
}

#[test]
fn only_a_trailing_test_module_is_cut_so_a_test_attribute_cannot_hide_code() {
    // The old scanner cut everything after the FIRST #[cfg(test)]. Code placed after one stays
    // visible now.
    let hidden_after_attr =
        "#[cfg(test)]\nfn helper() {}\nfn evil() { let c = Command::new(\"x\"); }";
    assert!(
        hits(&production_code(hidden_after_attr), SPAWN_TOKENS).contains(&"Command".to_string())
    );
    let hidden_after_mod =
        "#[cfg(test)]\nmod early { fn t() {} }\nfn evil() { std::fs::write(a, b); }";
    assert!(!hits(&production_code(hidden_after_mod), FS_WRITE_TOKENS).is_empty());
    // A trailing test module with braces in strings and chars is still found and cut.
    let trailing = "fn real() {}\n#[cfg(test)]\nmod tests {\n  fn t() { let s = \"}\"; let c = '{'; let q = '\"'; Command::new(\"x\"); }\n}\n";
    let code = production_code(trailing);
    assert!(code.contains("fn real"));
    assert!(hits(&code, SPAWN_TOKENS).is_empty(), "{code}");
    // `#[cfg(test)] mod x;` (a file) is not a body: nothing is cut.
    let decl = "#[cfg(test)]\nmod t;\nfn evil() { UdpSocket::bind(a); }";
    assert!(!hits(&production_code(decl), SOCKET_TOKENS).is_empty());
    // A comment hiding a token does not hide the code after it.
    assert!(!hits(
        &production_code("/* x */ fn f() { UdpSocket::bind(a); }"),
        SOCKET_TOKENS
    )
    .is_empty());
    // A second test attribute earlier in the file does not shield a non-test tail either.
    let two = "#[cfg(test)]\nmod a { fn t() {} }\nfn evil() { TcpStream::connect(x); }\n#[cfg(test)]\nmod b { fn t() {} }\n";
    assert!(!hits(&production_code(two), SOCKET_TOKENS).is_empty());
    // Real files: whatever the cut removes is exactly a trailing test module.
    for (name, src) in &agent_files() {
        let full = blank_comments(src);
        let cut = strip_trailing_test_mod(&full);
        if cut.len() != full.len() {
            let tail = &full[cut.len()..];
            assert!(tail.trim_start().starts_with("#[cfg(test)]"), "{name}");
            assert_eq!(tail.matches("#[cfg(test)]").count(), 1, "{name}");
        }
    }
}

#[test]
fn kill_is_only_ever_signal_zero_negative_control() {
    assert!(
        kill_calls_that_send_a_signal("unsafe { libc::kill(pid as libc::pid_t, 0) }").is_empty()
    );
    assert!(kill_calls_that_send_a_signal("let r = libc::kill(pid, 0);").is_empty());
    for bad in [
        "libc::kill(pid, 9)",
        "libc::kill(pid, libc::SIGTERM)",
        "libc::kill(pid, sig)",
        "libc::kill(pid as i32, 15)",
        "libc::kill(pid, -1)",
        "nix::kill(pid, 0 + 9)",
    ] {
        assert!(
            !kill_calls_that_send_a_signal(bad).is_empty(),
            "missed {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// The MCP dependency
// ---------------------------------------------------------------------------

/// Features the MCP SDK may be built with: protocol and framing over any async reader/writer.
/// Anything else (HTTP, child process, OAuth, a client) is out.
const ALLOWED_RMCP_FEATURES: &[&str] = &["server", "transport-async-rw"];

/// The text of every declaration of the `rmcp` dependency in a Cargo.toml, in inline form
/// (`rmcp = { ... }`, possibly spanning lines), dotted form (`rmcp.features = [...]`), or
/// table form (`[dependencies.rmcp]` ... up to the next table).
fn rmcp_declarations(toml: &str) -> Vec<String> {
    let lines: Vec<&str> = toml.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        let is_header = l.starts_with('[') && l.ends_with(']');
        if is_header
            && l.trim_matches(['[', ']'])
                .trim()
                .rsplit('.')
                .next()
                .map(str::trim)
                == Some("rmcp")
        {
            // Table form: until the next table header.
            let mut body = String::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with('[') {
                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }
            out.push(body);
            continue;
        }
        let key_is_rmcp =
            l.starts_with("rmcp") && l["rmcp".len()..].trim_start().starts_with(['=', '.']);
        if key_is_rmcp {
            // Inline or dotted form; keep reading while brackets or braces are open. A dotted
            // declaration spans several `rmcp.x = ...` lines, which are gathered together.
            let mut text = String::from(l);
            let open = |t: &str| {
                t.matches(['{', '[']).count() as i64 - t.matches(['}', ']']).count() as i64
            };
            while open(&text) > 0 && i + 1 < lines.len() {
                i += 1;
                text.push('\n');
                text.push_str(lines[i]);
            }
            let dotted = l["rmcp".len()..].trim_start().starts_with('.');
            if dotted {
                while i + 1 < lines.len() && lines[i + 1].trim().starts_with("rmcp.") {
                    i += 1;
                    text.push('\n');
                    text.push_str(lines[i].trim());
                }
                out.push(text);
                // All the dotted lines are one declaration; skip any further `rmcp.` lines.
            } else {
                out.push(text);
            }
        }
        i += 1;
    }
    out
}

/// Quoted strings inside the `features = [ ... ]` list of a declaration.
fn rmcp_features(decl: &str) -> Vec<String> {
    let Some(at) = decl.find("features") else {
        return vec![];
    };
    let rest = &decl[at..];
    let Some(open) = rest.find('[') else {
        return vec![];
    };
    let Some(close) = rest[open..].find(']') else {
        return vec![];
    };
    rest[open + 1..open + close]
        .split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

/// What is wrong with the rmcp declarations, if anything.
fn rmcp_problems(toml: &str) -> Vec<String> {
    let decls = rmcp_declarations(toml);
    let mut problems = Vec::new();
    if decls.len() != 1 {
        problems.push(format!(
            "expected exactly one rmcp declaration, found {}",
            decls.len()
        ));
    }
    for d in &decls {
        let flat: String = d.split_whitespace().collect();
        if !(flat.contains("default-features=false") || flat.contains("default_features=false")) {
            problems.push("default features are not switched off".into());
        }
        let feats = rmcp_features(d);
        if feats.is_empty() {
            problems.push("no explicit feature list".into());
        }
        for f in feats {
            if !ALLOWED_RMCP_FEATURES.contains(&f.as_str()) {
                problems.push(format!("feature {f} is not allowed"));
            }
        }
        if flat.contains("package=") || flat.contains("git=") || flat.contains("path=") {
            problems.push("rmcp must come from the registry under its own name".into());
        }
    }
    // A renamed dependency pointing at rmcp would dodge the check above.
    let flat_all: String = toml.split_whitespace().collect();
    if flat_all.contains("package=\"rmcp\"") {
        problems.push("a dependency renames the rmcp package".into());
    }
    problems
}

#[test]
fn the_mcp_dependency_has_only_the_allowed_features() {
    let toml =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    // FLOOR: the declaration was found.
    assert_eq!(rmcp_declarations(&toml).len(), 1, "rmcp declarations");
    assert_eq!(rmcp_problems(&toml), Vec::<String>::new());
    assert_eq!(
        rmcp_features(&rmcp_declarations(&toml)[0]),
        ALLOWED_RMCP_FEATURES
    );
}

#[test]
fn the_rmcp_check_can_fail_negative_control() {
    let good = r#"rmcp = { version = "3", default-features = false, features = ["server", "transport-async-rw"] }"#;
    assert!(rmcp_problems(good).is_empty());
    for (label, bad) in [
        (
            "inline risky feature",
            r#"rmcp = { version = "3", default-features = false, features = ["server", "transport-child-process"] }"#,
        ),
        (
            "inline default features on",
            r#"rmcp = { version = "3", features = ["server"] }"#,
        ),
        ("bare version (default features)", r#"rmcp = "3""#),
        (
            "table form with a banned feature",
            "[dependencies.rmcp]\nversion = \"3\"\ndefault-features = false\nfeatures = [\"server\", \"transport-streamable-http-server\"]\n",
        ),
        (
            "table form without default-features",
            "[dependencies.rmcp]\nversion = \"3\"\nfeatures = [\"server\"]\n",
        ),
        (
            "dotted form",
            "rmcp.version = \"3\"\nrmcp.default-features = false\nrmcp.features = [\"server\", \"auth\"]\n",
        ),
        (
            "multi-line inline",
            "rmcp = { version = \"3\",\n  default-features = false,\n  features = [\n    \"server\",\n    \"reqwest\",\n  ] }\n",
        ),
        (
            "target-specific table",
            "[target.'cfg(unix)'.dependencies.rmcp]\nversion = \"3\"\ndefault-features = false\nfeatures = [\"server\", \"transport-io\"]\n",
        ),
        (
            "renamed package",
            "mcp = { package = \"rmcp\", version = \"3\", default-features = false, features = [\"server\"] }\nrmcp = { version = \"3\", default-features = false, features = [\"server\"] }\n",
        ),
        (
            "declared twice",
            "rmcp = { version = \"3\", default-features = false, features = [\"server\"] }\n[dev-dependencies.rmcp]\nversion = \"3\"\nfeatures = [\"client\"]\n",
        ),
        (
            "from a git url",
            r#"rmcp = { git = "https://example.invalid/rmcp", default-features = false, features = ["server"] }"#,
        ),
    ] {
        assert!(!rmcp_problems(bad).is_empty(), "missed: {label}");
    }
    // Forms that are fine pass too.
    let ok_table = "[dependencies.rmcp]\nversion = \"3\"\ndefault-features = false\nfeatures = [\"server\", \"transport-async-rw\"]\n\n[dependencies.other]\nfeatures = [\"x\"]\n";
    assert!(
        rmcp_problems(ok_table).is_empty(),
        "{:?}",
        rmcp_problems(ok_table)
    );
    let ok_dotted =
        "rmcp.version = \"3\"\nrmcp.default-features = false\nrmcp.features = [\"server\"]\n";
    assert!(
        rmcp_problems(ok_dotted).is_empty(),
        "{:?}",
        rmcp_problems(ok_dotted)
    );
}
