//! Structural guarantees for the LAN module, checked against the crate's own source: the only
//! file that transmits is `src/lan/sweep.rs`, which has exactly two send sites (one ICMPv6 echo
//! request to the all-nodes address, one zero-byte UDP datagram to port 9 per IPv4 host), there
//! is no TCP anywhere, the mDNS socket is receive-only, and the crate spawns NO process at all
//! (Apple's `arp -an` and `ndp -an` are run by launchd as bundled background items, never by
//! the app). `NetSink::new` also needs a `GateToken` that only `gate::may_sweep` can build.
//!
//! These are text checks over ALL of `src/` (recursively), so each has a negative control that
//! runs the same scanner over a throwaway source tree and proves it can fail.
//!
//! Allowlist: send primitives only in `lan/sweep.rs`. Opening a socket (`UdpSocket`,
//! `Socket::new`) is allowed there and in `lan/mdns.rs`, whose listener must open its receive
//! sockets; mdns.rs is held to "no send primitive at all" and exactly two `Socket::new`.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

/// Anything that puts bytes on the wire or opens a connection. Allowed in `lan/sweep.rs` only.
const SEND_PATTERNS: &[&str] = &[
    r"send_to\w*\(",
    r"sendto",
    r"libc::send",
    r"sendmsg",
    r"send_vectored",
    r"\.send\(",
    r"\bsend\s*\(",
    r"\.connect\(",
    r"\bconnect\(",
    r"TcpStream",
    r"TcpListener",
    r"UdpSocket::connect",
    r"libc::write",
];

/// Opening a socket at all. Allowed in `lan/sweep.rs` and `lan/mdns.rs` (receive-only).
const SOCKET_PATTERNS: &[&str] = &[r"UdpSocket", r"Socket::new"];

/// Anything that starts a process. The app crate must contain none of these in production code.
const SPAWN_TOKENS: &[&str] = &[
    "Command::new",
    "std::process::Command",
    "process::Command",
    "tokio::process",
    "posix_spawn",
    "libc::system",
    "libc::popen",
    "libc::fork",
    "libc::vfork",
    "libc::exec",
    "NSTask",
    "Process::new",
    "launchctl",
];

/// Never anywhere in the crate.
const TCP_TOKENS: &[&str] = &["TcpStream", "TcpListener", "Type::STREAM", "Protocol::TCP"];

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn lan_dir() -> PathBuf {
    src_dir().join("lan")
}

// -- Source reading ---------------------------------------------------------------------

/// Index just past the `}` matching the `{` at `open`, skipping comments, strings, raw strings
/// and char literals (so a `"{"` in a test cannot unbalance it). `None` if unbalanced.
fn matching_brace(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut d = 1;
                i += 2;
                while i < b.len() && d > 0 {
                    if b[i..].starts_with(b"/*") {
                        d += 1;
                        i += 2;
                    } else if b[i..].starts_with(b"*/") {
                        d -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'r' if (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                && matches!(b.get(i + 1), Some(b'"') | Some(b'#')) =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                j += 1;
                let mut close = vec![b'"'];
                close.extend(std::iter::repeat_n(b'#', hashes));
                while j < b.len() && !b[j..].starts_with(&close) {
                    j += 1;
                }
                i = j + close.len();
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'\'' => {
                if b.get(i + 1) == Some(&b'\\') {
                    let mut j = i + 3;
                    while j < b.len() && b[j] != b'\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else {
                    // A one-character literal ('{'), or a lifetime ('a).
                    let len = match b.get(i + 1) {
                        Some(c) if *c < 0x80 => 1,
                        Some(c) if *c >= 0xf0 => 4,
                        Some(c) if *c >= 0xe0 => 3,
                        Some(_) => 2,
                        None => 0,
                    };
                    if len > 0 && b.get(i + 1 + len) == Some(&b'\'') {
                        i += 2 + len;
                    } else {
                        i += 1;
                    }
                }
            }
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Drop ONLY a trailing `#[cfg(test)] mod name { .. }` block: the one that is the last item in
/// the file. A `#[cfg(test)]` on anything else, or a test module with code after it, strips
/// nothing, so production code can never hide behind an early `#[cfg(test)]`.
fn strip_trailing_test_mod(src: &str) -> &str {
    let re = Regex::new(
        r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{",
    )
    .unwrap();
    for m in re.find_iter(src) {
        let open = m.end() - 1;
        if let Some(end) = matching_brace(src.as_bytes(), open) {
            if src[end..].trim().is_empty() {
                return &src[..m.start()];
            }
        }
    }
    src
}

/// Production code only: drop the trailing test module and comment lines.
fn production_code(src: &str) -> String {
    strip_trailing_test_mod(src)
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn regexes(patterns: &[&str]) -> Vec<(String, Regex)> {
    patterns
        .iter()
        .map(|p| (p.to_string(), Regex::new(p).unwrap()))
        .collect()
}

fn pattern_hits(code: &str, patterns: &[&str]) -> Vec<String> {
    regexes(patterns)
        .into_iter()
        .filter(|(_, re)| re.is_match(code))
        .map(|(p, _)| p)
        .collect()
}

fn literal_hits(code: &str, tokens: &[&str]) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| code.contains(*t))
        .map(|t| t.to_string())
        .collect()
}

/// Every `.rs` file under `root`, as (path relative to root with `/`, contents).
fn rs_files(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, fs::read_to_string(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Every rule that applies to a whole source tree, as human-readable violations.
fn violations(root: &Path) -> Vec<String> {
    let mut bad = Vec::new();
    for (rel, src) in rs_files(root) {
        let code = production_code(&src);
        if rel != "lan/sweep.rs" {
            for h in pattern_hits(&code, SEND_PATTERNS) {
                bad.push(format!("{rel}: send primitive /{h}/"));
            }
        }
        if rel != "lan/sweep.rs" && rel != "lan/mdns.rs" {
            for h in pattern_hits(&code, SOCKET_PATTERNS) {
                bad.push(format!("{rel}: socket /{h}/"));
            }
        }
        for h in literal_hits(&code, SPAWN_TOKENS) {
            bad.push(format!("{rel}: process spawn {h}"));
        }
        for h in literal_hits(&code, TCP_TOKENS) {
            bad.push(format!("{rel}: TCP {h}"));
        }
    }
    bad
}

/// A throwaway source tree for negative controls.
fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (rel, body) in files {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    dir
}

fn lan_files() -> Vec<(String, String)> {
    rs_files(&lan_dir())
}

/// `send_to`-family call sites in `code`.
fn send_sites(code: &str) -> usize {
    Regex::new(r"send_to\w*\(").unwrap().find_iter(code).count()
}

// -- The checks ---------------------------------------------------------------------------

#[test]
fn nothing_in_src_transmits_except_sweep_rs() {
    let files = rs_files(&src_dir());
    // FLOOR: the whole tree was found, including nested modules.
    assert!(files.len() >= 20, "found only {} source files", files.len());
    for must in [
        "lan/sweep.rs",
        "lan/mdns.rs",
        "lan/nd6.rs",
        "commands.rs",
        "ble/mod.rs",
    ] {
        assert!(files.iter().any(|(n, _)| n == must), "{must} not scanned");
    }
    assert_eq!(violations(&src_dir()), Vec::<String>::new());
}

#[test]
fn scanner_negative_controls_every_token_is_caught_outside_the_allowlist() {
    // Each send token, in a file outside src/lan AND inside src/lan but not sweep.rs.
    let samples = [
        "fn f() { s.send_to_anything(a, b); }",
        "fn f() { s.send_to(a, b); }",
        "fn f() { unsafe { libc::sendto(fd, p, n, 0, a, l) }; }",
        "fn f() { unsafe { libc::sendmsg(fd, m, 0) }; }",
        "fn f() { s.send_vectored(&b); }",
        "fn f() { s.send(&b); }",
        "fn f() { s.connect(&a); }",
        "fn f() { let _ = TcpStream::connect(a); }",
        "fn f() { unsafe { libc::write(fd, p, 1) }; }",
        "fn f() { let _ = UdpSocket::bind(a); }",
        "fn f() { let _ = Socket::new(d, t, p); }",
        "fn f() { let _ = std::process::Command::new(\"x\"); }",
    ];
    for s in samples {
        for rel in ["commands.rs", "wifi/mod.rs", "lan/arp.rs", "lan/mod.rs"] {
            let t = tree(&[(rel, s)]);
            assert!(!violations(t.path()).is_empty(), "missed `{s}` in {rel}");
        }
    }
    // Every spawn spelling, and every TCP spelling, is caught in a file outside src/lan.
    for t in SPAWN_TOKENS.iter().chain(TCP_TOKENS) {
        let t_tree = tree(&[("places/mod.rs", &format!("fn f() {{ {t}(); }}"))]);
        assert!(!violations(t_tree.path()).is_empty(), "missed {t}");
    }
    // NEGATIVE CONTROL OF THE CONTROL: the same text in sweep.rs is allowed (except spawn).
    let t = tree(&[(
        "lan/sweep.rs",
        "fn f() { s.send_to(a, b); let _ = Socket::new(d,t,p); }",
    )]);
    assert!(violations(t.path()).is_empty());
    let t = tree(&[("lan/sweep.rs", "fn f() { let _ = Command::new(\"x\"); }")]);
    assert!(!violations(t.path()).is_empty(), "sweep.rs may not spawn");
    // The mdns listener may open sockets but not send.
    let t = tree(&[("lan/mdns.rs", "fn f() { let _ = Socket::new(d, t, p); }")]);
    assert!(violations(t.path()).is_empty());
    let t = tree(&[("lan/mdns.rs", "fn f() { s.send_to(a, b); }")]);
    assert!(!violations(t.path()).is_empty());
    // Comments and a real trailing test module are ignored.
    let t = tree(&[(
        "commands.rs",
        "// s.send_to(a, b)\nfn f() {}\n#[cfg(test)]\nmod tests { fn g() { let s = \"{\"; x.send_to(a, b); } }\n",
    )]);
    assert!(violations(t.path()).is_empty());
}

#[test]
fn an_early_cfg_test_cannot_hide_production_code() {
    // The old scanner kept only the text BEFORE the first `#[cfg(test)]`.
    let cases = [
        "#[cfg(test)]\nfn helper() {}\nfn go() { s.send_to(a, b); }\n",
        "#[cfg(test)]\nmod early { fn t() {} }\nfn go() { s.send_to(a, b); }\n",
        "#[cfg(test)]\nuse std::fmt;\nfn go() { unsafe { libc::sendto(1, p, 0, 0, a, 0) }; }\n",
        // A test module that is NOT last, with a second one after it.
        "#[cfg(test)]\nmod a { }\nfn go() { s.send_to(a, b); }\n#[cfg(test)]\nmod b { }\n",
    ];
    for c in cases {
        let t = tree(&[("commands.rs", c)]);
        assert!(!violations(t.path()).is_empty(), "hid `{c}`");
    }
    // The real shape (production code, then a trailing test module) is still stripped, even
    // with braces in strings, chars and raw strings inside it.
    let ok = "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn g() { let _ = '{'; let _ = r#\"}\"#; let _ = \"}\"; s.send_to(a, b); }\n}\n";
    let t = tree(&[("commands.rs", ok)]);
    assert!(violations(t.path()).is_empty());
}

#[test]
fn sweep_rs_has_exactly_two_send_sites_counted_by_regex() {
    // NEGATIVE CONTROLS for the counter: variants of the name and a third site.
    assert_eq!(send_sites("a.send_to(x); b.send_to(y);"), 2);
    assert_eq!(
        send_sites("a.send_to(x); b.send_to(y); c.send_to_raw(z);"),
        3
    );
    assert_eq!(
        send_sites("a.send_to_all (x)"),
        0,
        "documented: needs the paren attached"
    );
    let files = lan_files();
    let (_, sweep) = files.iter().find(|(n, _)| n == "sweep.rs").unwrap();
    assert_eq!(
        send_sites(&production_code(sweep)),
        2,
        "exactly two send sites"
    );
}

#[test]
fn sweep_rs_is_one_icmpv6_echo_plus_zero_byte_udp_to_port_9() {
    let files = lan_files();
    let (_, sweep) = files.iter().find(|(n, _)| n == "sweep.rs").unwrap();
    let code = production_code(sweep);
    for banned in [
        "TcpStream",
        "TcpListener",
        ".connect(",
        "connect(",
        "send_vectored",
        "sendmsg",
        "Type::STREAM",
        "Protocol::TCP",
        "set_broadcast",
        "join_multicast",
        "Command::new",
        "libc::",
    ] {
        assert!(!code.contains(banned), "sweep.rs must not use {banned}");
    }
    assert_eq!(send_sites(&code), 2, "exactly two send sites");
    let squashed: String = code.split_whitespace().collect();
    assert_eq!(squashed.matches("self.icmp.send_to(").count(), 1);
    assert_eq!(squashed.matches("self.udp.send_to(&[],").count(), 1);
    assert!(code.contains("Protocol::ICMPV6") && code.contains("Protocol::UDP"));
    assert!(
        code.contains("Type::DGRAM"),
        "unprivileged datagram sockets"
    );
    // The UDP datagram carries no payload and goes to the discard port.
    assert!(code.contains("pub const DISCARD_PORT: u16 = 9;"));
    assert!(code.contains("SocketAddrV4::new(host, DISCARD_PORT)"));
    // Rate, size and TTL limits are in the source.
    assert!(code.contains("pub const MAX_PER_SEC: u32 = 50;"));
    assert!(code.contains("pub const MIN_PREFIX: u8 = 23;"));
    assert!(code.contains("set_ttl_v4(1)") && code.contains("set_multicast_hops_v6(1)"));
    // The echo goes to ff02::1 on the Wi-Fi interface.
    assert!(
        code.contains("SocketAddrV6::new(ALL_NODES, 0, 0, u32::from(if_index))"),
        "the destination is always ff02::1 on the Wi-Fi interface"
    );
    assert!(code
        .contains("pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);"));
    // `run_sweep` has one echo call outside any loop, and one UDP call inside the host loop.
    let run = &code[code.find("pub fn run_sweep").expect("run_sweep")..];
    assert_eq!(run.matches("send_echo(").count(), 1);
    assert_eq!(run.matches("send_udp(").count(), 1);
    assert!(run.find("send_echo(").unwrap() < run.find("for ").unwrap());
    assert!(run.find("for ").unwrap() < run.find("send_udp(").unwrap());
    assert_eq!(run.matches("for ").count(), 1);
    assert!(!run.contains("while ") && !run.contains("loop"));
    // The gate does not know about hosts or ports.
    let gate = fs::read_to_string(lan_dir().join("gate.rs")).unwrap();
    let g = production_code(&gate);
    assert!(!g.contains("DISCARD_PORT") && !g.contains("send_"));
}

#[test]
fn the_sink_needs_a_gate_token_only_may_sweep_can_build() {
    let sweep = production_code(&fs::read_to_string(lan_dir().join("sweep.rs")).unwrap());
    let new_sig = Regex::new(r"pub fn new\(\s*token: GateToken\s*\)").unwrap();
    assert!(
        new_sig.is_match(&sweep),
        "NetSink::new must take a GateToken"
    );
    // Construction sites of the token (struct literal with its private field).
    let build = Regex::new(r"GateToken\s*\{\s*if_index").unwrap();
    let attr = Regex::new(r"#\[cfg\(test\)\]\s*pub fn for_tests").unwrap();
    for (rel, src) in rs_files(&src_dir()) {
        let code = production_code(&src).replace("pub struct GateToken {", "");
        let n = build.find_iter(&code).count();
        if rel == "lan/gate.rs" {
            // may_sweep, plus the unit-test-only constructor.
            assert_eq!(
                n, 2,
                "gate.rs builds the token in may_sweep and for_tests only"
            );
            assert_eq!(code.matches("Ok(GateToken { if_index })").count(), 1);
            assert!(attr.is_match(&code), "for_tests must be cfg(test)");
        } else {
            assert_eq!(n, 0, "{rel} must not build a GateToken");
        }
    }
    // NEGATIVE CONTROL: the matcher sees a forged token anywhere else.
    assert!(build.is_match("let t = GateToken { if_index: 3 };"));
    // And the field stays private.
    let gate = fs::read_to_string(lan_dir().join("gate.rs")).unwrap();
    assert!(gate.contains("pub struct GateToken {\n    if_index: u16,\n}"));
}

// -- N3: other ways to reach the network or run code ------------------------------------------

/// Direct dependencies that can talk HTTP, open a shell, or start a process.
const DENIED_CRATES: &[&str] = &[
    "reqwest",
    "ureq",
    "hyper",
    "hyper-util",
    "isahc",
    "surf",
    "attohttpc",
    "curl",
    "tauri-plugin-http",
    "tauri-plugin-shell",
    "tauri-plugin-process",
    "tauri-plugin-opener",
    "tauri-plugin-websocket",
    "tungstenite",
    "tokio-tungstenite",
    "duct",
    "subprocess",
    "xshell",
    "async-process",
    "cmd_lib",
];

/// tokio features that add sockets or processes.
const DENIED_TOKIO_FEATURES: &[&str] = &["net", "process", "full"];

/// Crate names declared under any `[...dependencies]` table, plus tokio's features.
fn declared_crates(cargo_toml: &str) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut tokio_features = Vec::new();
    let mut in_deps = false;
    for line in cargo_toml.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_deps = l
                .trim_matches(|c| c == '[' || c == ']')
                .ends_with("dependencies");
            continue;
        }
        if !in_deps || l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((name, rest)) = l.split_once('=') {
            let name = name.trim().to_string();
            if name == "tokio" {
                if let Some(f) = rest.split("features").nth(1) {
                    let inner = f.split('[').nth(1).and_then(|x| x.split(']').next());
                    for feat in inner.unwrap_or("").split(',') {
                        tokio_features.push(feat.trim().trim_matches('"').to_string());
                    }
                }
            }
            names.push(name);
        }
    }
    (names, tokio_features)
}

fn dependency_violations(cargo_toml: &str) -> Vec<String> {
    let (names, features) = declared_crates(cargo_toml);
    let mut bad: Vec<String> = names
        .into_iter()
        .filter(|n| DENIED_CRATES.contains(&n.as_str()))
        .map(|n| format!("dependency {n}"))
        .collect();
    bad.extend(
        features
            .into_iter()
            .filter(|f| DENIED_TOKIO_FEATURES.contains(&f.as_str()))
            .map(|f| format!("tokio feature {f}")),
    );
    bad
}

#[test]
fn no_http_shell_or_process_crate_is_a_dependency() {
    let toml =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let (names, features) = declared_crates(&toml);
    // FLOOR: the parser actually found the manifest's dependencies.
    assert!(
        names.len() >= 10,
        "parsed only {} dependencies",
        names.len()
    );
    assert!(names.iter().any(|n| n == "socket2") && features.iter().any(|f| f == "rt"));
    assert_eq!(dependency_violations(&toml), Vec::<String>::new());
    // The capability file grants nothing that shells out, fetches or opens.
    let caps =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities/default.json"))
            .unwrap();
    for banned in ["shell:", "http:", "process:", "opener:", "websocket:"] {
        assert!(!caps.contains(banned), "capability {banned}");
    }
    // NEGATIVE CONTROLS: each denied crate, in any dependency table, and the tokio features.
    for c in DENIED_CRATES {
        for table in [
            "dependencies",
            "build-dependencies",
            "target.'cfg(unix)'.dependencies",
        ] {
            let t = format!("[{table}]\n{c} = \"1\"\n");
            assert!(
                !dependency_violations(&t).is_empty(),
                "missed {c} in [{table}]"
            );
        }
    }
    for f in DENIED_TOKIO_FEATURES {
        let t = format!(
            "[dependencies]\ntokio = {{ version = \"1\", features = [\"rt\", \"{f}\"] }}\n"
        );
        assert!(!dependency_violations(&t).is_empty(), "missed tokio {f}");
    }
    // And a dev-dependency table is parsed too, but an ordinary crate is fine.
    assert!(dependency_violations("[dev-dependencies]\ntempfile = \"3\"\n").is_empty());
}

#[test]
fn build_rs_generates_no_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let b = fs::read_to_string(root.join("build.rs")).unwrap();
    assert_eq!(
        build_rs_violations(&production_code(&b)),
        Vec::<String>::new()
    );
    // NEGATIVE CONTROLS
    for bad in [
        "fn main() { std::fs::write(\"src/gen.rs\", \"x\").unwrap(); }",
        "fn main() { let _ = std::fs::File::create(\"src/x.rs\"); }",
        "fn main() { let p = std::env::var(\"OUT_DIR\"); }",
        "fn main() { std::process::Command::new(\"sh\"); }",
        "fn main() { println!(\"cargo:rustc-env=X=1\"); }",
    ] {
        assert!(!build_rs_violations(bad).is_empty(), "missed {bad}");
    }
    assert!(build_rs_violations("fn main() { tauri_build::build() }").is_empty());
    // Nothing pulls generated code in: the include!/#[path bans below cover the other end.
}

fn build_rs_violations(code: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for pat in [
        r"fs::write",
        r"File::create",
        r"OpenOptions",
        r"OUT_DIR",
        r"Command",
        r"cargo:rustc-env",
        r"cargo:rustc-cfg",
        r"\bsrc\b",
    ] {
        if Regex::new(pat).unwrap().is_match(code) {
            bad.push(pat.to_string());
        }
    }
    bad
}

/// Ways to pull in code or reach the OS that the text scan could otherwise not see. None is
/// used by the crate; add an explicit allowlist entry here if one ever must be.
const CODE_ESCAPE_PATTERNS: &[&str] = &[
    r"include!\s*\(",
    r"#\s*\[\s*path\b",
    r#"extern\s+"C""#,
    r"transmute",
    r"libc::syscall",
    r"\bsyscall\s*\(",
    r"reqwest|ureq|hyper::|isahc|attohttpc|surf::|curl::",
    r"tauri_plugin_(shell|http|process|opener|websocket)",
    r"\.shell\(\)",
    r"\.opener\(\)",
];

/// Explicit allowlist: (file, pattern) pairs that are known and reviewed. Empty today.
const CODE_ESCAPE_ALLOWED: &[(&str, &str)] = &[];

fn escape_violations(root: &Path) -> Vec<String> {
    let mut bad = Vec::new();
    for (rel, src) in rs_files(root) {
        let code = production_code(&src);
        for p in CODE_ESCAPE_PATTERNS {
            if CODE_ESCAPE_ALLOWED.contains(&(rel.as_str(), *p)) {
                continue;
            }
            if Regex::new(p).unwrap().is_match(&code) {
                bad.push(format!("{rel}: /{p}/"));
            }
        }
        if rel == "lan/sweep.rs" {
            // A plain file or socket write has no business in the sweep: it sends only through
            // the two send_to sites.
            for p in [
                r"\.write\(",
                r"write_all\(",
                r"write_vectored",
                r"\bwrite!\(",
            ] {
                if Regex::new(p).unwrap().is_match(&code) {
                    bad.push(format!("{rel}: /{p}/"));
                }
            }
        }
    }
    bad
}

#[test]
fn no_code_inclusion_ffi_or_http_shell_use_anywhere_in_src() {
    assert_eq!(escape_violations(&src_dir()), Vec::<String>::new());
    // NEGATIVE CONTROLS: each spelling, outside src/lan and inside it.
    let samples = [
        "fn f() { reqwest::get(u); }",
        "fn f() { ureq::get(u); }",
        "fn f() { hyper::Client::new(); }",
        "fn f() { app.shell().command(\"sh\"); }",
        "use tauri_plugin_shell::ShellExt;",
        "include!(\"gen.rs\");",
        "#[path = \"other.rs\"]\nmod m;",
        "extern \"C\" { fn sendto(); }",
        "fn f() { unsafe { std::mem::transmute::<u8, i8>(1) }; }",
        "fn f() { unsafe { libc::syscall(1) }; }",
    ];
    for s in samples {
        for rel in ["commands.rs", "lan/arp.rs"] {
            let t = tree(&[(rel, s)]);
            assert!(
                !escape_violations(t.path()).is_empty(),
                "missed `{s}` in {rel}"
            );
        }
    }
    // Test-only code is ignored; production code behind an early cfg(test) is not.
    let t = tree(&[(
        "commands.rs",
        "fn f() {}\n#[cfg(test)]\nmod tests { fn g() { reqwest::get(u); } }\n",
    )]);
    assert!(escape_violations(t.path()).is_empty());
    let t = tree(&[(
        "commands.rs",
        "#[cfg(test)]\nfn helper() {}\nfn go() { include!(\"x.rs\"); }\n",
    )]);
    assert!(!escape_violations(t.path()).is_empty());
    // sweep.rs: a socket or file write is caught there (and only there).
    for w in [
        "f.write(b\"x\")",
        "f.write_all(b\"x\")",
        "f.write_vectored(&b)",
    ] {
        let t = tree(&[("lan/sweep.rs", &format!("fn f() {{ {w}; }}"))]);
        assert!(
            !escape_violations(t.path()).is_empty(),
            "missed {w} in sweep.rs"
        );
        let t = tree(&[("lan/helper.rs", &format!("fn f() {{ {w}; }}"))]);
        assert!(
            escape_violations(t.path()).is_empty(),
            "{w} is fine outside sweep.rs"
        );
    }
}

#[test]
fn the_bundled_jobs_are_exactly_arp_and_ndp_and_nothing_else_ships() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let conf = fs::read_to_string(root.join("tauri.conf.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&conf).unwrap();
    let files = json["bundle"]["macOS"]["files"].as_object().unwrap();
    let mut dests: Vec<&str> = files.keys().map(String::as_str).collect();
    dests.sort();
    assert_eq!(
        dests,
        [
            "Library/LaunchAgents/com.anomali007.wifibtmonitor.arp.plist",
            "Library/LaunchAgents/com.anomali007.wifibtmonitor.ndp.plist"
        ]
    );
    for (name, prog) in [("arp", "/usr/sbin/arp"), ("ndp", "/usr/sbin/ndp")] {
        let t = fs::read_to_string(root.join(format!(
            "helper/com.anomali007.wifibtmonitor.{name}.plist.in"
        )))
        .unwrap();
        let args: Vec<&str> = t
            .split("<key>ProgramArguments</key>")
            .nth(1)
            .and_then(|r| r.split("</array>").next())
            .unwrap()
            .split("<string>")
            .skip(1)
            .map(|p| p.split("</string>").next().unwrap())
            .collect();
        assert_eq!(args, [prog, "-an"]);
        // NEGATIVE CONTROL: a wrapper in ProgramArguments would not compare equal.
        assert_ne!(vec!["/bin/sh", "-c", "arp -an"], args);
    }
}

#[test]
fn scan_reaches_the_sweep_only_through_the_gate() {
    let files = lan_files();
    let (_, m) = files.iter().find(|(n, _)| n == "mod.rs").unwrap();
    let code = production_code(m);
    assert_eq!(code.matches("run_sweep(").count(), 1, "one call site");
    assert_eq!(code.matches("NetSink::new(").count(), 1, "one sink");
    // The call sits inside `if let Ok(token) = decision`, and `decision` comes from may_sweep.
    let decision = code
        .find("let decision = gate::may_sweep(")
        .expect("gate call");
    let guard = code.find("if let Ok(token) = decision").expect("guard");
    let call = code.find("run_sweep(").unwrap();
    assert!(decision < guard && guard < call);
    // The sweep is started only through `run_gated_sweep`, which needs the gate's token and
    // re-checks the network while it runs; scan calls it once, inside the guard.
    assert_eq!(code.matches("run_gated_sweep(").count(), 1, "one call site");
    let gated_call = code.find("run_gated_sweep(&mut").expect("call site");
    assert!(guard < gated_call);
    let sig = Regex::new(r"fn run_gated_sweep<[^>]*>\(\s*sink: &mut S,\s*token: gate::GateToken,")
        .unwrap();
    assert!(
        sig.is_match(&code),
        "run_gated_sweep must take the GateToken"
    );
    // Nothing outside src/lan constructs a sink or runs a sweep (every directory under src/).
    for (rel, src) in rs_files(&src_dir()) {
        if rel.starts_with("lan/") {
            continue;
        }
        let s = production_code(&src);
        assert!(!s.contains("run_sweep"), "{rel} must not sweep");
        assert!(!s.contains("NetSink"), "{rel} must not build a sink");
    }
    // And inside lan/, only mod.rs (and sweep.rs itself) mention them.
    for (name, src) in lan_files() {
        if name == "mod.rs" || name == "sweep.rs" {
            continue;
        }
        let s = production_code(&src);
        assert!(!s.contains("run_sweep") && !s.contains("NetSink"), "{name}");
    }
}

#[test]
fn mdns_listener_exposes_no_send_surface() {
    let files = lan_files();
    let (_, src) = files.iter().find(|(n, _)| n == "mdns.rs").unwrap();
    let code = production_code(src);
    // The socket field is private and only these methods touch it.
    assert!(code.contains("pub struct MdnsListener {\n    socket: UdpSocket,"));
    let methods: Vec<&str> = code
        .lines()
        .filter(|l| l.trim_start().starts_with("pub fn ") && l.contains("&self"))
        .collect();
    assert!(
        methods.iter().all(|m| [
            "fn recv(",
            "fn snapshot(",
            "fn get(",
            "fn heard(",
            "fn len(",
            "fn is_empty(",
            "fn announced_sources(",
            "fn set_link(",
            "fn admits("
        ]
        .iter()
        .any(|ok| m.contains(ok))),
        "unexpected &self methods: {methods:?}"
    );
    assert!(
        code.contains("join_multicast_v4") && code.contains("join_multicast_v6"),
        "it must join both groups to receive"
    );
    // Receive-only: no send tokens and no way to set an outgoing interface or TTL either.
    assert!(pattern_hits(&code, SEND_PATTERNS).is_empty());
    assert_eq!(
        code.matches("Socket::new(").count(),
        2,
        "exactly the two receive sockets"
    );
    for opt in ["set_multicast_if", "set_multicast_hops", "set_ttl"] {
        assert!(
            !code.contains(opt),
            "mdns.rs must not configure sending: {opt}"
        );
    }
}
