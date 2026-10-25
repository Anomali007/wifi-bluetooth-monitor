//! Structural guarantees for the LAN module, checked against its own source: the only file that
//! transmits is `sweep.rs`, which has exactly two send sites (one ICMPv6 echo request to the
//! all-nodes address, one zero-byte UDP datagram to port 9 per IPv4 host), there is no TCP
//! anywhere, the mDNS socket is receive-only, and the crate spawns NO process at all (Apple's
//! `arp -an` and `ndp -an` are run by launchd as bundled background items, never by the app).
//! These are text checks, so each has a negative control proving the scanner can fail.

use std::fs;
use std::path::PathBuf;

/// Calls that put bytes on the network or open a connection.
const TRANSMIT_TOKENS: &[&str] = &[
    "send_to",
    ".send(",
    "send_vectored",
    "sendmsg",
    ".connect(",
    "connect(",
    "TcpStream",
    "TcpListener",
    "UdpSocket::connect",
];

fn lan_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lan")
}

/// Production code only: drop the `#[cfg(test)]` tail and comment lines.
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

fn lan_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(lan_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            out.push((name, fs::read_to_string(&path).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn scanner_can_fail_negative_control() {
    // The checker must flag each token it claims to look for.
    for t in TRANSMIT_TOKENS {
        let sample = format!("fn f() {{ x{t}; }}");
        assert!(
            !hits(&production_code(&sample), TRANSMIT_TOKENS).is_empty(),
            "scanner missed {t}"
        );
    }
    // And it must ignore comments and the test tail.
    let quiet = "// socket.send_to(..)\nfn f() {}\n#[cfg(test)]\nmod t { fn g() { s.send_to(); } }";
    assert!(hits(&production_code(quiet), TRANSMIT_TOKENS).is_empty());
}

#[test]
fn only_sweep_rs_can_transmit() {
    let files = lan_files();
    // FLOOR: the module's files were actually found (incl. the new neighbor-table reader).
    assert!(files.len() >= 8, "found only {} lan files", files.len());
    assert!(files.iter().any(|(n, _)| n == "nd6.rs"));
    assert!(files.iter().any(|(n, _)| n == "systools.rs"));
    let mut checked = 0;
    for (name, src) in &files {
        if name == "sweep.rs" {
            continue;
        }
        let bad = hits(&production_code(src), TRANSMIT_TOKENS);
        assert!(bad.is_empty(), "{name} contains transmit calls: {bad:?}");
        checked += 1;
    }
    assert!(checked >= 6);
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
    ] {
        assert!(!code.contains(banned), "sweep.rs must not use {banned}");
    }
    // Exactly two send sites: the ICMPv6 socket and the UDP socket.
    assert_eq!(
        code.matches("send_to(").count(),
        2,
        "exactly two send sites"
    );
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
fn sweep_negative_controls_the_checks_can_fail() {
    // A UDP send anywhere else, a third send site, or a TCP socket in sweep.rs would be caught.
    let extra = "fn f() { s.send_to(a, b); s.send_to(c, d); s.send_to(e, f); }";
    assert_ne!(production_code(extra).matches("send_to(").count(), 2);
    let tcp = "fn f() { let _ = Protocol::TCP; }";
    assert!(production_code(tcp).contains("Protocol::TCP"));
    let other_file = "fn f() { UdpSocket::bind(a).unwrap().send_to(b, c); }";
    assert!(!hits(&production_code(other_file), TRANSMIT_TOKENS).is_empty());
}

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

fn spawn_hits(code: &str) -> Vec<&'static str> {
    SPAWN_TOKENS
        .iter()
        .copied()
        .filter(|t| code.contains(t))
        .collect()
}

#[test]
fn the_app_crate_spawns_no_process_at_all() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut scanned = 0;
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if !p.extension().is_some_and(|e| e == "rs") {
                continue;
            }
            scanned += 1;
            let code = production_code(&fs::read_to_string(&p).unwrap());
            assert_eq!(
                spawn_hits(&code),
                Vec::<&str>::new(),
                "{p:?} starts a process"
            );
        }
    }
    assert!(scanned >= 10, "only scanned {scanned} files");
}

#[test]
fn spawn_scanner_negative_controls() {
    // It must catch every spawn spelling, in production code, and ignore comments and tests.
    for t in SPAWN_TOKENS {
        let sample = format!("fn f() {{ {t}(); }}");
        assert!(spawn_hits(&production_code(&sample)).contains(t), "{t}");
    }
    assert!(!spawn_hits(&production_code("fn f() { Command::new(\"/bin/ls\"); }")).is_empty());
    assert!(spawn_hits(&production_code("// Command::new(\"x\")\nfn f() {}")).is_empty());
    assert!(spawn_hits(&production_code(
        "fn f() {}\n#[cfg(test)]\nmod t { fn g() { Command::new(\"x\"); } }"
    ))
    .is_empty());
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
fn no_tcp_anywhere_in_the_crate() {
    // Not just lan/: nothing under src/ opens or accepts a TCP stream.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    let mut scanned = 0;
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let code = production_code(&fs::read_to_string(&p).unwrap());
                for t in ["TcpStream", "TcpListener", "Type::STREAM", "Protocol::TCP"] {
                    assert!(!code.contains(t), "{p:?} uses {t}");
                }
                scanned += 1;
            }
        }
    }
    assert!(scanned >= 10, "only scanned {scanned} files");
    // NEGATIVE CONTROL: the matcher does flag a TCP use.
    let sample = production_code("fn f() { let _ = TcpStream::connect(a); }");
    assert!(sample.contains("TcpStream"));
}

#[test]
fn scan_reaches_the_sweep_only_through_the_gate() {
    let files = lan_files();
    let (_, m) = files.iter().find(|(n, _)| n == "mod.rs").unwrap();
    let code = production_code(m);
    assert_eq!(code.matches("run_sweep(").count(), 1, "one call site");
    assert_eq!(code.matches("NetSink::new(").count(), 1, "one sink");
    // The call sits inside `if let Ok(if_index) = decision`, and `decision` comes from may_sweep.
    let decision = code
        .find("let decision = gate::may_sweep(")
        .expect("gate call");
    let guard = code.find("if let Ok(if_index) = decision").expect("guard");
    let call = code.find("run_sweep(").unwrap();
    assert!(decision < guard && guard < call);
    // Nothing outside lan/ constructs a sink or runs a sweep.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(&src).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() && p.extension().is_some_and(|e| e == "rs") {
            let s = production_code(&fs::read_to_string(&p).unwrap());
            assert!(!s.contains("run_sweep"), "{p:?} must not sweep");
            assert!(!s.contains("NetSink"), "{p:?} must not build a sink");
        }
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
            "fn announced_sources("
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
    assert!(hits(&code, TRANSMIT_TOKENS).is_empty());
    for opt in ["set_multicast_if", "set_multicast_hops", "set_ttl"] {
        assert!(
            !code.contains(opt),
            "mdns.rs must not configure sending: {opt}"
        );
    }
}
