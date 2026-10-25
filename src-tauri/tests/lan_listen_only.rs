//! Structural guarantees for the LAN module, checked against its own source: the only file that
//! transmits is `sweep.rs`, it has exactly one send site and sends nothing but one ICMPv6 echo
//! request to the all-nodes address, there is no TCP anywhere, and the mDNS socket is
//! receive-only. These are text checks, so each has a negative control proving the scanner can
//! fail.

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
    assert!(files.len() >= 7, "found only {} lan files", files.len());
    assert!(files.iter().any(|(n, _)| n == "nd6.rs"));
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
fn sweep_rs_is_one_icmpv6_echo_to_the_all_nodes_address() {
    let files = lan_files();
    let (_, sweep) = files.iter().find(|(n, _)| n == "sweep.rs").unwrap();
    let code = production_code(sweep);
    for tcp in [
        "TcpStream",
        "TcpListener",
        "connect(",
        "send_vectored",
        "sendmsg",
        "Type::STREAM",
        "Protocol::TCP",
        "Protocol::UDP",
    ] {
        assert!(!code.contains(tcp), "sweep.rs must not use {tcp}");
    }
    assert_eq!(code.matches("send_to(").count(), 1, "exactly one send site");
    assert!(
        code.contains("Protocol::ICMPV6"),
        "the only socket is ICMPv6"
    );
    assert!(code.contains("Type::DGRAM"), "unprivileged datagram socket");
    assert!(
        code.contains("SocketAddrV6::new(ALL_NODES, 0, 0, u32::from(if_index))"),
        "the destination is always ff02::1 on the Wi-Fi interface"
    );
    assert!(code
        .contains("pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);"));
    // `run_sweep` makes one `send_echo` call, no loop around it.
    let run = &code[code.find("pub fn run_sweep").expect("run_sweep")..];
    assert_eq!(run.matches("send_echo(").count(), 1);
    assert!(!run.contains("for ") && !run.contains("while ") && !run.contains("loop"));
    // The old per-host UDP sweep is gone from the gate too.
    let gate = fs::read_to_string(lan_dir().join("gate.rs")).unwrap();
    let g = production_code(&gate);
    assert!(!g.contains("SWEEP_PORT") && !g.contains("MAX_SWEEP_HOSTS"));
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
    assert_eq!(code.matches("IcmpSink::new(").count(), 1, "one sink");
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
            assert!(!s.contains("IcmpSink"), "{p:?} must not build a sink");
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
