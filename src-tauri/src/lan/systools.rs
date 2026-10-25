//! Apple's own `/usr/sbin/arp -an` and `/usr/sbin/ndp -an`, run read-only, as the primary
//! neighbor source on macOS releases where the kernel hides the ARP and ND tables from
//! non-platform binaries (measured on 27.0.1: `sysctl` returns nothing, the tools still list
//! the entries). This is the ONLY place the crate spawns a process, and it is deliberately
//! narrow: absolute paths, fixed arguments, no shell, no user-supplied input, a cleared
//! environment, a hard timeout, and stdout that is parsed and dropped (never logged).
//! `tests/lan_listen_only.rs` scans the source and fails if any other `Command::new` appears.
//!
//! Anything that goes wrong (tool missing, non-zero exit, timeout, unparseable output) yields
//! no rows and a typed [`ToolFailure`]; the caller falls back to announced-only devices.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::arp::{usable_mac, ArpEntry};
use super::nd6::{normalize_v6, NeighborEntry};

/// How long a tool may run before it is killed.
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(3);
/// Output beyond this is ignored (a /23 plus IPv6 is a few tens of KB).
const MAX_OUTPUT: u64 = 1024 * 1024;
/// Rows kept per tool.
const MAX_ROWS: usize = 4096;

/// The two tools, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Arp,
    Ndp,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Tool::Arp => "arp",
            Tool::Ndp => "ndp",
        }
    }
}

/// Why a tool gave us nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolFailure {
    /// The binary is not there (a future macOS may remove it).
    Missing(Tool),
    /// It could not be started or exited non-zero.
    Failed(Tool),
    /// It ran past [`TOOL_TIMEOUT`] and was killed.
    TimedOut(Tool),
    /// It ran, printed something, and none of it looked like neighbor-table output.
    Unparseable(Tool),
    /// The tools ran and printed fine, but none of it was on the Wi-Fi interface: macOS is
    /// showing this app (and its children) no neighbor entries for the network.
    Hidden,
}

impl ToolFailure {
    /// Plain-language reason for the Network page.
    pub fn reason(self) -> String {
        match self {
            ToolFailure::Missing(t) => format!("macOS has no {} tool", t.name()),
            ToolFailure::Failed(t) => format!("the {} tool failed", t.name()),
            ToolFailure::TimedOut(t) => format!("the {} tool took too long", t.name()),
            ToolFailure::Unparseable(t) => {
                format!("the {} tool printed something unexpected", t.name())
            }
            ToolFailure::Hidden => {
                "macOS shows this app no neighbor entries for the Wi-Fi network".to_string()
            }
        }
    }
}

/// Runs a tool and returns its stdout. A trait so tests can inject output, a missing binary or
/// a timeout without spawning anything.
pub trait Runner {
    fn run(&self, tool: Tool) -> Result<String, ToolFailure>;
}

/// The real runner.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, tool: Tool) -> Result<String, ToolFailure> {
        run_with_timeout(tool, TOOL_TIMEOUT)
    }
}

fn run_with_timeout(tool: Tool, timeout: Duration) -> Result<String, ToolFailure> {
    // Two literal absolute paths and one fixed argument: the whole spawn surface of the crate.
    let mut cmd = match tool {
        Tool::Arp => Command::new("/usr/sbin/arp"),
        Tool::Ndp => Command::new("/usr/sbin/ndp"),
    };
    let mut child = cmd
        .arg("-an")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ToolFailure::Missing(tool),
            _ => ToolFailure::Failed(tool),
        })?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ToolFailure::Failed(tool));
    };
    // Drain on a thread so a full pipe can never stall the child past the timeout.
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(MAX_OUTPUT).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(ToolFailure::TimedOut(tool));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(ToolFailure::Failed(tool));
            }
        }
    };
    let bytes = reader.join().map_err(|_| ToolFailure::Failed(tool))?;
    if !status.success() {
        return Err(ToolFailure::Failed(tool));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One usable neighbor row from a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub ip: IpAddr,
    pub mac: [u8; 6],
    /// Interface name as the tool prints it (`en0`).
    pub iface: String,
    /// `arp` printed `ifscope` (the entry is bound to this interface).
    pub ifscope: bool,
}

/// What a parse found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub rows: Vec<Row>,
    /// Lines that looked like table entries (usable or deliberately skipped) or the header.
    pub recognized: usize,
    /// Non-empty lines that matched nothing.
    pub unrecognized: usize,
}

impl Parsed {
    fn failed(&self) -> bool {
        self.recognized == 0 && self.unrecognized > 0
    }
}

/// `a:b:c:d:e:f` with one or two hex digits per group, as `arp` and `ndp` print it.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = text.split(':');
    for slot in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn usable_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback())
}

fn usable_v6(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

/// Parse `arp -an` output: `? (192.0.2.9) at a:b:c:d:e:f on en0 ifscope [ethernet]`.
/// Incomplete, permanent (our own and group entries), multicast and broadcast rows are skipped;
/// so is anything malformed.
pub fn parse_arp_output(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let t: Vec<&str> = line.split_whitespace().collect();
        let ip = t
            .get(1)
            .and_then(|s| s.strip_prefix('('))
            .and_then(|s| s.strip_suffix(')'))
            .and_then(|s| s.parse::<Ipv4Addr>().ok());
        let (Some(ip), Some("at")) = (ip, t.get(2).copied()) else {
            p.unrecognized += 1;
            continue;
        };
        p.recognized += 1;
        let mac = t.get(3).and_then(|s| parse_mac(s));
        let iface = (t.get(4).copied() == Some("on"))
            .then(|| t.get(5).copied())
            .flatten();
        let (Some(mac), Some(iface)) = (mac, iface) else {
            continue; // "(incomplete)", or a truncated line
        };
        let flags = t.get(6..).unwrap_or(&[]);
        if flags.contains(&"permanent") || !usable_v4(ip) || !usable_mac(&mac) {
            continue;
        }
        if p.rows.len() < MAX_ROWS {
            p.rows.push(Row {
                ip: IpAddr::V4(ip),
                mac,
                iface: iface.to_string(),
                ifscope: flags.contains(&"ifscope"),
            });
        }
    }
    p
}

/// Parse `ndp -an` output: `fe80::1%en0  a:b:c:d:e:f  en0  23h59m55s  S  R`, after a header line.
/// Incomplete and permanent entries (our own addresses) are skipped, as is anything malformed.
pub fn parse_ndp_output(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.first() == Some(&"Neighbor") {
            p.recognized += 1;
            continue;
        }
        let ip = t
            .first()
            .map(|s| s.split('%').next().unwrap_or(s))
            .and_then(|s| s.parse::<Ipv6Addr>().ok());
        let Some(ip) = ip else {
            p.unrecognized += 1;
            continue;
        };
        p.recognized += 1;
        let (Some(mac), Some(iface), Some(expire)) =
            (t.get(1).and_then(|s| parse_mac(s)), t.get(2), t.get(3))
        else {
            continue; // "(incomplete)", or a truncated line
        };
        let ip = normalize_v6(ip);
        if *expire == "permanent" || !usable_v6(ip) || !usable_mac(&mac) {
            continue;
        }
        if p.rows.len() < MAX_ROWS {
            p.rows.push(Row {
                ip: IpAddr::V6(ip),
                mac,
                iface: iface.to_string(),
                ifscope: false,
            });
        }
    }
    p
}

/// Rows for one tool, or why there are none.
#[derive(Debug, PartialEq, Eq)]
pub struct ToolRead {
    pub rows: Vec<Row>,
    pub failure: Option<ToolFailure>,
    /// Non-empty lines the tool printed, and how many looked like table entries. Counts only.
    pub lines: usize,
    pub recognized: usize,
}

/// Run `tool` through `runner` and parse its output.
pub fn read_tool<R: Runner + ?Sized>(runner: &R, tool: Tool) -> ToolRead {
    let out = match runner.run(tool) {
        Ok(out) => out,
        Err(failure) => {
            return ToolRead {
                rows: Vec::new(),
                failure: Some(failure),
                lines: 0,
                recognized: 0,
            }
        }
    };
    let parsed = match tool {
        Tool::Arp => parse_arp_output(&out),
        Tool::Ndp => parse_ndp_output(&out),
    };
    let failure = parsed.failed().then_some(ToolFailure::Unparseable(tool));
    ToolRead {
        lines: parsed.recognized + parsed.unrecognized,
        recognized: parsed.recognized,
        rows: if failure.is_some() {
            Vec::new()
        } else {
            parsed.rows
        },
        failure,
    }
}

/// IPv4 rows on the Wi-Fi interface as table entries.
pub fn arp_entries(rows: &[Row], if_name: &str, if_index: u16) -> Vec<ArpEntry> {
    rows.iter()
        .filter(|r| r.iface == if_name)
        .filter_map(|r| match r.ip {
            IpAddr::V4(ip) => Some(ArpEntry {
                ip,
                mac: r.mac,
                if_index,
            }),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// IPv6 rows on the Wi-Fi interface as table entries.
pub fn nd6_entries(rows: &[Row], if_name: &str, if_index: u16) -> Vec<NeighborEntry> {
    rows.iter()
        .filter(|r| r.iface == if_name)
        .filter_map(|r| match r.ip {
            IpAddr::V6(ip) => Some(NeighborEntry {
                ip,
                mac: r.mac,
                if_index,
            }),
            IpAddr::V4(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic output in the real formats (documentation addresses, locally administered MACs).
    const ARP_SAMPLE: &str = "\
? (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope [ethernet]
? (192.0.2.9) at 2:0:0:0:0:9 on en0 ifscope [ethernet]
? (192.0.2.10) at (incomplete) on en0 ifscope [ethernet]
? (192.0.2.11) at (incomplete) on en0 [ethernet]
? (192.0.2.7) at 2:0:0:0:0:7 on en0 ifscope permanent [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope [ethernet]
? (198.51.100.4) at 2:0:0:0:0:4 on en5 ifscope [ethernet]
? (192.0.2.30) at 2:0:0:0:0:1e on en0 [ethernet]
";

    const NDP_SAMPLE: &str = "\
Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
2001:db8::7                             2:0:0:0:0:7        en0 permanent R
2001:db8::10                            2:0:0:0:0:10       en0 10h47m46s S
2001:db8::11                            (incomplete)       en0 expired   N
fe80::1%en0                             2:0:0:0:0:1        en0 23h59m55s S  R
fe80::20%en0                            2:0:0:0:0:20       en0 21h38m1s  S
fe80::5%utun0                           (incomplete)       utun0 permanent R
fe80::6%lo0                             (incomplete)       lo0 permanent R
fe80::30                                2:0:0:0:0:30       en5 5m3s      S
ff02::fb%en0                            33:33:0:0:0:fb     en0 permanent R
";

    fn ips(p: &Parsed) -> Vec<String> {
        p.rows.iter().map(|r| r.ip.to_string()).collect()
    }

    #[test]
    fn arp_parser_keeps_resolved_unicast_rows_only() {
        let p = parse_arp_output(ARP_SAMPLE);
        assert_eq!(
            ips(&p),
            ["192.0.2.1", "192.0.2.9", "198.51.100.4", "192.0.2.30"]
        );
        assert_eq!(p.recognized, 9);
        assert_eq!(p.unrecognized, 0);
        let first = &p.rows[0];
        assert_eq!(first.mac, [2, 0, 0, 0, 0, 1], "single-digit hex groups");
        assert_eq!(first.iface, "en0");
        assert!(first.ifscope);
        assert!(!p.rows[3].ifscope, "a row without the ifscope flag");
        assert_eq!(p.rows[2].iface, "en5");
    }

    #[test]
    fn broadcast_hardware_address_rows_are_skipped() {
        // Built at runtime so no all-ones MAC literal sits in the source.
        let line = format!(
            "? (192.0.2.255) at {} on en0 ifscope [ethernet]\n",
            ["ff"; 6].join(":")
        );
        let p = parse_arp_output(&line);
        assert!(p.rows.is_empty());
        assert_eq!(p.recognized, 1);
        // NEGATIVE CONTROL: the same line with an ordinary address is kept.
        let ok = line.replace(&["ff"; 6].join(":"), "2:0:0:0:0:5");
        assert_eq!(parse_arp_output(&ok).rows.len(), 1);
    }

    #[test]
    fn ndp_parser_handles_zones_incomplete_permanent_and_multicast() {
        let p = parse_ndp_output(NDP_SAMPLE);
        assert_eq!(
            ips(&p),
            ["2001:db8::10", "fe80::1", "fe80::20", "fe80::30"],
            "%en0 zone stripped; permanent, incomplete and multicast skipped"
        );
        assert_eq!(p.rows[1].mac, [2, 0, 0, 0, 0, 1]);
        assert_eq!(p.rows[3].iface, "en5");
        assert_eq!(p.unrecognized, 0);
        assert!(p.recognized >= 9, "header + rows all recognized");
    }

    #[test]
    fn garbage_and_truncated_lines_never_panic() {
        let junk = "\
? (192.0.2.1) at 2:0:0:0:0:1 on
? (192.0.2.1) at
? (192.0.2.1
(((( at at at
? (999.1.1.1) at 2:0:0:0:0:1 on en0 ifscope
? (192.0.2.5) at 2:0:0:0:0:zz on en0
? (192.0.2.6) at 2:0:0:0:0:1:2 on en0
\u{0}\u{1}\u{2}
";
        let p = parse_arp_output(junk);
        assert!(p.rows.is_empty());
        let q = parse_ndp_output("fe80::1%en0 2:0:0:0:0:1\nfe80::2%en0\n::::\n\u{0}\n");
        assert!(q.rows.is_empty());
        // Truncated mid-line: earlier complete rows survive.
        let cut = &ARP_SAMPLE[..ARP_SAMPLE.len() - 20];
        assert!(parse_arp_output(cut).rows.len() >= 3);
        assert!(parse_arp_output("").rows.is_empty());
        assert!(parse_ndp_output("").rows.is_empty());
    }

    #[test]
    fn mac_text_forms() {
        assert_eq!(parse_mac("a:b:c:d:e:f"), Some([10, 11, 12, 13, 14, 15]));
        assert_eq!(
            parse_mac("02:bb:cc:dd:ee:0f"),
            Some([2, 0xbb, 0xcc, 0xdd, 0xee, 0x0f])
        );
        for bad in [
            "",
            "(incomplete)",
            "a:b:c:d:e",
            "a:b:c:d:e:f:0",
            "aaa:b:c:d:e:f",
            "g:b:c:d:e:f",
            "a::c:d:e:f",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
    }

    struct Fake(Result<String, ToolFailure>);
    impl Runner for Fake {
        fn run(&self, _tool: Tool) -> Result<String, ToolFailure> {
            self.0.clone()
        }
    }

    #[test]
    fn runner_failures_become_typed_reasons_with_no_rows() {
        for failure in [
            ToolFailure::Missing(Tool::Arp),
            ToolFailure::Failed(Tool::Arp),
            ToolFailure::TimedOut(Tool::Arp),
        ] {
            let r = read_tool(&Fake(Err(failure)), Tool::Arp);
            assert_eq!(r.failure, Some(failure));
            assert!(r.rows.is_empty());
            assert!(!failure.reason().is_empty());
        }
        assert_eq!(
            ToolFailure::Missing(Tool::Ndp).reason(),
            "macOS has no ndp tool"
        );
    }

    #[test]
    fn unparseable_output_is_a_failure_but_an_empty_table_is_not() {
        let r = read_tool(
            &Fake(Ok("Segmentation fault\nwho knows\n".into())),
            Tool::Arp,
        );
        assert_eq!(r.failure, Some(ToolFailure::Unparseable(Tool::Arp)));
        assert!(r.rows.is_empty());
        // NEGATIVE CONTROL: genuinely empty output is a quiet network, not a failure.
        let r = read_tool(&Fake(Ok(String::new())), Tool::Arp);
        assert_eq!(r.failure, None);
        // And an ndp table with only a header and skipped rows is fine too.
        let r = read_tool(
            &Fake(Ok(
                "Neighbor Linklayer Address Netif Expire St Flgs Prbs\n".into()
            )),
            Tool::Ndp,
        );
        assert_eq!(r.failure, None);
        // Good output parses.
        let r = read_tool(&Fake(Ok(ARP_SAMPLE.into())), Tool::Arp);
        assert_eq!((r.failure, r.rows.len()), (None, 4));
    }

    #[test]
    fn rows_become_entries_for_the_wifi_interface_only() {
        let a = parse_arp_output(ARP_SAMPLE);
        let v4 = arp_entries(&a.rows, "en0", 11);
        assert_eq!(v4.len(), 3);
        assert!(v4.iter().all(|e| e.if_index == 11));
        let n = parse_ndp_output(NDP_SAMPLE);
        let v6 = nd6_entries(&n.rows, "en0", 11);
        assert_eq!(v6.len(), 3, "the en5 row is dropped");
        // Family separation.
        assert!(arp_entries(&n.rows, "en0", 11).is_empty());
        assert!(nd6_entries(&a.rows, "en0", 11).is_empty());
    }

    #[test]
    fn real_runner_times_out_and_kills_the_child() {
        // A zero timeout expires on the first poll, before `arp` can finish. Retry in case the
        // child wins the race once; it must lose at least once in 50 tries.
        let mut timed_out = false;
        for _ in 0..50 {
            if matches!(
                run_with_timeout(Tool::Arp, Duration::ZERO),
                Err(ToolFailure::TimedOut(Tool::Arp))
            ) {
                timed_out = true;
                break;
            }
        }
        assert!(timed_out, "timeout path never taken");
        // NEGATIVE CONTROL: with a real timeout the same call returns text (macOS) or a typed
        // failure elsewhere, never a timeout.
        let r = run_with_timeout(Tool::Arp, TOOL_TIMEOUT);
        assert!(!matches!(r, Err(ToolFailure::TimedOut(_))));
    }

    /// Prints counts only. `cargo test -- --ignored systools_live --nocapture`.
    #[test]
    #[ignore]
    fn systools_live() {
        for tool in [Tool::Arp, Tool::Ndp] {
            let r = read_tool(&SystemRunner, tool);
            println!(
                "systools_live: {} rows={} failure={:?}",
                tool.name(),
                r.rows.len(),
                r.failure.map(|f| f.reason())
            );
        }
    }
}
