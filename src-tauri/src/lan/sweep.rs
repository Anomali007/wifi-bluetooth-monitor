//! The opt-in sweep. Two kinds of packet, nothing else:
//!
//! 1. ONE ICMPv6 echo request to the link-local all-nodes address `ff02::1`, scoped to the
//!    Wi-Fi interface (hop limit 1).
//! 2. ONE zero-byte UDP datagram to port 9 (discard) of each IPv4 address on the joined
//!    network, at most [`MAX_PER_SEC`] per second, only when the subnet is [`MIN_PREFIX`] or
//!    smaller (a /23 or tighter), skipping the network, broadcast and our own address. The
//!    datagram has no payload and TTL 1; its only purpose is to make the kernel ARP for the
//!    host so the neighbor table learns it.
//!
//! This is the ONLY file in the crate that transmits on the LAN, and `tests/lan_listen_only.rs`
//! fails if any other file under `lan/` gains a send or connect call.
//!
//! Never here: TCP, port scans, service probes, mDNS queries. Both sockets are unprivileged
//! datagram sockets, and the caller ([`super::scan`]) only gets here through
//! [`super::gate::may_sweep`].

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use super::gate::{GateToken, Subnet};

/// `ff02::1`: every IPv6 node on the link.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// UDP "discard" port.
pub const DISCARD_PORT: u16 = 9;
/// Highest IPv4 send rate.
pub const MAX_PER_SEC: u32 = 50;
/// Gap between IPv4 datagrams that keeps the rate at or under [`MAX_PER_SEC`].
pub const SEND_GAP: Duration = Duration::from_millis(1000 / MAX_PER_SEC as u64);
/// The IPv4 pass runs only when the subnet prefix is at least this long (a /23 is 510 hosts).
pub const MIN_PREFIX: u8 = 23;
/// ICMPv6 type 128.
const ECHO_REQUEST: u8 = 128;
/// Identifier ("WM"). Datagram ICMP sockets let the kernel pick its own; this is a hint.
const ECHO_ID: u16 = 0x574d;

/// An 8-byte ICMPv6 echo request with no payload. The checksum is left zero: the kernel fills
/// it in for ICMPv6 sockets (it needs the source address, which only the kernel knows).
pub fn echo_request(seq: u16) -> [u8; 8] {
    let id = ECHO_ID.to_be_bytes();
    let seq = seq.to_be_bytes();
    [ECHO_REQUEST, 0, 0, 0, id[0], id[1], seq[0], seq[1]]
}

/// Why the IPv4 pass was skipped (the ICMPv6 echo still goes out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4Skip {
    /// The subnet is larger than a /23.
    TooLarge,
    /// The subnet is not in a private, link-local or shared-address range.
    NotPrivate,
}

impl V4Skip {
    pub fn message(self) -> &'static str {
        match self {
            V4Skip::TooLarge => "the network is larger than a /23",
            V4Skip::NotPrivate => "the network is not in a private address range",
        }
    }
}

fn private_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_private() || a.is_link_local() || (o[0] == 100 && o[1] & 0xc0 == 64)
}

/// The IPv4 addresses the sweep may send to: every host in `subnet` except the network address,
/// the broadcast address and our own. `Err` when the subnet is too large or not private.
pub fn v4_targets(subnet: &Subnet) -> Result<Vec<Ipv4Addr>, V4Skip> {
    if subnet.prefix < MIN_PREFIX {
        return Err(V4Skip::TooLarge);
    }
    if !private_v4(subnet.addr) {
        return Err(V4Skip::NotPrivate);
    }
    let (net, bcast) = (u32::from(subnet.network()), u32::from(subnet.broadcast()));
    if bcast <= net + 1 {
        return Ok(Vec::new());
    }
    Ok((net + 1..bcast)
        .map(Ipv4Addr::from)
        .filter(|a| *a != subnet.addr)
        .collect())
}

/// Where packets go out. A trait so tests can record what would have been sent.
pub trait SweepSink {
    /// Send `packet` (an ICMPv6 message) to `to`.
    fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()>;
    /// Send one zero-byte UDP datagram to `to`.
    fn send_udp(&mut self, to: SocketAddrV4) -> io::Result<()>;
    /// Called between IPv4 sends to hold the rate; the real sink sleeps [`SEND_GAP`].
    fn pace(&mut self) {}
}

/// The real sink: an unprivileged ICMPv6 datagram socket and a UDP socket, both pinned to one
/// interface.
pub struct NetSink {
    icmp: Socket,
    udp: Socket,
}

impl NetSink {
    /// Needs the [`GateToken`] that only [`super::gate::may_sweep`] hands out.
    pub fn new(token: GateToken) -> io::Result<NetSink> {
        let if_index = token.if_index();
        let icmp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
        icmp.set_multicast_if_v6(u32::from(if_index))?;
        icmp.set_multicast_hops_v6(1)?;
        icmp.set_multicast_loop_v6(false)?;
        let udp = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp.set_ttl_v4(1)?;
        #[cfg(target_os = "macos")]
        if let Some(idx) = std::num::NonZeroU32::new(u32::from(if_index)) {
            udp.bind_device_by_index_v4(Some(idx))?;
        }
        Ok(NetSink { icmp, udp })
    }
}

impl SweepSink for NetSink {
    fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()> {
        self.icmp
            .send_to(packet, &SocketAddr::V6(to).into())
            .map(|_| ())
    }

    fn send_udp(&mut self, to: SocketAddrV4) -> io::Result<()> {
        self.udp
            .send_to(&[], &SocketAddr::V4(to).into())
            .map(|_| ())
    }

    fn pace(&mut self) {
        std::thread::sleep(SEND_GAP);
    }
}

/// Counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// ICMPv6 echo requests sent (0 or 1).
    pub sent_v6: usize,
    /// UDP datagrams sent.
    pub sent_v4: usize,
    pub failed: usize,
    /// Why the IPv4 pass did not run, when it did not.
    pub v4_skip: Option<V4Skip>,
    /// The run stopped early because the network or the setting changed under it.
    pub aborted: bool,
}

/// Sends between checks that the joined network and the setting are unchanged.
pub const RECHECK_EVERY: usize = 16;

/// Send exactly one echo request to `ff02::1` on interface `if_index`, then one zero-byte UDP
/// datagram to port 9 of each IPv4 host in `subnet` (when there is one and it qualifies). A
/// failed send is counted, not retried.
pub fn run_sweep<S: SweepSink>(
    sink: &mut S,
    if_index: u16,
    subnet: Option<&Subnet>,
    still_ok: &mut dyn FnMut() -> bool,
) -> SweepStats {
    let mut stats = SweepStats::default();
    let mut attempts = 1usize;
    let to = SocketAddrV6::new(ALL_NODES, 0, 0, u32::from(if_index));
    match sink.send_echo(to, &echo_request(1)) {
        Ok(()) => stats.sent_v6 = 1,
        Err(_) => stats.failed += 1,
    }
    let Some(subnet) = subnet else {
        return stats;
    };
    match v4_targets(subnet) {
        Err(skip) => stats.v4_skip = Some(skip),
        Ok(hosts) => {
            for (i, host) in hosts.into_iter().enumerate() {
                if i > 0 {
                    sink.pace();
                }
                // Every RECHECK_EVERY sends, ask whether the network and the setting are still
                // what the sweep was approved on; stop at once if not.
                if attempts % RECHECK_EVERY == 0 && !still_ok() {
                    stats.aborted = true;
                    break;
                }
                attempts += 1;
                match sink.send_udp(SocketAddrV4::new(host, DISCARD_PORT)) {
                    Ok(()) => stats.sent_v4 += 1,
                    Err(_) => stats.failed += 1,
                }
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        echoes: Vec<(SocketAddrV6, Vec<u8>)>,
        udp: Vec<SocketAddrV4>,
        paces: usize,
        fail: bool,
    }

    impl SweepSink for Recorder {
        fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()> {
            self.echoes.push((to, packet.to_vec()));
            if self.fail {
                Err(io::Error::other("synthetic"))
            } else {
                Ok(())
            }
        }
        fn send_udp(&mut self, to: SocketAddrV4) -> io::Result<()> {
            self.udp.push(to);
            if self.fail {
                Err(io::Error::other("synthetic"))
            } else {
                Ok(())
            }
        }
        fn pace(&mut self) {
            self.paces += 1;
        }
    }

    fn subnet(last: u8, prefix: u8) -> Subnet {
        Subnet {
            addr: Ipv4Addr::new(192, 168, 77, last),
            prefix,
        }
    }

    #[test]
    fn one_echo_request_to_all_nodes_on_the_wifi_interface() {
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, 11, None, &mut || true);
        assert_eq!(
            stats,
            SweepStats {
                sent_v6: 1,
                ..Default::default()
            }
        );
        assert_eq!(rec.echoes.len(), 1, "exactly one ICMPv6 packet per run");
        assert!(rec.udp.is_empty(), "no IPv4 subnet, no UDP");
        let (to, packet) = &rec.echoes[0];
        assert_eq!(*to.ip(), "ff02::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(to.scope_id(), 11, "scoped to the Wi-Fi interface");
        assert_eq!(packet.len(), 8, "header only, no payload");
        assert_eq!(packet[0], 128, "ICMPv6 echo request");
        assert_eq!(packet[1], 0, "code 0");
    }

    #[test]
    fn one_echo_plus_one_udp_per_host_on_a_slash_24() {
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, 11, Some(&subnet(7, 24)), &mut || true);
        // 254 hosts, minus ourselves (.7).
        assert_eq!(rec.udp.len(), 253);
        assert_eq!(rec.echoes.len(), 1);
        assert_eq!((stats.sent_v6, stats.sent_v4, stats.failed), (1, 253, 0));
        assert!(rec.udp.iter().all(|a| a.port() == 9));
        assert!(!rec
            .udp
            .iter()
            .any(|a| *a.ip() == Ipv4Addr::new(192, 168, 77, 7)));
        assert!(!rec
            .udp
            .iter()
            .any(|a| *a.ip() == Ipv4Addr::new(192, 168, 77, 0)));
        assert!(!rec
            .udp
            .iter()
            .any(|a| *a.ip() == Ipv4Addr::new(192, 168, 77, 255)));
        assert_eq!(rec.paces, 252, "a gap between every pair of datagrams");
        // The gap really is a rate limit of at most 50/s.
        assert!(SEND_GAP >= Duration::from_millis(20));
    }

    #[test]
    fn a_slash_23_is_swept_and_a_slash_22_is_not() {
        let mut rec = Recorder::default();
        let s23 = Subnet {
            addr: Ipv4Addr::new(10, 0, 0, 9),
            prefix: 23,
        };
        let stats = run_sweep(&mut rec, 11, Some(&s23), &mut || true);
        assert_eq!(rec.udp.len(), 510 - 1);
        assert_eq!(stats.v4_skip, None);

        let mut rec = Recorder::default();
        let s22 = Subnet {
            addr: Ipv4Addr::new(10, 0, 0, 9),
            prefix: 22,
        };
        let stats = run_sweep(&mut rec, 11, Some(&s22), &mut || true);
        assert_eq!(rec.udp.len(), 0, "zero UDP when larger than a /23");
        assert_eq!(rec.echoes.len(), 1, "the ICMPv6 echo still goes out");
        assert_eq!(stats.v4_skip, Some(V4Skip::TooLarge));
        assert_eq!((stats.sent_v6, stats.sent_v4), (1, 0));
        // And a /8 is no different.
        let mut rec = Recorder::default();
        let s8 = Subnet {
            addr: Ipv4Addr::new(10, 1, 2, 3),
            prefix: 8,
        };
        run_sweep(&mut rec, 11, Some(&s8), &mut || true);
        assert!(rec.udp.is_empty());
    }

    #[test]
    fn a_public_range_is_never_swept_over_ipv4() {
        let mut rec = Recorder::default();
        let public = Subnet {
            addr: Ipv4Addr::new(198, 51, 100, 7),
            prefix: 24,
        };
        let stats = run_sweep(&mut rec, 11, Some(&public), &mut || true);
        assert!(rec.udp.is_empty());
        assert_eq!(stats.v4_skip, Some(V4Skip::NotPrivate));
        for a in [
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
        ] {
            assert!(private_v4(a), "{a}");
        }
        assert!(!private_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn tiny_subnets_have_no_hosts() {
        for prefix in [31u8, 32] {
            let mut rec = Recorder::default();
            let s = Subnet {
                addr: Ipv4Addr::new(192, 168, 77, 1),
                prefix,
            };
            run_sweep(&mut rec, 11, Some(&s), &mut || true);
            assert!(rec.udp.is_empty(), "/{prefix}");
            assert_eq!(rec.echoes.len(), 1);
        }
    }

    #[test]
    fn failed_sends_are_counted_and_not_retried() {
        let mut rec = Recorder {
            fail: true,
            ..Default::default()
        };
        let stats = run_sweep(&mut rec, 11, Some(&subnet(7, 30)), &mut || true);
        // One echo attempt, and one attempt per IPv4 host, each counted as a failure.
        assert_eq!(rec.echoes.len(), 1, "no retry");
        assert_eq!(stats.sent_v6 + stats.sent_v4, 0);
        assert_eq!(stats.failed, 1 + rec.udp.len());
    }

    #[test]
    fn every_run_sends_one_echo_never_more() {
        // NEGATIVE CONTROL for "exactly one": the recorder does count more than one if asked.
        let mut rec = Recorder::default();
        let to = SocketAddrV6::new(ALL_NODES, 0, 0, 1);
        rec.send_echo(to, &echo_request(1)).unwrap();
        rec.send_echo(to, &echo_request(2)).unwrap();
        assert_eq!(rec.echoes.len(), 2);
        for if_index in [1u16, 4, 11, 65535] {
            let mut rec = Recorder::default();
            run_sweep(&mut rec, if_index, Some(&subnet(7, 24)), &mut || true);
            assert_eq!(rec.echoes.len(), 1);
            assert_eq!(rec.echoes[0].0.scope_id(), u32::from(if_index));
        }
    }

    /// Sends one echo to ff02::1 scoped to the LOOPBACK interface only, so nothing reaches the
    /// real network. Proves the unprivileged ICMPv6 datagram socket opens and sends on this
    /// macOS. `cargo test -- --ignored sweep_loopback --nocapture`.
    #[test]
    #[ignore]
    fn sweep_loopback() {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the argument is a valid NUL-terminated string.
            let lo = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
            let mut sink = match NetSink::new(GateToken::for_tests(lo as u16)) {
                Ok(s) => s,
                Err(e) => {
                    println!("sweep_loopback: socket error kind={:?}", e.kind());
                    return;
                }
            };
            let stats = run_sweep(&mut sink, lo as u16, None, &mut || true);
            println!(
                "sweep_loopback: sent_v6={} failed={}",
                stats.sent_v6, stats.failed
            );
        }
    }

    #[test]
    fn the_sweep_asks_every_sixteen_sends_and_stops_when_told() {
        // The echo is send 1, so the first question comes after UDP send 15.
        let mut asked = 0;
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, 11, Some(&subnet(7, 24)), &mut || {
            asked += 1;
            asked < 3
        });
        assert!(stats.aborted);
        assert_eq!(asked, 3);
        assert_eq!(rec.echoes.len() + rec.udp.len(), 3 * RECHECK_EVERY);
        // NEGATIVE CONTROL: answering yes every time sends everything and never aborts.
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, 11, Some(&subnet(7, 24)), &mut || true);
        assert!(!stats.aborted);
        assert_eq!(rec.udp.len(), 253);
    }
}
