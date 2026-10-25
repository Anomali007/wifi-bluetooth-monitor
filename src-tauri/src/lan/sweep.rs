//! The opt-in sweep: ONE ICMPv6 echo request to the link-local all-nodes address `ff02::1`,
//! scoped to the Wi-Fi interface. Every IPv6 host on the link answers, which fills the kernel's
//! neighbor table; the caller then re-reads that table. This is the ONLY file in the crate
//! that transmits on the LAN, and `tests/lan_listen_only.rs` fails if any other file under
//! `lan/` gains a send or connect call.
//!
//! Never here: TCP, port scans, service probes, mDNS queries, per-host packets. The socket is
//! unprivileged (`SOCK_DGRAM` + `IPPROTO_ICMPV6`), the hop limit is 1 so the packet cannot
//! leave the link, and the caller ([`super::scan`]) only gets here through
//! [`super::gate::may_sweep`].

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};

/// `ff02::1`: every IPv6 node on the link.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
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

/// Where a packet goes out. A trait so tests can record what would have been sent.
pub trait EchoSink {
    /// Send `packet` (an ICMPv6 message) to `to`.
    fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()>;
}

/// The real sink: an unprivileged ICMPv6 datagram socket pinned to one interface.
pub struct IcmpSink {
    socket: Socket,
}

impl IcmpSink {
    pub fn new(if_index: u16) -> io::Result<IcmpSink> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
        socket.set_multicast_if_v6(u32::from(if_index))?;
        socket.set_multicast_hops_v6(1)?;
        socket.set_multicast_loop_v6(false)?;
        Ok(IcmpSink { socket })
    }
}

impl EchoSink for IcmpSink {
    fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()> {
        self.socket
            .send_to(packet, &SocketAddr::V6(to).into())
            .map(|_| ())
    }
}

/// Counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub sent: usize,
    pub failed: usize,
}

/// Send exactly one echo request to `ff02::1` on interface `if_index`. A failed send (no
/// route, link down) is counted, not retried.
pub fn run_sweep<S: EchoSink>(sink: &mut S, if_index: u16) -> SweepStats {
    let to = SocketAddrV6::new(ALL_NODES, 0, 0, u32::from(if_index));
    match sink.send_echo(to, &echo_request(1)) {
        Ok(()) => SweepStats { sent: 1, failed: 0 },
        Err(_) => SweepStats { sent: 0, failed: 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        sent: Vec<(SocketAddrV6, Vec<u8>)>,
        fail: bool,
    }

    impl EchoSink for Recorder {
        fn send_echo(&mut self, to: SocketAddrV6, packet: &[u8]) -> io::Result<()> {
            self.sent.push((to, packet.to_vec()));
            if self.fail {
                Err(io::Error::other("synthetic"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn one_echo_request_to_all_nodes_on_the_wifi_interface() {
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, 11);
        assert_eq!(stats, SweepStats { sent: 1, failed: 0 });
        assert_eq!(rec.sent.len(), 1, "exactly one packet per run");
        let (to, packet) = &rec.sent[0];
        assert_eq!(*to.ip(), "ff02::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(to.scope_id(), 11, "scoped to the Wi-Fi interface");
        assert_eq!(packet.len(), 8, "header only, no payload");
        assert_eq!(packet[0], 128, "ICMPv6 echo request");
        assert_eq!(packet[1], 0, "code 0");
    }

    #[test]
    fn a_failed_send_is_counted_and_not_retried() {
        let mut rec = Recorder {
            fail: true,
            ..Default::default()
        };
        let stats = run_sweep(&mut rec, 11);
        assert_eq!(stats, SweepStats { sent: 0, failed: 1 });
        assert_eq!(rec.sent.len(), 1, "no retry");
    }

    #[test]
    fn every_run_sends_one_packet_never_more() {
        // NEGATIVE CONTROL for "exactly one": the recorder does count more than one if asked.
        let mut rec = Recorder::default();
        let to = SocketAddrV6::new(ALL_NODES, 0, 0, 1);
        rec.send_echo(to, &echo_request(1)).unwrap();
        rec.send_echo(to, &echo_request(2)).unwrap();
        assert_eq!(rec.sent.len(), 2);
        for if_index in [1u16, 4, 11, 65535] {
            let mut rec = Recorder::default();
            run_sweep(&mut rec, if_index);
            assert_eq!(rec.sent.len(), 1);
            assert_eq!(rec.sent[0].0.scope_id(), u32::from(if_index));
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
            let mut sink = match IcmpSink::new(lo as u16) {
                Ok(s) => s,
                Err(e) => {
                    println!("sweep_loopback: socket error kind={:?}", e.kind());
                    return;
                }
            };
            let direct = sink.send_echo(SocketAddrV6::new(ALL_NODES, 0, 0, lo), &echo_request(1));
            if let Err(e) = &direct {
                println!(
                    "sweep_loopback: direct send errno={:?} kind={:?}",
                    e.raw_os_error(),
                    e.kind()
                );
            }
            let stats = run_sweep(&mut sink, lo as u16);
            println!(
                "sweep_loopback: sent={} failed={}",
                stats.sent, stats.failed
            );
        }
    }
}
