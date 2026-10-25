//! The opt-in sweep: one zero-byte UDP datagram to port 9 per host. This is the ONLY file in
//! the crate that transmits on the LAN, and `tests/lan_listen_only.rs` fails if any other file
//! under `lan/` gains a send or connect call.
//!
//! Never here: TCP, port scans, service probes, mDNS queries. The caller ([`super::scan`])
//! only gets here through [`super::gate::may_sweep`].

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use super::gate::{send_interval, MAX_SWEEP_HOSTS, SWEEP_PORT};

/// Where a datagram goes out. A trait so tests can record what would have been sent.
pub trait DatagramSink {
    /// Send one zero-byte datagram to `to`.
    fn send_empty(&mut self, to: SocketAddrV4) -> io::Result<()>;
}

/// The real sink: an unconnected UDP socket on an ephemeral port.
pub struct UdpSink {
    socket: UdpSocket,
}

impl UdpSink {
    pub fn new() -> io::Result<UdpSink> {
        Ok(UdpSink {
            socket: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        })
    }
}

impl DatagramSink for UdpSink {
    fn send_empty(&mut self, to: SocketAddrV4) -> io::Result<()> {
        self.socket.send_to(&[], to).map(|_| ())
    }
}

/// Counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub sent: usize,
    pub failed: usize,
}

/// Send one empty datagram to each of `hosts` (at most [`MAX_SWEEP_HOSTS`]), calling `sleep`
/// with [`send_interval`] between datagrams. The pause is on top of however long a send takes,
/// so the real rate can only be lower than 50/s. A failed send (no route, buffer full) is
/// counted and skipped.
pub fn run_sweep<S: DatagramSink>(
    sink: &mut S,
    hosts: &[Ipv4Addr],
    mut sleep: impl FnMut(Duration),
) -> SweepStats {
    let mut stats = SweepStats::default();
    for (i, host) in hosts.iter().take(MAX_SWEEP_HOSTS).enumerate() {
        if i > 0 {
            sleep(send_interval());
        }
        match sink.send_empty(SocketAddrV4::new(*host, SWEEP_PORT)) {
            Ok(()) => stats.sent += 1,
            Err(_) => stats.failed += 1,
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        sent: Vec<SocketAddrV4>,
        fail_every: Option<usize>,
    }

    impl DatagramSink for Recorder {
        fn send_empty(&mut self, to: SocketAddrV4) -> io::Result<()> {
            let n = self.sent.len() + 1;
            self.sent.push(to);
            match self.fail_every {
                Some(k) if n % k == 0 => Err(io::Error::other("synthetic")),
                _ => Ok(()),
            }
        }
    }

    fn hosts(n: u32) -> Vec<Ipv4Addr> {
        (0..n).map(|i| Ipv4Addr::from(0xC000_0200 + i)).collect()
    }

    #[test]
    fn every_datagram_goes_to_port_9_once_and_is_paced() {
        let mut rec = Recorder::default();
        let list = hosts(100);
        let mut slept = Duration::ZERO;
        let stats = run_sweep(&mut rec, &list, |d| slept += d);
        assert_eq!(
            stats,
            SweepStats {
                sent: 100,
                failed: 0
            }
        );
        assert_eq!(rec.sent.len(), 100);
        assert!(rec.sent.iter().all(|a| a.port() == 9));
        let dests: Vec<Ipv4Addr> = rec.sent.iter().map(|a| *a.ip()).collect();
        assert_eq!(dests, list, "one datagram per host, in order, none extra");
        // 99 gaps of 20 ms: at most 50 datagrams per second.
        assert_eq!(slept, Duration::from_millis(99 * 20));
    }

    #[test]
    fn host_list_is_capped_at_512() {
        let mut rec = Recorder::default();
        let stats = run_sweep(&mut rec, &hosts(5000), |_| {});
        assert_eq!(stats.sent, MAX_SWEEP_HOSTS);
        assert_eq!(rec.sent.len(), MAX_SWEEP_HOSTS);
    }

    #[test]
    fn failures_are_counted_not_fatal() {
        let mut rec = Recorder {
            fail_every: Some(4),
            ..Default::default()
        };
        let stats = run_sweep(&mut rec, &hosts(8), |_| {});
        assert_eq!(stats, SweepStats { sent: 6, failed: 2 });
        assert_eq!(rec.sent.len(), 8);
    }

    #[test]
    fn empty_host_list_sends_nothing() {
        let mut rec = Recorder::default();
        let mut sleeps = 0;
        let stats = run_sweep(&mut rec, &[], |_| sleeps += 1);
        assert_eq!(stats, SweepStats::default());
        assert!(rec.sent.is_empty());
        assert_eq!(sleeps, 0);
    }
}
