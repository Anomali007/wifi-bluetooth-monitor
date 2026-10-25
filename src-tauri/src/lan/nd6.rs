//! The IPv6 neighbor table, read with `sysctl` (`CTL_NET, PF_ROUTE, 0, AF_INET6, NET_RT_FLAGS,
//! RTF_LLINFO`), the call `ndp -an` makes, without running it. Read-only: the kernel hands back
//! what it already learned. On macOS 27 this is the table non-platform binaries CAN read (the
//! IPv4 ARP table comes back empty), so it is the main source of hardware addresses.
//!
//! Same safety rules as [`super::arp`]: the parser works on a plain byte buffer, never trusts a
//! length field, and treats malformed input as "stop walking", never a panic.

use std::net::Ipv6Addr;

use super::arp::{
    i32_at, parse_sockaddr_dl, sa_size, u16_at, usable_mac, MAX_ENTRIES, OFF_ADDRS, OFF_INDEX,
    OFF_MSGLEN, OFF_TYPE, RTA_DST, RTA_GATEWAY, RTM_GET, RT_MSGHDR_LEN,
};

/// `AF_INET6` on macOS.
const AF_INET6: u8 = 30;
/// Bytes of a `sockaddr_in6` the parser needs (through the address).
const SOCKADDR_IN6_MIN: usize = 24;

/// One resolved IPv6 neighbor: address, hardware address, and the interface it was learned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub if_index: u16,
}

/// Link-local addresses carry their interface index inside the address (`fe80:0004::1`, the
/// KAME embedding) in kernel tables. Clear it so the address reads as the user would write it.
pub fn normalize_v6(ip: Ipv6Addr) -> Ipv6Addr {
    let mut o = ip.octets();
    let link_local_unicast = o[0] == 0xfe && o[1] & 0xc0 == 0x80;
    let link_local_multicast = o[0] == 0xff && o[1] & 0x0f == 0x02;
    if link_local_unicast || link_local_multicast {
        o[2] = 0;
        o[3] = 0;
    }
    Ipv6Addr::from(o)
}

/// Addresses that are not a unicast neighbor.
fn usable_ip(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

/// Parse a NET_RT_FLAGS dump into neighbors. Incomplete entries (no hardware address yet),
/// multicast rows and anything malformed are skipped. A truncated or garbage buffer yields
/// whatever parsed cleanly before the damage, never a panic.
pub fn parse_nd6_buffer(buf: &[u8]) -> Vec<NeighborEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + RT_MSGHDR_LEN <= buf.len() && out.len() < MAX_ENTRIES {
        let Some(msglen) = u16_at(buf, off + OFF_MSGLEN).map(usize::from) else {
            break;
        };
        if msglen < RT_MSGHDR_LEN || off + msglen > buf.len() {
            break;
        }
        let msg = &buf[off..off + msglen];
        if msg[OFF_TYPE] == RTM_GET {
            if let Some(entry) = parse_message(msg) {
                out.push(entry);
            }
        }
        off += msglen;
    }
    out
}

fn parse_message(msg: &[u8]) -> Option<NeighborEntry> {
    let if_index = u16_at(msg, OFF_INDEX)?;
    let addrs = i32_at(msg, OFF_ADDRS)?;
    if addrs & RTA_DST == 0 || addrs & RTA_GATEWAY == 0 {
        return None;
    }
    let mut ip = None;
    let mut mac = None;
    let mut off = RT_MSGHDR_LEN;
    // DST (bit 0) is a sockaddr_in6, GATEWAY (bit 1) a sockaddr_dl; later ones are not needed.
    for bit in 0..2 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let sa_len = *msg.get(off)?;
        let size = sa_size(sa_len);
        let sa = msg.get(off..off + size)?;
        let valid = usize::from(sa_len).min(size);
        match bit {
            0 => ip = parse_sockaddr_in6(&sa[..valid]),
            _ => mac = parse_sockaddr_dl(&sa[..valid]),
        }
        off += size;
    }
    let (ip, mac) = (ip?, mac?);
    (usable_ip(ip) && usable_mac(&mac)).then_some(NeighborEntry { ip, mac, if_index })
}

/// `struct sockaddr_in6`: len, family, port(2), flowinfo(4), addr(16), scope_id(4).
fn parse_sockaddr_in6(sa: &[u8]) -> Option<Ipv6Addr> {
    if sa.len() < SOCKADDR_IN6_MIN || sa[1] != AF_INET6 {
        return None;
    }
    let octets: [u8; 16] = sa.get(8..24)?.try_into().ok()?;
    Some(normalize_v6(Ipv6Addr::from(octets)))
}

/// Read the kernel's IPv6 neighbor table. macOS only; elsewhere an empty table.
#[cfg(target_os = "macos")]
pub fn read_neighbor_table() -> std::io::Result<Vec<NeighborEntry>> {
    Ok(parse_nd6_buffer(&super::arp::read_route_dump(
        libc::AF_INET6,
    )?))
}

#[cfg(not(target_os = "macos"))]
pub fn read_neighbor_table() -> std::io::Result<Vec<NeighborEntry>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const MAC_2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    fn sockaddr_in6(ip: Ipv6Addr) -> Vec<u8> {
        let mut v = vec![28, AF_INET6, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&ip.octets());
        v.resize(28, 0);
        v
    }

    fn sockaddr_dl(mac: &[u8], nlen: u8) -> Vec<u8> {
        let alen = mac.len() as u8;
        let len = 8 + nlen + alen;
        let mut v = vec![len, super::super::arp::AF_LINK, 0, 0, 6, nlen, alen, 0];
        v.extend(std::iter::repeat_n(b'e', nlen as usize));
        v.extend_from_slice(mac);
        v.resize(sa_size(len), 0);
        v
    }

    fn message(ip: Ipv6Addr, dl: Vec<u8>, if_index: u16) -> Vec<u8> {
        let mut m = vec![0u8; RT_MSGHDR_LEN];
        m[OFF_TYPE] = RTM_GET;
        m[OFF_INDEX..OFF_INDEX + 2].copy_from_slice(&if_index.to_ne_bytes());
        m[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&(RTA_DST | RTA_GATEWAY).to_ne_bytes());
        m.extend(sockaddr_in6(ip));
        m.extend(dl);
        let len = m.len() as u16;
        m[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
        m
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_global_and_link_local_entries() {
        let mut buf = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        // Link-local with the KAME-embedded scope (interface 11 = 0x000b) in bytes 2..4.
        buf.extend(message(v6("fe80:b::2"), sockaddr_dl(&MAC_2, 3), 11));
        let got = parse_nd6_buffer(&buf);
        assert_eq!(
            got,
            vec![
                NeighborEntry {
                    ip: v6("2001:db8::10"),
                    mac: MAC_1,
                    if_index: 11
                },
                NeighborEntry {
                    ip: v6("fe80::2"),
                    mac: MAC_2,
                    if_index: 11
                },
            ]
        );
    }

    #[test]
    fn skips_incomplete_multicast_loopback_and_bad_mac_entries() {
        let mut buf = Vec::new();
        // Incomplete: no link-layer address yet.
        buf.extend(message(v6("2001:db8::20"), sockaddr_dl(&[], 0), 11));
        // Multicast destination.
        buf.extend(message(v6("ff02::1"), sockaddr_dl(&MAC_1, 0), 11));
        buf.extend(message(v6("ff02:b::fb"), sockaddr_dl(&MAC_1, 0), 11));
        // Unspecified and loopback.
        buf.extend(message(v6("::"), sockaddr_dl(&MAC_1, 0), 11));
        buf.extend(message(v6("::1"), sockaddr_dl(&MAC_1, 0), 11));
        // Multicast / broadcast / zero hardware addresses.
        buf.extend(message(
            v6("2001:db8::21"),
            sockaddr_dl(&[0x33, 0x33, 0, 0, 0, 1], 0),
            11,
        ));
        buf.extend(message(v6("2001:db8::22"), sockaddr_dl(&[0xff; 6], 0), 11));
        buf.extend(message(v6("2001:db8::23"), sockaddr_dl(&[0; 6], 0), 11));
        // One good entry at the end proves the walk continued past every skip.
        buf.extend(message(v6("2001:db8::30"), sockaddr_dl(&MAC_2, 0), 11));
        let got = parse_nd6_buffer(&buf);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, v6("2001:db8::30"));
    }

    #[test]
    fn wrong_type_and_family_are_skipped() {
        let mut m = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        m[OFF_TYPE] = 1; // RTM_ADD
        assert!(parse_nd6_buffer(&m).is_empty());
        let mut m = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        m[RT_MSGHDR_LEN + 1] = 2; // dst family AF_INET
        assert!(parse_nd6_buffer(&m).is_empty());
        let mut m = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        m[RT_MSGHDR_LEN + 28 + 1] = AF_INET6; // gateway family not AF_LINK
        assert!(parse_nd6_buffer(&m).is_empty());
        // A message carrying only a destination has no hardware address.
        let mut m = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        m[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&RTA_DST.to_ne_bytes());
        assert!(parse_nd6_buffer(&m).is_empty());
    }

    #[test]
    fn truncated_and_garbage_input_never_panics() {
        let good = message(v6("2001:db8::10"), sockaddr_dl(&MAC_1, 0), 11);
        assert_eq!(
            parse_nd6_buffer(&good).len(),
            1,
            "control: the full buffer parses"
        );
        for cut in 0..good.len() {
            let _ = parse_nd6_buffer(&good[..cut]);
        }
        assert!(parse_nd6_buffer(&good[..good.len() - 1]).is_empty());
        assert!(parse_nd6_buffer(&[]).is_empty());
        // msglen shorter than the header, and past the buffer.
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&10u16.to_ne_bytes());
        assert!(parse_nd6_buffer(&bad).is_empty());
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(parse_nd6_buffer(&bad).is_empty());
        // sa_len smaller than the fields the parser needs.
        let mut bad = good.clone();
        bad[RT_MSGHDR_LEN] = 12;
        assert!(parse_nd6_buffer(&bad).is_empty());
        // Zero sa_len, and an nlen that runs past the sockaddr_dl.
        let mut bad = good.clone();
        bad[RT_MSGHDR_LEN] = 0;
        let _ = parse_nd6_buffer(&bad);
        let mut bad = good.clone();
        bad[RT_MSGHDR_LEN + 28 + 5] = 200;
        assert!(parse_nd6_buffer(&bad).is_empty());
        // Deterministic pseudo-random garbage, half with a plausible header prefix.
        let mut x: u32 = 0x8765_4321;
        for round in 0..300 {
            let mut junk: Vec<u8> = (0..400)
                .map(|_| {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (x >> 24) as u8
                })
                .collect();
            if round % 2 == 0 {
                junk[..2].copy_from_slice(&200u16.to_ne_bytes());
                junk[OFF_TYPE] = RTM_GET;
                junk[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&3i32.to_ne_bytes());
            }
            let _ = parse_nd6_buffer(&junk);
        }
    }

    #[test]
    fn normalize_clears_only_link_local_scope() {
        assert_eq!(normalize_v6(v6("fe80:4::1")), v6("fe80::1"));
        assert_eq!(normalize_v6(v6("febf:4::1")), v6("febf::1"));
        // Not link-local: untouched (the second group is real address bits).
        assert_eq!(normalize_v6(v6("2001:db8::1")), v6("2001:db8::1"));
        assert_eq!(normalize_v6(v6("fd00:4::1")), v6("fd00:4::1"));
        assert_eq!(normalize_v6(v6("fec0:4::1")), v6("fec0:4::1"));
    }

    /// Reads the real table. Prints counts only. `cargo test -- --ignored nd6_live --nocapture`.
    #[test]
    #[ignore]
    fn nd6_live() {
        match read_neighbor_table() {
            Ok(t) => {
                let ifaces: std::collections::BTreeSet<u16> =
                    t.iter().map(|e| e.if_index).collect();
                println!("nd6_live: entries={} interfaces={}", t.len(), ifaces.len());
                // Interface names are not sensitive; this is how to tell Wi-Fi from AWDL/VPN.
                #[cfg(target_os = "macos")]
                for i in &ifaces {
                    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
                    // SAFETY: `name` is IF_NAMESIZE bytes, as if_indextoname requires.
                    let p = unsafe { libc::if_indextoname(u32::from(*i), name.as_mut_ptr()) };
                    let n = if p.is_null() {
                        "?".to_string()
                    } else {
                        // SAFETY: on success the buffer holds a NUL-terminated name.
                        unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                            .to_string_lossy()
                            .into_owned()
                    };
                    println!(
                        "nd6_live: interface {n} (index {i}) rows={}",
                        t.iter().filter(|e| e.if_index == *i).count()
                    );
                }
            }
            Err(e) => println!("nd6_live: error kind={:?}", e.kind()),
        }
    }
}
