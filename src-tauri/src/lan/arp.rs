//! The neighbor (ARP) table, read with `sysctl` (`CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,
//! RTF_LLINFO`), the same call `arp -an` makes, without running it. Read-only: the kernel
//! hands back what it already learned; nothing is sent.
//!
//! The parser works on a plain byte buffer so it can be tested with synthetic messages. It
//! never trusts a length field: every read is bounds-checked and malformed input just ends
//! the walk.

use std::net::Ipv4Addr;

/// `sizeof(struct rt_msghdr)` on macOS (checked against `libc` in a macOS-only test).
const RT_MSGHDR_LEN: usize = 92;
const OFF_MSGLEN: usize = 0;
const OFF_TYPE: usize = 3;
const OFF_INDEX: usize = 4;
const OFF_ADDRS: usize = 12;
/// `RTM_GET`: what a NET_RT_FLAGS dump returns.
const RTM_GET: u8 = 4;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
/// Most route messages one dump is allowed to yield (a /23 plus slack).
const MAX_ENTRIES: usize = 4096;

/// One resolved neighbor: IPv4 address, hardware address, and the interface it was learned on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub if_index: u16,
}

/// Six lowercase hex pairs joined by colons. The only text form a MAC takes before hashing.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Bytes a sockaddr occupies in a routing message: `sa_len` rounded up to 4, 4 when zero.
fn sa_size(sa_len: u8) -> usize {
    if sa_len == 0 {
        4
    } else {
        (usize::from(sa_len) + 3) & !3
    }
}

/// Hardware addresses that are not a real neighbor: all-zero, broadcast, multicast.
fn usable_mac(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && *mac != [0xff; 6] && mac[0] & 1 == 0
}

/// Addresses that are not a unicast neighbor.
fn usable_ip(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback())
}

/// Parse a NET_RT_FLAGS dump into neighbors. Incomplete entries (no hardware address yet),
/// multicast/broadcast rows and anything malformed are skipped. A truncated or garbage buffer
/// yields whatever parsed cleanly before the damage, never a panic.
pub fn parse_arp_buffer(buf: &[u8]) -> Vec<ArpEntry> {
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

fn parse_message(msg: &[u8]) -> Option<ArpEntry> {
    let if_index = u16_at(msg, OFF_INDEX)?;
    let addrs = i32_at(msg, OFF_ADDRS)?;
    if addrs & RTA_DST == 0 || addrs & RTA_GATEWAY == 0 {
        return None;
    }
    let mut ip = None;
    let mut mac = None;
    let mut off = RT_MSGHDR_LEN;
    // sockaddrs follow the header in RTAX order; only DST (bit 0) and GATEWAY (bit 1) matter
    // here, but the rest must be stepped over in order.
    for bit in 0..8 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let sa_len = *msg.get(off)?;
        let size = sa_size(sa_len);
        let sa = msg.get(off..off + size)?;
        let valid = usize::from(sa_len).min(size);
        match bit {
            0 => ip = parse_sockaddr_in(&sa[..valid]),
            1 => mac = parse_sockaddr_dl(&sa[..valid]),
            _ => {}
        }
        off += size;
        if bit >= 1 {
            break;
        }
    }
    let (ip, mac) = (ip?, mac?);
    (usable_ip(ip) && usable_mac(&mac)).then_some(ArpEntry { ip, mac, if_index })
}

/// `struct sockaddr_in`: len, family, port(2), addr(4).
fn parse_sockaddr_in(sa: &[u8]) -> Option<Ipv4Addr> {
    if sa.len() < 8 || sa[1] != AF_INET {
        return None;
    }
    Some(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]))
}

/// `struct sockaddr_dl`: len, family, index(2), type, nlen, alen, slen, then name + address.
fn parse_sockaddr_dl(sa: &[u8]) -> Option<[u8; 6]> {
    if sa.len() < 8 || sa[1] != AF_LINK {
        return None;
    }
    let (nlen, alen) = (usize::from(sa[5]), usize::from(sa[6]));
    if alen != 6 {
        return None;
    }
    let start = 8 + nlen;
    sa.get(start..start + 6)?.try_into().ok()
}

/// Read the kernel's neighbor table. macOS only; elsewhere an empty table.
#[cfg(target_os = "macos")]
pub fn read_arp_table() -> std::io::Result<Vec<ArpEntry>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_LLINFO,
    ];
    // The table can grow between the size query and the read; retry a few times.
    for _ in 0..4 {
        let mut len: libc::size_t = 0;
        // SAFETY: size query only (null output buffer); `mib` is a valid 6-element array.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        len += len / 8 + 1024;
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` is `len` bytes long and `len` is passed by pointer so the kernel
        // reports how much it wrote.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(len);
            return Ok(parse_arp_buffer(&buf));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
    }
    Err(std::io::Error::other("neighbor table kept changing"))
}

#[cfg(not(target_os = "macos"))]
pub fn read_arp_table() -> std::io::Result<Vec<ArpEntry>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_in(ip: [u8; 4]) -> Vec<u8> {
        let mut v = vec![16, AF_INET, 0, 0, ip[0], ip[1], ip[2], ip[3]];
        v.resize(16, 0);
        v
    }

    fn sockaddr_dl(mac: &[u8], nlen: u8) -> Vec<u8> {
        let alen = mac.len() as u8;
        let len = 8 + nlen + alen;
        let mut v = vec![len, AF_LINK, 0, 0, 6, nlen, alen, 0];
        v.extend(std::iter::repeat_n(b'e', nlen as usize));
        v.extend_from_slice(mac);
        v.resize(sa_size(len), 0);
        v
    }

    /// A synthetic `rt_msghdr` + DST + GATEWAY message.
    fn message(ip: [u8; 4], dl: Vec<u8>, if_index: u16) -> Vec<u8> {
        let mut m = vec![0u8; RT_MSGHDR_LEN];
        m[OFF_TYPE] = RTM_GET;
        m[OFF_INDEX..OFF_INDEX + 2].copy_from_slice(&if_index.to_ne_bytes());
        m[OFF_ADDRS..OFF_ADDRS + 4].copy_from_slice(&(RTA_DST | RTA_GATEWAY).to_ne_bytes());
        m.extend(sockaddr_in(ip));
        m.extend(dl);
        let len = m.len() as u16;
        m[OFF_MSGLEN..OFF_MSGLEN + 2].copy_from_slice(&len.to_ne_bytes());
        m
    }

    const MAC_1: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const MAC_2: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    #[test]
    fn parses_two_entries() {
        let mut buf = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        buf.extend(message([192, 0, 2, 11], sockaddr_dl(&MAC_2, 3), 11));
        let got = parse_arp_buffer(&buf);
        assert_eq!(
            got,
            vec![
                ArpEntry {
                    ip: Ipv4Addr::new(192, 0, 2, 10),
                    mac: MAC_1,
                    if_index: 11
                },
                ArpEntry {
                    ip: Ipv4Addr::new(192, 0, 2, 11),
                    mac: MAC_2,
                    if_index: 11
                },
            ]
        );
    }

    #[test]
    fn skips_incomplete_broadcast_multicast_and_zero_entries() {
        let mut buf = Vec::new();
        // Incomplete: link-layer address not resolved yet (alen 0).
        buf.extend(message([192, 0, 2, 20], sockaddr_dl(&[], 0), 11));
        // Broadcast hardware address.
        buf.extend(message([192, 0, 2, 255], sockaddr_dl(&[0xff; 6], 0), 11));
        // Multicast hardware address (low bit of first byte).
        buf.extend(message(
            [192, 0, 2, 21],
            sockaddr_dl(&[1, 0, 0x5e, 0, 0, 1], 0),
            11,
        ));
        // All-zero hardware address.
        buf.extend(message([192, 0, 2, 22], sockaddr_dl(&[0; 6], 0), 11));
        // Multicast IP.
        buf.extend(message([224, 0, 0, 251], sockaddr_dl(&MAC_1, 0), 11));
        // Limited broadcast IP.
        buf.extend(message([255, 255, 255, 255], sockaddr_dl(&MAC_1, 0), 11));
        // One good entry at the end proves the walk continued past the skips.
        buf.extend(message([192, 0, 2, 30], sockaddr_dl(&MAC_2, 0), 11));
        let got = parse_arp_buffer(&buf);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ip, Ipv4Addr::new(192, 0, 2, 30));
    }

    #[test]
    fn wrong_message_type_and_family_are_skipped() {
        let mut m = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        m[OFF_TYPE] = 1; // RTM_ADD
        assert!(parse_arp_buffer(&m).is_empty());
        let mut m = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        m[RT_MSGHDR_LEN + 1] = 30; // dst family AF_INET6
        assert!(parse_arp_buffer(&m).is_empty());
        let mut m = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        m[RT_MSGHDR_LEN + 16 + 1] = AF_INET; // gateway family not AF_LINK
        assert!(parse_arp_buffer(&m).is_empty());
    }

    #[test]
    fn truncated_and_garbage_input_never_panics() {
        let good = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        // Every possible truncation.
        for cut in 0..good.len() {
            let _ = parse_arp_buffer(&good[..cut]);
        }
        assert!(parse_arp_buffer(&good[..good.len() - 1]).is_empty());
        assert!(parse_arp_buffer(&[]).is_empty());
        // msglen shorter than the header, and msglen past the buffer.
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&10u16.to_ne_bytes());
        assert!(parse_arp_buffer(&bad).is_empty());
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(parse_arp_buffer(&bad).is_empty());
        // Zero sa_len and an alen that runs past the sockaddr.
        let mut bad = good.clone();
        bad[RT_MSGHDR_LEN] = 0;
        let _ = parse_arp_buffer(&bad);
        let mut bad = good.clone();
        let dl = RT_MSGHDR_LEN + 16;
        bad[dl + 5] = 200; // nlen
        assert!(parse_arp_buffer(&bad).is_empty());
        // Deterministic pseudo-random garbage, with and without a plausible header prefix.
        let mut x: u32 = 0x1234_5678;
        for round in 0..200 {
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
            let _ = parse_arp_buffer(&junk);
        }
    }

    #[test]
    fn undersized_sockaddr_len_is_rejected_not_read_past() {
        // sa_len smaller than the fields the parser needs.
        let mut m = message([192, 0, 2, 10], sockaddr_dl(&MAC_1, 0), 11);
        m[RT_MSGHDR_LEN] = 4;
        assert!(parse_arp_buffer(&m).is_empty());
    }

    #[test]
    fn mac_formatting_is_lowercase_colon() {
        assert_eq!(
            format_mac(&[0x02, 0, 0, 0xAB, 0xCD, 0xEF]),
            "02:00:00:ab:cd:ef"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn header_size_matches_the_platform() {
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), RT_MSGHDR_LEN);
        let h: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        let base = &h as *const _ as usize;
        assert_eq!(&h.rtm_msglen as *const _ as usize - base, OFF_MSGLEN);
        assert_eq!(&h.rtm_type as *const _ as usize - base, OFF_TYPE);
        assert_eq!(&h.rtm_index as *const _ as usize - base, OFF_INDEX);
        assert_eq!(&h.rtm_addrs as *const _ as usize - base, OFF_ADDRS);
    }

    /// Reads the real table. Prints counts only. `cargo test -- --ignored arp_live --nocapture`.
    #[test]
    #[ignore]
    fn arp_live() {
        match read_arp_table() {
            Ok(t) => {
                let ifaces: std::collections::BTreeSet<u16> =
                    t.iter().map(|e| e.if_index).collect();
                println!("arp_live: entries={} interfaces={}", t.len(), ifaces.len());
            }
            Err(e) => println!("arp_live: error kind={:?}", e.kind()),
        }
    }
}
