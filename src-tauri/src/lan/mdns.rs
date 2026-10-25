//! Receive-only mDNS: a listener that joins the multicast group and READS announcements, plus a
//! defensive packet parser. It never sends: [`MdnsListener`] wraps its socket privately and
//! exposes no send method, and `tests/lan_listen_only.rs` fails if a send call appears in this
//! file.
//!
//! What it keeps, per source IPv4 address: a `.local` hostname and the service types the device
//! announces (`_http._tcp`). TXT record contents, instance names and addresses are discarded.
//! Everything on the wire is attacker-controlled, so the parser bounds every read, caps name
//! length, pointer hops and record counts, and treats any malformed packet as "nothing learned".

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::model::Millis;

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Largest datagram read (anything longer is truncated and then fails to parse cleanly).
const MAX_PACKET: usize = 9000;
/// Records examined per packet.
const MAX_RECORDS: usize = 256;
/// Compression-pointer hops followed per name.
const MAX_HOPS: usize = 8;
/// DNS name limit.
const MAX_NAME_LEN: usize = 255;
/// Longest hostname kept (including `.local`).
const MAX_HOSTNAME_LEN: usize = 80;
/// Longest service-type label kept.
const MAX_SERVICE_LABEL: usize = 16;
/// Service types remembered per device.
const MAX_SERVICES_PER_DEVICE: usize = 24;
/// Devices remembered.
const MAX_CACHE_ENTRIES: usize = 512;
/// An entry nobody refreshed for this long is dropped when the cache is full.
const CACHE_TTL_MS: Millis = 60 * 60 * 1000;

/// What one packet taught us about its sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announcement {
    /// Best hostname candidate (`my-device.local`), if any.
    pub hostname: Option<String>,
    pub services: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

/// Decode a (possibly compressed) name starting at `start`. Returns its labels and the offset
/// just past the name's first occurrence (past the pointer, when one was used).
fn read_name(pkt: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut total = 0usize;
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut hops = 0usize;
    loop {
        let len = *pkt.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some((labels, end.unwrap_or(pos + 1)));
                }
                let len = usize::from(len);
                let raw = pkt.get(pos + 1..pos + 1 + len)?;
                total += len + 1;
                if total > MAX_NAME_LEN {
                    return None;
                }
                let label = std::str::from_utf8(raw).ok()?;
                if label.chars().any(char::is_control) {
                    return None;
                }
                labels.push(label.to_string());
                pos += 1 + len;
            }
            0xC0 => {
                let target = usize::from(be16(pkt, pos)? & 0x3FFF);
                if end.is_none() {
                    end = Some(pos + 2);
                }
                hops += 1;
                if hops > MAX_HOPS || target >= pkt.len() {
                    return None;
                }
                pos = target;
            }
            // 0x40 / 0x80: reserved label types.
            _ => return None,
        }
    }
}

fn is_local(label: &str) -> bool {
    label.eq_ignore_ascii_case("local")
}

/// `["My TV", "_http", "_tcp", "local"]` -> `_http._tcp`. Needs `_proto._tcp|_udp.local` at the end.
fn service_type(labels: &[String]) -> Option<String> {
    let n = labels.len();
    if n < 3 || !is_local(&labels[n - 1]) {
        return None;
    }
    let (svc, proto) = (&labels[n - 3], &labels[n - 2]);
    let proto_ok = proto.eq_ignore_ascii_case("_tcp") || proto.eq_ignore_ascii_case("_udp");
    let svc_ok = svc.len() > 1
        && svc.len() <= MAX_SERVICE_LABEL
        && svc.starts_with('_')
        && svc
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    (proto_ok && svc_ok).then(|| {
        format!(
            "{}.{}",
            svc.to_ascii_lowercase(),
            proto.to_ascii_lowercase()
        )
    })
}

/// `["my-device", "local"]` -> `my-device.local`. Single-label `.local` names only: a dotted
/// instance name is not a hostname.
fn hostname(labels: &[String]) -> Option<String> {
    if labels.len() != 2 || !is_local(&labels[1]) {
        return None;
    }
    let host = &labels[0];
    let ok = !host.is_empty()
        && host.len() + 6 <= MAX_HOSTNAME_LEN
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    ok.then(|| format!("{host}.local"))
}

/// Parse an mDNS packet sent from `src`. Only responses (QR bit set) are read. A hostname is
/// attributed to the sender only when an A record for it carries the sender's own address;
/// SRV targets and AAAA owners are a weaker fallback. Never panics; garbage returns the empty
/// announcement.
pub fn parse_announcement(pkt: &[u8], src: Ipv4Addr) -> Announcement {
    let mut out = Announcement::default();
    let (Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) = (
        be16(pkt, 2),
        be16(pkt, 4),
        be16(pkt, 6),
        be16(pkt, 8),
        be16(pkt, 10),
    ) else {
        return out;
    };
    if flags & 0x8000 == 0 {
        return out;
    }
    let mut pos = 12usize;
    for _ in 0..qd.min(32) {
        let Some((_, next)) = read_name(pkt, pos) else {
            return out;
        };
        pos = next + 4;
        if pos > pkt.len() {
            return out;
        }
    }
    let (mut verified, mut fallback): (Option<String>, Option<String>) = (None, None);
    let records = (usize::from(an) + usize::from(ns) + usize::from(ar)).min(MAX_RECORDS);
    for _ in 0..records {
        let Some((owner, next)) = read_name(pkt, pos) else {
            break;
        };
        let (Some(rtype), Some(class), Some(rdlen)) =
            (be16(pkt, next), be16(pkt, next + 2), be16(pkt, next + 8))
        else {
            break;
        };
        let rd_start = next + 10;
        let rd_end = rd_start + usize::from(rdlen);
        if rd_end > pkt.len() {
            break;
        }
        pos = rd_end;
        if class & 0x7FFF != 1 {
            continue;
        }
        let rdata = &pkt[rd_start..rd_end];
        match rtype {
            // A
            1 => {
                if rdata == src.octets() && verified.is_none() {
                    verified = hostname(&owner);
                }
            }
            // AAAA: the address cannot be checked against an IPv4 source.
            28 => {
                if rdata.len() == 16 && fallback.is_none() {
                    fallback = hostname(&owner);
                }
            }
            // PTR: a service type directly, or the service-type enumeration's answers.
            12 => {
                let enumeration = owner.len() == 4
                    && owner[0].eq_ignore_ascii_case("_services")
                    && owner[1].eq_ignore_ascii_case("_dns-sd");
                if enumeration {
                    if let Some((target, _)) = read_name(pkt, rd_start) {
                        if let Some(s) = service_type(&target) {
                            out.services.insert(s);
                        }
                    }
                } else if let Some(s) = service_type(&owner) {
                    out.services.insert(s);
                }
            }
            // SRV: owner names the service; the target is a hostname.
            33 => {
                if let Some(s) = service_type(&owner) {
                    out.services.insert(s);
                }
                if rdata.len() >= 6 && fallback.is_none() {
                    if let Some((target, _)) = read_name(pkt, rd_start + 6) {
                        fallback = hostname(&target);
                    }
                }
            }
            // TXT: only the owner's service type; the contents are never read.
            16 => {
                if let Some(s) = service_type(&owner) {
                    out.services.insert(s);
                }
            }
            _ => {}
        }
    }
    out.hostname = verified.or(fallback);
    out
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CacheEntry {
    info: Announcement,
    last_seen: Millis,
}

/// Bounded per-source memory of what was announced.
#[derive(Debug, Default)]
pub struct MdnsCache {
    by_ip: HashMap<Ipv4Addr, CacheEntry>,
}

impl MdnsCache {
    pub fn observe(&mut self, ip: Ipv4Addr, a: Announcement, now: Millis) {
        if a == Announcement::default() {
            return;
        }
        if !self.by_ip.contains_key(&ip) && self.by_ip.len() >= MAX_CACHE_ENTRIES {
            self.by_ip.retain(|_, e| now - e.last_seen < CACHE_TTL_MS);
            if self.by_ip.len() >= MAX_CACHE_ENTRIES {
                return;
            }
        }
        let e = self.by_ip.entry(ip).or_default();
        e.last_seen = now;
        if a.hostname.is_some() {
            e.info.hostname = a.hostname;
        }
        for s in a.services {
            if e.info.services.len() < MAX_SERVICES_PER_DEVICE {
                e.info.services.insert(s);
            }
        }
    }

    pub fn get(&self, ip: Ipv4Addr) -> Option<&Announcement> {
        self.by_ip.get(&ip).map(|e| &e.info)
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// A bound, group-joined UDP socket that can only be read from.
pub struct MdnsListener {
    socket: UdpSocket,
}

impl MdnsListener {
    /// Bind `0.0.0.0:5353` (shared with the system responder via SO_REUSEADDR + SO_REUSEPORT)
    /// and join 224.0.0.251. Binding is what triggers the Local Network prompt.
    pub fn bind() -> io::Result<MdnsListener> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
        socket.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        Ok(MdnsListener {
            socket: socket.into(),
        })
    }

    /// Read one datagram. `Ok(None)` on timeout or when the sender is not IPv4.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<(usize, Ipv4Addr)>> {
        match self.socket.recv_from(buf) {
            Ok((n, SocketAddr::V4(from))) => Ok(Some((n, *from.ip()))),
            Ok(_) => Ok(None),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Handle to the process-wide listener thread and its cache.
pub struct MdnsHandle {
    cache: Arc<Mutex<MdnsCache>>,
}

impl MdnsHandle {
    /// Look up what `ip` announced.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<Announcement> {
        self.cache.lock().ok()?.get(ip).cloned()
    }
}

static HANDLE: OnceLock<MdnsHandle> = OnceLock::new();

/// Start the background listener once and return its handle. If the socket cannot be bound
/// (or the permission is denied) the thread keeps retrying every 30 s; lookups just come back
/// empty meanwhile.
pub fn ensure_listener() -> &'static MdnsHandle {
    HANDLE.get_or_init(|| {
        let cache = Arc::new(Mutex::new(MdnsCache::default()));
        let thread_cache = Arc::clone(&cache);
        let spawned = std::thread::Builder::new()
            .name("wbm-mdns".into())
            .spawn(move || listen_forever(&thread_cache));
        drop(spawned); // no thread = no mDNS names; the ARP table still works
        MdnsHandle { cache }
    })
}

fn listen_forever(cache: &Mutex<MdnsCache>) {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let Ok(listener) = MdnsListener::bind() else {
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        loop {
            match listener.recv(&mut buf) {
                Ok(Some((n, from))) => {
                    let a = parse_announcement(&buf[..n], from);
                    if let Ok(mut c) = cache.lock() {
                        c.observe(from, a, super::now_ms());
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    std::thread::sleep(Duration::from_secs(1));
                    break; // rebind
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in labels {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn record(owner: &[u8], rtype: u16, class: u16, rdata: &[u8]) -> Vec<u8> {
        let mut v = owner.to_vec();
        v.extend(rtype.to_be_bytes());
        v.extend(class.to_be_bytes());
        v.extend(120u32.to_be_bytes());
        v.extend((rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    fn packet(flags: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0, 0];
        v.extend(flags.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend((records.len() as u16).to_be_bytes());
        v.extend([0, 0, 0, 0]);
        for r in records {
            v.extend_from_slice(r);
        }
        v
    }

    fn announcement_packet() -> Vec<u8> {
        let host = name(&["device-a", "local"]);
        let svc_owner = name(&["Device A", "_http", "_tcp", "local"]);
        let mut srv = vec![0, 0, 0, 0, 0x1F, 0x90];
        srv.extend(&host);
        packet(
            0x8400,
            &[
                record(&host, 1, 0x8001, &SRC.octets()),
                record(&name(&["_http", "_tcp", "local"]), 12, 1, &svc_owner),
                record(&svc_owner, 33, 0x8001, &srv),
                record(&svc_owner, 16, 0x8001, &[3, b'a', b'=', b'b']),
            ],
        )
    }

    #[test]
    fn parses_a_realistic_announcement() {
        let a = parse_announcement(&announcement_packet(), SRC);
        assert_eq!(a.hostname.as_deref(), Some("device-a.local"));
        assert_eq!(
            a.services.into_iter().collect::<Vec<_>>(),
            vec!["_http._tcp".to_string()]
        );
    }

    #[test]
    fn service_enumeration_ptr_yields_the_listed_type() {
        let owner = name(&["_services", "_dns-sd", "_udp", "local"]);
        let pkt = packet(
            0x8400,
            &[record(&owner, 12, 1, &name(&["_airplay", "_tcp", "local"]))],
        );
        let a = parse_announcement(&pkt, SRC);
        assert!(a.services.contains("_airplay._tcp"));
        assert_eq!(a.hostname, None);
    }

    #[test]
    fn a_record_for_someone_elses_address_is_not_attributed() {
        let host = name(&["device-b", "local"]);
        let pkt = packet(0x8400, &[record(&host, 1, 1, &[192, 0, 2, 99])]);
        assert_eq!(parse_announcement(&pkt, SRC).hostname, None);
    }

    #[test]
    fn verified_a_beats_srv_and_aaaa_fallbacks() {
        let aaaa_host = name(&["other", "local"]);
        let host = name(&["device-a", "local"]);
        let pkt = packet(
            0x8400,
            &[
                record(&aaaa_host, 28, 1, &[0u8; 16]),
                record(&host, 1, 1, &SRC.octets()),
            ],
        );
        assert_eq!(
            parse_announcement(&pkt, SRC).hostname.as_deref(),
            Some("device-a.local")
        );
        // Without the A record, the AAAA owner is the fallback.
        let pkt = packet(0x8400, &[record(&aaaa_host, 28, 1, &[0u8; 16])]);
        assert_eq!(
            parse_announcement(&pkt, SRC).hostname.as_deref(),
            Some("other.local")
        );
    }

    #[test]
    fn queries_are_ignored() {
        let mut pkt = announcement_packet();
        pkt[2] = 0x00; // QR bit cleared
        pkt[3] = 0x00;
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
    }

    #[test]
    fn follows_compression_pointers() {
        // Owner of record 2 is a pointer to the name bytes at offset 12.
        let host = name(&["device-a", "local"]);
        let mut pkt = packet(0x8400, &[record(&host, 1, 1, &SRC.octets())]);
        let second = record(&[0xC0, 12], 1, 1, &SRC.octets());
        pkt.extend(second);
        pkt[7] = 2; // ancount = 2
        let a = parse_announcement(&pkt, SRC);
        assert_eq!(a.hostname.as_deref(), Some("device-a.local"));
    }

    #[test]
    fn pointer_loops_and_forward_garbage_terminate() {
        // A pointer to itself.
        let mut pkt = packet(0x8400, &[]);
        pkt[7] = 1;
        pkt.extend([0xC0, 12]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Two pointers pointing at each other.
        let mut pkt = packet(0x8400, &[]);
        pkt[7] = 1;
        pkt.extend([0xC0, 14, 0xC0, 12]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Pointer past the end.
        let mut pkt = packet(0x8400, &[]);
        pkt[7] = 1;
        pkt.extend([0xC3, 0xFF]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
    }

    #[test]
    fn truncated_packets_never_panic() {
        let full = announcement_packet();
        for cut in 0..full.len() {
            let _ = parse_announcement(&full[..cut], SRC);
        }
        assert_eq!(parse_announcement(&[], SRC), Announcement::default());
        assert_eq!(parse_announcement(&[0; 11], SRC), Announcement::default());
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0xDEAD_BEEF;
        let full = announcement_packet();
        for round in 0..2000 {
            let mut junk: Vec<u8> = (0..(round % 300))
                .map(|_| {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (x >> 24) as u8
                })
                .collect();
            if round % 3 == 0 && junk.len() > 12 {
                junk[2] = 0x84; // look like a response so the record loop runs
                junk[3] = 0x00;
            }
            let _ = parse_announcement(&junk, SRC);
            // Bit-flip a valid packet.
            let mut flipped = full.clone();
            let i = (x as usize) % flipped.len();
            flipped[i] ^= (round & 0xFF) as u8 | 1;
            let _ = parse_announcement(&flipped, SRC);
        }
    }

    #[test]
    fn oversized_and_malformed_names_are_rejected() {
        // Label length 63 repeated past 255 bytes.
        let long_label = "a".repeat(63);
        let labels: Vec<&str> = vec![long_label.as_str(); 5];
        let owner = name(&labels);
        let pkt = packet(0x8400, &[record(&owner, 1, 1, &SRC.octets())]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Reserved label type 0x40.
        let mut pkt = packet(0x8400, &[]);
        pkt[7] = 1;
        pkt.extend([0x45, 1, 2, 3, 4, 5, 0]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Control character inside a label.
        let owner = name(&["bad\u{7}name", "local"]);
        let pkt = packet(0x8400, &[record(&owner, 1, 1, &SRC.octets())]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
    }

    #[test]
    fn rdata_length_past_the_packet_ends_the_walk() {
        let host = name(&["device-a", "local"]);
        let mut pkt = packet(0x8400, &[record(&host, 1, 1, &SRC.octets())]);
        let n = pkt.len();
        pkt[n - 5] = 0xFF; // rdlength high byte
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
    }

    #[test]
    fn non_service_names_and_odd_hostnames_are_dropped() {
        for bad in [
            name(&["_http", "_tcp"]),               // no .local
            name(&["x", "_http", "_ftp", "local"]), // bad protocol
            name(&["x", "http", "_tcp", "local"]),  // no leading underscore
            name(&["x", "_waytoolongservicename", "_tcp", "local"]),
        ] {
            let pkt = packet(0x8400, &[record(&bad, 16, 1, &[0])]);
            assert!(parse_announcement(&pkt, SRC).services.is_empty());
        }
        // Dotted instance name is not a hostname; spaces are not allowed.
        for bad in [name(&["a", "b", "local"]), name(&["has space", "local"])] {
            let pkt = packet(0x8400, &[record(&bad, 1, 1, &SRC.octets())]);
            assert_eq!(parse_announcement(&pkt, SRC).hostname, None);
        }
    }

    #[test]
    fn cache_is_bounded_merges_and_ignores_empty() {
        let mut c = MdnsCache::default();
        let now = 1_000_000;
        c.observe(SRC, Announcement::default(), now);
        assert!(c.is_empty());
        let mut a = Announcement {
            hostname: Some("a.local".into()),
            ..Default::default()
        };
        a.services.insert("_http._tcp".into());
        c.observe(SRC, a, now);
        let mut b = Announcement::default();
        b.services.insert("_ipp._tcp".into());
        c.observe(SRC, b, now + 1);
        let got = c.get(SRC).unwrap();
        assert_eq!(got.hostname.as_deref(), Some("a.local"));
        assert_eq!(got.services.len(), 2);
        // Fill it past the cap with fresh entries: size stays bounded.
        for i in 0..(MAX_CACHE_ENTRIES as u32 + 100) {
            let mut x = Announcement::default();
            x.services.insert("_x._tcp".into());
            c.observe(Ipv4Addr::from(0xC000_0300 + i), x, now);
        }
        assert!(c.len() <= MAX_CACHE_ENTRIES);
        // Per-device service cap.
        let mut many = Announcement::default();
        for i in 0..100 {
            many.services.insert(format!("_s{i}._tcp"));
        }
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mut c2 = MdnsCache::default();
        c2.observe(ip, many, now);
        assert!(c2.get(ip).unwrap().services.len() <= MAX_SERVICES_PER_DEVICE);
    }

    #[test]
    fn listener_type_has_no_send_surface() {
        // Compile-time-ish guard: the only public methods are bind / recv.
        let src = include_str!("mdns.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let code: String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "send_to",
            ".send(",
            "send_vectored",
            "connect(",
            "TcpStream",
        ] {
            assert!(
                !code.contains(forbidden),
                "mdns.rs must not contain {forbidden}"
            );
        }
    }
}
