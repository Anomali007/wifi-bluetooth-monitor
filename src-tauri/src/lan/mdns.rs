//! Receive-only mDNS: a listener that joins the multicast group and READS announcements, plus a
//! defensive packet parser. It never sends: [`MdnsListener`] wraps its socket privately and
//! exposes no send method, and `tests/lan_listen_only.rs` fails if a send call appears in this
//! file.
//!
//! What it keeps, per source address (IPv4 or IPv6, each on its own receive-only socket): a
//! `.local` hostname, the addresses (A/AAAA) that hostname owns in the same packet, and the
//! service types the device announces (`_http._tcp`). TXT record contents and instance names
//! are discarded. Addresses stay in memory only, to join a host to a neighbor-table entry.
//! Everything on the wire is attacker-controlled, so the parser bounds every read, caps name
//! length, pointer hops and record counts, and treats any malformed packet as "nothing learned".

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::model::Millis;

use super::gate::Subnet;

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

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
/// Addresses remembered per announced hostname.
const MAX_ADDRS_PER_DEVICE: usize = 8;
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
    /// Addresses the sender is known by: A/AAAA records owned by `hostname` in the same
    /// packet, plus the source address when the hostname is verified. In memory
    /// only; used to join the host to a neighbor-table entry.
    pub addrs: BTreeSet<IpAddr>,
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

/// Addresses worth remembering for a host.
fn usable_addr(a: IpAddr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_loopback())
}

/// Parse an mDNS packet sent from `src`. Only responses (QR bit set) are read. A hostname is
/// attributed to the sender only when an A (or AAAA) record for it carries the sender's own
/// address; SRV targets and other AAAA owners are a weaker fallback. Never panics; garbage
/// returns the empty announcement.
pub fn parse_announcement(pkt: &[u8], src: IpAddr) -> Announcement {
    let src = match src {
        IpAddr::V6(a) => IpAddr::V6(super::nd6::normalize_v6(a)),
        v4 => v4,
    };
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
    // (owner hostname, address) for every A/AAAA record seen; filtered to the chosen host below.
    let mut addr_records: Vec<(Option<String>, IpAddr)> = Vec::new();
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
                if let Ok(o) = <[u8; 4]>::try_from(rdata) {
                    let a = IpAddr::V4(Ipv4Addr::from(o));
                    if usable_addr(a) {
                        addr_records.push((hostname(&owner), a));
                    }
                    if a == src && verified.is_none() {
                        verified = hostname(&owner);
                    }
                }
            }
            // AAAA: verified when it carries the sender's own IPv6 address; otherwise the
            // owner is only a fallback (an IPv4 sender cannot be checked against it).
            28 => {
                if let Ok(o) = <[u8; 16]>::try_from(rdata) {
                    let a = IpAddr::V6(super::nd6::normalize_v6(Ipv6Addr::from(o)));
                    if usable_addr(a) {
                        addr_records.push((hostname(&owner), a));
                    }
                    if a == src && verified.is_none() {
                        verified = hostname(&owner);
                    } else if fallback.is_none() {
                        fallback = hostname(&owner);
                    }
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
    let was_verified = verified.is_some();
    out.hostname = verified.or(fallback);
    if let Some(host) = &out.hostname {
        for (owner, a) in &addr_records {
            if owner.as_deref() == Some(host.as_str()) && out.addrs.len() < MAX_ADDRS_PER_DEVICE {
                out.addrs.insert(*a);
            }
        }
    }
    // The sender is the host itself only when its own address vouched for the name; a proxy
    // announcing someone else's records must not donate its address to a stranger's hostname.
    if was_verified {
        out.addrs.insert(src);
    }
    out
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CacheEntry {
    info: Announcement,
    last_seen: Millis,
    /// Interface scope the datagram arrived on (IPv6 only; 0 for IPv4 or unknown).
    scope: u32,
}

/// One cached source, as handed to the device builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    pub from: IpAddr,
    pub scope: u32,
    pub info: Announcement,
}

/// The joined Wi-Fi link: only sources on it are cached. Anyone else who can reach the mDNS
/// port (another interface, a spoofed source) must not be able to fill the cache.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkFilter {
    /// The interface's IPv4 subnet; `None` admits no IPv4 source.
    pub subnet: Option<Subnet>,
    /// OS index of the Wi-Fi interface; link-local IPv6 sources must arrive on it.
    pub if_index: Option<u16>,
    /// The interface's own IPv6 addresses: a global/ULA source must share a /64 with one.
    pub own_v6: Vec<Ipv6Addr>,
}

impl LinkFilter {
    /// Whether a datagram from `ip` (arriving with IPv6 `scope`) came from this link.
    pub fn admits(&self, ip: IpAddr, scope: u32) -> bool {
        match ip {
            IpAddr::V4(a) => self.subnet.is_some_and(|s| s.contains(a)),
            IpAddr::V6(a) => {
                let link_local = (a.segments()[0] & 0xffc0) == 0xfe80;
                if link_local {
                    self.if_index.is_some_and(|i| u32::from(i) == scope)
                } else {
                    self.own_v6.iter().any(|own| {
                        (own.segments()[0] & 0xffc0) != 0xfe80
                            && own.segments()[..4] == a.segments()[..4]
                    })
                }
            }
        }
    }
}

/// Bounded per-source memory of what was announced.
#[derive(Debug, Default)]
pub struct MdnsCache {
    by_ip: HashMap<IpAddr, CacheEntry>,
    filter: Option<LinkFilter>,
}

impl MdnsCache {
    /// Restrict the cache to one link and drop what is already cached from elsewhere. `None`
    /// lifts the restriction (before the first scan has read the link).
    pub fn set_filter(&mut self, filter: Option<LinkFilter>) {
        if let Some(f) = &filter {
            self.by_ip.retain(|ip, e| f.admits(*ip, e.scope));
        }
        self.filter = filter;
    }

    pub fn observe(&mut self, ip: IpAddr, scope: u32, a: Announcement, now: Millis) {
        // An announcement that is only the sender's own address teaches nothing.
        if a.hostname.is_none() && a.services.is_empty() {
            return;
        }
        if self.filter.as_ref().is_some_and(|f| !f.admits(ip, scope)) {
            return;
        }
        if !self.by_ip.contains_key(&ip) && self.by_ip.len() >= MAX_CACHE_ENTRIES {
            self.by_ip.retain(|_, e| now - e.last_seen < CACHE_TTL_MS);
            // Still full: make room by dropping the entry heard longest ago, so a flood of
            // spoofed sources cannot lock real devices out for the whole TTL.
            if self.by_ip.len() >= MAX_CACHE_ENTRIES {
                let oldest = self
                    .by_ip
                    .iter()
                    .min_by_key(|(_, e)| e.last_seen)
                    .map(|(ip, _)| *ip);
                if let Some(old) = oldest {
                    self.by_ip.remove(&old);
                }
            }
        }
        let e = self.by_ip.entry(ip).or_default();
        e.last_seen = now;
        e.scope = scope;
        if a.hostname.is_some() {
            e.info.hostname = a.hostname;
        }
        for addr in a.addrs {
            if e.info.addrs.len() < MAX_ADDRS_PER_DEVICE {
                e.info.addrs.insert(addr);
            }
        }
        for s in a.services {
            if e.info.services.len() < MAX_SERVICES_PER_DEVICE {
                e.info.services.insert(s);
            }
        }
    }

    pub fn get(&self, ip: IpAddr) -> Option<&Announcement> {
        self.by_ip.get(&ip).map(|e| &e.info)
    }

    /// Every cached source, in a stable order.
    pub fn heard(&self) -> Vec<Heard> {
        let mut v: Vec<Heard> = self
            .by_ip
            .iter()
            .map(|(ip, e)| Heard {
                from: *ip,
                scope: e.scope,
                info: e.info.clone(),
            })
            .collect();
        v.sort_by_key(|h| h.from);
        v
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
        let l = MdnsListener {
            socket: socket.into(),
        };
        l.report_hops(false);
        Ok(l)
    }

    /// Bind `[::]:5353` (IPv6 only) and join ff02::fb on every interface.
    pub fn bind_v6() -> io::Result<MdnsListener> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())?;
        socket.join_multicast_v6(&MDNS_GROUP_V6, 0)?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        let l = MdnsListener {
            socket: socket.into(),
        };
        l.report_hops(true);
        Ok(l)
    }

    /// Ask the OS to report each datagram's TTL (IPv4) or hop limit (IPv6). Best effort: if it
    /// refuses, `recv` simply reports no value.
    fn report_hops(&self, v6: bool) {
        use std::os::fd::AsRawFd;
        let (level, opt) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        } else {
            (libc::IPPROTO_IP, libc::IP_RECVTTL)
        };
        let on: libc::c_int = 1;
        // SAFETY: valid fd, and a pointer/length pair for one c_int.
        let _ = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                level,
                opt,
                std::ptr::addr_of!(on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }

    /// Read one datagram with its sender, interface scope and (when the OS reports it) hop
    /// limit. `Ok(None)` on timeout.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        use std::os::fd::AsRawFd;
        // SAFETY: zeroed C structs are valid initial values; the pointers handed to recvmsg
        // point at locals that outlive the call; the control buffer is 8-byte aligned.
        unsafe {
            let mut name: libc::sockaddr_storage = std::mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut control = [0u64; 16];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = std::ptr::addr_of_mut!(name).cast();
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            let n = libc::recvmsg(self.socket.as_raw_fd(), &mut msg, 0);
            if n < 0 {
                let e = io::Error::last_os_error();
                return if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let (from, scope) = match libc::c_int::from(name.ss_family) {
                libc::AF_INET => {
                    let a = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in>();
                    (
                        IpAddr::V4(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))),
                        0,
                    )
                }
                libc::AF_INET6 => {
                    let a = &*std::ptr::addr_of!(name).cast::<libc::sockaddr_in6>();
                    (
                        IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                        a.sin6_scope_id,
                    )
                }
                _ => return Ok(None),
            };
            let mut hop = None;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                let h = &*c;
                let data = libc::CMSG_DATA(c);
                let len = (h.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_RECVTTL && len >= 1 {
                    // macOS reports one byte, other systems an int.
                    hop = Some(if len >= 4 {
                        data.cast::<libc::c_int>().read_unaligned() as u8
                    } else {
                        *data
                    });
                } else if h.cmsg_level == libc::IPPROTO_IPV6
                    && h.cmsg_type == libc::IPV6_HOPLIMIT
                    && len >= 4
                {
                    hop = Some(data.cast::<libc::c_int>().read_unaligned() as u8);
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            Ok(Some((n as usize, from, scope, hop)))
        }
    }
}

/// `(length, sender, interface scope, hop limit / TTL if the OS reported one)`.
pub type Received = (usize, IpAddr, u32, Option<u8>);

/// RFC 6762 section 11: a genuine link-local mDNS packet is sent with hop limit / TTL 255, and
/// anything else has been routed (or forged from off the link). `None` = the OS did not report
/// it, which is accepted: failing closed there would break receive on a system that cannot
/// deliver the value.
pub fn hop_ok(hop: Option<u8>) -> bool {
    hop.is_none_or(|h| h == 255)
}

/// Handle to the process-wide listener threads and their shared cache.
pub struct MdnsHandle {
    cache: Arc<Mutex<MdnsCache>>,
}

impl MdnsHandle {
    /// How many sources have announced (a count for the log; no content).
    pub fn announced_sources(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Tell the cache which link to accept sources from (called each scan with the joined Wi-Fi).
    pub fn set_link(&self, filter: LinkFilter) {
        if let Ok(mut c) = self.cache.lock() {
            if c.filter.as_ref() != Some(&filter) {
                c.set_filter(Some(filter));
            }
        }
    }

    /// Everything heard so far, per source.
    pub fn snapshot(&self) -> Vec<Heard> {
        self.cache.lock().map(|c| c.heard()).unwrap_or_default()
    }
}

static HANDLE: OnceLock<MdnsHandle> = OnceLock::new();

// Counters for the diagnostic log line (counts only).
static BOUND_V4: AtomicBool = AtomicBool::new(false);
static BOUND_V6: AtomicBool = AtomicBool::new(false);
static BIND_FAILURES: AtomicU64 = AtomicU64::new(0);
static PACKETS: AtomicU64 = AtomicU64::new(0);

/// Listener health for the log: counts and booleans only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerCounts {
    pub bound_v4: bool,
    pub bound_v6: bool,
    pub bind_failures: u64,
    pub datagrams: u64,
}

pub fn listener_counts() -> ListenerCounts {
    ListenerCounts {
        bound_v4: BOUND_V4.load(Ordering::Relaxed),
        bound_v6: BOUND_V6.load(Ordering::Relaxed),
        bind_failures: BIND_FAILURES.load(Ordering::Relaxed),
        datagrams: PACKETS.load(Ordering::Relaxed),
    }
}

/// Start the background listeners once (one thread per address family) and return the shared
/// handle. If a socket cannot be bound (or the permission is denied) its thread keeps retrying
/// every 30 s; the snapshot is just emptier meanwhile.
pub fn ensure_listener() -> &'static MdnsHandle {
    HANDLE.get_or_init(|| {
        let cache = Arc::new(Mutex::new(MdnsCache::default()));
        for v6 in [false, true] {
            let thread_cache = Arc::clone(&cache);
            let spawned = std::thread::Builder::new()
                .name(if v6 { "wbm-mdns6" } else { "wbm-mdns4" }.into())
                .spawn(move || listen_forever(&thread_cache, v6));
            drop(spawned); // no thread = no mDNS names; the neighbor table still works
        }
        MdnsHandle { cache }
    })
}

fn listen_forever(cache: &Mutex<MdnsCache>, v6: bool) {
    let flag = if v6 { &BOUND_V6 } else { &BOUND_V4 };
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let bound = if v6 {
            MdnsListener::bind_v6()
        } else {
            MdnsListener::bind()
        };
        let Ok(listener) = bound else {
            BIND_FAILURES.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_secs(30));
            continue;
        };
        flag.store(true, Ordering::Relaxed);
        loop {
            match listener.recv(&mut buf) {
                Ok(Some((n, from, scope, hop))) => {
                    PACKETS.fetch_add(1, Ordering::Relaxed);
                    if !hop_ok(hop) {
                        continue;
                    }
                    let a = parse_announcement(&buf[..n], from);
                    if let Ok(mut c) = cache.lock() {
                        let from = match from {
                            IpAddr::V6(a) => IpAddr::V6(super::nd6::normalize_v6(a)),
                            v4 => v4,
                        };
                        c.observe(from, scope, a, super::now_ms());
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    flag.store(false, Ordering::Relaxed);
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

    const SRC4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const SRC: IpAddr = IpAddr::V4(SRC4);

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
                record(&host, 1, 0x8001, &SRC4.octets()),
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
                record(&host, 1, 1, &SRC4.octets()),
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

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn aaaa_from_an_ipv6_sender_verifies_the_hostname_and_collects_addresses() {
        let src = IpAddr::V6(v6("fe80::10"));
        let host = name(&["device-a", "local"]);
        let other = name(&["device-b", "local"]);
        let pkt = packet(
            0x8400,
            &[
                record(&other, 28, 1, &v6("2001:db8::bb").octets()),
                record(&host, 28, 0x8001, &v6("2001:db8::10").octets()),
                record(&host, 28, 0x8001, &v6("fe80::10").octets()),
                record(&host, 1, 0x8001, &[192, 0, 2, 10]),
            ],
        );
        let a = parse_announcement(&pkt, src);
        assert_eq!(a.hostname.as_deref(), Some("device-a.local"));
        let want: BTreeSet<IpAddr> = [
            IpAddr::V6(v6("2001:db8::10")),
            IpAddr::V6(v6("fe80::10")),
            IpAddr::V4(SRC4),
            src,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            a.addrs, want,
            "only the chosen host's addresses, plus the verified sender"
        );
        assert!(!a.addrs.contains(&IpAddr::V6(v6("2001:db8::bb"))));
    }

    #[test]
    fn kame_scope_in_a_link_local_sender_is_normalised() {
        // The kernel may hand back fe80:4::10 for fe80::10; both must verify the same name.
        let host = name(&["device-a", "local"]);
        let pkt = packet(0x8400, &[record(&host, 28, 1, &v6("fe80::10").octets())]);
        let a = parse_announcement(&pkt, IpAddr::V6(v6("fe80:4::10")));
        assert_eq!(a.hostname.as_deref(), Some("device-a.local"));
        assert!(a.addrs.contains(&IpAddr::V6(v6("fe80::10"))));
    }

    #[test]
    fn a_sender_that_is_not_the_host_does_not_donate_its_address() {
        // An IPv4 sender announcing someone else's AAAA: the name is only a fallback, and the
        // sender's address must not be filed under it.
        let host = name(&["device-a", "local"]);
        let pkt = packet(
            0x8400,
            &[record(&host, 28, 1, &v6("2001:db8::10").octets())],
        );
        let a = parse_announcement(&pkt, SRC);
        assert_eq!(a.hostname.as_deref(), Some("device-a.local"));
        assert_eq!(
            a.addrs.into_iter().collect::<Vec<_>>(),
            vec![IpAddr::V6(v6("2001:db8::10"))]
        );
    }

    #[test]
    fn unspecified_loopback_and_multicast_addresses_are_not_kept() {
        let host = name(&["device-a", "local"]);
        let pkt = packet(
            0x8400,
            &[
                record(&host, 1, 1, &[0, 0, 0, 0]),
                record(&host, 1, 1, &[127, 0, 0, 1]),
                record(&host, 1, 1, &[224, 0, 0, 251]),
                record(&host, 28, 1, &v6("::1").octets()),
                record(&host, 28, 1, &v6("ff02::fb").octets()),
                record(&host, 1, 1, &SRC4.octets()),
            ],
        );
        let a = parse_announcement(&pkt, SRC);
        assert_eq!(a.addrs.into_iter().collect::<Vec<_>>(), vec![SRC]);
    }

    #[test]
    fn address_lists_are_capped() {
        let host = name(&["device-a", "local"]);
        let recs: Vec<Vec<u8>> = (1..=40u16)
            .map(|i| {
                record(
                    &host,
                    28,
                    1,
                    &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i).octets(),
                )
            })
            .collect();
        let a = parse_announcement(&packet(0x8400, &recs), SRC);
        assert!(a.addrs.len() <= MAX_ADDRS_PER_DEVICE);
        assert!(!a.addrs.is_empty());
    }

    #[test]
    fn cache_keeps_ipv6_sources_with_their_scope_and_lists_them_in_order() {
        let mut c = MdnsCache::default();
        let a6 = IpAddr::V6(v6("fe80::10"));
        let mut a = Announcement {
            hostname: Some("a.local".into()),
            ..Default::default()
        };
        a.addrs.insert(a6);
        c.observe(a6, 11, a.clone(), 5);
        c.observe(SRC, 0, a, 6);
        let h = c.heard();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].from, SRC, "IPv4 sorts before IPv6");
        assert_eq!(h[1].scope, 11);
        assert!(h[1].info.addrs.contains(&a6));
        // An announcement that is only an address teaches nothing.
        let mut only_addr = Announcement::default();
        only_addr.addrs.insert(a6);
        let mut c2 = MdnsCache::default();
        c2.observe(a6, 11, only_addr, 5);
        assert!(c2.is_empty());
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
        let mut pkt = packet(0x8400, &[record(&host, 1, 1, &SRC4.octets())]);
        let second = record(&[0xC0, 12], 1, 1, &SRC4.octets());
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
        let pkt = packet(0x8400, &[record(&owner, 1, 1, &SRC4.octets())]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Reserved label type 0x40.
        let mut pkt = packet(0x8400, &[]);
        pkt[7] = 1;
        pkt.extend([0x45, 1, 2, 3, 4, 5, 0]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
        // Control character inside a label.
        let owner = name(&["bad\u{7}name", "local"]);
        let pkt = packet(0x8400, &[record(&owner, 1, 1, &SRC4.octets())]);
        assert_eq!(parse_announcement(&pkt, SRC), Announcement::default());
    }

    #[test]
    fn rdata_length_past_the_packet_ends_the_walk() {
        let host = name(&["device-a", "local"]);
        let mut pkt = packet(0x8400, &[record(&host, 1, 1, &SRC4.octets())]);
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
            let pkt = packet(0x8400, &[record(&bad, 1, 1, &SRC4.octets())]);
            assert_eq!(parse_announcement(&pkt, SRC).hostname, None);
        }
    }

    #[test]
    fn cache_is_bounded_merges_and_ignores_empty() {
        let mut c = MdnsCache::default();
        let now = 1_000_000;
        c.observe(SRC, 0, Announcement::default(), now);
        assert!(c.is_empty());
        let mut a = Announcement {
            hostname: Some("a.local".into()),
            ..Default::default()
        };
        a.services.insert("_http._tcp".into());
        c.observe(SRC, 0, a, now);
        let mut b = Announcement::default();
        b.services.insert("_ipp._tcp".into());
        c.observe(SRC, 0, b, now + 1);
        let got = c.get(SRC).unwrap();
        assert_eq!(got.hostname.as_deref(), Some("a.local"));
        assert_eq!(got.services.len(), 2);
        // Fill it past the cap with fresh entries: size stays bounded.
        for i in 0..(MAX_CACHE_ENTRIES as u32 + 100) {
            let mut x = Announcement::default();
            x.services.insert("_x._tcp".into());
            c.observe(IpAddr::V4(Ipv4Addr::from(0xC000_0300 + i)), 0, x, now);
        }
        assert!(c.len() <= MAX_CACHE_ENTRIES);
        // Per-device service cap.
        let mut many = Announcement::default();
        for i in 0..100 {
            many.services.insert(format!("_s{i}._tcp"));
        }
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        let mut c2 = MdnsCache::default();
        c2.observe(ip, 0, many, now);
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

    // -- L5: spoofed sources cannot lock real devices out of the cache -----------------------------

    fn named(host: &str) -> Announcement {
        Announcement {
            hostname: Some(host.into()),
            ..Default::default()
        }
    }

    fn spoof(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0xC000_0200 + i)) // 192.0.2.x, 198-style TEST-NET
    }

    #[test]
    fn a_full_cache_evicts_its_oldest_entry_instead_of_dropping_a_real_device() {
        let mut c = MdnsCache::default();
        let t0: Millis = 1_000_000;
        for i in 0..MAX_CACHE_ENTRIES as u32 {
            c.observe(
                spoof(i),
                0,
                named(&format!("spoof-{i}.local")),
                t0 + Millis::from(i),
            );
        }
        assert_eq!(c.len(), MAX_CACHE_ENTRIES);
        // Within the TTL, a real device announces. It must be cached, displacing the oldest.
        let real = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 20));
        c.observe(real, 0, named("real.local"), t0 + 10_000);
        assert_eq!(
            c.get(real).and_then(|a| a.hostname.as_deref()),
            Some("real.local"),
            "the real device is cached"
        );
        assert_eq!(c.len(), MAX_CACHE_ENTRIES, "still bounded");
        assert!(c.get(spoof(0)).is_none(), "the OLDEST spoof was evicted");
        assert!(c.get(spoof(1)).is_some(), "newer entries stay");
        // NEGATIVE CONTROL: an entry that is already cached is refreshed, nothing evicted.
        c.observe(spoof(5), 0, named("spoof-5.local"), t0 + 20_000);
        assert!(c.get(spoof(1)).is_some());
    }

    fn filter() -> LinkFilter {
        LinkFilter {
            subnet: Some(Subnet {
                addr: Ipv4Addr::new(192, 168, 77, 7),
                prefix: 24,
            }),
            if_index: Some(11),
            own_v6: vec![
                "fe80::7".parse().unwrap(),
                "2001:db8:1:2::7".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn only_sources_on_the_wifi_link_are_admitted() {
        let f = filter();
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        assert!(f.admits(v4("192.168.77.20"), 0));
        assert!(!f.admits(v4("192.168.78.20"), 0), "other subnet");
        assert!(!f.admits(v4("10.9.9.9"), 0));
        // Link-local IPv6 must arrive on the Wi-Fi interface.
        assert!(f.admits(v6("fe80::20"), 11));
        assert!(!f.admits(v6("fe80::20"), 4), "other interface");
        assert!(!f.admits(v6("fe80::20"), 0), "unknown interface");
        // A global source must share a /64 with one of our own addresses.
        assert!(f.admits(v6("2001:db8:1:2::99"), 0));
        assert!(!f.admits(v6("2001:db8:9:9::99"), 0));
        // No IPv4 subnet known -> no IPv4 source admitted; a default filter admits nothing.
        let none = LinkFilter::default();
        assert!(!none.admits(v4("192.168.77.20"), 0));
        assert!(!none.admits(v6("fe80::20"), 11));
    }

    #[test]
    fn spoofed_off_link_sources_never_fill_the_cache_and_setting_the_filter_purges() {
        let mut c = MdnsCache::default();
        let t0: Millis = 1_000_000;
        // Before the link is known everything is cached; the filter then clears what is off-link.
        c.observe(
            IpAddr::V4(Ipv4Addr::new(192, 168, 77, 20)),
            0,
            named("real.local"),
            t0,
        );
        c.observe(
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
            0,
            named("elsewhere.local"),
            t0,
        );
        c.set_filter(Some(filter()));
        assert_eq!(c.len(), 1, "the off-link entry was purged");
        // 2000 spoofed off-subnet sources do not occupy a single slot.
        for i in 0..2000u32 {
            c.observe(
                IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i)),
                0,
                named("x.local"),
                t0 + 1,
            );
        }
        assert_eq!(c.len(), 1);
        let late = IpAddr::V4(Ipv4Addr::new(192, 168, 77, 21));
        c.observe(late, 0, named("late.local"), t0 + 2);
        assert!(c.get(late).is_some());
    }

    // -- N4: hop limit 255 -----------------------------------------------------------------------

    #[test]
    fn only_hop_limit_255_or_unreported_is_accepted() {
        assert!(hop_ok(Some(255)));
        assert!(
            hop_ok(None),
            "an OS that cannot report it must not break receive"
        );
        for h in [0u8, 1, 64, 254] {
            assert!(!hop_ok(Some(h)), "{h}");
        }
    }

    /// A listener on a loopback socket (never the real 5353), fed by a plain loopback sender.
    fn loopback_listener() -> (MdnsListener, std::net::SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr = sock.local_addr().unwrap();
        let l = MdnsListener { socket: sock };
        l.report_hops(false);
        (l, addr)
    }

    #[test]
    fn the_listener_reads_the_ttl_of_each_datagram() {
        let (l, to) = loopback_listener();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 64];
        for ttl in [64u32, 255] {
            tx.set_ttl(ttl).unwrap();
            tx.send_to(b"x", to).unwrap();
            let (n, from, _, hop) = l.recv(&mut buf).unwrap().expect("a datagram");
            assert_eq!((n, from), (1, IpAddr::V4(Ipv4Addr::LOCALHOST)));
            assert_eq!(
                hop,
                Some(ttl as u8),
                "the OS reports the TTL it arrived with"
            );
            assert_eq!(hop_ok(hop), ttl == 255);
        }
    }
}
