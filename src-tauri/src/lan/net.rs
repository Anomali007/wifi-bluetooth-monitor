//! The joined Wi-Fi network: SSID and BSSID from CoreWLAN, IPv4 address and netmask and the
//! interface's own IPv6 addresses from `getifaddrs`. Read-only. The raw BSSID is hashed before it leaves this file.

#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

#[cfg(target_os = "macos")]
use crate::model::hash_identifier;
use crate::model::Salt;
#[cfg(target_os = "macos")]
use crate::vendor;

use super::gate::Subnet;

/// What we know about the joined network. No raw identifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    pub ssid: Option<String>,
    pub bssid_hash: Option<String>,
    pub group_id: Option<String>,
    /// OS interface index of the Wi-Fi interface (matches `rtm_index` in the ARP dump).
    pub if_index: Option<u16>,
    /// The Wi-Fi interface's name (`en0`), to pick its rows out of `arp`/`ndp` output.
    pub if_name: Option<String>,
    pub subnet: Option<Subnet>,
    /// The Wi-Fi interface's own IPv6 addresses, so our own entries are never listed as devices.
    pub own_v6: Vec<Ipv6Addr>,
}

/// The key a network's devices are stored under: the access point's radio-group id when known,
/// else its BSSID hash. `None` when macOS withholds the BSSID.
pub fn network_key(bssid_hash: Option<&str>, group_id: Option<&str>) -> Option<String> {
    group_id.or(bssid_hash).map(str::to_string)
}

/// IPv4 address and netmask of `ifname`, via `getifaddrs`.
#[cfg(target_os = "macos")]
fn interface_v4(ifname: &str) -> Option<Subnet> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() != ifname.as_bytes() {
            continue;
        }
        // SAFETY: both pointers were checked non-null; sa_family tells us the concrete type.
        let (addr, mask) = unsafe {
            if i32::from((*ifa.ifa_addr).sa_family) != libc::AF_INET {
                continue;
            }
            let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
            (
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                Ipv4Addr::from(u32::from_be(m.sin_addr.s_addr)),
            )
        };
        found = Subnet::from_addr_mask(addr, mask);
        break;
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    found
}

/// Every IPv6 address configured on `ifname` (scope bits cleared), via `getifaddrs`.
#[cfg(target_os = "macos")]
fn interface_v6(ifname: &str) -> Vec<Ipv6Addr> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() != ifname.as_bytes() {
            continue;
        }
        // SAFETY: the pointer was checked non-null; sa_family tells us the concrete type.
        let addr = unsafe {
            if i32::from((*ifa.ifa_addr).sa_family) != libc::AF_INET6 {
                continue;
            }
            let a = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
            Ipv6Addr::from(a.sin6_addr.s6_addr)
        };
        found.push(super::nd6::normalize_v6(addr));
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    found
}

#[cfg(target_os = "macos")]
fn interface_index(ifname: &str) -> Option<u16> {
    let c = std::ffi::CString::new(ifname).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    u16::try_from(idx).ok().filter(|i| *i != 0)
}

/// The Wi-Fi interface's current network. SSID and BSSID are nil until Location is granted;
/// the subnet comes from the interface and needs no permission.
#[cfg(target_os = "macos")]
pub fn read_link(salt: &Salt) -> Link {
    use objc2_core_wlan::CWWiFiClient;

    // SAFETY: CoreWLAN property reads on objects created and used on this thread. Nothing here
    // associates, scans or probes; these are the joined network's current attributes.
    let (ifname, ssid, bssid) = unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let Some(interface) = client.interface() else {
            return Link::default();
        };
        (
            interface.interfaceName().map(|s| s.to_string()),
            interface.ssid().map(|s| s.to_string()),
            interface.bssid().map(|s| s.to_string()),
        )
    };
    let Some(ifname) = ifname else {
        return Link::default();
    };
    let bssid = bssid
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());
    Link {
        ssid: ssid.filter(|s| !s.is_empty()),
        bssid_hash: bssid.as_deref().map(|b| hash_identifier(salt, b)),
        group_id: bssid.as_deref().and_then(|b| vendor::group_id(salt, b)),
        if_index: interface_index(&ifname),
        subnet: interface_v4(&ifname),
        own_v6: interface_v6(&ifname),
        if_name: Some(ifname),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn read_link(_salt: &Salt) -> Link {
    Link::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_prefers_group_then_bssid() {
        assert_eq!(network_key(Some("b"), Some("g")).as_deref(), Some("g"));
        assert_eq!(network_key(Some("b"), None).as_deref(), Some("b"));
        assert_eq!(network_key(None, None), None);
        // A group id alone (BSSID hash absent) still identifies the network.
        assert_eq!(network_key(None, Some("g")).as_deref(), Some("g"));
    }

    /// Prints counts/booleans only. `cargo test -- --ignored link_live --nocapture`.
    #[test]
    #[ignore]
    fn link_live() {
        let l = read_link(&Salt::from_bytes(vec![7; 16]));
        println!(
            "link_live: ssid={} bssid={} group={} if_index={} subnet_prefix={:?}",
            l.ssid.is_some(),
            l.bssid_hash.is_some(),
            l.group_id.is_some(),
            l.if_index.is_some(),
            l.subnet.map(|s| s.prefix)
        );
        println!("link_live: own_v6={}", l.own_v6.len());
    }
}
