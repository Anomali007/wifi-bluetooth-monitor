# Wi-Fi + Bluetooth Monitor

A desktop app for macOS that watches the Wi-Fi networks, Bluetooth Low Energy devices and (on your own network) LAN devices around you and flags a few specific situations: an access point impersonating a network you trust, a Bluetooth tracker or a network that keeps showing up wherever you go, a name on your watchlist, and a new device on a network you marked as yours. Everything stays on your Mac.

**Listen-only, with one opt-in exception.** By default the app does not transmit, deauthenticate, jam, inject, probe, connect to or pair with any device. It reads the Wi-Fi scan, Bluetooth advertisements, the Mac's own neighbor tables (IPv6, and IPv4 ARP where macOS lets it), and mDNS announcements it overhears (the mDNS sockets are receive-only). The single exception is the optional **network sweep**, off by default. It runs only while you are joined to an access point you marked as yours. It sends **one ICMPv6 echo request to the link-local all-nodes address `ff02::1`**, scoped to your Wi-Fi interface with a hop limit of 1 (so it cannot leave your network), then re-reads the neighbor table about two seconds later. That is one packet per sweep, not one per device. It runs automatically at most every 10 minutes, or when you press "Sweep now". It never opens a TCP connection, scans ports, probes services or sends mDNS queries, and it refuses to run on any other network, including one that merely uses the same name.

Built with Tauri 2 (Rust backend in `src-tauri/`) and a Next.js 16 (React 19) static-export frontend (`app/`). macOS only.

> **Verified on:** macOS 27.0.1 (26A434), Apple silicon, signed debug build, 2026-10-24, about five minutes of running. Live run, counts only: 0 scan errors in the log; the receive-only mDNS sockets bound on IPv4 and IPv6 and heard 1,306 datagrams from 9 announcing sources; the store migrated from schema 3 to 4 in place; **4 LAN devices recorded, all from mDNS announcements alone (4 with a hostname, 0 with a hardware address, 0 with a vendor)**. **Not working on this macOS:** both neighbor tables. The IPv4 ARP table and the IPv6 neighbor table return no Wi-Fi entries to this signed app (only 7 loopback rows, which are filtered out), so no device has a hardware address or vendor. **Not tested live:** the network sweep (never turned on; the gate, the one-packet sink and opening the unprivileged ICMPv6 socket are tested, the echo itself was never sent on a real network), the alert rules for followed-across-places, watchlist and new LAN device (unit tests and mock UI only), and the Local Network prompt flow. No scan data is published.

## Features

Everything in this list exists in the code and has tests; see [Limitations](#limitations) for what is and is not verified in the field.

- **Wi-Fi scan** through CoreWLAN, every 60 seconds by default. Records signal, channel and security mode for each access point. SSIDs are only readable once Location access is granted (see [Permissions](#permissions)).
- **Bluetooth LE scan** through CoreBluetooth (10-second listen window per cycle). Passive: advertisements are read, nothing is connected to.
- **Tracker signatures**: an advertisement is matched against documented signatures for Apple Find My, Tile, Samsung SmartTag, Chipolo, Pebblebee and Google Find My Device, plus the generic DULT (Detecting Unwanted Location Trackers) advertisement. Constants are taken from the open-source [AirGuard](https://github.com/seemoo-lab/AirGuard) app and the IETF DULT draft. Find My style advertisements only count as trackers when they say they are **separated from their owner** (see [Limitations](#limitations)); an owner-nearby Find My signal is shown as such and never alerts.
- **Eight alert rules**, each switchable in Settings:
  - **Evil twin**: the same network name from two or more access points with different security modes (for example one open, one WPA2).
  - **Open lookalike**: an open network whose name matches or nearly matches a network you trust (case, whitespace, look-alike characters, small edit distance).
  - **Trusted network changed**: a trusted name seen from an access point you have not marked as yours, or with weaker security than you expect.
  - **Persistent tracker**: a tracker-signature device present across at least 5 scans spanning at least 20 minutes (both adjustable). A tracker *family* that stays continuously present while its identifiers change is also reported, at lower severity.
  - **New device**: first sighting of a non-tracker Bluetooth device (off by default; noisy).
  - **Followed across places**: a tracker-signature Bluetooth device, or a Wi-Fi access point, seen during stays at two or more different places at least 30 minutes apart (high severity at three or more places). Worded as "possible". Anything you marked as yours is excluded.
  - **Watchlist match**: a nearby access point whose name or hardware vendor matches an entry on your watchlist (see below).
  - **New device on your network**: a device not seen before on a network whose access point you marked as yours. It stays quiet during a 15-minute learning window (from when the network was first observed or marked as yours), so the existing devices are not all reported as new.
- **Places and "followed across places"**: a place is a fingerprint of the Wi-Fi access points around you, with no GPS and no coordinates. Needs Location access for the access-point addresses. A scan only counts toward a stay after three consecutive scans match the same place (so a bus or train does not create places), and access points seen in two or more places are treated as movers rather than landmarks. Name a place ("Home") or forget it in Settings. Place data is kept 14 days by default (configurable).
- **Mine**: mark an access point (or a whole multi-radio device), a Bluetooth device or a LAN device as yours, with an optional label. Marked items never raise followed, watchlist or new-device alerts. For Bluetooth devices that change their address every few minutes the app warns that the mark will not last. Marking an access point also trusts it for the "trusted network changed" rule.
- **Vendors**: each Wi-Fi access point and LAN device shows the manufacturer from its address prefix, looked up in the IEEE MA-L registry (data from the IEEE Registration Authority, public registry at standards-oui.ieee.org). The compact table is committed; regenerate it with `scripts/update-oui.sh`. Locally administered (randomized) addresses show as "Private address". The lookup runs on the raw address before it is hashed; only the vendor name is stored.
- **Multi-radio devices**: access points whose addresses share the first five bytes and the high nibble of the last byte are one physical device (a router's 2.4, 5 and 6 GHz radios) and are shown as "1 device, 3 radios".
- **Watchlist**: list network names or hardware vendors to be told about. "Exact" means the same name after ignoring case, spacing and look-alike characters (no near-miss matching: "King" does not match "Kind"); "Contains" is a substring match after the same folding. Entries are stored only in the local database.
- **Network devices**: a Network page lists devices on the network you are joined to, with vendor, name and services. Devices are built from three sources and joined: the Mac's **IPv6 neighbor table** (hardware address plus IPv6 address, on the Wi-Fi interface only, never your own addresses), **mDNS announcements** it overhears over IPv4 and IPv6 (hostname and service types, per sender), and the **IPv4 ARP table** as a best-effort extra. On macOS 27 the two neighbor tables come back with no Wi-Fi entries to this app (see Limitations), so there the list is built from mDNS announcements alone. An announcing host whose address matches a neighbor entry gets that hardware address and vendor; a host that only announced is still listed (keyed by a salted hash of its hostname, no vendor), so one device is one row where the data allows. The Network page shows each device's source: neighbor table, announced, or both. An optional sweep (see [Legal and ethical use](#legal-and-ethical-use)) sends one IPv6 echo to all nodes to wake quiet devices into the neighbor table. IP addresses are shown live and never stored.
- **Notifications**: one system notification per newly created alert (repeat sightings of the same condition do not notify again). Notification text names the kind of finding ("possible tracker", ...) and never contains a network name, device name, or identifier.
- **UI pages**: Dashboard (permission banner, scan problems, device table, signal chart, Scan now), Alerts (with dismiss), History (sightings over the retention window, with vendor, filter by Wi-Fi or Bluetooth), Network (devices on the joined network, Sweep now), Settings (trusted networks, Mine, Places, Watchlist, network devices and the sweep switch, intervals, retention, alert toggles, notifications).

## Install and build

Requirements: macOS 13 or newer, [Rust](https://rustup.rs) (1.85+), Node.js 22+, and pnpm 10. Xcode command line tools are needed for the native build.

```sh
git clone https://github.com/Anomali007/wifi-bluetooth-monitor.git
cd wifi-bluetooth-monitor
pnpm install
pnpm tauri build --debug        # or: pnpm tauri build
```

The app bundle is written to `src-tauri/target/debug/bundle/macos/` (or `target/release/bundle/macos/`).

**Build the bundle; do not rely on `pnpm tauri dev` for the real thing.** macOS only shows the Location and Bluetooth prompts to a bundled app with an Info.plist, so an unbundled dev binary never gets either permission and will see Wi-Fi networks without names and no Bluetooth at all.

### Signing

macOS ties Location and Bluetooth grants to the app's code signature. An ad-hoc signed build gets a new identity on every rebuild, so macOS can ask again (or silently stop granting). To keep grants stable across rebuilds, sign with your own Apple Development certificate. Pass it through the environment, never a committed file:

```sh
APPLE_SIGNING_IDENTITY="<SHA-1 or name of your Apple Development identity>" pnpm tauri build --debug
```

The app uses the hardened runtime. `src-tauri/Entitlements.plist` carries the Bluetooth entitlement and the Location entitlement (`com.apple.security.personal-information.location`); without the latter a hardened app is never granted Location.

### Tests and checks

```sh
pnpm test                          # vitest: formatting, API mock routing, mock-data invariants
pnpm test:interaction              # headless-Chrome click-through of the mock build (see script header)
npx tsc --noEmit && pnpm lint
cd src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
scripts/check-public-safety.sh     # no real-looking MACs, placeholder salts, stray prints or images
scripts/live-counts.sh             # counts only (scans, networks, devices, trackers, alerts) from the local store
```

`NEXT_PUBLIC_WBM_MOCK=1 pnpm build` makes a build that runs against synthetic data in a plain browser (no Tauri), for UI work. Production builds contain none of the mock code.

## Permissions

| Permission | Why | How to grant |
| --- | --- | --- |
| **Location Services** | macOS withholds Wi-Fi network names (SSID) and access-point addresses (BSSID) from apps without Location access. The app uses it only to unlock those names; it never reads or stores your location. | Accept the prompt on first launch, or System Settings > Privacy & Security > Location Services > switch the app on. |
| **Bluetooth** | Needed to receive BLE advertisements. | Accept the prompt, or System Settings > Privacy & Security > Bluetooth. |
| **Local Network** | Needed to read the devices on your Wi-Fi network (mDNS announcements, the neighbor tables and, if you turn it on, the sweep). Without it the Network page stays empty; nothing else is affected. | Accept the prompt the first time the app looks at the network, or System Settings > Privacy & Security > Local Network. |
| **Notifications** | Optional; for alert notifications. | Accept the prompt, or System Settings > Notifications. |

Without Location the Wi-Fi scan still runs but the networks have no names; the dashboard shows a banner and a scan-problem entry explaining why. Grants belong to the code signature (see [Signing](#signing)): a rebuilt or re-signed app may need to be granted again.

## Limitations

- **CoreBluetooth hides MAC addresses.** macOS gives each Bluetooth device a per-Mac identifier, not its hardware address. The app hashes that identifier. It cannot match a device to anything outside this Mac.
- **Find My identifiers rotate**: per the DULT draft an accessory changes its address about every 15 minutes near its owner and about every 24 hours when separated, so one physical tag can appear as several devices over time. The persistent-tracker rule also groups a tracker family that stays present, which is a heuristic.
- **Tracker alerts are "possible", a best guess.** A signature match means "an advertisement of this type", not "this device is following you". Apple's Find My advertisement is also sent by other Find My accessories and by some Apple devices; crowded places can look the same. A tracker not heard for more than 10 minutes stops alerting.
- **Only separated Find My adverts count.** Apple's Find My advertisement is also sent by AirTags and accessories near their owner, and by iPhones, Macs and AirPods. Following AirGuard, the app treats an Apple advert as a tracker only when it is in separated mode and its status says AirTag or Find My accessory. Before this rule, a 3-minute run at home matched 28 distinct identifiers. With it, a 10-minute run matched 1. The trade-off: a tracker still near its owner, or one using a status type the app does not know, is not flagged.
- **Tracker detection is unit-tested on synthetic advertisements but NOT field-verified with a real AirTag, Tile or other tracker. None was available during development.** Treat the tracker feature as unproven against real hardware.
- **Places are approximate.** A place is a set of nearby access points; a changed router or a different part of a large building can split or merge places. "Followed across places" is a heuristic and says "possible".
- **Neighbor tables are unreadable for Wi-Fi on macOS 27 (found in testing).** The `sysctl` that backs `arp -an` and `ndp -an` returns no entries for the Wi-Fi interface to a signed, bundled build, for IPv4 and IPv6 alike, with every operation tried (`NET_RT_FLAGS`, `NET_RT_DUMP`, `NET_RT_DUMP2`, the privileged variant). What does come back is only the Mac's own loopback entries, which the app filters out as "not on the Wi-Fi interface". The system `arp` and `ndp` tools still see the entries. The app keeps both tables as sources in case another macOS version allows it. **Today the Network page is therefore built from mDNS announcements only:** a device that never announces itself over mDNS does not appear, devices known only from an announcement show no vendor and no hardware address, and the optional sweep (one ICMPv6 echo to all nodes) cannot surface anything on macOS 27 because the table it fills cannot be read. IPv4-only silent devices may be missed on any macOS version.
- **Randomized addresses.** Phones and laptops that use private Wi-Fi addresses change identity per network, so they can look like new devices and show no vendor.
- Wi-Fi alert titles include the network name (SSID); device identifiers are never shown, only short hash fragments in tables.
- Network names (SSIDs) and Bluetooth advertised names are stored as plain text in the local database until the retention window expires. Only addresses and identifiers are hashed.
- WPA2/WPA3 transition networks are reported as WPA3. OWE ("enhanced open") networks are reported as OWE (encrypted), not as open.
- macOS only (13 or newer). Linux and Windows are not supported.
- Not notarized and not distributed as a download; build it yourself.

## Privacy

- **Local only.** Scan history lives in an SQLite database in the app's data folder (`~/Library/Application Support/com.anomali007.wifibtmonitor/`). Nothing is uploaded, and there is no export feature. Besides scans, the database holds place fingerprints (hashes only, no coordinates), your Mine and Watchlist entries, and LAN devices (hashed hardware address, or a salted hostname hash for a device only heard announcing; vendor; mDNS hostname and service types; how it was learned; never the IP).
- **Salted hashes.** Access-point addresses and Bluetooth identifiers are hashed (SHA-256) with a random per-install salt before they leave the scanning code. Raw addresses and identifiers are never stored or logged (names are, see Limitations).
- **The salt** is 32 random bytes in `salt.key` next to the database, mode `0600`, kept separate from the database so a copied database cannot be brute-forced back to addresses.
- **Retention.** Scan history is deleted automatically after 24 hours by default; place and network-device data after 14 days by default (both configurable in Settings). Items marked as yours are kept until you unmark them.
- **No logging of scan data.** Release builds print nothing about scans; debug builds log counts only.

## Legal and ethical use

This tool is for understanding your own radio environment. Use it responsibly.

- **Listen-only, with one opt-in exception.** By default the app does not transmit, deauthenticate, jam, inject, probe, connect to or pair with any device. It reads the Wi-Fi scan, Bluetooth advertisements, the Mac's own neighbor tables (IPv6, and IPv4 ARP where macOS lets it), and mDNS announcements it overhears (the mDNS sockets are receive-only). The single exception is the optional **network sweep**, off by default. It runs only while you are joined to an access point you marked as yours. It sends **one ICMPv6 echo request to the link-local all-nodes address `ff02::1`**, scoped to your Wi-Fi interface with a hop limit of 1 (so it cannot leave your network), then re-reads the neighbor table about two seconds later. That is one packet per sweep, not one per device. It runs automatically at most every 10 minutes, or when you press "Sweep now". It never opens a TCP connection, scans ports, probes services or sends mDNS queries, and it refuses to run on any other network, including one that merely uses the same name. Keep it that way in any change you make.
- **Do not use it to follow, locate or profile a person.** History expires on purpose, identifiers are hashed on purpose, and there is no export on purpose.
- Know the laws where you live regarding electronic communications and stalking. If in doubt, consult a legal professional.
- If you think a tracker is following you, do not rely on this app alone. Use your phone's built-in unwanted-tracker alerts and contact local authorities if you feel unsafe.
- Provided "as is", without warranty of any kind. The authors are not responsible for misuse.

## Contributing

Issues and pull requests are welcome. Before opening one, run the checks in [Tests and checks](#tests-and-checks). This repository is public: never commit real scan data, real SSIDs or BSSIDs, screenshots of a real scan, secrets, or signing details. Fixtures use synthetic names (`Net-A`) and locally administered addresses (`02:00:00:...`), and `scripts/check-public-safety.sh` enforces the basics.

See [ROADMAP.md](ROADMAP.md) for what is not built yet.

## License

MIT. See [LICENSE](LICENSE).
