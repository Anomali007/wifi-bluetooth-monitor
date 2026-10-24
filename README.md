# Wi-Fi + Bluetooth Monitor

A listen-only desktop app for macOS that watches the Wi-Fi networks and Bluetooth Low Energy devices around you and flags a few specific situations: an access point impersonating a network you trust, and a Bluetooth tracker that keeps showing up near you.

It never transmits, probes, connects to, or pairs with anything it finds. Everything stays on your Mac.

Built with Tauri 2 (Rust backend in `src-tauri/`) and a Next.js 14 static-export frontend (`app/`). macOS only.

> **Verified on:** `{{VERIFIED_ON}}` (placeholder: macOS version, build, and live-run counts are filled in after a real run: Wi-Fi networks seen, share with a readable name, BLE devices, trackers, alerts, scans stored)

## Features

Everything in this list exists in the code and has tests; see [Limitations](#limitations) for what is and is not verified in the field.

- **Wi-Fi scan** through CoreWLAN, every 60 seconds by default. Records signal, channel and security mode for each access point. SSIDs are only readable once Location access is granted (see [Permissions](#permissions)).
- **Bluetooth LE scan** through CoreBluetooth (10-second listen window per cycle). Passive: advertisements are read, nothing is connected to.
- **Tracker signatures**: an advertisement is matched against documented signatures for Apple Find My, Tile, Samsung SmartTag, Chipolo, Pebblebee and Google Find My Device, plus the generic DULT (Detecting Unwanted Location Trackers) advertisement. Constants are taken from the open-source [AirGuard](https://github.com/seemoo-lab/AirGuard) app and the IETF DULT draft. Find My style advertisements only count as trackers when they say they are **separated from their owner** (see [Limitations](#limitations)); an owner-nearby Find My signal is shown as such and never alerts.
- **Five alert rules**, each switchable in Settings:
  - **Evil twin**: the same network name from two or more access points with different security modes (for example one open, one WPA2).
  - **Open lookalike**: an open network whose name matches or nearly matches a network you trust (case, whitespace, look-alike characters, small edit distance).
  - **Trusted network changed**: a trusted name seen from an access point you have not marked as yours, or with weaker security than you expect.
  - **Persistent tracker**: a tracker-signature device present across at least 5 scans spanning at least 20 minutes (both adjustable). A tracker *family* that stays continuously present while its identifiers change is also reported, at lower severity.
  - **New device**: first sighting of a non-tracker Bluetooth device (off by default; noisy).
- **Notifications**: one system notification per newly created alert (repeat sightings of the same condition do not notify again). Notification text names the kind of finding ("possible tracker", ...) and never contains a network name, device name, or identifier.
- **UI pages**: Dashboard (permission banner, scan problems, device table, signal chart, Scan now), Alerts (with dismiss), History (sightings over the retention window, filter by Wi-Fi or Bluetooth), Settings (trusted networks, intervals, retention, alert toggles, notifications).

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
| **Notifications** | Optional; for alert notifications. | Accept the prompt, or System Settings > Notifications. |

Without Location the Wi-Fi scan still runs but the networks have no names; the dashboard shows a banner and a scan-problem entry explaining why. Grants belong to the code signature (see [Signing](#signing)): a rebuilt or re-signed app may need to be granted again.

## Limitations

- **CoreBluetooth hides MAC addresses.** macOS gives each Bluetooth device a per-Mac identifier, not its hardware address. The app hashes that identifier. It cannot match a device to anything outside this Mac.
- **Find My identifiers rotate**: per the DULT draft an accessory changes its address about every 15 minutes near its owner and about every 24 hours when separated, so one physical tag can appear as several devices over time. The persistent-tracker rule also groups a tracker family that stays present, which is a heuristic.
- **Tracker alerts are "possible", a best guess.** A signature match means "an advertisement of this type", not "this device is following you". Apple's Find My advertisement is also sent by other Find My accessories and by some Apple devices; crowded places can look the same. A tracker not heard for more than 10 minutes stops alerting.
- **The Apple Find My signature is broad.** Any Apple device or accessory advertising in the Find My network matches it, and many do. On a first live run in a normal home or street setting, dozens of distinct Find My identifiers appeared within minutes. Expect false positives from the persistent-tracker rule around many Apple devices; the alerts are hints to check, not findings.
- **Tracker detection is unit-tested on synthetic advertisements but NOT field-verified with a real AirTag, Tile or other tracker. None was available during development.** Treat the tracker feature as unproven against real hardware.
- Wi-Fi alert titles include the network name (SSID); device identifiers are never shown, only short hash fragments in tables.
- Network names (SSIDs) and Bluetooth advertised names are stored as plain text in the local database until the retention window expires. Only addresses and identifiers are hashed.
- WPA2/WPA3 transition networks are reported as WPA3. OWE ("enhanced open") networks are reported as OWE (encrypted), not as open.
- macOS only (13 or newer). Linux and Windows are not supported.
- Not notarized and not distributed as a download; build it yourself.

## Privacy

- **Local only.** Scan history lives in an SQLite database in the app's data folder (`~/Library/Application Support/com.anomali007.wifibtmonitor/`). Nothing is uploaded, and there is no export feature.
- **Salted hashes.** Access-point addresses and Bluetooth identifiers are hashed (SHA-256) with a random per-install salt before they leave the scanning code. Raw addresses and identifiers are never stored or logged (names are, see Limitations).
- **The salt** is 32 random bytes in `salt.key` next to the database, mode `0600`, kept separate from the database so a copied database cannot be brute-forced back to addresses.
- **Retention.** History is deleted automatically after 24 hours by default (configurable in Settings).
- **No logging of scan data.** Release builds print nothing about scans; debug builds log counts only.

## Legal and ethical use

This tool is for understanding your own radio environment. Use it responsibly.

- **Listen-only.** The app does not transmit, deauthenticate, jam, inject, probe, connect to or pair with any device. Keep it that way in any change you make.
- **Do not use it to follow, locate or profile a person.** History expires on purpose, identifiers are hashed on purpose, and there is no export on purpose.
- Know the laws where you live regarding electronic communications and stalking. If in doubt, consult a legal professional.
- If you think a tracker is following you, do not rely on this app alone. Use your phone's built-in unwanted-tracker alerts and contact local authorities if you feel unsafe.
- Provided "as is", without warranty of any kind. The authors are not responsible for misuse.

## Contributing

Issues and pull requests are welcome. Before opening one, run the checks in [Tests and checks](#tests-and-checks). This repository is public: never commit real scan data, real SSIDs or BSSIDs, screenshots of a real scan, secrets, or signing details. Fixtures use synthetic names (`Net-A`) and locally administered addresses (`02:00:00:...`), and `scripts/check-public-safety.sh` enforces the basics.

See [ROADMAP.md](ROADMAP.md) for what is not built yet.

## License

MIT. See [LICENSE](LICENSE).
