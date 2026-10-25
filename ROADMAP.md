# Roadmap

Only what is **not** built yet. What exists is described in the [README](README.md).

## Verification gaps

- **LAN devices: a readable neighbor source on macOS 27.** The kernel hides both neighbor tables from a signed third-party app (`sysctl` NET_RT_FLAGS / NET_RT_DUMP / NET_RT_DUMP2 / the privileged variant return only loopback rows), and Apple's built-in `arp` and `ndp`, which the app now runs as a fallback, also returned no Wi-Fi rows when started by the app on the tested build (they list 15 and 19 entries from a terminal or launchd). Find out why (which process or app identity the kernel keys on; whether granting Local Network access, an entitlement or a different launch path changes it), then check whether the fallback parses real output into devices inside the app. Until then the Network page is announced-devices-only.

- **Field-verify tracker detection with real hardware** (an AirTag, a Tile, a SmartTag). Today it is unit-tested on synthetic advertisements only; thresholds (5 scans / 20 minutes, 10-minute staleness) were tuned on synthetic data.
- Confirm on real adverts that the separated-only Find My rule (length byte 0x19 plus AirTag/Find My status type, DULT near-owner bit) neither misses a real separated AirTag nor still flags ordinary Apple devices. It follows AirGuard source and is tested on synthetic bytes only.
- Verify the network sweep on a real network (the gate, the packet sink, the rate limit, the /23 cap and the socket opening are tested; no packet of either kind has been sent on a real Wi-Fi link, and how many more devices it surfaces is unmeasured) and the Local Network prompt on more than one macOS version.
- Verify the Location prompt and grant flow across rebuilds on more than one macOS version.

## Dependencies

- Track the expired DULT draft the Network ID table comes from, and update when a final spec is published.

## Distribution

- Developer ID signing and notarization, and a downloadable build. Today you build and sign it yourself.
- Auto-update.

## Features

- Alert history that survives the retention window (dismissed state is lost when an alert is purged).
- An in-app "add the current access points to this trusted network" action for networks that are already trusted.
- Linux and Windows backends (different radio APIs; none exist).
