# Roadmap

Only what is **not** built yet. What exists is described in the [README](README.md).

## Verification gaps

- **LAN devices: find a readable source on macOS 27.** The ARP `sysctl` (NET_RT_FLAGS, NET_RT_DUMPX_FLAGS and the privileged variant, IPv4 and unspecified family) returns no IPv4 neighbors to a signed third-party app; only IPv6 neighbor entries come back. Options to evaluate: IPv6 neighbor entries joined to mDNS names, or a different permitted API.

- **Field-verify tracker detection with real hardware** (an AirTag, a Tile, a SmartTag). Today it is unit-tested on synthetic advertisements only; thresholds (5 scans / 20 minutes, 10-minute staleness) were tuned on synthetic data.
- Confirm on real adverts that the separated-only Find My rule (length byte 0x19 plus AirTag/Find My status type, DULT near-owner bit) neither misses a real separated AirTag nor still flags ordinary Apple devices. It follows AirGuard source and is tested on synthetic bytes only.
- Verify the network sweep on a real network (unit-tested gate only; never run live) and the Local Network prompt on more than one macOS version.
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
