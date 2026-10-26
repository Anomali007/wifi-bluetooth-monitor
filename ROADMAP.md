# Roadmap

Only what is **not** built yet. What exists is described in the [README](README.md).

## Verification gaps

- **LAN devices on macOS 27: done as an opt-in background item (launchd runs Apple's `arp -an` / `ndp -an`, the app reads the files).** Still open: why the kernel keys on the process chain (a launchd job whose program is Apple's own tool sees the entries; anything else in the chain sees none); whether a future macOS fixes the `sysctl` path (the sysctl readers are kept for that); a Developer ID signed and notarized build so the Login Items entry shows a stable name; and a controlled check that unregistering the background item on quit and registering it again at launch never asks for Login Items approval a second time (it looked stable in the system's background-item records, but that is indirect). The item runs only for the user who built the app, because the bundled plists carry the builder's data folder path; a signed, notarized build that works for any user needs a different way to hand launchd that path (for example a small helper that writes to a fixed shared location).

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
