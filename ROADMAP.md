# Roadmap

Only what is **not** built yet. What exists is described in the [README](README.md).

## Verification gaps

- **LAN devices on macOS 27: done as an opt-in background item (launchd runs Apple's `arp -an` / `ndp -an`, the app reads the files).** Still open: why the kernel keys on the process chain (a launchd job whose program is Apple's own tool sees the entries; anything else in the chain sees none); whether a future macOS fixes the `sysctl` path (the sysctl readers are kept for that); a Developer ID signed and notarized build so the Login Items entry shows a stable name; and a way to bound the output file while the app is closed (launchd appends, nothing rotates it).

- **Field-verify tracker detection with real hardware** (an AirTag, a Tile, a SmartTag). Today it is unit-tested on synthetic advertisements only; thresholds (5 scans / 20 minutes, 10-minute staleness) were tuned on synthetic data.
- Confirm on real adverts that the separated-only Find My rule (length byte 0x19 plus AirTag/Find My status type, DULT near-owner bit) neither misses a real separated AirTag nor still flags ordinary Apple devices. It follows AirGuard source and is tested on synthetic bytes only.
- Verify the network sweep on a real network (the gate, the packet sink, the rate limit, the /23 cap and the socket opening are tested; no packet of either kind has been sent on a real Wi-Fi link, and how many more devices it surfaces is unmeasured) and the Local Network prompt on more than one macOS version.
- Verify the Location prompt and grant flow across rebuilds on more than one macOS version.
- **Agent tools (`wbm`) against a real agent session.** Tested end to end over stdio with a scripted client and synthetic data; not yet run from Claude Code against the real database for a working session. Also unverified: how a long-open settings window behaves after an agent edit on a real machine (the merge is unit-tested; the window itself does not live-refresh).

## Dependencies

- Track the expired DULT draft the Network ID table comes from, and update when a final spec is published.

## Distribution

- Developer ID signing and notarization, and a downloadable build. Today you build and sign it yourself.
- Auto-update.

## Features

- Agent tools: a live-refresh path for an open app window when `wbm` edits Mine, the watchlist or trusted networks (today the window shows the change after its next reload; saves from a stale window are merged, never destructive).
- Agent tools: an opt-in, per-tool allowlist (for example read-only mode, or hiding history/LAN tools) for people who want to hand an agent less than the default set.
- Agent tools: a signed/notarized `wbm` that ships inside the app bundle, so `claude mcp add` can point at a stable path.
- Alert history that survives the retention window (dismissed state is lost when an alert is purged).
- An in-app "add the current access points to this trusted network" action for networks that are already trusted.
- Linux and Windows backends (different radio APIs; none exist).
