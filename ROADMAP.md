# Roadmap

Only what is **not** built yet. What exists is described in the [README](README.md).

## Verification gaps

- **Field-verify tracker detection with real hardware** (an AirTag, a Tile, a SmartTag). Today it is unit-tested on synthetic advertisements only; thresholds (5 scans / 20 minutes, 10-minute staleness) were tuned on synthetic data.
- Confirm the Find My "separated from owner" bit (`apple_find_my_separated`, already in `ble::classify`) improves precision on real adverts. It is not wired into the alert rules because carrying it would need a new field on `BleObservation` and a store migration.
- Verify the Location prompt and grant flow across rebuilds on more than one macOS version.

## Dependencies

- **Upgrade to Next 15** to clear the remaining advisories that `pnpm audit` reports against Next 14.2. None are reachable in a static export, but they should not linger.
- Track the expired DULT draft the Network ID table comes from, and update when a final spec is published.

## Distribution

- Developer ID signing and notarization, and a downloadable build. Today you build and sign it yourself.
- Auto-update.

## Features

- Alert history that survives the retention window (dismissed state is lost when an alert is purged).
- An in-app "add the current access points to this trusted network" action for networks that are already trusted.
- Linux and Windows backends (different radio APIs; none exist).
