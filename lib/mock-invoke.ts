/**
 * Mock backend for UI development (NEXT_PUBLIC_WBM_MOCK=1). OWNER: WP5.
 * SYNTHETIC DATA ONLY: this repo is public. SSIDs like "Net-A", BSSID hashes are fake hex,
 * never anything recorded from a real scan.
 *
 * Contract used by lib/api.ts: `mockInvoke(cmd, args)` mirrors the Tauri commands and
 * `mockListen(event, cb)` mirrors `listen`, returning an unsubscribe function.
 */
import type { CommandName } from "./api";
import type { PermissionState, ScanResult, Settings } from "./types";
import { DEFAULT_SETTINGS } from "./types";

let settings: Settings = { ...DEFAULT_SETTINGS };

const permissions: PermissionState = {
  bluetooth: "granted",
  location: "granted",
};

function fakeScan(): ScanResult {
  const now = Date.now();
  return {
    scannedAt: now,
    wifi: [
      {
        ssid: "Net-A",
        bssidHash: "00".repeat(32),
        rssi: -55,
        channel: 36,
        security: "wpa2Personal",
        seenAt: now,
      },
    ],
    ble: [],
    errors: [],
    permissions,
  };
}

export async function mockInvoke<T>(
  cmd: CommandName,
  args?: Record<string, unknown>,
): Promise<T> {
  switch (cmd) {
    case "scan_now":
      return fakeScan() as T;
    case "get_history":
      return { scans: [] } as T;
    case "get_alerts":
      return [] as T;
    case "dismiss_alert":
      return undefined as T;
    case "get_settings":
      return settings as T;
    case "set_settings":
      settings = (args?.settings as Settings) ?? settings;
      return settings as T;
    case "get_permissions":
      return permissions as T;
  }
}

export function mockListen<T>(
  _event: string,
  _cb: (payload: T) => void,
): () => void {
  return () => {};
}
