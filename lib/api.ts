/**
 * Typed wrappers for the Tauri commands in src-tauri/src/commands.rs.
 * FROZEN signatures. UI code must go through this file, never `invoke` directly.
 *
 * Mock hook point: when NEXT_PUBLIC_WBM_MOCK === "1" at build/dev time, every call is routed
 * to lib/mock-invoke.ts (synthetic data, owned by WP5). Next inlines that env var, so in a
 * normal build the branch is dead code and the mock module is not bundled.
 */
import type {
  Alert,
  History,
  Millis,
  PermissionState,
  ScanResult,
  Settings,
} from "./types";
import { EVENT_ALERT, EVENT_SCAN } from "./types";

export type CommandName =
  | "scan_now"
  | "get_history"
  | "get_alerts"
  | "dismiss_alert"
  | "get_settings"
  | "set_settings"
  | "get_permissions";

async function call<T>(
  cmd: CommandName,
  args?: Record<string, unknown>,
): Promise<T> {
  if (process.env.NEXT_PUBLIC_WBM_MOCK === "1") {
    const { mockInvoke } = await import("./mock-invoke");
    return mockInvoke<T>(cmd, args);
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

/** Run one scan cycle now. */
export const scanNow = () => call<ScanResult>("scan_now");

/** Stored scans with scannedAt >= since (Unix ms); omit for the whole retention window. */
export const getHistory = (since?: Millis) =>
  call<History>("get_history", { since: since ?? null });

/** Newest first; dismissed alerts hidden unless includeDismissed. */
export const getAlerts = (includeDismissed = false) =>
  call<Alert[]>("get_alerts", { includeDismissed });

export const dismissAlert = (id: string) =>
  call<void>("dismiss_alert", { id });

export const getSettings = () => call<Settings>("get_settings");

/** Persists and returns the stored settings. */
export const setSettings = (settings: Settings) =>
  call<Settings>("set_settings", { settings });

export const getPermissions = () => call<PermissionState>("get_permissions");

type Unsubscribe = () => void;

async function subscribe<T>(
  event: string,
  cb: (payload: T) => void,
): Promise<Unsubscribe> {
  if (process.env.NEXT_PUBLIC_WBM_MOCK === "1") {
    const { mockListen } = await import("./mock-invoke");
    return mockListen<T>(event, cb);
  }
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(event, (e) => cb(e.payload));
}

/** Fires after every completed scan cycle. */
export const onScan = (cb: (r: ScanResult) => void) =>
  subscribe<ScanResult>(EVENT_SCAN, cb);

/** Fires once when an alert is first created. */
export const onAlert = (cb: (a: Alert) => void) =>
  subscribe<Alert>(EVENT_ALERT, cb);
