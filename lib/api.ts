/**
 * Typed wrappers for the Tauri commands in src-tauri/src/commands.rs.
 * FROZEN signatures. UI code must go through this file, never `invoke` directly.
 *
 * Mock hook point: when NEXT_PUBLIC_WBM_MOCK === "1" at build/dev time, every call is routed
 * to lib/mock-invoke.ts (synthetic data, owned by WP5). Next inlines that env var, so in a
 * normal build the branch is dead code and the mock module is not bundled.
 */
import type {
  AgentAuditEntry,
  AgentDecision,
  AgentProposal,
  HelperStatus,
  Alert,
  History,
  LanDevice,
  Millis,
  MineEntry,
  MineKind,
  NetworkInfo,
  PermissionState,
  Place,
  ScanResult,
  Settings,
  WatchKind,
  WatchMatch,
  WatchlistEntry,
} from "./types";
import { EVENT_ALERT, EVENT_SCAN } from "./types";

export type CommandName =
  | "scan_now"
  | "get_history"
  | "get_alerts"
  | "dismiss_alert"
  | "get_settings"
  | "set_settings"
  | "get_permissions"
  | "list_places"
  | "rename_place"
  | "forget_place"
  | "list_mine"
  | "add_mine"
  | "remove_mine"
  | "list_watchlist"
  | "add_watchlist"
  | "remove_watchlist"
  | "list_lan_devices"
  | "get_current_network"
  | "sweep_now"
  | "get_helper_status"
  | "open_login_items"
  | "list_agent_proposals"
  | "decide_agent_proposal"
  | "list_agent_audit"
  | "undo_agent_change";

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

// ---- Places, Mine, watchlist, LAN -------------------------------------------

export const listPlaces = () => call<Place[]>("list_places");

/** Blank or null clears the label. Returns the updated place. */
export const renamePlace = (id: number, label: string | null) =>
  call<Place>("rename_place", { id, label });

/** Forgets the place and every sighting recorded there. */
export const forgetPlace = (id: number) => call<void>("forget_place", { id });

export const listMine = () => call<MineEntry[]>("list_mine");

/** Mark an access point, radio group, BLE device or LAN device as mine (by hash). */
export const addMine = (
  kind: MineKind,
  idHash: string,
  label: string | null = null,
  ssid: string | null = null,
) => call<MineEntry>("add_mine", { kind, idHash, label, ssid });

export const removeMine = (kind: MineKind, idHash: string) =>
  call<void>("remove_mine", { kind, idHash });

export const listWatchlist = () => call<WatchlistEntry[]>("list_watchlist");

export const addWatchlist = (kind: WatchKind, pattern: string, matchMode: WatchMatch) =>
  call<WatchlistEntry>("add_watchlist", { kind, pattern, matchMode });

export const removeWatchlist = (id: number) => call<void>("remove_watchlist", { id });

/** Stored LAN devices, newest first; omit networkKey for every network. */
export const listLanDevices = (networkKey?: string) =>
  call<LanDevice[]>("list_lan_devices", { networkKey: networkKey ?? null });

export const getCurrentNetwork = () => call<NetworkInfo>("get_current_network");

/** Observe the LAN now (the sweep gate still applies); returns the joined network's devices. */
export const sweepNow = () => call<LanDevice[]>("sweep_now");

/** Off, enabled, or waiting for approval in System Settings, Login Items. */
export const getHelperStatus = () => call<HelperStatus>("get_helper_status");

/** Open System Settings at Login Items. */
export const openLoginItems = () => call<void>("open_login_items");

// ---- Agent requests ----------------------------------------------------------

/** Changes an agent asked for that wait for a person. Stale ones are expired first. */
export const listAgentProposals = () => call<AgentProposal[]>("list_agent_proposals");

/** Approve (re-validated against current data, then applied) or reject one request. */
export const decideAgentProposal = (id: number, approve: boolean) =>
  call<AgentDecision>("decide_agent_proposal", { id, approve });

/** Changes agents made (directly, or approved), newest first. */
export const listAgentAudit = (limit?: number) =>
  call<AgentAuditEntry[]>("list_agent_audit", { limit: limit ?? null });

/** One-click undo of an audited agent change. */
export const undoAgentChange = (id: number) => call<void>("undo_agent_change", { id });

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
