/**
 * Mock backend for UI development (NEXT_PUBLIC_WBM_MOCK=1). OWNER: WP5.
 * SYNTHETIC DATA ONLY: this repo is public. SSIDs like "Net-A", hashes are fake hex built
 * from a counter, never anything recorded from a real scan.
 *
 * Contract used by lib/api.ts: `mockInvoke(cmd, args)` mirrors the Tauri commands and
 * `mockListen(event, cb)` mirrors `listen`, returning an unsubscribe function.
 *
 * Scenarios: append `?mock=denied` to the page URL for the permission-denied state with
 * scan errors; the default scenario has everything granted and one alert of every kind.
 */
import type { CommandName } from "./api";
import type {
  Alert,
  BleObservation,
  History,
  LanDevice,
  Millis,
  MineEntry,
  MineKind,
  NetworkInfo,
  PermissionState,
  Place,
  ScanError,
  ScanResult,
  ScanSnapshot,
  Settings,
  WatchKind,
  WatchMatch,
  WatchlistEntry,
  WifiObservation,
} from "./types";
import { DEFAULT_SETTINGS, EVENT_ALERT, EVENT_SCAN } from "./types";

/** 64-char lowercase hex, obviously fake: starts with 02 (locally administered), then a counter. */
function fakeHash(n: number): string {
  return ("02" + n.toString(16).padStart(62, "0")).slice(0, 64);
}

function scenario(): "ok" | "denied" {
  try {
    if (
      typeof window !== "undefined" &&
      new URLSearchParams(window.location.search).get("mock") === "denied"
    ) {
      return "denied";
    }
  } catch {
    /* no window / blocked: default scenario */
  }
  return "ok";
}

const H_NET_A = fakeHash(0xa1);
const H_NET_A_TWIN = fakeHash(0xa2);
const H_CAFE = fakeHash(0xb1);
const H_CAFE_OPEN = fakeHash(0xb2);
const H_HOME = fakeHash(0xc1);
const H_OFFICE = fakeHash(0xd1);
const H_TAG = fakeHash(0xe1);
const H_PHONE = fakeHash(0xe2);
const H_BUDS = fakeHash(0xe3);
const H_WATCH = fakeHash(0xe4);
const H_NEW = fakeHash(0xe5);
const H_GROUP_A = fakeHash(0xf1);
const H_LAN_NET = fakeHash(0xf2);
const H_LAN_1 = fakeHash(0xf3);
const H_LAN_2 = fakeHash(0xf4);
const H_LAN_3 = fakeHash(0xf5);
const H_PLACE_1 = fakeHash(0xf5);

let settings: Settings = {
  ...DEFAULT_SETTINGS,
  trustedNetworks: [
    {
      ssid: "Net-A",
      knownBssidHashes: [H_NET_A],
      expectedSecurity: "wpa2Personal",
    },
  ],
};

function permissions(): PermissionState {
  return scenario() === "denied"
    ? { bluetooth: "denied", location: "notDetermined" }
    : { bluetooth: "granted", location: "granted" };
}

function jitter(base: number, seed: number, step: number): number {
  return base + Math.round(Math.sin(seed * 1.7 + step) * 4);
}

function wifiAt(now: Millis, step: number): WifiObservation[] {
  const denied = scenario() === "denied";
  const rows: WifiObservation[] = [
    {
      ssid: "Net-A",
      bssidHash: H_NET_A,
      rssi: jitter(-48, 1, step),
      channel: 36,
      security: "wpa2Personal",
      seenAt: now,
      vendor: "Vendor-A",
      groupId: H_GROUP_A,
    },
    {
      ssid: "Net-A",
      bssidHash: H_NET_A_TWIN,
      rssi: jitter(-61, 2, step),
      channel: 6,
      security: "wpa2Personal",
      seenAt: now,
      vendor: "Private address",
      groupId: H_GROUP_A,
    },
    {
      ssid: "Cafe-Guest",
      bssidHash: H_CAFE,
      rssi: jitter(-70, 3, step),
      channel: 11,
      security: "wpa2Personal",
      seenAt: now,
      vendor: "Vendor-A",
      groupId: null,
    },
    {
      ssid: "Cafe-Guest",
      bssidHash: H_CAFE_OPEN,
      rssi: jitter(-66, 4, step),
      channel: 1,
      security: "open",
      seenAt: now,
      vendor: "Private address",
      groupId: null,
    },
    {
      ssid: "Home-5G",
      bssidHash: H_HOME,
      rssi: jitter(-80, 5, step),
      channel: 149,
      security: "wpa3Personal",
      seenAt: now,
      vendor: "Vendor-A",
      groupId: null,
    },
    {
      ssid: "Office-Corp",
      bssidHash: H_OFFICE,
      rssi: jitter(-74, 6, step),
      channel: 44,
      security: "wpa2Enterprise",
      seenAt: now,
      vendor: "Vendor-A",
      groupId: null,
    },
  ];
  // Without Location permission macOS withholds SSID and BSSID.
  return denied
    ? rows.map((r) => ({ ...r, ssid: null, bssidHash: null, vendor: null, groupId: null }))
    : rows;
}

function bleAt(now: Millis, step: number, withNew: boolean): BleObservation[] {
  if (scenario() === "denied") return [];
  const rows: BleObservation[] = [
    {
      name: null,
      peripheralHash: H_TAG,
      rssi: jitter(-58, 7, step),
      tracker: "tile",
      ownerState: null,
      manufacturerId: null,
      seenAt: now,
    },
    {
      name: "Phone-1",
      peripheralHash: H_PHONE,
      rssi: jitter(-45, 8, step),
      tracker: null,
      ownerState: "nearOwner",
      manufacturerId: 76,
      seenAt: now,
    },
    {
      name: "Buds-2",
      peripheralHash: H_BUDS,
      rssi: jitter(-62, 9, step),
      tracker: null,
      ownerState: null,
      manufacturerId: 117,
      seenAt: now,
    },
    {
      name: "Watch-3",
      peripheralHash: H_WATCH,
      rssi: null,
      tracker: null,
      ownerState: null,
      manufacturerId: null,
      seenAt: now,
    },
  ];
  if (withNew) {
    rows.push({
      name: "Speaker-4",
      peripheralHash: H_NEW,
      rssi: jitter(-72, 10, step),
      tracker: null,
      ownerState: null,
      manufacturerId: 6,
      seenAt: now,
    });
  }
  return rows;
}

function scanErrors(): ScanError[] {
  if (scenario() !== "denied") return [];
  return [
    {
      source: "ble",
      code: "permissionDenied",
      message: "Bluetooth access was denied for this app.",
    },
    {
      source: "wifi",
      code: "permissionDenied",
      message: "Wi-Fi names are withheld until Location access is granted.",
    },
  ];
}

const MIN = 60_000;
let scanCount = 0;

function currentScan(): ScanResult {
  const now = Date.now();
  return {
    scannedAt: now,
    wifi: wifiAt(now, scanCount),
    ble: bleAt(now, scanCount, true),
    errors: scanErrors(),
    permissions: permissions(),
  };
}

function buildHistory(since?: Millis | null): History {
  const now = Date.now();
  const scans: ScanSnapshot[] = [];
  // 48 scans, 30 minutes apart: the full default 24 h window, oldest first.
  for (let i = 47; i >= 0; i--) {
    const t = now - i * 30 * MIN;
    scans.push({
      scannedAt: t,
      wifi: wifiAt(t, i),
      ble: bleAt(t, i, i < 6),
    });
  }
  return { scans: since ? scans.filter((s) => s.scannedAt >= since) : scans };
}

function buildAlerts(): Alert[] {
  const now = Date.now();
  return [
    {
      id: "mock-evil-twin",
      kind: "evilTwin",
      severity: "high",
      title: "Possible evil twin: Net-A",
      detail:
        "Two access points advertise Net-A with different hardware identifiers on different channels. One may be an impostor.",
      firstSeen: now - 3 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_NET_A_TWIN,
      dismissed: false,
    },
    {
      id: "mock-open-lookalike",
      kind: "openLookalike",
      severity: "medium",
      title: "Open lookalike of Cafe-Guest",
      detail:
        "An unencrypted network uses the same name as a secured one nearby.",
      firstSeen: now - 5 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_CAFE_OPEN,
      dismissed: false,
    },
    {
      id: "mock-trusted-changed",
      kind: "trustedNetworkChanged",
      severity: "medium",
      title: "Trusted network Net-A changed",
      detail:
        "Net-A was seen from hardware that is not on your trusted list.",
      firstSeen: now - 2 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_NET_A_TWIN,
      dismissed: false,
    },
    {
      id: "mock-tracker",
      kind: "persistentTracker",
      severity: "high",
      title: "Possible tracker nearby",
      detail:
        "A tracker-type Bluetooth device has been nearby across 9 scans over 4 hours. This may be a possible tracker, or someone's own tag nearby.",
      firstSeen: now - 4 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_TAG,
      dismissed: false,
    },
    {
      id: "mock-followed",
      kind: "followedAcrossPlaces",
      severity: "high",
      title: "Possible device following you",
      detail:
        "A network that appears wherever you go: seen at Home and Place 2, at least 30 minutes apart. This may be a portable access point, or a coincidence.",
      firstSeen: now - 6 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_GROUP_A,
      dismissed: false,
    },
    {
      id: "mock-watchlist",
      kind: "watchlist",
      severity: "medium",
      title: "Watchlist match: Net-A",
      detail: "A network on your watchlist is nearby (Vendor-A).",
      firstSeen: now - 2 * 60 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_NET_A,
      dismissed: false,
    },
    {
      id: "mock-new-lan-device",
      kind: "newLanDevice",
      severity: "medium",
      title: "New device on your network",
      detail: "A device not seen before appeared on Net-A (Vendor-A).",
      firstSeen: now - 10 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_LAN_2,
      dismissed: false,
    },
    {
      id: "mock-new-device",
      kind: "newDevice",
      severity: "info",
      title: "New Bluetooth device nearby",
      detail: "A device not seen earlier in this window appeared.",
      firstSeen: now - 3 * MIN,
      lastSeen: now - 1 * MIN,
      subjectHash: H_NEW,
      dismissed: false,
    },
  ];
}

let alerts: Alert[] | null = null;
const dismissedIds = new Set<string>();

function allAlerts(): Alert[] {
  if (!alerts) alerts = buildAlerts();
  return alerts.map((a) => ({ ...a, dismissed: dismissedIds.has(a.id) }));
}

// ---- v2 state: places, Mine, watchlist, LAN (all synthetic) -------------------

const DAY = 24 * 60 * MIN;

let places: Place[] = [
  {
    id: 1,
    label: "Home",
    members: [H_NET_A, H_NET_A_TWIN, H_HOME],
    firstSeen: Date.now() - 12 * DAY,
    lastSeen: Date.now() - 1 * MIN,
  },
  {
    id: 2,
    label: null,
    members: [H_CAFE, H_OFFICE, H_PLACE_1],
    firstSeen: Date.now() - 3 * DAY,
    lastSeen: Date.now() - 5 * 60 * MIN,
  },
];

let mine: MineEntry[] = [
  { kind: "wifiGroup", idHash: H_GROUP_A, label: "Router-A", ssid: "Net-A", addedAt: Date.now() - 2 * DAY },
];

let watchlist: WatchlistEntry[] = [
  { id: 1, kind: "ssid", pattern: "Net-A", match: "contains", addedAt: Date.now() - DAY },
];
let nextWatchId = 2;

function currentNetwork(): NetworkInfo {
  const isMine = mine.some((m) => m.kind === "wifiGroup" && m.idHash === H_GROUP_A);
  const sweepEnabled = settings.lanActiveSweep && isMine;
  return {
    networkKey: H_LAN_NET,
    ssid: "Net-A",
    bssidHash: H_NET_A,
    groupId: H_GROUP_A,
    subnet: "192.0.2.0/24",
    isMine,
    sweepEnabled,
    mode: sweepEnabled ? "sweep" : "passive",
    lastSweepAt: sweepEnabled ? Date.now() - 4 * MIN : null,
    // `/network?noTools=1` previews the "tools unavailable" status line.
    neighborNote:
      typeof window !== "undefined" && window.location.search.includes("noTools=1")
        ? "macOS has no arp tool"
        : null,
  };
}

function lanDevices(networkKey?: string | null): LanDevice[] {
  const now = Date.now();
  const all: LanDevice[] = [
    {
      networkKey: H_LAN_NET,
      macHash: H_LAN_1,
      vendor: "Vendor-A",
      hostname: "device-1.local",
      services: ["_http._tcp", "_ipp._tcp"],
      firstSeen: now - 9 * DAY,
      lastSeen: now - 1 * MIN,
      ip: "192.0.2.10",
      mine: false,
      source: "both",
    },
    {
      networkKey: H_LAN_NET,
      macHash: H_LAN_2,
      vendor: "Private address",
      hostname: null,
      services: [],
      firstSeen: now - 10 * MIN,
      lastSeen: now - 1 * MIN,
      ip: "2001:db8::23",
      mine: false,
      source: "neighbor",
    },
    {
      networkKey: H_LAN_NET,
      macHash: H_LAN_3,
      vendor: null,
      hostname: "device-3.local",
      services: ["_airplay._tcp"],
      firstSeen: now - 2 * DAY,
      lastSeen: now - 3 * MIN,
      ip: "192.0.2.41",
      mine: false,
      source: "announced",
    },
  ];
  return all
    .filter((d) => !networkKey || d.networkKey === networkKey)
    .map((d) => ({
      ...d,
      mine: mine.some((m) => m.kind === "lan" && m.idHash === d.macHash),
    }));
}

type Listener = (payload: unknown) => void;
const listeners = new Map<string, Set<Listener>>();

function emit(event: string, payload: unknown) {
  listeners.get(event)?.forEach((cb) => cb(payload));
}

export async function mockInvoke<T>(
  cmd: CommandName,
  args?: Record<string, unknown>,
): Promise<T> {
  switch (cmd) {
    case "scan_now": {
      scanCount += 1;
      const result = currentScan();
      emit(EVENT_SCAN, result);
      return result as T;
    }
    case "get_history":
      return buildHistory(args?.since as Millis | null | undefined) as T;
    case "get_alerts": {
      const includeDismissed = Boolean(args?.includeDismissed);
      const list = allAlerts()
        .filter((a) => includeDismissed || !a.dismissed)
        .sort((a, b) => b.lastSeen - a.lastSeen);
      return list as T;
    }
    case "dismiss_alert":
      dismissedIds.add(String(args?.id));
      return undefined as T;
    case "get_settings":
      return settings as T;
    case "set_settings":
      settings = (args?.settings as Settings) ?? settings;
      return settings as T;
    case "get_permissions":
      return permissions() as T;
    case "list_places":
      return places.map((p) => ({ ...p })) as T;
    case "rename_place": {
      const id = Number(args?.id);
      const raw = args?.label as string | null | undefined;
      const label = raw && raw.trim() ? raw.trim() : null;
      const found = places.find((p) => p.id === id);
      if (!found) throw "no such place";
      found.label = label;
      return { ...found } as T;
    }
    case "forget_place":
      places = places.filter((p) => p.id !== Number(args?.id));
      return undefined as T;
    case "list_mine":
      return mine.map((m) => ({ ...m })) as T;
    case "add_mine": {
      const kind = args?.kind as MineKind;
      const idHash = String(args?.idHash);
      const raw = args?.label as string | null | undefined;
      const existing = mine.find((m) => m.kind === kind && m.idHash === idHash);
      const label = raw && raw.trim() ? raw.trim() : null;
      // Like the backend: only access-point marks carry a name, and a re-mark without one keeps it.
      const rawSsid = args?.ssid as string | null | undefined;
      const ssid =
        (kind === "wifiAp" || kind === "wifiGroup") && rawSsid ? rawSsid : null;
      if (existing) {
        existing.label = label;
        if (ssid) existing.ssid = ssid;
        return { ...existing } as T;
      }
      const entry: MineEntry = { kind, idHash, label, ssid, addedAt: Date.now() };
      mine = [...mine, entry];
      return { ...entry } as T;
    }
    case "remove_mine":
      mine = mine.filter(
        (m) => !(m.kind === args?.kind && m.idHash === args?.idHash),
      );
      return undefined as T;
    case "list_watchlist":
      return watchlist.map((w) => ({ ...w })) as T;
    case "add_watchlist": {
      const pattern = String(args?.pattern ?? "").trim();
      if (!pattern) throw "watchlist pattern is empty";
      const entry: WatchlistEntry = {
        id: nextWatchId++,
        kind: args?.kind as WatchKind,
        pattern,
        match: args?.matchMode as WatchMatch,
        addedAt: Date.now(),
      };
      watchlist = [...watchlist, entry];
      return { ...entry } as T;
    }
    case "remove_watchlist":
      watchlist = watchlist.filter((w) => w.id !== Number(args?.id));
      return undefined as T;
    case "list_lan_devices":
      return lanDevices(args?.networkKey as string | null | undefined) as T;
    case "get_current_network":
      return currentNetwork() as T;
    case "get_helper_status":
      return (settings.lanNeighborHelper ? "enabled" : "off") as T;
    case "open_login_items":
      return undefined as T;
    case "sweep_now": {
      // Same strings as the Rust gate (lan/gate.rs SweepRefusal::message).
      if (!settings.lanActiveSweep)
        return Promise.reject("The active sweep is switched off in Settings.");
      if (!currentNetwork().isMine)
        return Promise.reject(
          "This access point is not marked as yours. Mark it as mine first.",
        );
      return lanDevices(currentNetwork().networkKey) as T;
    }
  }
}

export function mockListen<T>(
  event: string,
  cb: (payload: T) => void,
): () => void {
  const set = listeners.get(event) ?? new Set<Listener>();
  const l = cb as Listener;
  set.add(l);
  listeners.set(event, set);
  return () => {
    set.delete(l);
  };
}

/** Exported so a dev can push a fresh alert event from the console if desired. */
export function mockEmitAlert(a: Alert) {
  emit(EVENT_ALERT, a);
}
