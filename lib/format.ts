import type {
  Millis,
  Security,
  TrackerKind,
  WatchKind,
  WatchMatch,
  WatchlistEntry,
  WifiObservation,
} from "./types";

export function formatTime(ms: Millis): string {
  return new Date(ms).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDateTime(ms: Millis): string {
  return new Date(ms).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatAgo(ms: Millis, now: Millis = Date.now()): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m ago`;
}

export const SECURITY_LABEL: Record<Security, string> = {
  open: "Open",
  wep: "WEP",
  wpaPersonal: "WPA",
  wpa2Personal: "WPA2",
  wpa3Personal: "WPA3",
  wpaEnterprise: "WPA Enterprise",
  wpa2Enterprise: "WPA2 Enterprise",
  wpa3Enterprise: "WPA3 Enterprise",
  owe: "OWE (encrypted)",
  unknown: "Unknown",
};

/** Deliberately hedged: a match is a hint, never proof. */
export const TRACKER_LABEL: Record<TrackerKind, string> = {
  appleFindMy: "Possible tracker (Find My)",
  tile: "Possible tracker (Tile)",
  samsungSmartTag: "Possible tracker (SmartTag)",
  chipolo: "Possible tracker (Chipolo)",
  pebblebee: "Possible tracker (Pebblebee)",
  googleFindMy: "Possible tracker (Find My Device)",
  unknownTracker: "Possible tracker",
};

export function shortHash(h: string | null): string {
  return h ? h.slice(0, 8) : "n/a";
}

/** Mirror of `Security::strength` in model.rs (Open/Unknown 0, Owe/Wep 1, Wpa 2, Wpa2 3, Wpa3 4). */
export function securityStrength(s: Security): number {
  switch (s) {
    case "wep":
    case "owe":
      return 1;
    case "wpaPersonal":
    case "wpaEnterprise":
      return 2;
    case "wpa2Personal":
    case "wpa2Enterprise":
      return 3;
    case "wpa3Personal":
    case "wpa3Enterprise":
      return 4;
    default:
      return 0;
  }
}

// ---- Watchlist and multi-radio display (WP-C) -----------------------------------------

export const WATCH_KIND_LABEL: Record<WatchKind, string> = {
  ssid: "Network name",
  vendor: "Vendor",
};

export const WATCH_MATCH_LABEL: Record<WatchMatch, string> = {
  exact: "is exactly",
  contains: "contains",
};

/** One line for a list row, e.g. `Network name contains "Net-A"`. */
export function describeWatchEntry(e: Pick<WatchlistEntry, "kind" | "pattern" | "match">): string {
  return `${WATCH_KIND_LABEL[e.kind]} ${WATCH_MATCH_LABEL[e.match]} "${e.pattern}"`;
}

/**
 * Check a new watchlist entry before it is sent. Returns the trimmed pattern, or an error to
 * show. Duplicates (same kind, mode and pattern, ignoring case) are refused; a blank pattern
 * would match everything under "contains", so it is refused too.
 */
export function checkWatchEntry(
  kind: WatchKind,
  match: WatchMatch,
  pattern: string,
  existing: readonly WatchlistEntry[],
): { ok: true; pattern: string } | { ok: false; error: string } {
  const p = pattern.trim();
  if (p === "") return { ok: false, error: "Enter a name to watch for." };
  const dup = existing.some(
    (e) => e.kind === kind && e.match === match && e.pattern.trim().toLowerCase() === p.toLowerCase(),
  );
  if (dup) return { ok: false, error: "That entry is already on the list." };
  return { ok: true, pattern: p };
}

/** "1 device" for a single radio, "1 device · 3 radios" for several. */
export function radiosLabel(radios: number): string {
  return radios > 1 ? `1 device · ${radios} radios` : "1 device";
}

export interface WifiGroup {
  /** The strongest radio; its name, security and vendor represent the group. */
  rep: WifiObservation;
  radios: WifiObservation[];
}

/**
 * Collapse the radios of one physical device (same `groupId` within a scan) into one entry.
 * Observations without a group id stay on their own. Order follows first appearance.
 */
export function groupWifiByRadio(wifi: readonly WifiObservation[]): WifiGroup[] {
  const out: WifiGroup[] = [];
  const byGroup = new Map<string, WifiGroup>();
  for (const w of wifi) {
    const g = w.groupId ? byGroup.get(w.groupId) : undefined;
    if (g) {
      g.radios.push(w);
      if (w.rssi > g.rep.rssi) g.rep = w;
      continue;
    }
    const fresh: WifiGroup = { rep: w, radios: [w] };
    out.push(fresh);
    if (w.groupId) byGroup.set(w.groupId, fresh);
  }
  return out;
}
