import type { Millis, Security, TrackerKind } from "./types";

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
