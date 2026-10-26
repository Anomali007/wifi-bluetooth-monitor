/**
 * What the command palette can find, as plain data. Pure: components fetch, this builds and
 * ranks. Search never changes a setting. The only action is Scan now, which is read-only.
 */
import { SETTINGS_REGISTRY, settingHref } from "./settings-registry";
import { rank, type Searchable } from "./search";
import type { Alert, LanDevice } from "./types";

export type GroupId = "pages" | "actions" | "settings" | "wifi" | "bluetooth" | "lan" | "places" | "alerts";

export const GROUP_LABEL: Record<GroupId, string> = {
  pages: "Pages",
  actions: "Actions",
  settings: "Settings",
  wifi: "Wi-Fi networks",
  bluetooth: "Bluetooth",
  lan: "Network devices",
  places: "Places",
  alerts: "Alerts",
};

/** Fixed order, used to break ties between groups. */
const GROUP_ORDER: GroupId[] = ["pages", "actions", "settings", "wifi", "bluetooth", "lan", "places", "alerts"];
const APP_GROUPS: ReadonlySet<GroupId> = new Set(["pages", "actions", "settings"]);
const PIN_SCORE = 800; // the prefix tier in lib/search.ts

export const GROUP_LIMIT: Record<GroupId, number> = {
  pages: 5,
  actions: 3,
  settings: 6,
  wifi: 4,
  bluetooth: 4,
  lan: 4,
  places: 3,
  alerts: 4,
};

export type ActionId = "scan-now";

export interface PaletteItem extends Searchable {
  /** Unique across the whole list; also the option's DOM id suffix. */
  id: string;
  group: GroupId;
  /** Second line: section, vendor, severity... */
  hint?: string;
  /** Route to open (with an optional #anchor). Absent for actions. */
  href?: string;
  action?: ActionId;
  /** DOM id to scroll to and highlight after navigating. */
  target?: string;
}

export const PAGES: readonly PaletteItem[] = [
  { id: "page-dashboard", group: "pages", label: "Dashboard", hint: "Nearby devices and signal strength", href: "/", keywords: ["home", "devices", "nearby", "signal"] },
  { id: "page-alerts", group: "pages", label: "Alerts", hint: "Active alerts", href: "/alerts", keywords: ["warnings", "notifications", "dismiss"] },
  { id: "page-history", group: "pages", label: "History", hint: "Past scans", href: "/history", keywords: ["past", "timeline", "log"] },
  { id: "page-network", group: "pages", label: "Network", hint: "Devices on your network", href: "/network", keywords: ["lan", "router", "local network"] },
  { id: "page-settings", group: "pages", label: "Settings", hint: "All settings", href: "/settings", keywords: ["preferences", "options", "configure"] },
];

/**
 * Harmless actions only. Nothing here may switch on transmitting or the background helper;
 * tests/palette-items.test.ts pins this list.
 */
export const ACTIONS: readonly PaletteItem[] = [
  { id: "action-scan-now", group: "actions", label: "Scan now", hint: "Listen for Wi-Fi and Bluetooth once", action: "scan-now", keywords: ["refresh", "rescan", "update"] },
];

export const SETTING_ITEMS: readonly PaletteItem[] = SETTINGS_REGISTRY.map((e) => ({
  id: `setting-${e.id}`,
  group: "settings" as const,
  label: e.label,
  hint: e.section === e.label ? "Settings" : `Settings, ${e.section}`,
  description: e.description,
  keywords: e.keywords,
  href: settingHref(e.id),
  target: e.id,
}));

/** Items from already-loaded data. Hidden or unnamed things are skipped. */
export function dataItems(d: {
  wifi: { ssid: string; vendor: string | null; rowKey: string }[];
  ble: { name: string; rowKey: string }[];
  lan: LanDevice[];
  places: { id: number; label: string }[];
  alerts: Alert[];
}): PaletteItem[] {
  const out: PaletteItem[] = [];
  const seen = new Set<string>();
  const add = (it: PaletteItem) => {
    if (!seen.has(it.id)) {
      seen.add(it.id);
      out.push(it);
    }
  };
  for (const w of d.wifi) {
    add({
      id: `wifi-${w.rowKey}`,
      group: "wifi",
      label: w.ssid,
      hint: w.vendor ? `Wi-Fi, ${w.vendor}` : "Wi-Fi",
      keywords: w.vendor ? [w.vendor] : [],
      href: "/",
      target: `row-${w.rowKey}`,
    });
  }
  for (const b of d.ble) {
    add({
      id: `ble-${b.rowKey}`,
      group: "bluetooth",
      label: b.name,
      hint: "Bluetooth",
      keywords: [],
      href: "/",
      target: `row-${b.rowKey}`,
    });
  }
  for (const l of d.lan) {
    const name = l.hostname ? l.hostname.replace(/\.local$/i, "") : l.vendor ? `${l.vendor} device` : null;
    if (!name) continue;
    add({
      id: `lan-${l.networkKey}-${l.macHash}`,
      group: "lan",
      label: name,
      hint: l.vendor ? `Network, ${l.vendor}` : "Network",
      keywords: l.vendor ? [l.vendor, ...l.services] : [...l.services],
      href: "/network",
      target: `lan-${l.networkKey}-${l.macHash}`,
    });
  }
  for (const p of d.places) {
    add({
      id: `place-${p.id}`,
      group: "places",
      label: p.label,
      hint: "Place, in Settings",
      keywords: [],
      href: `/settings#place-${p.id}`,
      target: `place-${p.id}`,
    });
  }
  for (const a of d.alerts) {
    add({
      id: `alert-${a.id}`,
      group: "alerts",
      label: a.title,
      hint: `Alert, ${a.severity}`,
      keywords: [a.kind],
      href: "/alerts",
      target: `alert-${a.id}`,
    });
  }
  return out;
}

export interface Section {
  group: GroupId;
  title: string;
  items: PaletteItem[];
}

/**
 * Group, rank and cap. With an empty query: pages and actions only. Groups are ordered by their
 * best hit (ties by fixed order), and each is capped at GROUP_LIMIT.
 */
export function search(query: string, items: readonly PaletteItem[]): Section[] {
  const q = query.trim();
  const pool = q === "" ? items.filter((i) => i.group === "pages" || i.group === "actions") : items;
  const ranked = q === "" ? pool.map((item) => ({ item, match: { score: 0, tier: "exact" as const } })) : rank(q, pool);
  const byGroup = new Map<GroupId, { items: PaletteItem[]; best: number }>();
  for (const { item, match } of ranked) {
    const g = byGroup.get(item.group) ?? { items: [], best: match.score };
    if (g.items.length < GROUP_LIMIT[item.group]) g.items.push(item);
    byGroup.set(item.group, g);
  }
  // Data labels are broadcast by anyone nearby, so an SSID named "scan" must not outrank the
  // "Scan now" action and capture Enter: app groups with a prefix-or-better hit go first.
  const pinned = (group: GroupId, best: number) => (APP_GROUPS.has(group) && best >= PIN_SCORE ? 1 : 0);
  return [...byGroup.entries()]
    .sort(
      (a, b) =>
        pinned(b[0], b[1].best) - pinned(a[0], a[1].best) ||
        b[1].best - a[1].best ||
        GROUP_ORDER.indexOf(a[0]) - GROUP_ORDER.indexOf(b[0]),
    )
    .map(([group, g]) => ({ group, title: GROUP_LABEL[group], items: g.items }));
}
