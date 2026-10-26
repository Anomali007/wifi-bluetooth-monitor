import { describe, expect, it } from "vitest";
import { ACTIONS, GROUP_LIMIT, PAGES, SETTING_ITEMS, dataItems, search } from "../lib/palette-items";
import type { Alert, LanDevice } from "../lib/types";

const lan = (n: number, hostname: string | null, vendor: string | null): LanDevice => ({
  networkKey: "net-x",
  macHash: `h${n}`,
  vendor,
  hostname,
  services: ["_http._tcp"],
  firstSeen: 0,
  lastSeen: 0,
  ip: null,
  mine: false,
  source: "both",
});

const alert = (id: string, title: string): Alert => ({
  id,
  kind: "evilTwin",
  severity: "high",
  title,
  detail: "d",
  firstSeen: 0,
  lastSeen: 0,
  subjectHash: "s",
  dismissed: false,
});

const data = dataItems({
  wifi: [
    { ssid: "Net-A", vendor: "Vendor-A", rowKey: "w-1-0" },
    { ssid: "Café Net-B", vendor: "Vendor-B", rowKey: "w-2-1" },
  ],
  ble: [{ name: "Tag-A", rowKey: "b-1" }],
  lan: [lan(1, "printer-a.local", "Vendor-A"), lan(2, null, null)],
  places: [{ id: 1, label: "Place A" }],
  alerts: [alert("a1", "Possible evil twin: Net-A")],
});
const all = [...PAGES, ...ACTIONS, ...SETTING_ITEMS, ...data];

describe("palette actions are harmless", () => {
  it("the only action is Scan now", () => {
    expect(ACTIONS.map((a) => a.action)).toEqual(["scan-now"]);
  });
  it("no sweep, helper or toggle is reachable as an action", () => {
    for (const q of ["sweep now", "sweep", "helper", "turn on", "enable"]) {
      const hits = search(q, all).flatMap((s) => s.items);
      expect(
        hits.filter((i) => i.action),
        q,
      ).toEqual([]);
    }
    // Settings results navigate; none carries an action.
    expect(SETTING_ITEMS.filter((i) => i.action)).toEqual([]);
    // The sweep setting is findable, as a navigation.
    const sweep = search("sweep", all).flatMap((s) => s.items);
    expect(sweep.find((i) => i.target === "lan-active-sweep")?.href).toBe("/settings#lan-active-sweep");
  });
  it("Scan now is findable", () => {
    expect(search("scan now", all)[0].items[0].action).toBe("scan-now");
  });
});

describe("data results", () => {
  const g = (q: string, group: string) =>
    search(q, all)
      .find((s) => s.group === group)
      ?.items.map((i) => i.label);

  it("finds a network by SSID or vendor, folded and case-insensitive", () => {
    expect(g("net-a", "wifi")).toContain("Net-A");
    expect(g("vendor-b", "wifi")).toEqual(["Café Net-B"]);
    expect(g("CAFE", "wifi")).toEqual(["Café Net-B"]);
  });
  it("finds bluetooth names, LAN hostnames, places and alert titles", () => {
    expect(g("tag-a", "bluetooth")).toEqual(["Tag-A"]);
    expect(g("printer", "lan")).toEqual(["printer-a"]);
    expect(g("place a", "places")).toEqual(["Place A"]);
    expect(g("evil twin: net", "alerts")).toEqual(["Possible evil twin: Net-A"]);
  });
  it("targets point at the row the page renders", () => {
    const w = data.find((i) => i.group === "wifi")!;
    expect(w.href).toBe("/");
    expect(w.target).toBe("row-w-1-0");
    expect(data.find((i) => i.group === "lan")!.target).toBe("lan-net-x-h1");
  });
  it("skips LAN devices with no name to show", () => {
    expect(data.filter((i) => i.group === "lan").length).toBe(1);
  });
  it("caps each group", () => {
    const many = dataItems({
      wifi: Array.from({ length: 20 }, (_, i) => ({ ssid: `Net-${i}`, vendor: null, rowKey: `w-${i}` })),
      ble: [],
      lan: [],
      places: [],
      alerts: [],
    });
    const sec = search("net", many).find((s) => s.group === "wifi")!;
    expect(sec.items.length).toBe(GROUP_LIMIT.wifi);
  });
  it("nonsense returns no groups", () => {
    expect(search("zzqxj", all)).toEqual([]);
  });
  it("empty query shows only pages and actions", () => {
    expect(search("", all).map((s) => s.group).sort()).toEqual(["actions", "pages"]);
  });
});
