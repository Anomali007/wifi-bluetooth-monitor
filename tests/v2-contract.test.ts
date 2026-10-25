// Contract tests for the v2 commands (places, Mine, watchlist, LAN) against the mock backend,
// plus the same public-repo invariants the v1 mock data has to meet.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  addMine,
  addWatchlist,
  forgetPlace,
  getAlerts,
  getCurrentNetwork,
  getHelperStatus,
  getSettings,
  listLanDevices,
  listMine,
  listPlaces,
  listWatchlist,
  removeMine,
  removeWatchlist,
  renamePlace,
  scanNow,
  setSettings,
  sweepNow,
} from "../lib/api";
import { DEFAULT_SETTINGS } from "../lib/types";

const original = process.env.NEXT_PUBLIC_WBM_MOCK;
beforeEach(() => {
  process.env.NEXT_PUBLIC_WBM_MOCK = "1";
});
afterEach(() => {
  if (original === undefined) delete process.env.NEXT_PUBLIC_WBM_MOCK;
  else process.env.NEXT_PUBLIC_WBM_MOCK = original;
});

const HASH64 = /^02[0-9a-f]{62}$/;
const SYNTHETIC_VENDOR = /^(Vendor-[A-Z]|Private address)$/;
const MAC_SHAPED = /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi;

describe("v2 defaults", () => {
  it("settings defaults match model.rs", () => {
    expect(DEFAULT_SETTINGS.placeRetentionDays).toBe(14);
    expect(DEFAULT_SETTINGS.lanActiveSweep).toBe(false);
    expect(DEFAULT_SETTINGS.lanNeighborHelper).toBe(false);
    const t = DEFAULT_SETTINGS.alertToggles;
    expect([t.followedAcrossPlaces, t.watchlist, t.newLanDevice]).toEqual([true, true, true]);
  });

  it("the mock serves the new settings fields", async () => {
    const s = await getSettings();
    expect(s.placeRetentionDays).toBe(14);
    expect(s.lanActiveSweep).toBe(false);
    expect(s.lanNeighborHelper).toBe(false);
  });
});

describe("neighbor helper", () => {
  it("status follows the setting in the mock", async () => {
    const s = await getSettings();
    expect(await getHelperStatus()).toBe("off");
    await setSettings({ ...s, lanNeighborHelper: true });
    expect(await getHelperStatus()).toBe("enabled");
    await setSettings({ ...s, lanNeighborHelper: false });
    expect(await getHelperStatus()).toBe("off");
  });
});

describe("places", () => {
  it("lists, renames (trimming, blank clears) and forgets", async () => {
    const before = await listPlaces();
    expect(before.length).toBeGreaterThanOrEqual(2);
    const id = before[1].id;
    expect((await renamePlace(id, "  Place-B  ")).label).toBe("Place-B");
    expect((await renamePlace(id, "   ")).label).toBeNull();
    await forgetPlace(id);
    const after = await listPlaces();
    expect(after.some((p) => p.id === id)).toBe(false);
    expect(after.length).toBe(before.length - 1);
  });

  it("renaming an unknown place fails", async () => {
    await expect(renamePlace(99999, "x")).rejects.toBeDefined();
  });
});

describe("mine", () => {
  it("add is per kind, relabel keeps one entry, remove deletes", async () => {
    const hash = "02" + "a".repeat(62);
    const n0 = (await listMine()).length;
    await addMine("ble", hash, "Tag-A");
    await addMine("lan", hash); // same hash, different kind: distinct entry
    expect((await listMine()).length).toBe(n0 + 2);
    const again = await addMine("ble", hash, "Tag-B");
    expect(again.label).toBe("Tag-B");
    expect((await listMine()).length).toBe(n0 + 2);
    await removeMine("ble", hash);
    const rest = await listMine();
    expect(rest.length).toBe(n0 + 1);
    expect(rest.some((m) => m.kind === "ble" && m.idHash === hash)).toBe(false);
    expect(rest.some((m) => m.kind === "lan" && m.idHash === hash)).toBe(true);
  });

  it("marking a LAN device mine shows on the device list", async () => {
    const dev = (await listLanDevices())[0];
    expect(dev.mine).toBe(false);
    await addMine("lan", dev.macHash);
    expect((await listLanDevices()).find((d) => d.macHash === dev.macHash)?.mine).toBe(true);
  });
});

describe("watchlist", () => {
  it("adds (trimmed), rejects empty, removes", async () => {
    const n0 = (await listWatchlist()).length;
    const e = await addWatchlist("vendor", "  Vendor-A ", "exact");
    expect(e.pattern).toBe("Vendor-A");
    expect(e.match).toBe("exact");
    await expect(addWatchlist("ssid", "   ", "contains")).rejects.toBeDefined();
    expect((await listWatchlist()).length).toBe(n0 + 1);
    await removeWatchlist(e.id);
    expect((await listWatchlist()).length).toBe(n0);
  });
});

describe("LAN", () => {
  it("current network is passive until the sweep is allowed AND the AP is mine", async () => {
    const off = await getCurrentNetwork();
    expect(off.isMine).toBe(true); // the mock's Router-A group is in Mine
    expect(off.sweepEnabled).toBe(false);
    expect(off.mode).toBe("passive");
    const s = await getSettings();
    await setSettings({ ...s, lanActiveSweep: true });
    const on = await getCurrentNetwork();
    expect(on.sweepEnabled && on.mode === "sweep").toBe(true);
    await setSettings({ ...s, lanActiveSweep: false });
  });

  it("devices are filterable by network and sweepNow returns the joined network's", async () => {
    const net = await getCurrentNetwork();
    const all = await listLanDevices();
    expect(all.length).toBeGreaterThan(0);
    expect((await listLanDevices(net.networkKey!)).length).toBe(all.length);
    expect(await listLanDevices("no-such-network")).toEqual([]);
    // The gate: refused (with the Rust gate's wording) while the setting is off...
    await expect(sweepNow()).rejects.toBe(
      "The active sweep is switched off in Settings.",
    );
    const s = await getSettings();
    await setSettings({ ...s, lanActiveSweep: true });
    expect((await sweepNow()).length).toBe(all.length);
    // ...and when the joined access point is not Mine.
    const mineList = await listMine();
    const group = mineList.find((m) => m.kind === "wifiGroup")!;
    await removeMine(group.kind, group.idHash);
    await expect(sweepNow()).rejects.toBe(
      "This access point is not marked as yours. Mark it as mine first.",
    );
    await addMine(group.kind, group.idHash, group.label ?? null);
    await setSettings({ ...s, lanActiveSweep: false });
  });
});

describe("synthetic-only invariants for the v2 mock data", () => {
  async function everything() {
    const scan = await scanNow();
    return {
      scan,
      places: await listPlaces(),
      mine: await listMine(),
      watchlist: await listWatchlist(),
      network: await getCurrentNetwork(),
      devices: await listLanDevices(),
      alerts: await getAlerts(true),
    };
  }

  it("vendors are synthetic and every hash is 64 hex starting 02", async () => {
    const e = await everything();
    const vendors = [
      ...e.scan.wifi.map((w) => w.vendor),
      ...e.devices.map((d) => d.vendor),
    ].filter((v): v is string => v !== null);
    expect(vendors.length).toBeGreaterThan(0);
    for (const v of vendors) expect(v).toMatch(SYNTHETIC_VENDOR);
    const hashes = [
      ...e.scan.wifi.flatMap((w) => [w.bssidHash, w.groupId]),
      ...e.places.flatMap((p) => p.members),
      ...e.mine.map((m) => m.idHash),
      ...e.devices.flatMap((d) => [d.macHash, d.networkKey]),
      e.network.networkKey,
      e.network.bssidHash,
      e.network.groupId,
    ].filter((h): h is string => h !== null);
    expect(hashes.length).toBeGreaterThan(0);
    for (const h of hashes) expect(h).toMatch(HASH64);
  });

  it("no MAC-shaped string outside 02:, and IPs are in the documentation range", async () => {
    const all = JSON.stringify(await everything());
    for (const m of all.match(MAC_SHAPED) ?? []) expect(m.toLowerCase()).toMatch(/^02[:-]/);
    const ips = [...all.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d+)?\b/g)].map((m) => m[1]);
    expect(ips.length).toBeGreaterThan(0);
    for (const ip of ips) expect(ip).toMatch(/^192\.0\.2\./);
    // IPv6 addresses (neighbor-table devices) are in the 2001:db8::/32 documentation range.
    const V6 = /\b([0-9a-f]{1,4}(?::{1,2}[0-9a-f]{1,4}){2,7})\b/gi;
    const found = (text: string) =>
      [...text.matchAll(V6)].map((m) => m[1]).filter((s) => !/^02(?::|-)/i.test(s));
    // Negative control: the matcher sees a real-looking address, and ignores a 02: MAC.
    expect(found("x 2001:4860::1 y")).toEqual(["2001:4860::1"]);
    expect(found("x 02:00:00:00:00:01 y")).toEqual([]);
    const v6 = found(all);
    expect(v6.length).toBeGreaterThan(0);
    for (const a of v6) expect(a.toLowerCase()).toMatch(/^2001:db8:/);
  });

  it("LAN devices cover every source, and announced-only ones have no vendor", async () => {
    const devs = await listLanDevices();
    const bySource = new Set(devs.map((d) => d.source));
    expect([...bySource].sort()).toEqual(["announced", "both", "neighbor"]);
    for (const d of devs.filter((d) => d.source === "announced")) {
      expect(d.vendor).toBeNull();
      expect(d.hostname).not.toBeNull();
    }
    for (const d of devs.filter((d) => d.source !== "announced")) {
      expect(d.vendor).not.toBeNull();
    }
  });

  it("can fail: a real-looking vendor is rejected; can pass: a synthetic one is accepted", () => {
    expect("Acme Networks Inc").not.toMatch(SYNTHETIC_VENDOR);
    expect("Vendor-A").toMatch(SYNTHETIC_VENDOR);
    expect("Private address").toMatch(SYNTHETIC_VENDOR);
    expect("03" + "a".repeat(62)).not.toMatch(HASH64);
  });

  it("the new alert kinds are in the mock and hedged", async () => {
    const { alerts } = await everything();
    const kinds = new Set(alerts.map((a) => a.kind));
    for (const k of ["followedAcrossPlaces", "watchlist", "newLanDevice"] as const) {
      expect(kinds.has(k)).toBe(true);
    }
    const f = alerts.find((a) => a.kind === "followedAcrossPlaces")!;
    expect(`${f.title} ${f.detail}`.toLowerCase()).toContain("possible");
  });
});
