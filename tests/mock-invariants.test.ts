// The repo is public: the mock backend must contain synthetic identifiers only.
import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { mockInvoke } from "../lib/mock-invoke";
import type { Alert, History, ScanResult, Settings } from "../lib/types";

/** Allowed fake network names. Extend deliberately; a real-looking name must fail. */
const SYNTHETIC_SSID = /^(Net-[A-Z]|Cafe-Guest|Home-5G|Office-Corp)$/;
const MAC_SHAPED = /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi;
const HASH64 = /^[0-9a-f]{64}$/;

afterEach(() => vi.unstubAllGlobals());

async function everything(denied: boolean) {
  if (denied) vi.stubGlobal("window", { location: { search: "?mock=denied" } });
  const scan = await mockInvoke<ScanResult>("scan_now");
  const history = await mockInvoke<History>("get_history", {});
  const alerts = await mockInvoke<Alert[]>("get_alerts", { includeDismissed: true });
  const settings = await mockInvoke<Settings>("get_settings");
  return { scan, history, alerts, settings };
}

describe.each([false, true])("mock data (denied=%s)", (denied) => {
  it("every SSID matches the synthetic allow-pattern", async () => {
    const { scan, history, alerts, settings } = await everything(denied);
    const ssids = [
      ...scan.wifi.map((w) => w.ssid),
      ...history.scans.flatMap((s) => s.wifi.map((w) => w.ssid)),
      ...settings.trustedNetworks.map((t) => t.ssid),
    ].filter((s): s is string => s !== null);
    expect(ssids.length).toBeGreaterThan(0);
    for (const s of ssids) expect(s).toMatch(SYNTHETIC_SSID);
    // SSIDs quoted in alert text must be synthetic too.
    for (const a of alerts) {
      for (const m of `${a.title} ${a.detail}`.matchAll(/\b(Net-\w+|Cafe-\w+|Home-\w+|Office-\w+)\b/g)) {
        expect(m[1]).toMatch(SYNTHETIC_SSID);
      }
    }
  });

  it("every MAC-shaped string starts with 02: (locally administered)", async () => {
    const all = JSON.stringify(await everything(denied));
    for (const m of all.match(MAC_SHAPED) ?? []) expect(m.toLowerCase()).toMatch(/^02[:-]/);
  });

  it("every hash is 64 hex chars starting 02 (obviously fake)", async () => {
    const { scan, history, alerts, settings } = await everything(denied);
    const hashes = [
      ...scan.wifi.map((w) => w.bssidHash),
      ...scan.ble.map((b) => b.peripheralHash),
      ...history.scans.flatMap((s) => [
        ...s.wifi.map((w) => w.bssidHash),
        ...s.ble.map((b) => b.peripheralHash),
      ]),
      ...alerts.map((a) => a.subjectHash),
      ...settings.trustedNetworks.flatMap((t) => t.knownBssidHashes),
    ].filter((h): h is string => h !== null);
    expect(hashes.length).toBeGreaterThan(0);
    for (const h of hashes) {
      expect(h).toMatch(HASH64);
      expect(h.startsWith("02")).toBe(true);
    }
  });

  it("tracker wording is hedged", async () => {
    const { alerts } = await everything(denied);
    for (const a of alerts.filter((x) => x.kind === "persistentTracker")) {
      expect(`${a.title} ${a.detail}`.toLowerCase()).toContain("possible");
      expect(a.title.toLowerCase()).not.toContain("following you");
    }
  });
});

describe("the denied scenario", () => {
  it("withholds SSIDs and reports the permission states", async () => {
    const { scan } = await everything(true);
    expect(scan.permissions.location).not.toBe("granted");
    expect(scan.wifi.every((w) => w.ssid === null && w.bssidHash === null)).toBe(true);
    expect(scan.errors.length).toBeGreaterThan(0);
  });
});

describe("the invariant checks themselves", () => {
  it("can fail: real-looking names and MACs are rejected", () => {
    expect("HomeWiFi-4821").not.toMatch(SYNTHETIC_SSID);
    expect("Net-AB").not.toMatch(SYNTHETIC_SSID);
    // Built from parts so this file itself never contains a MAC-shaped literal.
    const real = ["3c", "22", "fb", "aa", "bb", "cc"].join(":");
    expect(real.match(MAC_SHAPED)).not.toBeNull();
    expect(real).not.toMatch(/^02[:-]/);
  });
  it("can pass: synthetic names are accepted", () => {
    for (const s of ["Net-A", "Cafe-Guest", "Home-5G", "Office-Corp"]) {
      expect(s).toMatch(SYNTHETIC_SSID);
    }
  });
  it("fixture files carry no MAC outside 02:", () => {
    const src = readFileSync(new URL("../lib/mock-invoke.ts", import.meta.url), "utf8");
    for (const m of src.match(MAC_SHAPED) ?? []) expect(m.toLowerCase()).toMatch(/^02[:-]/);
  });
});
