import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  dismissAlert,
  getAlerts,
  getHistory,
  getPermissions,
  getSettings,
  onAlert,
  onScan,
  scanNow,
  setSettings,
} from "../lib/api";
import { DEFAULT_SETTINGS } from "../lib/types";

const original = process.env.NEXT_PUBLIC_WBM_MOCK;
afterEach(() => {
  if (original === undefined) delete process.env.NEXT_PUBLIC_WBM_MOCK;
  else process.env.NEXT_PUBLIC_WBM_MOCK = original;
});

describe("api.ts with the mock flag on", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_WBM_MOCK = "1";
  });

  it("routes every command to the mock backend", async () => {
    const scan = await scanNow();
    expect(scan.wifi.length).toBeGreaterThan(0);
    expect(scan.permissions).toEqual({ bluetooth: "granted", location: "granted" });
    expect((await getHistory()).scans.length).toBe(48);
    expect((await getPermissions()).location).toBe("granted");
    expect((await getSettings()).retentionHours).toBe(DEFAULT_SETTINGS.retentionHours);
    expect((await getAlerts()).length).toBeGreaterThan(0);
  });

  it("getHistory(since) filters by time", async () => {
    const all = await getHistory();
    const mid = all.scans[24].scannedAt;
    const recent = await getHistory(mid);
    expect(recent.scans.length).toBe(24);
    expect(recent.scans.every((s) => s.scannedAt >= mid)).toBe(true);
  });

  it("dismissAlert hides an alert unless includeDismissed", async () => {
    const before = await getAlerts();
    const id = before[0].id;
    await dismissAlert(id);
    expect((await getAlerts()).some((a) => a.id === id)).toBe(false);
    const withDismissed = await getAlerts(true);
    expect(withDismissed.find((a) => a.id === id)?.dismissed).toBe(true);
  });

  it("setSettings persists and returns the new value", async () => {
    const s = await getSettings();
    const saved = await setSettings({ ...s, scanIntervalSecs: 120 });
    expect(saved.scanIntervalSecs).toBe(120);
    expect((await getSettings()).scanIntervalSecs).toBe(120);
  });

  it("scanNow emits a scan event to subscribers, and unsubscribe stops it", async () => {
    let n = 0;
    const off = await onScan(() => {
      n += 1;
    });
    await scanNow();
    expect(n).toBe(1);
    off();
    await scanNow();
    expect(n).toBe(1);
    const offAlert = await onAlert(() => {});
    offAlert();
  });
});

describe("api.ts with the mock flag off", () => {
  it("does not fall back to the mock backend (no Tauri runtime here, so it must reject)", async () => {
    process.env.NEXT_PUBLIC_WBM_MOCK = "0";
    await expect(getSettings()).rejects.toBeDefined();
    await expect(scanNow()).rejects.toBeDefined();
  });
});
