import { describe, expect, it } from "vitest";
import { SECURITY_LABEL, TRACKER_LABEL, formatAgo, shortHash } from "../lib/format";
import type { Security, TrackerKind } from "../lib/types";

describe("formatAgo", () => {
  const now = 1_000_000_000;
  it.each([
    [0, "0s ago"],
    [30_000, "30s ago"],
    [59_000, "59s ago"],
    [60_000, "1m ago"],
    [29 * 60_000, "29m ago"],
    [60 * 60_000, "1h 0m ago"],
    [90 * 60_000, "1h 30m ago"],
    [5 * 3_600_000 + 7 * 60_000, "5h 7m ago"],
  ])("%d ms back reads %s", (back, expected) => {
    expect(formatAgo(now - back, now)).toBe(expected);
  });

  it("never goes negative for a timestamp in the future", () => {
    expect(formatAgo(now + 5_000, now)).toBe("0s ago");
  });
});

describe("shortHash", () => {
  it("shows the first 8 chars", () => {
    expect(shortHash("0123456789abcdef")).toBe("01234567");
  });
  it("shows n/a for a withheld hash", () => {
    expect(shortHash(null)).toBe("n/a");
  });
});

describe("labels", () => {
  const securities: Security[] = [
    "open", "wep", "wpaPersonal", "wpa2Personal", "wpa3Personal",
    "wpaEnterprise", "wpa2Enterprise", "wpa3Enterprise", "owe", "unknown",
  ];
  const trackers: TrackerKind[] = [
    "appleFindMy", "tile", "samsungSmartTag", "chipolo",
    "pebblebee", "googleFindMy", "unknownTracker",
  ];

  it("labels every Security variant", () => {
    expect(Object.keys(SECURITY_LABEL).sort()).toEqual([...securities].sort());
    for (const s of securities) expect(SECURITY_LABEL[s].length).toBeGreaterThan(0);
  });

  it("hedges every tracker label: a match is a hint, never proof", () => {
    expect(Object.keys(TRACKER_LABEL).sort()).toEqual([...trackers].sort());
    for (const t of trackers) expect(TRACKER_LABEL[t]).toMatch(/^Possible tracker/);
  });
});

describe("securityStrength", () => {
  it("orders modes like Security::strength in model.rs", async () => {
    const { securityStrength } = await import("../lib/format");
    expect(securityStrength("open")).toBe(0);
    expect(securityStrength("unknown")).toBe(0);
    expect(securityStrength("owe")).toBe(1);
    expect(securityStrength("wep")).toBe(1);
    expect(securityStrength("wpaPersonal")).toBe(2);
    expect(securityStrength("wpa2Enterprise")).toBe(3);
    expect(securityStrength("wpa3Personal")).toBe(4);
    expect(securityStrength("wpa3Personal")).toBeGreaterThan(securityStrength("wpa2Personal"));
  });
});
