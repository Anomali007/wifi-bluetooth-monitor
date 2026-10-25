import { describe, expect, it } from "vitest";
import { checkWatchEntry, describeWatchEntry } from "../lib/format";
import type { WatchlistEntry } from "../lib/types";

const existing: WatchlistEntry[] = [
  { id: 1, kind: "ssid", pattern: "Net-A", match: "contains", addedAt: 0 },
];

describe("checkWatchEntry", () => {
  it("accepts a new entry and trims the pattern", () => {
    expect(checkWatchEntry("ssid", "exact", "  Net-B ", existing)).toEqual({
      ok: true,
      pattern: "Net-B",
    });
  });

  it.each(["", "   ", "\t"])("refuses a blank pattern %j (it would match everything)", (p) => {
    const r = checkWatchEntry("ssid", "contains", p, existing);
    expect(r.ok).toBe(false);
  });

  it("refuses a duplicate regardless of case or padding", () => {
    expect(checkWatchEntry("ssid", "contains", " NET-a ", existing).ok).toBe(false);
  });

  it("allows the same text under a different kind or match mode", () => {
    expect(checkWatchEntry("vendor", "contains", "Net-A", existing).ok).toBe(true);
    expect(checkWatchEntry("ssid", "exact", "Net-A", existing).ok).toBe(true);
  });
});

describe("describeWatchEntry", () => {
  it("reads naturally for each kind and mode", () => {
    expect(describeWatchEntry(existing[0])).toBe('Network name contains "Net-A"');
    expect(
      describeWatchEntry({ kind: "vendor", pattern: "Vendor-A", match: "exact" }),
    ).toBe('Vendor is exactly "Vendor-A"');
  });
});
