import { describe, expect, it } from "vitest";
import { groupWifiByRadio, radiosLabel } from "../lib/format";
import { rowsFrom } from "../components/device-table";
import type { WifiObservation } from "../lib/types";

function w(n: number, groupId: string | null, rssi: number, channel = 36): WifiObservation {
  return {
    ssid: `Net-${n}`,
    bssidHash: `bssid-${n}`,
    rssi,
    channel,
    security: "wpa2Personal",
    seenAt: 1000 + n,
    vendor: "Vendor-A",
    groupId,
  };
}

describe("groupWifiByRadio", () => {
  it("collapses radios sharing a group id and keeps the strongest as representative", () => {
    const g = groupWifiByRadio([w(1, "g1", -70), w(2, "g1", -50, 6), w(3, "g1", -60, 149)]);
    expect(g).toHaveLength(1);
    expect(g[0].radios).toHaveLength(3);
    expect(g[0].rep.bssidHash).toBe("bssid-2");
  });

  it("keeps different groups and ungrouped observations apart, in first-seen order", () => {
    const g = groupWifiByRadio([w(1, "g1", -50), w(2, null, -50), w(3, null, -50), w(4, "g2", -50), w(5, "g1", -50)]);
    expect(g.map((x) => x.radios.length)).toEqual([2, 1, 1, 1]);
    expect(g.map((x) => x.rep.bssidHash)).toEqual(["bssid-1", "bssid-2", "bssid-3", "bssid-4"]);
  });

  it("returns nothing for no observations", () => {
    expect(groupWifiByRadio([])).toEqual([]);
  });
});

describe("radiosLabel", () => {
  it("names the radio count only when there is more than one", () => {
    expect(radiosLabel(1)).toBe("1 device");
    expect(radiosLabel(3)).toBe("1 device · 3 radios");
  });
});

describe("rowsFrom", () => {
  it("shows one row per physical device with vendor and radio count", () => {
    const rows = rowsFrom([w(1, "g1", -60, 36), w(2, "g1", -50, 6), w(3, null, -80, 11)], []);
    expect(rows).toHaveLength(2);
    expect(rows[0].radios).toBe(2);
    expect(rows[0].vendor).toBe("Vendor-A");
    expect(rows[0].detail).toContain("1 device · 2 radios");
    expect(rows[0].detail).toContain("ch 36, 6");
    expect(rows[0].mine).toEqual({ kind: "wifiGroup", idHash: "g1", rotatingAddress: false });
    expect(rows[1].radios).toBe(1);
    expect(rows[1].detail).not.toContain("radios");
    expect(rows[1].mine?.kind).toBe("wifiAp");
  });
});
