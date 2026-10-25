import { describe, expect, it } from "vitest";
import {
  deviceName,
  modeLabel,
  serviceLabel,
  subnetPrefix,
  sweepBlockedReason,
} from "../components/network/lan-logic";
import type { LanDevice, NetworkInfo } from "../lib/types";

const open: NetworkInfo = {
  networkKey: "key-a",
  ssid: "Net-A",
  bssidHash: "ap-1",
  groupId: null,
  subnet: "192.0.2.0/24",
  isMine: true,
  sweepEnabled: true,
  mode: "passive",
  lastSweepAt: null,
};
const on = { lanActiveSweep: true };

describe("sweepBlockedReason", () => {
  it("is null only when every condition holds", () => {
    expect(sweepBlockedReason(open, on)).toBeNull();
  });

  it("refuses in each negative case, with a reason", () => {
    const cases: [string, NetworkInfo | null, { lanActiveSweep: boolean } | null][] = [
      ["setting off", open, { lanActiveSweep: false }],
      ["settings not loaded", open, null],
      ["no network", null, on],
      ["network key withheld", { ...open, networkKey: null }, on],
      ["AP not mine", { ...open, isMine: false }, on],
      ["no subnet", { ...open, subnet: null }, on],
      ["/22 too large", { ...open, subnet: "192.0.0.0/22" }, on],
      ["/16 too large", { ...open, subnet: "192.0.0.0/16" }, on],
      ["/31 nothing to sweep", { ...open, subnet: "192.0.2.4/31" }, on],
      ["garbage subnet", { ...open, subnet: "not-a-cidr" }, on],
    ];
    let ran = 0;
    for (const [name, n, s] of cases) {
      const reason = sweepBlockedReason(n, s);
      expect(reason, name).toBeTypeOf("string");
      expect(reason!.length, name).toBeGreaterThan(10);
      ran++;
    }
    expect(ran).toBe(10);
  });

  it("allows the /23 and /30 boundaries", () => {
    expect(sweepBlockedReason({ ...open, subnet: "192.0.2.0/23" }, on)).toBeNull();
    expect(sweepBlockedReason({ ...open, subnet: "192.0.2.4/30" }, on)).toBeNull();
  });

  it("checks the setting before the network", () => {
    expect(sweepBlockedReason(null, { lanActiveSweep: false })).toMatch(/switched off/);
    expect(sweepBlockedReason(null, on)).toMatch(/identified/);
  });
});

describe("subnetPrefix", () => {
  it("parses CIDR and rejects the rest", () => {
    expect(subnetPrefix("192.0.2.0/24")).toBe(24);
    expect(subnetPrefix("192.0.2.0/33")).toBeNull();
    expect(subnetPrefix("192.0.2.0")).toBeNull();
    expect(subnetPrefix(null)).toBeNull();
  });
});

describe("labels", () => {
  const dev = (over: Partial<LanDevice>): LanDevice => ({
    networkKey: "k",
    macHash: "h",
    vendor: null,
    hostname: null,
    services: [],
    firstSeen: 0,
    lastSeen: 0,
    ip: null,
    mine: false,
    ...over,
  });

  it("names devices", () => {
    expect(deviceName(dev({ hostname: "device-1.local" }))).toBe("device-1");
    expect(deviceName(dev({ vendor: "Vendor-A" }))).toBe("Vendor-A device");
    expect(deviceName(dev({}))).toBe("Unnamed device");
  });

  it("shortens service types", () => {
    expect(serviceLabel("_http._tcp")).toBe("http");
    expect(serviceLabel("_airplay._udp")).toBe("airplay");
  });

  it("badges the mode", () => {
    expect(modeLabel(open)).toBe("Passive");
    expect(modeLabel({ ...open, mode: "sweep" })).toBe("Passive + sweep");
    expect(modeLabel(null)).toBe("Passive");
  });
});
