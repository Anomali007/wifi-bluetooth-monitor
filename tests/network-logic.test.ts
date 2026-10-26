import { describe, expect, it } from "vitest";
import {
  deviceName,
  helperStatusLine,
  modeLabel,
  neighborStatus,
  serviceLabel,
  sourceLabel,
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
  neighborNote: null,
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
    ];
    let ran = 0;
    for (const [name, n, s] of cases) {
      const reason = sweepBlockedReason(n, s);
      expect(reason, name).toBeTypeOf("string");
      expect(reason!.length, name).toBeGreaterThan(10);
      ran++;
    }
    expect(ran).toBe(5);
  });

  it("does not care about the IPv4 subnet: the sweep is one IPv6 packet", () => {
    for (const subnet of [null, "192.0.2.0/24", "192.0.0.0/16", "192.0.2.4/31"]) {
      expect(sweepBlockedReason({ ...open, subnet }, on), String(subnet)).toBeNull();
    }
  });

  it("checks the setting before the network", () => {
    expect(sweepBlockedReason(null, { lanActiveSweep: false })).toMatch(/switched off/);
    expect(sweepBlockedReason(null, on)).toMatch(/identified/);
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
    source: null,
    ...over,
  });

  it("names devices", () => {
    expect(deviceName(dev({ hostname: "device-1.local" }))).toBe("device-1");
    expect(deviceName(dev({ vendor: "Vendor-A" }))).toBe("Vendor-A device");
    expect(deviceName(dev({}))).toBe("Unnamed device");
  });

  it("says where a device came from", () => {
    expect(sourceLabel({ source: "neighbor" })).toBe("Neighbor table");
    expect(sourceLabel({ source: "announced" })).toBe("Announced");
    expect(sourceLabel({ source: "both" })).toBe("Both");
    expect(sourceLabel({ source: null })).toBe("Earlier version");
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

describe("neighborStatus", () => {
  it("names the reason when the tools are unavailable, else says nothing", () => {
    expect(neighborStatus({ neighborNote: "macOS has no arp tool" })).toBe(
      "Showing announced devices only: macOS has no arp tool.",
    );
    expect(neighborStatus({ neighborNote: "the ndp tool took too long" })).toContain("took too long");
    // NEGATIVE CONTROLS: no note, blank note, no network.
    expect(neighborStatus({ neighborNote: null })).toBeNull();
    expect(neighborStatus({ neighborNote: "  " })).toBeNull();
    expect(neighborStatus(null)).toBeNull();
    expect(neighborStatus(open)).toBeNull();
  });
});

describe("helperStatusLine", () => {
  it("says what each state needs", () => {
    expect(helperStatusLine("enabled", true)).toMatch(/^On/);
    expect(helperStatusLine("needsApproval", true)).toMatch(/Login Items/);
    expect(helperStatusLine("off", false)).toBe("Off.");
    expect(helperStatusLine("unavailable", true)).toMatch(/^Unavailable in this build/);
    expect(helperStatusLine("unavailable", true)).toMatch(/user who built/);
    // NEGATIVE CONTROL: a pending toggle is not reported as on.
    expect(helperStatusLine("off", true)).toMatch(/Save/);
    expect(helperStatusLine("off", true)).not.toMatch(/^On/);
  });
});
