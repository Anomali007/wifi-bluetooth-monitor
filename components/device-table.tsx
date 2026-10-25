"use client";

import type { BleObservation, WifiObservation } from "@/lib/types";
import MineButton, { type MineTarget } from "./mine-button";
import {
  SECURITY_LABEL,
  TRACKER_LABEL,
  formatTime,
} from "@/lib/format";

export interface DeviceRow {
  key: string;
  type: "Wi-Fi" | "Bluetooth";
  name: string;
  detail: string;
  rssi: number | null;
  tracker: string | null;
  lastSeen: number;
  /** Wi-Fi only: vendor from the OUI and the multi-radio group (WP-C renders them). */
  vendor: string | null;
  groupId: string | null;
  /** What "Mark as mine" would mark; null when the identifier is withheld. */
  mine: MineTarget | null;
}

export function rowsFrom(
  wifi: WifiObservation[],
  ble: BleObservation[],
): DeviceRow[] {
  return [
    ...wifi.map((w, i) => ({
      key: `w-${w.bssidHash ?? "x"}-${i}`,
      type: "Wi-Fi" as const,
      name: w.ssid ?? "(hidden or withheld)",
      detail: `${SECURITY_LABEL[w.security]}${w.channel ? `, ch ${w.channel}` : ""}`,
      rssi: w.rssi,
      tracker: null,
      lastSeen: w.seenAt,
      vendor: w.vendor,
      groupId: w.groupId,
      mine: w.groupId
        ? { kind: "wifiGroup" as const, idHash: w.groupId, rotatingAddress: false }
        : w.bssidHash
          ? { kind: "wifiAp" as const, idHash: w.bssidHash, rotatingAddress: false }
          : null,
    })),
    ...ble.map((b) => ({
      key: `b-${b.peripheralHash}`,
      type: "Bluetooth" as const,
      name: b.name ?? "Unnamed device",
      detail:
        b.ownerState === "nearOwner"
          ? "Find My signal, owner nearby (not flagged)"
          : b.manufacturerId !== null
            ? `Manufacturer ${b.manufacturerId}`
            : "",
      rssi: b.rssi,
      tracker: b.tracker ? TRACKER_LABEL[b.tracker] : null,
      lastSeen: b.seenAt,
      vendor: null,
      groupId: null,
      mine: {
        kind: "ble" as const,
        idHash: b.peripheralHash,
        rotatingAddress: b.manufacturerId === 0x004c, // Apple rotates every few minutes
      },
    })),
  ];
}

export default function DeviceTable({ rows }: { rows: DeviceRow[] }) {
  if (rows.length === 0) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        No devices seen yet.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="p-2 font-medium">Type</th>
            <th className="p-2 font-medium">Name / SSID</th>
            <th className="p-2 font-medium">Details</th>
            <th className="p-2 font-medium">Signal</th>
            <th className="p-2 font-medium">Last seen</th>
            <th className="p-2 font-medium">Mine</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className="border-b last:border-0">
              <td className="p-2">{r.type}</td>
              <td className="p-2">
                {r.name}
                {r.tracker && (
                  <span className="ml-2 rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-900">
                    {r.tracker}
                  </span>
                )}
              </td>
              <td className="p-2 text-muted-foreground">{r.detail}</td>
              <td className="p-2 tabular-nums">
                {r.rssi === null ? "n/a" : `${r.rssi} dBm`}
              </td>
              <td className="p-2 tabular-nums">{formatTime(r.lastSeen)}</td>
              <td className="p-2">{r.mine && <MineButton target={r.mine} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
