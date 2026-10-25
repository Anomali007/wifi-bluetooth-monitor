"use client";

import MineButton from "@/components/mine-button";
import { formatAgo, formatDateTime } from "@/lib/format";
import type { LanDevice } from "@/lib/types";
import { deviceName, serviceLabel, sourceLabel } from "./lan-logic";

/**
 * Devices seen on the joined network. IPs are live only; the store never keeps them. A device
 * that only announced itself has no hardware address, so no vendor is known for it.
 */
export default function LanDeviceTable({ devices }: { devices: LanDevice[] }) {
  if (devices.length === 0) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        No devices seen yet. Devices show up when they announce themselves on
        the network (and, on macOS versions that allow it, from your Mac&apos;s
        neighbor table). If this stays empty, check that this app is allowed
        under System Settings &gt; Privacy &amp; Security &gt; Local Network.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-muted-foreground">
            <th className="p-2 font-medium">Name</th>
            <th className="p-2 font-medium">Vendor</th>
            <th className="p-2 font-medium">Source</th>
            <th className="p-2 font-medium">Services</th>
            <th className="p-2 font-medium">Address</th>
            <th className="p-2 font-medium">First seen</th>
            <th className="p-2 font-medium">Last seen</th>
            <th className="p-2 font-medium">Mine</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={`${d.networkKey}-${d.macHash}`} className="border-b last:border-0">
              <td className="p-2">{deviceName(d)}</td>
              <td className="p-2 text-muted-foreground">
                {d.vendor ?? (d.source === "announced" ? "Not known (no hardware address)" : "Unknown")}
              </td>
              <td className="p-2 text-muted-foreground" data-testid="lan-source">
                {sourceLabel(d)}
              </td>
              <td className="p-2 text-muted-foreground">
                {d.services.length === 0 ? "none announced" : d.services.map(serviceLabel).join(", ")}
              </td>
              <td className="p-2 tabular-nums text-muted-foreground">{d.ip ?? "not online"}</td>
              <td className="p-2 tabular-nums">{formatDateTime(d.firstSeen)}</td>
              <td className="p-2 tabular-nums">{formatAgo(d.lastSeen)}</td>
              <td className="p-2">
                <MineButton
                  target={{ kind: "lan", idHash: d.macHash, rotatingAddress: false }}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
