"use client";

import { useEffect, useState } from "react";
import { getCurrentNetwork, listLanDevices } from "@/lib/api";
import type { LanDevice, NetworkInfo } from "@/lib/types";

/** STUB (WP-D owns): current network, device table, passive/sweep badge, "Sweep now". */
export default function NetworkPage() {
  const [network, setNetwork] = useState<NetworkInfo | null>(null);
  const [devices, setDevices] = useState<LanDevice[]>([]);
  useEffect(() => {
    let live = true;
    Promise.all([getCurrentNetwork(), listLanDevices()])
      .then(([n, d]) => {
        if (!live) return;
        setNetwork(n);
        setDevices(d);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);
  return (
    <div className="max-w-2xl space-y-4">
      <h1 className="text-2xl font-bold">Network</h1>
      <section className="space-y-2 rounded-xl border bg-card p-4 shadow">
        <h2 className="font-semibold">{network?.ssid ?? "Not on a known network"}</h2>
        <p className="text-sm text-muted-foreground">
          {devices.length} device{devices.length === 1 ? "" : "s"} remembered.
        </p>
      </section>
    </div>
  );
}
