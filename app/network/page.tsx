"use client";

import { useCallback, useEffect, useState } from "react";
import LanDeviceTable from "@/components/network/lan-device-table";
import { modeLabel, sweepBlockedReason } from "@/components/network/lan-logic";
import { formatAgo } from "@/lib/format";
import { getCurrentNetwork, getSettings, listLanDevices, sweepNow } from "@/lib/api";
import type { LanDevice, NetworkInfo, Settings } from "@/lib/types";

/**
 * Devices on the joined network: the IPv6 neighbor table, IPv4 ARP where readable, and mDNS
 * announcements, plus the opt-in sweep (one IPv6 packet to the link's all-nodes address).
 */
export default function NetworkPage() {
  const [network, setNetwork] = useState<NetworkInfo | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [devices, setDevices] = useState<LanDevice[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [n, s] = await Promise.all([getCurrentNetwork(), getSettings()]);
    setNetwork(n);
    setSettings(s);
    setDevices(await listLanDevices(n.networkKey ?? undefined));
  }, []);

  useEffect(() => {
    let live = true;
    const load = () => {
      refresh().catch(() => {
        if (live) setError("Could not read the network.");
      });
    };
    load();
    const t = setInterval(load, 30_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [refresh]);

  const blocked = sweepBlockedReason(network, settings);

  async function onSweep() {
    setBusy(true);
    setError(null);
    try {
      setDevices(await sweepNow());
      await refresh();
    } catch (e) {
      setError(typeof e === "string" ? e : "The sweep did not run.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-4xl space-y-4">
      <h1 className="text-2xl font-bold">Network</h1>

      <section className="space-y-2 rounded-xl border bg-card p-4 shadow">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="font-semibold">{network?.ssid ?? "Not on an identified network"}</h2>
          {network?.networkKey && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{modeLabel(network)}</span>
          )}
          {network?.isMine && (
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-900">
              Marked as mine
            </span>
          )}
        </div>
        <p className="text-sm text-muted-foreground">
          {network?.networkKey
            ? `${network.subnet ?? "No IPv4 address"} · ${devices.length} device${devices.length === 1 ? "" : "s"} remembered`
            : "macOS only reveals the joined network to apps with Location access, so there is nothing to list yet."}
        </p>
        {network?.lastSweepAt != null && (
          <p className="text-sm text-muted-foreground">
            Last sweep {formatAgo(network.lastSweepAt)}.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            type="button"
            onClick={onSweep}
            disabled={busy || blocked !== null}
            className="rounded-md border px-3 py-1 text-sm disabled:opacity-50"
          >
            {busy ? "Sweeping…" : "Sweep now"}
          </button>
          {blocked && <span className="text-sm text-muted-foreground">{blocked}</span>}
          {error && (
            <span role="alert" className="text-sm text-red-700">
              {error}
            </span>
          )}
        </div>
      </section>

      <section className="rounded-xl border bg-card shadow">
        <LanDeviceTable devices={devices} />
      </section>
    </div>
  );
}
