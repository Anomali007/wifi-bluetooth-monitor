"use client";

import { useEffect, useMemo, useState } from "react";
import { getHistory } from "@/lib/api";
import { useMonitor } from "@/components/monitor-provider";
import { SECURITY_LABEL, TRACKER_LABEL, formatDateTime } from "@/lib/format";
import type { History } from "@/lib/types";
import { cn } from "@/lib/utils";

type Filter = "all" | "wifi" | "ble";
const WINDOWS = [
  { label: "1 h", hours: 1 },
  { label: "6 h", hours: 6 },
  { label: "24 h", hours: 24 },
];

interface Sighting {
  key: string;
  type: "Wi-Fi" | "Bluetooth";
  name: string;
  detail: string;
  scans: number;
  first: number;
  last: number;
  rssiSum: number;
  rssiN: number;
}

export default function HistoryPage() {
  const { settings, scan } = useMonitor();
  const maxHours = settings?.retentionHours ?? 24;
  const [hours, setHours] = useState(24);
  const [filter, setFilter] = useState<Filter>("all");
  const [history, setHistory] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  const effective = Math.min(hours, maxHours);
  const latest = scan?.scannedAt;

  useEffect(() => {
    let alive = true;
    getHistory(Date.now() - effective * 3_600_000)
      .then((h) => alive && setHistory(h))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, [effective, latest]);

  const sightings = useMemo(() => {
    const map = new Map<string, Sighting>();
    for (const s of history?.scans ?? []) {
      if (filter !== "ble") {
        for (const w of s.wifi) {
          const key = `w-${w.bssidHash ?? w.ssid ?? "hidden"}`;
          const cur = map.get(key) ?? {
            key,
            type: "Wi-Fi" as const,
            name: w.ssid ?? "(hidden or withheld)",
            detail: SECURITY_LABEL[w.security],
            scans: 0,
            first: s.scannedAt,
            last: s.scannedAt,
            rssiSum: 0,
            rssiN: 0,
          };
          cur.scans += 1;
          cur.last = Math.max(cur.last, s.scannedAt);
          cur.first = Math.min(cur.first, s.scannedAt);
          cur.rssiSum += w.rssi;
          cur.rssiN += 1;
          map.set(key, cur);
        }
      }
      if (filter !== "wifi") {
        for (const b of s.ble) {
          const key = `b-${b.peripheralHash}`;
          const cur = map.get(key) ?? {
            key,
            type: "Bluetooth" as const,
            name: b.name ?? "Unnamed device",
            detail: b.tracker ? TRACKER_LABEL[b.tracker] : "",
            scans: 0,
            first: s.scannedAt,
            last: s.scannedAt,
            rssiSum: 0,
            rssiN: 0,
          };
          cur.scans += 1;
          cur.last = Math.max(cur.last, s.scannedAt);
          cur.first = Math.min(cur.first, s.scannedAt);
          if (b.rssi !== null) {
            cur.rssiSum += b.rssi;
            cur.rssiN += 1;
          }
          map.set(key, cur);
        }
      }
    }
    return Array.from(map.values()).sort((a, b) => b.last - a.last);
  }, [history, filter]);

  const btn = (active: boolean) =>
    cn("rounded-md border px-3 py-1 text-sm", active && "bg-accent font-medium");

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">History</h1>
      <div className="flex flex-wrap items-center gap-2">
        {(["all", "wifi", "ble"] as Filter[]).map((f) => (
          <button key={f} onClick={() => setFilter(f)} className={btn(filter === f)}>
            {f === "all" ? "All" : f === "wifi" ? "Wi-Fi" : "Bluetooth"}
          </button>
        ))}
        <span className="mx-2 text-muted-foreground">|</span>
        {WINDOWS.map((w) => (
          <button
            key={w.hours}
            onClick={() => setHours(w.hours)}
            className={btn(hours === w.hours)}
          >
            {w.label}
          </button>
        ))}
        <span className="ml-auto text-sm text-muted-foreground">
          {history?.scans.length ?? 0} scans, {sightings.length} distinct devices
          (retention {maxHours} h)
        </span>
      </div>
      {error && <p role="alert" className="text-sm">Error: {error}</p>}
      <div className="overflow-x-auto rounded-xl border bg-card shadow">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-muted-foreground">
              <th className="p-2 font-medium">Type</th>
              <th className="p-2 font-medium">Name / SSID</th>
              <th className="p-2 font-medium">Details</th>
              <th className="p-2 font-medium">Scans seen</th>
              <th className="p-2 font-medium">Avg signal</th>
              <th className="p-2 font-medium">First seen</th>
              <th className="p-2 font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {sightings.map((s) => (
              <tr key={s.key} className="border-b last:border-0">
                <td className="p-2">{s.type}</td>
                <td className="p-2">{s.name}</td>
                <td className="p-2 text-muted-foreground">{s.detail}</td>
                <td className="p-2 tabular-nums">{s.scans}</td>
                <td className="p-2 tabular-nums">
                  {s.rssiN ? `${Math.round(s.rssiSum / s.rssiN)} dBm` : "n/a"}
                </td>
                <td className="p-2 tabular-nums">{formatDateTime(s.first)}</td>
                <td className="p-2 tabular-nums">{formatDateTime(s.last)}</td>
              </tr>
            ))}
            {sightings.length === 0 && (
              <tr>
                <td colSpan={7} className="p-4 text-muted-foreground">
                  No sightings in this window.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
