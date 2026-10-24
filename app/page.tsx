"use client";

import DeviceChart from "./components/DeviceChart";
import DeviceTable, { rowsFrom } from "@/components/device-table";
import PermissionBanner from "@/components/permission-banner";
import { useMonitor } from "@/components/monitor-provider";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { formatTime } from "@/lib/format";

export default function Dashboard() {
  const { scan, scanning, error, refresh } = useMonitor();
  const rows = scan ? rowsFrom(scan.wifi, scan.ble) : [];
  const chart = rows.map((r) => ({
    name: r.name,
    signal_strength: r.rssi === null ? null : Math.max(0, r.rssi + 100),
    device_type: r.type,
  }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          {scan && <span>Last scan {formatTime(scan.scannedAt)}</span>}
          <button
            onClick={() => void refresh()}
            disabled={scanning}
            className="rounded-md bg-primary px-3 py-1.5 text-primary-foreground disabled:opacity-50"
          >
            {scanning ? "Scanning..." : "Scan now"}
          </button>
        </div>
      </div>

      <PermissionBanner />

      {error && (
        <p role="alert" className="rounded-md border border-destructive/50 p-3 text-sm">
          Error: {error}
        </p>
      )}

      {scan && scan.errors.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Scan problems ({scan.errors.length})</CardTitle>
            <CardDescription>
              Parts of the last scan could not run.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {scan.errors.map((e, i) => (
                <li key={i}>
                  <span className="mr-2 rounded bg-secondary px-1.5 py-0.5 text-xs uppercase">
                    {e.source}
                  </span>
                  <span className="mr-2 text-muted-foreground">{e.code}</span>
                  {e.message}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Signal strength</CardTitle>
          <CardDescription>Latest scan; bar height = dBm + 100, so taller means stronger (-40 dBm = 60, -90 dBm = 10)</CardDescription>
        </CardHeader>
        <CardContent>
          <DeviceChart data={chart} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Nearby devices ({rows.length})</CardTitle>
          <CardDescription>
            Passive observations only. A tracker badge means a possible tracker,
            not a confirmed one.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DeviceTable rows={rows} />
        </CardContent>
      </Card>
    </div>
  );
}
