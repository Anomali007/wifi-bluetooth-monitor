"use client";

import { useMonitor } from "@/components/monitor-provider";
import { formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEV_STYLE: Record<Severity, string> = {
  high: "bg-red-100 text-red-900",
  medium: "bg-orange-100 text-orange-900",
  low: "bg-yellow-100 text-yellow-900",
  info: "bg-blue-100 text-blue-900",
};

export default function AlertsPage() {
  const { alerts, dismiss } = useMonitor();
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Alerts</h1>
      {alerts.length === 0 ? (
        <p className="text-sm text-muted-foreground">No active alerts.</p>
      ) : (
        <ul className="space-y-3">
          {alerts.map((a) => (
            <li key={a.id} className="rounded-xl border bg-card p-4 shadow">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <span
                    className={cn(
                      "mr-2 rounded px-2 py-0.5 text-xs font-semibold uppercase",
                      SEV_STYLE[a.severity],
                    )}
                  >
                    {a.severity}
                  </span>
                  <span className="font-semibold">{a.title}</span>
                  <p className="mt-1 text-sm text-muted-foreground">{a.detail}</p>
                  <p className="mt-2 text-xs text-muted-foreground">
                    First seen {formatDateTime(a.firstSeen)} / last seen{" "}
                    {formatDateTime(a.lastSeen)}
                  </p>
                </div>
                <button
                  onClick={() => void dismiss(a.id)}
                  className="shrink-0 rounded-md border px-3 py-1 text-sm hover:bg-accent"
                >
                  Dismiss
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
