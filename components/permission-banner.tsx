"use client";

import type { PermissionStatus } from "@/lib/types";
import { useMonitor } from "./monitor-provider";

const STATE_TEXT: Record<PermissionStatus, string> = {
  granted: "Granted",
  denied: "Denied",
  notDetermined: "Not asked yet",
  restricted: "Restricted by policy",
  unknown: "Unknown",
};

function Row({
  label,
  status,
  how,
}: {
  label: string;
  status: PermissionStatus;
  how: string;
}) {
  const ok = status === "granted";
  return (
    <li className="flex flex-col gap-0.5 text-sm">
      <span>
        <span className={ok ? "text-green-600" : "font-semibold text-destructive"}>
          {ok ? "OK" : "Needs attention"}
        </span>{" "}
        <strong>{label}</strong>: {STATE_TEXT[status]}
      </span>
      {!ok && <span className="text-muted-foreground">{how}</span>}
    </li>
  );
}

export default function PermissionBanner() {
  const { permissions } = useMonitor();
  if (!permissions) return null;
  const allGood =
    permissions.bluetooth === "granted" && permissions.location === "granted";
  if (allGood) return null;
  return (
    <section
      role="alert"
      className="mb-4 rounded-lg border border-destructive/50 bg-destructive/5 p-4"
    >
      <h2 className="mb-2 font-semibold">Permissions needed for a full scan</h2>
      <ul className="space-y-2">
        <Row
          label="Bluetooth"
          status={permissions.bluetooth}
          how="Open System Settings > Privacy & Security > Bluetooth and switch this app on."
        />
        <Row
          label="Location"
          status={permissions.location}
          how="Open System Settings > Privacy & Security > Location Services and switch this app on. macOS hides Wi-Fi names until Location is allowed."
        />
      </ul>
      <p className="mt-2 text-xs text-muted-foreground">
        Location is used only so macOS will reveal nearby network names. Nothing
        leaves this computer.
      </p>
    </section>
  );
}
