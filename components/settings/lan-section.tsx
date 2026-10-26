"use client";

import { useCallback, useEffect, useState } from "react";
import { getHelperStatus, openLoginItems } from "@/lib/api";
import { helperStatusLine } from "@/components/network/lan-logic";
import type { HelperStatus } from "@/lib/types";
import type { SectionProps } from "./section";

function HelperStatusLine({ wanted }: { wanted: boolean }) {
  const [status, setStatus] = useState<HelperStatus | null>(null);
  const refresh = useCallback(() => {
    getHelperStatus().then(setStatus, () => setStatus(null));
  }, []);
  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 3000);
    return () => window.clearInterval(id);
  }, [refresh]);
  return (
    <p className="ml-6 flex flex-wrap items-center gap-2 text-sm" data-testid="helper-status">
      <span>{helperStatusLine(status, wanted)}</span>
      {status === "needsApproval" && (
        <button
          type="button"
          className="rounded border px-2 py-0.5 text-xs"
          onClick={() => void openLoginItems()}
        >
          Open Login Items
        </button>
      )}
    </p>
  );
}

/** Explains the sweep and carries its opt-in switch. */
export default function LanSection({ draft, set }: SectionProps) {
  return (
    <section id="network-devices" className="scroll-mt-4 space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Network devices</h2>
      <p className="text-sm text-muted-foreground">
        The Network page lists devices on the network you are joined to, using
        what your Mac has already learned about its neighbors (read through
        Apple&apos;s arp and ndp tools, if you turn on the full device list below)
        and what devices announce about themselves. This app never connects to
        a device or looks for open ports. Quiet devices that your Mac has not
        talked to recently can be missed.
      </p>
      <label className="flex items-start gap-2 text-sm">
        <input
          id="lan-neighbor-helper"
          type="checkbox"
          className="mt-1"
          checked={draft.lanNeighborHelper}
          onChange={(e) => set({ lanNeighborHelper: e.target.checked })}
        />
        <span>
          Read the full device list
          <span className="block text-muted-foreground">
            Adds a background item that runs Apple&apos;s arp and ndp every
            minute. macOS 27 hides the list of nearby devices from apps, but not
            from these two built-in tools when the system starts them. This app
            never starts them itself; it reads the text they write into its own
            private folder, then empties the files. Off by default. Turning it
            off removes the item and deletes the files.
          </span>
        </span>
      </label>
      <HelperStatusLine wanted={draft.lanNeighborHelper} />
      <label className="flex items-start gap-2 text-sm">
        <input
          id="lan-active-sweep"
          type="checkbox"
          className="mt-1"
          checked={draft.lanActiveSweep}
          onChange={(e) => set({ lanActiveSweep: e.target.checked })}
        />
        <span>
          Find quiet devices with an active sweep
          <span className="block text-muted-foreground">
            Sends one IPv6 packet to the all-devices address and one small,
            empty packet to each IPv4 address on your own network (at most 50 a
            second, on networks up to a /23), then reads which devices answered.
            It never opens a connection or scans ports. It only runs while you
            are joined to an access point you marked as mine, at most every 10
            minutes and when you press Sweep now. Off by default.
          </span>
        </span>
      </label>
    </section>
  );
}
