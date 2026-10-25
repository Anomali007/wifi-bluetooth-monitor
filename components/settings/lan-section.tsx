"use client";

import type { SectionProps } from "./section";

/** Explains the sweep and carries its opt-in switch. */
export default function LanSection({ draft, set }: SectionProps) {
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Network devices</h2>
      <p className="text-sm text-muted-foreground">
        The Network page lists devices on the network you are joined to, using
        only what the network already announces. This app never connects to a
        device or looks for open ports.
      </p>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-1"
          checked={draft.lanActiveSweep}
          onChange={(e) => set({ lanActiveSweep: e.target.checked })}
        />
        <span>
          Find quiet devices with an active sweep
          <span className="block text-muted-foreground">
            Sends one small, empty packet to each address on your own network
            (at most 50 per second, networks up to 512 addresses), then reads
            which devices answered. It only runs while you are joined to an
            access point you marked as mine, at most every 10 minutes and when
            you press Sweep now. Off by default.
          </span>
        </span>
      </label>
    </section>
  );
}
