"use client";

import type { SectionProps } from "./section";

/** STUB (WP-D owns): explains the sweep and carries its opt-in switch. */
export default function LanSection({ draft, set }: SectionProps) {
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Network devices</h2>
      <p className="text-sm text-muted-foreground">
        The Network page lists devices on the network you are joined to, using
        only what the network already announces. The optional sweep sends one
        empty message to each address, and only on a network whose access point
        you marked as yours.
      </p>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={draft.lanActiveSweep}
          onChange={(e) => set({ lanActiveSweep: e.target.checked })}
        />
        Allow the active sweep on networks I marked as mine
      </label>
    </section>
  );
}
