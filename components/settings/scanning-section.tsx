"use client";

import NumberField from "./number-field";
import type { SectionProps } from "./section";

export default function ScanningSection({ draft, set }: SectionProps) {
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Scanning</h2>
      <NumberField
        label="Scan interval (seconds)"
        min={10}
        value={draft.scanIntervalSecs}
        onChange={(n) => set({ scanIntervalSecs: n })}
      />
      <NumberField
        label="Bluetooth listen time per scan (seconds)"
        min={1}
        value={draft.bleScanSecs}
        onChange={(n) => set({ bleScanSecs: n })}
      />
      <NumberField
        label="Keep history for (hours)"
        min={1}
        value={draft.retentionHours}
        onChange={(n) => set({ retentionHours: n })}
      />
    </section>
  );
}
