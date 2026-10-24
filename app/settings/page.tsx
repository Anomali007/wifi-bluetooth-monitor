"use client";

import { useEffect, useState } from "react";
import { useMonitor } from "@/components/monitor-provider";
import { SECURITY_LABEL } from "@/lib/format";
import type { AlertToggles, Settings, TrustedNetwork } from "@/lib/types";

const TOGGLE_LABEL: Record<keyof AlertToggles, string> = {
  evilTwin: "Evil twin (same name, different hardware)",
  openLookalike: "Open lookalike of a secured network",
  trustedNetworkChanged: "Trusted network changed",
  persistentTracker: "Possible tracker following you",
  newDevice: "New device nearby (noisy)",
};

function NumberField({
  label,
  value,
  min,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  onChange: (n: number) => void;
}) {
  return (
    <label className="flex items-center justify-between gap-4 text-sm">
      {label}
      <input
        type="number"
        min={min}
        value={value}
        onChange={(e) => onChange(Math.max(min, Number(e.target.value) || min))}
        className="w-24 rounded-md border bg-background px-2 py-1"
      />
    </label>
  );
}

export default function SettingsPage() {
  const { settings, saveSettings, scan } = useMonitor();
  const [draft, setDraft] = useState<Settings | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    if (settings && !draft) setDraft(settings);
  }, [settings, draft]);

  if (!draft) return <p className="text-sm text-muted-foreground">Loading settings...</p>;

  const set = (patch: Partial<Settings>) => setDraft({ ...draft, ...patch });

  // Current visible networks that can be trusted: named ones, grouped by SSID.
  const candidates = new Map<string, TrustedNetwork>();
  for (const w of scan?.wifi ?? []) {
    if (!w.ssid) continue;
    const cur = candidates.get(w.ssid) ?? {
      ssid: w.ssid,
      knownBssidHashes: [],
      expectedSecurity: w.security,
    };
    if (w.bssidHash && !cur.knownBssidHashes.includes(w.bssidHash)) {
      cur.knownBssidHashes.push(w.bssidHash);
    }
    candidates.set(w.ssid, cur);
  }
  const trustedSsids = new Set(draft.trustedNetworks.map((t) => t.ssid));

  const save = async () => {
    setStatus("Saving...");
    try {
      await saveSettings(draft);
      setStatus("Saved");
    } catch {
      setStatus("Save failed");
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
        <h2 className="font-semibold">Trusted networks</h2>
        <p className="text-sm text-muted-foreground">
          If a trusted name shows up from unfamiliar hardware or weaker security,
          you get an alert.
        </p>
        {draft.trustedNetworks.length === 0 && (
          <p className="text-sm text-muted-foreground">None yet.</p>
        )}
        <ul className="space-y-1">
          {draft.trustedNetworks.map((t) => (
            <li key={t.ssid} className="flex items-center justify-between text-sm">
              <span>
                {t.ssid}{" "}
                <span className="text-muted-foreground">
                  ({SECURITY_LABEL[t.expectedSecurity]}, {t.knownBssidHashes.length}{" "}
                  known access point{t.knownBssidHashes.length === 1 ? "" : "s"})
                </span>
              </span>
              <button
                onClick={() =>
                  set({
                    trustedNetworks: draft.trustedNetworks.filter(
                      (x) => x.ssid !== t.ssid,
                    ),
                  })
                }
                className="rounded-md border px-2 py-0.5 hover:bg-accent"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        <div>
          <h3 className="mb-1 text-sm font-medium">Add from current scan</h3>
          {candidates.size === 0 ? (
            <p className="text-sm text-muted-foreground">
              No named networks in the latest scan (Location permission may be
              missing).
            </p>
          ) : (
            <ul className="space-y-1">
              {Array.from(candidates.values()).map((c) => (
                <li key={c.ssid} className="flex items-center justify-between text-sm">
                  <span>
                    {c.ssid}{" "}
                    <span className="text-muted-foreground">
                      ({SECURITY_LABEL[c.expectedSecurity]})
                    </span>
                  </span>
                  <button
                    disabled={trustedSsids.has(c.ssid)}
                    onClick={() =>
                      set({ trustedNetworks: [...draft.trustedNetworks, c] })
                    }
                    className="rounded-md border px-2 py-0.5 hover:bg-accent disabled:opacity-40"
                  >
                    {trustedSsids.has(c.ssid) ? "Trusted" : "Trust"}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

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

      <section className="space-y-2 rounded-xl border bg-card p-4 shadow">
        <h2 className="font-semibold">Alerts</h2>
        {(Object.keys(TOGGLE_LABEL) as Array<keyof AlertToggles>).map((k) => (
          <label key={k} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={draft.alertToggles[k]}
              onChange={(e) =>
                set({ alertToggles: { ...draft.alertToggles, [k]: e.target.checked } })
              }
            />
            {TOGGLE_LABEL[k]}
          </label>
        ))}
        <NumberField
          label="Tracker: minimum scans"
          min={1}
          value={draft.trackerMinScans}
          onChange={(n) => set({ trackerMinScans: n })}
        />
        <NumberField
          label="Tracker: minimum minutes"
          min={1}
          value={draft.trackerMinMinutes}
          onChange={(n) => set({ trackerMinMinutes: n })}
        />
        <label className="flex items-center gap-2 pt-2 text-sm">
          <input
            type="checkbox"
            checked={draft.notify}
            onChange={(e) => set({ notify: e.target.checked })}
          />
          Show desktop notifications for new alerts
        </label>
      </section>

      <div className="flex items-center gap-3">
        <button
          onClick={() => void save()}
          className="rounded-md bg-primary px-4 py-1.5 text-primary-foreground"
        >
          Save settings
        </button>
        {status && <span className="text-sm text-muted-foreground">{status}</span>}
      </div>
    </div>
  );
}
