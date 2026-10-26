"use client";

import type { AlertToggles } from "@/lib/types";
import NumberField from "./number-field";
import type { SectionProps } from "./section";

const TOGGLE_LABEL: Record<keyof AlertToggles, string> = {
  evilTwin: "Evil twin (same name, different hardware)",
  openLookalike: "Open lookalike of a secured network",
  trustedNetworkChanged: "Trusted network changed",
  persistentTracker: "Possible tracker nearby (persistent)",
  newDevice: "New device nearby (noisy)",
  followedAcrossPlaces: "Possible device following you across places",
  watchlist: "Watchlist match",
  newLanDevice: "New device on a network you marked as yours",
};

/** DOM ids for the toggles; lib/settings-registry.ts has a matching entry for each. */
const TOGGLE_ID: Record<keyof AlertToggles, string> = {
  evilTwin: "alert-evil-twin",
  openLookalike: "alert-open-lookalike",
  trustedNetworkChanged: "alert-trusted-network-changed",
  persistentTracker: "alert-persistent-tracker",
  newDevice: "alert-new-device",
  followedAcrossPlaces: "alert-followed-across-places",
  watchlist: "alert-watchlist",
  newLanDevice: "alert-new-lan-device",
};

export default function AlertsSection({ draft, set }: SectionProps) {
  return (
    <section id="alerts" className="scroll-mt-4 space-y-2 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Alerts</h2>
      {(Object.keys(TOGGLE_LABEL) as Array<keyof AlertToggles>).map((k) => (
        <label key={k} className="flex items-center gap-2 text-sm">
          <input
            id={TOGGLE_ID[k]}
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
        id="tracker-min-scans"
        label="Tracker: minimum scans"
        min={1}
        value={draft.trackerMinScans}
        onChange={(n) => set({ trackerMinScans: n })}
      />
      <NumberField
        id="tracker-min-minutes"
        label="Tracker: minimum minutes"
        min={1}
        value={draft.trackerMinMinutes}
        onChange={(n) => set({ trackerMinMinutes: n })}
      />
      <label className="flex items-center gap-2 pt-2 text-sm">
        <input
          id="notify"
          type="checkbox"
          checked={draft.notify}
          onChange={(e) => set({ notify: e.target.checked })}
        />
        Show desktop notifications for new alerts
      </label>
    </section>
  );
}
