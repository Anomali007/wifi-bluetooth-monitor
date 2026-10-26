"use client";

import { useEffect, useState } from "react";
import { useMonitor } from "@/components/monitor-provider";
import AlertsSection from "@/components/settings/alerts-section";
import LanSection from "@/components/settings/lan-section";
import MineSection from "@/components/settings/mine-section";
import PlacesSection from "@/components/settings/places-section";
import ScanningSection from "@/components/settings/scanning-section";
import TrustedNetworksSection from "@/components/settings/trusted-networks-section";
import WatchlistSection from "@/components/settings/watchlist-section";
import { reveal } from "@/lib/reveal";
import type { Settings } from "@/lib/types";

export default function SettingsPage() {
  const { settings, saveSettings, scan } = useMonitor();
  // Local edits start from the loaded settings; derived at render time instead of copied in an effect.
  const [edits, setDraft] = useState<Settings | null>(null);
  const draft = edits ?? settings;
  const [status, setStatus] = useState<string | null>(null);

  // Arriving with #id (a search result, or a pasted link): scroll to it once the page has rendered.
  const ready = draft !== null;
  useEffect(() => {
    if (!ready) return;
    let id = "";
    try {
      id = decodeURIComponent(window.location.hash.slice(1));
    } catch {
      return; // malformed escape in a pasted link: ignore it rather than blank the page
    }
    return id ? reveal(id) : undefined;
  }, [ready]);

  if (!draft) return <p className="text-sm text-muted-foreground">Loading settings...</p>;

  const set = (patch: Partial<Settings>) => setDraft({ ...draft, ...patch });

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

      <TrustedNetworksSection draft={draft} set={set} wifi={scan?.wifi ?? []} />
      <MineSection />
      <PlacesSection draft={draft} set={set} />
      <WatchlistSection />
      <LanSection draft={draft} set={set} />
      <ScanningSection draft={draft} set={set} />
      <AlertsSection draft={draft} set={set} />

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
