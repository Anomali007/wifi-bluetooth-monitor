"use client";

import { useEffect, useState } from "react";
import { listWatchlist } from "@/lib/api";
import type { WatchlistEntry } from "@/lib/types";

/** STUB (WP-C owns): add and remove SSID / vendor patterns. */
export default function WatchlistSection() {
  const [entries, setEntries] = useState<WatchlistEntry[] | null>(null);
  useEffect(() => {
    let live = true;
    listWatchlist()
      .then((e) => live && setEntries(e))
      .catch(() => live && setEntries([]));
    return () => {
      live = false;
    };
  }, []);
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Watchlist</h2>
      <p className="text-sm text-muted-foreground">
        Get an alert when a network name or hardware vendor you list shows up.
        Entries stay on this Mac.
      </p>
      <p className="text-sm text-muted-foreground">
        {entries === null ? "Loading..." : `${entries.length} entries.`}
      </p>
    </section>
  );
}
