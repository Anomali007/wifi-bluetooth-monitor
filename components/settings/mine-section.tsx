"use client";

import { useEffect, useState } from "react";
import { listMine } from "@/lib/api";
import type { MineEntry } from "@/lib/types";

/** STUB (WP-AB owns): list of things marked mine, with unmark and rename. */
export default function MineSection() {
  const [mine, setMine] = useState<MineEntry[] | null>(null);
  useEffect(() => {
    let live = true;
    listMine()
      .then((m) => live && setMine(m))
      .catch(() => live && setMine([]));
    return () => {
      live = false;
    };
  }, []);
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Mine</h2>
      <p className="text-sm text-muted-foreground">
        Access points, Bluetooth devices and network devices you marked as yours
        are left out of tracking and new-device alerts.
      </p>
      <p className="text-sm text-muted-foreground">
        {mine === null ? "Loading..." : `${mine.length} marked.`}
      </p>
    </section>
  );
}
