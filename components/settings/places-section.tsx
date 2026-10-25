"use client";

import { useEffect, useState } from "react";
import { listPlaces } from "@/lib/api";
import type { Place } from "@/lib/types";
import NumberField from "./number-field";
import type { SectionProps } from "./section";

/** STUB (WP-AB owns): places list with rename and forget; the retention field is wired. */
export default function PlacesSection({ draft, set }: SectionProps) {
  const [places, setPlaces] = useState<Place[] | null>(null);
  useEffect(() => {
    let live = true;
    listPlaces()
      .then((p) => live && setPlaces(p))
      .catch(() => live && setPlaces([]));
    return () => {
      live = false;
    };
  }, []);
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Places</h2>
      <p className="text-sm text-muted-foreground">
        Places are remembered as a set of nearby Wi-Fi hashes, never as
        coordinates. They let the app notice something that shows up at more
        than one of them.
      </p>
      <p className="text-sm text-muted-foreground">
        {places === null ? "Loading..." : `${places.length} remembered.`}
      </p>
      <NumberField
        label="Keep places and network devices for (days)"
        min={1}
        value={draft.placeRetentionDays}
        onChange={(n) => set({ placeRetentionDays: n })}
      />
    </section>
  );
}
