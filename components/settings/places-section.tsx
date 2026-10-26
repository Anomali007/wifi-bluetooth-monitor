"use client";

import { useEffect, useState } from "react";
import { forgetPlace, listPlaces, renamePlace } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import type { Place } from "@/lib/types";
import { cleanLabel, placeName } from "../mine-state";
import NumberField from "./number-field";
import type { SectionProps } from "./section";

/** Places list with rename and forget, plus the retention setting. */
export default function PlacesSection({ draft, set }: SectionProps) {
  const [places, setPlaces] = useState<Place[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    listPlaces()
      .then((p) => live && setPlaces(p))
      .catch(() => live && setPlaces([]));
    return () => {
      live = false;
    };
  }, []);

  const guard = async (fn: () => Promise<void>) => {
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Places</h2>
      <p className="text-sm text-muted-foreground">
        Places are remembered as a set of nearby Wi-Fi hashes, never as
        coordinates. A place is only recorded after you stay for a few scans, and
        they let the app notice something that shows up at more than one of them.
        Name them so alerts can say where.
      </p>
      {error && <p className="text-sm text-red-700">{error}</p>}
      {places === null ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : places.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          None remembered yet. Places appear after a few scans in the same spot.
        </p>
      ) : (
        <ul className="space-y-1">
          {places.map((p) => (
            <PlaceRow
              key={p.id}
              place={p}
              guard={guard}
              onRenamed={(u) =>
                setPlaces((cur) => cur && cur.map((x) => (x.id === u.id ? u : x)))
              }
              onForgotten={() =>
                setPlaces((cur) => cur && cur.filter((x) => x.id !== p.id))
              }
            />
          ))}
        </ul>
      )}
      <NumberField
        label="Keep places and network devices for (days)"
        min={1}
        value={draft.placeRetentionDays}
        onChange={(n) => set({ placeRetentionDays: n })}
      />
    </section>
  );
}

function PlaceRow({
  place,
  guard,
  onRenamed,
  onForgotten,
}: {
  place: Place;
  guard: (fn: () => Promise<void>) => Promise<void>;
  onRenamed: (p: Place) => void;
  onForgotten: () => void;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <span>
        {placeName(place)}{" "}
        <span className="text-muted-foreground">
          {place.members.length} access point{place.members.length === 1 ? "" : "s"},
          last here {formatDateTime(place.lastSeen)}
        </span>
      </span>
      <span className="flex items-center gap-2">
        {draft === null ? (
          <button
            onClick={() => setDraft(place.label ?? "")}
            className="rounded-md border px-2 py-0.5 hover:bg-accent"
          >
            Rename
          </button>
        ) : (
          <>
            <input
              value={draft}
              onChange={(ev) => setDraft(ev.target.value)}
              aria-label="Place name"
              maxLength={60}
              className="w-36 rounded-md border bg-background px-2 py-0.5"
            />
            <button
              onClick={() =>
                guard(async () => {
                  onRenamed(await renamePlace(place.id, cleanLabel(draft)));
                  setDraft(null);
                })
              }
              className="rounded-md border px-2 py-0.5 hover:bg-accent"
            >
              Save
            </button>
            <button
              onClick={() => setDraft(null)}
              className="rounded-md border px-2 py-0.5 hover:bg-accent"
            >
              Cancel
            </button>
          </>
        )}
        {confirming ? (
          <button
            onClick={() =>
              guard(async () => {
                await forgetPlace(place.id);
                onForgotten();
              })
            }
            className="rounded-md border border-red-300 px-2 py-0.5 text-red-800 hover:bg-accent"
          >
            Forget it and its sightings
          </button>
        ) : (
          <button
            onClick={() => setConfirming(true)}
            className="rounded-md border px-2 py-0.5 hover:bg-accent"
          >
            Forget
          </button>
        )}
      </span>
    </li>
  );
}
