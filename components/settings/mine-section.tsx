"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { shortHash } from "@/lib/format";
import type { MineEntry } from "@/lib/types";
import {
  MINE_KIND_LABEL,
  ROTATING_NOTE,
  cleanLabel,
  mineStore,
} from "../mine-state";

const EMPTY: readonly never[] = [];

/** Everything marked mine, with rename (edit the label) and unmark. */
export default function MineSection() {
  const entries = useSyncExternalStore(
    mineStore.subscribe,
    mineStore.getSnapshot,
    () => EMPTY,
  );
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    mineStore.ensureLoaded().finally(() => live && setLoaded(true));
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
    <section id="mine" className="scroll-mt-4 space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Mine</h2>
      <p className="text-sm text-muted-foreground">
        Access points, Bluetooth devices and network devices you marked as yours
        are left out of tracking and new-device alerts. Mark them from the
        Devices table.
      </p>
      <p className="text-xs text-muted-foreground">
        Apple and other rotating Bluetooth devices: {ROTATING_NOTE}
      </p>
      {error && <p className="text-sm text-red-700">{error}</p>}
      {!loaded ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing marked yet.</p>
      ) : (
        <ul className="space-y-1">
          {entries.map((e) => (
            <MineRow key={`${e.kind}:${e.idHash}`} entry={e} guard={guard} />
          ))}
        </ul>
      )}
    </section>
  );
}

function MineRow({
  entry,
  guard,
}: {
  entry: MineEntry;
  guard: (fn: () => Promise<void>) => Promise<void>;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 text-sm">
      <span>
        {entry.label ?? "(no label)"}{" "}
        <span className="text-muted-foreground">
          {MINE_KIND_LABEL[entry.kind]}, {shortHash(entry.idHash)}
        </span>
      </span>
      <span className="flex items-center gap-2">
        {draft === null ? (
          <button
            onClick={() => setDraft(entry.label ?? "")}
            className="rounded-md border px-2 py-0.5 hover:bg-accent"
          >
            Rename
          </button>
        ) : (
          <>
            <input
              data-search-exempt="per-row rename field"
              value={draft}
              onChange={(ev) => setDraft(ev.target.value)}
              aria-label="Label"
              maxLength={60}
              className="w-36 rounded-md border bg-background px-2 py-0.5"
            />
            <button
              onClick={() =>
                guard(async () => {
                  await mineStore.mark(
                    entry.kind,
                    entry.idHash,
                    cleanLabel(draft),
                    entry.ssid ?? null,
                  );
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
        <button
          onClick={() => guard(() => mineStore.unmark(entry.kind, entry.idHash))}
          className="rounded-md border px-2 py-0.5 hover:bg-accent"
        >
          Unmark
        </button>
      </span>
    </li>
  );
}
