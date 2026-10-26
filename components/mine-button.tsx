"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import type { MineKind } from "@/lib/types";
import {
  ROTATING_NOTE,
  cleanLabel,
  findEntry,
  mineStore,
} from "./mine-state";

export interface MineTarget {
  kind: MineKind;
  idHash: string;
  /** The device rotates its address (e.g. Apple BLE), so a mark will not last. */
  rotatingAddress: boolean;
  /** For access points: the network name to save with the mark (the sweep checks it). */
  ssid?: string | null;
}

const EMPTY: readonly never[] = [];

/** "Mark as mine" / "Mine" toggle for a device-table row, with an optional label. */
export default function MineButton({ target }: { target: MineTarget }) {
  const entries = useSyncExternalStore(
    mineStore.subscribe,
    mineStore.getSnapshot,
    () => EMPTY,
  );
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    void mineStore.ensureLoaded();
  }, []);

  const entry = findEntry(entries, target.kind, target.idHash);
  const run = async (fn: () => Promise<void>) => {
    setError(null);
    try {
      await fn();
      setEditing(false);
      setLabel("");
    } catch (e) {
      setError(String(e));
    }
  };

  if (entry) {
    return (
      <span className="inline-flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-900">
          Mine{entry.label ? `: ${entry.label}` : ""}
        </span>
        <button
          onClick={() => run(() => mineStore.unmark(target.kind, target.idHash))}
          className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
        >
          Unmark
        </button>
        {target.rotatingAddress && (
          <span className="text-xs text-muted-foreground">{ROTATING_NOTE}</span>
        )}
        {error && <span className="text-xs text-red-700">{error}</span>}
      </span>
    );
  }

  if (!editing) {
    return (
      <button
        onClick={() => setEditing(true)}
        className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
      >
        Mark as mine
      </button>
    );
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <input
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        placeholder="Label (optional)"
        aria-label="Label (optional)"
        maxLength={60}
        className="w-36 rounded-md border bg-background px-2 py-0.5 text-xs"
      />
      <button
        onClick={() =>
          run(() => mineStore.mark(target.kind, target.idHash, cleanLabel(label), target.ssid ?? null))
        }
        className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
      >
        Save
      </button>
      <button
        onClick={() => setEditing(false)}
        className="rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
      >
        Cancel
      </button>
      {target.rotatingAddress && (
        <span className="basis-full text-xs text-muted-foreground">
          {ROTATING_NOTE}
        </span>
      )}
      {error && <span className="text-xs text-red-700">{error}</span>}
    </span>
  );
}
