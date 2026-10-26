"use client";

import { useEffect, useState } from "react";
import { addWatchlist, listWatchlist, removeWatchlist } from "@/lib/api";
import {
  WATCH_KIND_LABEL,
  WATCH_MATCH_LABEL,
  checkWatchEntry,
  describeWatchEntry,
} from "@/lib/format";
import type { WatchKind, WatchMatch, WatchlistEntry } from "@/lib/types";

const FIELD = "rounded-md border bg-background px-2 py-1 text-sm";

/** Add and remove network-name / vendor patterns. Entries are saved on their own, not with Save. */
export default function WatchlistSection() {
  const [entries, setEntries] = useState<WatchlistEntry[] | null>(null);
  const [kind, setKind] = useState<WatchKind>("ssid");
  const [match, setMatch] = useState<WatchMatch>("contains");
  const [pattern, setPattern] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    listWatchlist()
      .then((e) => live && setEntries(e))
      .catch(() => live && setEntries([]));
    return () => {
      live = false;
    };
  }, []);

  async function add() {
    const checked = checkWatchEntry(kind, match, pattern, entries ?? []);
    if (!checked.ok) {
      setError(checked.error);
      return;
    }
    try {
      const created = await addWatchlist(kind, checked.pattern, match);
      setEntries((cur) => [...(cur ?? []), created]);
      setPattern("");
      setError(null);
    } catch {
      setError("Could not add the entry.");
    }
  }

  async function remove(id: number) {
    try {
      await removeWatchlist(id);
      setEntries((cur) => (cur ?? []).filter((e) => e.id !== id));
      setError(null);
    } catch {
      setError("Could not remove the entry.");
    }
  }

  return (
    <section className="space-y-3 rounded-xl border bg-card p-4 shadow">
      <h2 className="font-semibold">Watchlist</h2>
      <p className="text-sm text-muted-foreground">
        Get an alert when a network name or hardware vendor you list shows up.
        Matching ignores case, spacing and look-alike characters. Exact means the same name, not a similar one.
        Entries stay on this Mac.
      </p>
      {entries === null ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing on the list yet.</p>
      ) : (
        <ul className="space-y-1">
          {entries.map((e) => (
            <li key={e.id} className="flex items-center justify-between text-sm">
              <span>{describeWatchEntry(e)}</span>
              <button
                onClick={() => remove(e.id)}
                className="rounded-md border px-2 py-0.5 hover:bg-accent"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(ev) => {
          ev.preventDefault();
          void add();
        }}
      >
        <select
          aria-label="Watch for"
          value={kind}
          onChange={(ev) => setKind(ev.target.value as WatchKind)}
          className={FIELD}
        >
          {(Object.keys(WATCH_KIND_LABEL) as WatchKind[]).map((k) => (
            <option key={k} value={k}>
              {WATCH_KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <select
          aria-label="Match mode"
          value={match}
          onChange={(ev) => setMatch(ev.target.value as WatchMatch)}
          className={FIELD}
        >
          {(Object.keys(WATCH_MATCH_LABEL) as WatchMatch[]).map((m) => (
            <option key={m} value={m}>
              {WATCH_MATCH_LABEL[m]}
            </option>
          ))}
        </select>
        <input
          aria-label="Pattern"
          value={pattern}
          onChange={(ev) => setPattern(ev.target.value)}
          placeholder={kind === "ssid" ? "Network name" : "Vendor name"}
          className={`${FIELD} min-w-48 flex-1`}
        />
        <button type="submit" className="rounded-md border px-3 py-1 text-sm hover:bg-accent">
          Add
        </button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-red-600">
          {error}
        </p>
      )}
    </section>
  );
}
