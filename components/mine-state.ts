// Shared "Mine" state and the pure helpers around it. One cached list serves every row's
// MineButton and the Settings section, so marking in a table updates Settings and back.
import { addMine, listMine, removeMine } from "@/lib/api";
import type { MineEntry, MineKind, Place } from "@/lib/types";

export const ROTATING_NOTE =
  "This device changes its address every few minutes, so this mark won't last.";

export const MINE_KIND_LABEL: Record<MineKind, string> = {
  wifiAp: "Access point",
  wifiGroup: "Access point (all radios)",
  ble: "Bluetooth device",
  lan: "Network device",
};

export function findEntry(
  entries: readonly MineEntry[],
  kind: MineKind,
  idHash: string,
): MineEntry | undefined {
  return entries.find((e) => e.kind === kind && e.idHash === idHash);
}

/** Trimmed label, or null when blank (the backend treats null as "no label"). */
export function cleanLabel(raw: string): string | null {
  const t = raw.trim();
  return t ? t : null;
}

/** What a place is called in lists and alerts: the typed label, else "Place N". */
export function placeName(p: Pick<Place, "id" | "label">): string {
  return p.label && p.label.trim() ? p.label.trim() : `Place ${p.id}`;
}

export interface MineStore {
  getSnapshot: () => readonly MineEntry[];
  subscribe: (fn: () => void) => () => void;
  /** Load once; later calls reuse the first request. Failures leave the list empty. */
  ensureLoaded: () => Promise<void>;
  reload: () => Promise<void>;
  mark: (kind: MineKind, idHash: string, label: string | null) => Promise<void>;
  unmark: (kind: MineKind, idHash: string) => Promise<void>;
}

export function createMineStore(): MineStore {
  let entries: readonly MineEntry[] = [];
  let loading: Promise<void> | null = null;
  const listeners = new Set<() => void>();
  const publish = (next: readonly MineEntry[]) => {
    entries = next;
    listeners.forEach((fn) => fn());
  };
  const reload = async () => {
    publish(await listMine());
  };
  return {
    getSnapshot: () => entries,
    subscribe: (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    ensureLoaded: () => {
      loading ??= reload().catch(() => {
        loading = null; // allow a retry on the next mount
      });
      return loading;
    },
    reload,
    mark: async (kind, idHash, label) => {
      const saved = await addMine(kind, idHash, label);
      publish([...entries.filter((e) => !(e.kind === kind && e.idHash === idHash)), saved]);
    },
    unmark: async (kind, idHash) => {
      await removeMine(kind, idHash);
      publish(entries.filter((e) => !(e.kind === kind && e.idHash === idHash)));
    },
  };
}

export const mineStore = createMineStore();
