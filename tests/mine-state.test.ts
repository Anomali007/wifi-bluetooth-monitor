import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ROTATING_NOTE,
  cleanLabel,
  createMineStore,
  findEntry,
  placeName,
} from "../components/mine-state";
import type { MineEntry } from "../lib/types";

const original = process.env.NEXT_PUBLIC_WBM_MOCK;
beforeEach(() => {
  process.env.NEXT_PUBLIC_WBM_MOCK = "1";
});
afterEach(() => {
  if (original === undefined) delete process.env.NEXT_PUBLIC_WBM_MOCK;
  else process.env.NEXT_PUBLIC_WBM_MOCK = original;
});

const HASH = "02" + "ab".repeat(31);

describe("cleanLabel / placeName", () => {
  it("trims and nulls blanks", () => {
    expect(cleanLabel("  Home router ")).toBe("Home router");
    expect(cleanLabel("   ")).toBeNull();
    expect(cleanLabel("")).toBeNull();
  });
  it("falls back to Place N", () => {
    expect(placeName({ id: 3, label: null })).toBe("Place 3");
    expect(placeName({ id: 3, label: "  " })).toBe("Place 3");
    expect(placeName({ id: 3, label: " Home " })).toBe("Home");
  });
});

describe("findEntry", () => {
  const e: MineEntry = { kind: "ble", idHash: HASH, label: null, addedAt: 1 };
  it("matches kind and hash together", () => {
    expect(findEntry([e], "ble", HASH)).toBe(e);
    expect(findEntry([e], "wifiAp", HASH)).toBeUndefined();
    expect(findEntry([e], "ble", "other")).toBeUndefined();
  });
});

describe("rotating-address note", () => {
  it("states the limitation in plain words", () => {
    expect(ROTATING_NOTE).toBe(
      "This device changes its address every few minutes, so this mark won't last.",
    );
  });
});

describe("mine store against the mock backend", () => {
  it("loads, marks (with and without a label), relabels and unmarks", async () => {
    const store = createMineStore();
    let notified = 0;
    const off = store.subscribe(() => notified++);
    await store.ensureLoaded();
    const base = store.getSnapshot().length;
    expect(base).toBeGreaterThan(0);

    await store.mark("ble", HASH, "My tag");
    expect(findEntry(store.getSnapshot(), "ble", HASH)?.label).toBe("My tag");
    expect(store.getSnapshot().length).toBe(base + 1);

    // Marking again relabels instead of duplicating.
    await store.mark("ble", HASH, null);
    expect(findEntry(store.getSnapshot(), "ble", HASH)?.label).toBeNull();
    expect(store.getSnapshot().length).toBe(base + 1);

    await store.unmark("ble", HASH);
    expect(findEntry(store.getSnapshot(), "ble", HASH)).toBeUndefined();
    expect(store.getSnapshot().length).toBe(base);

    expect(notified).toBeGreaterThanOrEqual(4);
    off();
  });

  it("ensureLoaded asks the backend once", async () => {
    const store = createMineStore();
    const a = store.ensureLoaded();
    const b = store.ensureLoaded();
    expect(a).toBe(b);
    await a;
  });

  it("snapshot identity is stable between changes", async () => {
    const store = createMineStore();
    await store.ensureLoaded();
    expect(store.getSnapshot()).toBe(store.getSnapshot());
  });
});
