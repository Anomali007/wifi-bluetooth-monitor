import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SETTING_ITEMS, search } from "../lib/palette-items";
import { SETTINGS_REGISTRY, registryGaps, settingHref } from "../lib/settings-registry";
import { DEFAULT_SETTINGS } from "../lib/types";

const DIR = join(__dirname, "..", "components", "settings");
const files = readdirSync(DIR).filter((f) => f.endsWith(".tsx"));

/** Opening tags (with attribute text) of the given elements; tolerant of `=>` and `>` inside {}. */
function tags(src: string, names: string[]): string[] {
  const out: string[] = [];
  const re = new RegExp(`<(${names.join("|")})(?=[\\s/>])`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    let depth = 0;
    let quote: string | null = null;
    let i = m.index;
    for (; i < src.length; i++) {
      const c = src[i];
      if (quote) {
        if (c === quote) quote = null;
      } else if (c === '"' || c === "'") quote = c;
      else if (c === "{") depth++;
      else if (c === "}") depth--;
      else if (c === ">" && depth === 0) break;
    }
    out.push(src.slice(m.index, i + 1));
  }
  return out;
}

/** ids from a `FOO_ID = { key: "id", ... }` map, for controls rendered in a loop */
function mapIds(src: string): string[] {
  const out: string[] = [];
  for (const m of src.matchAll(/_ID\b[^=]*=\s*\{([^}]*)\}/g)) {
    for (const s of m[1].matchAll(/"([^"]+)"/g)) out.push(s[1]);
  }
  return out;
}

interface Scan {
  controlIds: string[];
  allIds: string[];
  unnamed: string[];
  controls: number;
}

function scanSources(sources: Record<string, string>): Scan {
  const controlIds: string[] = [];
  const allIds: string[] = [];
  const unnamed: string[] = [];
  let controls = 0;
  for (const [file, src] of Object.entries(sources)) {
    const mapped = mapIds(src);
    allIds.push(...mapped);
    for (const m of src.matchAll(/\bid="([^"]+)"/g)) allIds.push(m[1]);
    for (const t of tags(src, ["input", "select", "textarea", "NumberField", "section"])) {
      controls++;
      if (t.includes("data-search-exempt=")) continue;
      // NumberField's inner <input id={id}> passes the caller's id through; call sites are checked.
      if (/\bid=\{id\}/.test(t)) continue;
      const lit = /\bid="([^"]+)"/.exec(t);
      if (lit) controlIds.push(lit[1]);
      else if (/\bid=\{[A-Z_]+_ID\[/.test(t)) controlIds.push(...mapped);
      else unnamed.push(`${file}: ${t.replace(/\s+/g, " ").slice(0, 60)}`);
    }
  }
  return { controlIds: [...new Set(controlIds)], allIds, unnamed, controls };
}

const sources = Object.fromEntries(files.map((f) => [f, readFileSync(join(DIR, f), "utf8")]));
const scanned = scanSources(sources);

describe("settings registry covers the Settings page", () => {
  it("scanned a real set of controls (floor)", () => {
    expect(files.length).toBeGreaterThanOrEqual(7);
    expect(scanned.controls).toBeGreaterThanOrEqual(20);
    expect(scanned.controlIds.length).toBeGreaterThanOrEqual(20);
  });

  it("every control and section has a DOM id (or is marked exempt with a reason)", () => {
    expect(scanned.unnamed).toEqual([]);
  });

  it("every control id has a registry entry, and every entry points at an id that exists", () => {
    const gaps = registryGaps(scanned.controlIds, scanned.allIds);
    expect(gaps.missingEntries).toEqual([]);
    expect(gaps.danglingEntries).toEqual([]);
    expect(gaps.duplicates).toEqual([]);
  });

  it("every entry is complete", () => {
    for (const e of SETTINGS_REGISTRY) {
      expect(e.label, e.id).not.toBe("");
      expect(e.section, e.id).not.toBe("");
      expect(e.description, e.id).not.toBe("");
      expect(e.keywords.length, e.id).toBeGreaterThan(0);
      expect(e.id, e.id).toMatch(/^[a-z][a-z0-9-]*$/);
    }
  });

  it("every alert toggle has an id in the page source", () => {
    expect(mapIds(sources["alerts-section.tsx"]).length).toBe(
      Object.keys(DEFAULT_SETTINGS.alertToggles).length,
    );
  });
});

describe("negative controls for the registry check", () => {
  it("catches a control with no entry", () => {
    const withoutOne = SETTINGS_REGISTRY.filter((e) => e.id !== "lan-neighbor-helper");
    const gaps = registryGaps(scanned.controlIds, scanned.allIds, withoutOne);
    expect(gaps.missingEntries).toEqual(["lan-neighbor-helper"]);
  });

  it("catches a new control added to the source without an entry", () => {
    const extra = scanSources({
      ...sources,
      "new-section.tsx": '<section id="brand-new">\n<input id="brand-new-toggle" type="checkbox" />\n</section>',
    });
    const gaps = registryGaps(extra.controlIds, extra.allIds);
    expect(gaps.missingEntries.sort()).toEqual(["brand-new", "brand-new-toggle"]);
  });

  it("catches a control with no id at all", () => {
    const bare = scanSources({ "bare.tsx": '<input type="checkbox" onChange={(e) => go(e.target.value)} />' });
    expect(bare.unnamed.length).toBe(1);
  });

  it("catches an entry pointing at an id that does not exist", () => {
    const bad = [
      ...SETTINGS_REGISTRY,
      { id: "no-such-control", label: "x", section: "x", description: "x", keywords: ["x"] },
    ];
    const gaps = registryGaps(scanned.controlIds, scanned.allIds, bad);
    expect(gaps.danglingEntries).toEqual(["no-such-control"]);
  });

  it("catches a duplicate entry", () => {
    const dup = [...SETTINGS_REGISTRY, SETTINGS_REGISTRY[0]];
    expect(registryGaps(scanned.controlIds, scanned.allIds, dup).duplicates).toEqual([
      SETTINGS_REGISTRY[0].id,
    ]);
  });
});

describe("queries find the right setting", () => {
  const top = (q: string, n = 3) =>
    (search(q, SETTING_ITEMS).find((s) => s.group === "settings")?.items ?? [])
      .slice(0, n)
      .map((i) => i.target);

  it.each([
    ["trust", "trusted-networks"],
    ["evil twin", "alert-evil-twin"],
    ["impostor", "trusted-networks"],
    ["arp", "lan-neighbor-helper"],
    ["neighbor", "lan-neighbor-helper"],
    ["background item", "lan-neighbor-helper"],
    ["sweep", "lan-active-sweep"],
    ["scan network", "lan-active-sweep"],
    ["retention", "retention-hours"],
    ["retention", "place-retention-days"],
    ["watch", "watchlist"],
    ["notifications", "notify"],
  ])("%s finds %s near the top", (q, id) => {
    expect(top(q, 4)).toContain(id);
  });

  it("trust, watch and arp each rank the right setting first", () => {
    expect(top("trust", 1)).toEqual(["trusted-networks"]);
    expect(top("watch", 1)).toEqual(["watchlist"]);
    expect(top("arp", 1)).toEqual(["lan-neighbor-helper"]);
  });

  it("nonsense finds nothing", () => {
    expect(search("zzqxj", SETTING_ITEMS)).toEqual([]);
  });

  it("every result opens /settings#<id>", () => {
    for (const i of SETTING_ITEMS) expect(i.href).toBe(settingHref(i.target!));
  });
});
