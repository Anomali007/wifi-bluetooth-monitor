import { describe, expect, it } from "vitest";
import { fold, matchItem, rank } from "../lib/search";

const item = (label: string, keywords: string[] = [], description?: string) => ({
  label,
  keywords,
  description,
});

describe("fold", () => {
  it("lowercases, strips diacritics and punctuation", () => {
    expect(fold("  Café-Net_A  ")).toBe("cafe net a");
    expect(fold("NAÏVE")).toBe("naive");
  });
});

describe("matchItem tiers", () => {
  const a = item("Scan interval", ["frequency"], "Time between automatic scans");
  const matches = ["scan interval", "scan i", "interv", "frequency", "automatic", "scint"].map((q) =>
    matchItem(q, a),
  );
  it("exact beats prefix beats word beats keyword beats description beats fuzzy", () => {
    expect(matches.map((m) => m?.tier)).toEqual([
      "exact",
      "prefix",
      "word",
      "keyword",
      "description",
      "fuzzy",
    ]);
    const scores = matches.map((m) => m!.score);
    expect([...scores].sort((x, y) => y - x)).toEqual(scores);
    expect(new Set(scores).size).toBe(scores.length);
  });
  it("is case-insensitive and folds diacritics both ways", () => {
    expect(matchItem("CAFE", item("Café Net"))?.tier).toBe("prefix");
    expect(matchItem("café", item("Cafe Net"))?.tier).toBe("prefix");
  });
  it("needs every token for a multi-word query", () => {
    expect(matchItem("trusted chan", item("Trusted network changed"))).not.toBeNull();
    expect(matchItem("trusted zebra", item("Trusted network changed"))).toBeNull();
  });
  it("empty and whitespace queries match nothing", () => {
    expect(matchItem("", a)).toBeNull();
    expect(matchItem("   ", a)).toBeNull();
  });
});

describe("negative controls", () => {
  const items = [
    item("Trusted networks", ["trust"]),
    item("Scan interval (seconds)"),
    item("Net-A"),
    item("Vendor-A device"),
  ];
  it("nonsense returns 0 results", () => {
    for (const q of ["zzqxj", "qqq", "xkcd9", "!!!", "zzzzzzzzzzzz"]) {
      expect(rank(q, items), q).toEqual([]);
    }
  });
  it("a real query is not empty (the check can pass as well as fail)", () => {
    expect(rank("trust", items).length).toBeGreaterThan(0);
  });
  it("fuzzy does not match a scattered subsequence", () => {
    expect(matchItem("tstnk", item("Trusted networks and a very long tail of extra words"))).toBeNull();
  });
});

describe("rank", () => {
  it("orders by tier, then shorter label, then input order", () => {
    const r = rank("net", [
      item("Home network"), // word
      item("Net-A"), // prefix, short
      item("Network devices"), // prefix, longer
      item("Other", ["net"]), // keyword
    ]);
    expect(r.map((x) => x.item.label)).toEqual(["Net-A", "Network devices", "Home network", "Other"]);
  });
  it("is stable for equal candidates", () => {
    const r = rank("a", [item("A1"), item("A2"), item("A3")]);
    expect(r.map((x) => x.item.label)).toEqual(["A1", "A2", "A3"]);
  });
});
