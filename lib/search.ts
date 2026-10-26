/**
 * Small pure matcher for the command palette. No DOM, no state.
 *
 * Tiers, best first: exact label > prefix of the label > a word of the label > a keyword >
 * the description > fuzzy subsequence of the label. Case and diacritics are ignored.
 */

export interface Searchable {
  label: string;
  keywords?: readonly string[];
  description?: string;
}

export type MatchTier = "exact" | "prefix" | "word" | "keyword" | "description" | "fuzzy";

export interface Match {
  tier: MatchTier;
  score: number;
}

const TIER_SCORE: Record<MatchTier, number> = {
  exact: 1000,
  prefix: 800,
  word: 600,
  keyword: 400,
  description: 250,
  fuzzy: 100,
};

/** Lower-case, strip diacritics, turn punctuation into single spaces. */
export function fold(s: string): string {
  return s
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function words(s: string): string[] {
  const f = fold(s);
  return f === "" ? [] : f.split(" ");
}

/** Every query token is the start of some word in `hay`. */
function allTokensStartWords(tokens: string[], hay: string[]): boolean {
  return tokens.every((t) => hay.some((w) => w.startsWith(t)));
}

/** Characters of `q` appear in `text` in order. Returns the span they cover, or -1. */
function subsequenceSpan(q: string, text: string): number {
  let at = 0;
  let first = -1;
  for (const ch of q) {
    const i = text.indexOf(ch, at);
    if (i < 0) return -1;
    if (first < 0) first = i;
    at = i + 1;
  }
  return at - first;
}

/** Best match of `query` against one item, or null. An empty query matches nothing. */
export function matchItem(query: string, item: Searchable): Match | null {
  const q = fold(query);
  if (q === "") return null;
  const tokens = q.split(" ");
  const label = fold(item.label);

  if (label === q) return { tier: "exact", score: TIER_SCORE.exact };
  if (label.startsWith(q)) return { tier: "prefix", score: TIER_SCORE.prefix };

  const labelWords = words(item.label);
  if (allTokensStartWords(tokens, labelWords)) {
    return { tier: "word", score: TIER_SCORE.word };
  }

  // A keyword hit: the whole query is a keyword or the start of one; or each token starts a
  // word taken from the label and keywords together.
  const kws = (item.keywords ?? []).map(fold);
  if (kws.some((k) => k === q)) return { tier: "keyword", score: TIER_SCORE.keyword + 20 };
  if (kws.some((k) => k.startsWith(q))) return { tier: "keyword", score: TIER_SCORE.keyword + 10 };
  const kwWords = [...labelWords, ...kws.flatMap((k) => k.split(" "))];
  if (allTokensStartWords(tokens, kwWords)) return { tier: "keyword", score: TIER_SCORE.keyword };

  if (item.description) {
    if (allTokensStartWords(tokens, [...kwWords, ...words(item.description)])) {
      return { tier: "description", score: TIER_SCORE.description };
    }
  }

  // Fuzzy: a single run of letters typed loosely ("sclint" -> "Scan interval"). Needs 3+
  // letters and a tight span so a long label cannot match noise.
  const compact = q.replace(/ /g, "");
  if (compact.length >= 3) {
    const span = subsequenceSpan(compact, label.replace(/ /g, ""));
    if (span >= 0 && span <= compact.length * 2) {
      return { tier: "fuzzy", score: TIER_SCORE.fuzzy - (span - compact.length) };
    }
  }
  return null;
}

export interface Ranked<T> {
  item: T;
  match: Match;
}

/**
 * Matching items, best first. Ties go to the shorter label, then to the original order, so the
 * result is deterministic.
 */
export function rank<T extends Searchable>(query: string, items: readonly T[]): Ranked<T>[] {
  const out: Array<Ranked<T> & { i: number }> = [];
  items.forEach((item, i) => {
    const match = matchItem(query, item);
    if (match) out.push({ item, match, i });
  });
  out.sort(
    (a, b) =>
      b.match.score - a.match.score ||
      a.item.label.length - b.item.label.length ||
      a.i - b.i,
  );
  return out.map(({ item, match }) => ({ item, match }));
}
