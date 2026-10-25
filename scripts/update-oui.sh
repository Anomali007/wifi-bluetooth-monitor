#!/usr/bin/env bash
# Regenerates src-tauri/src/vendor/oui.tsv from the IEEE MA-L registry.
# Output: one "<6 hex digit prefix>\t<short vendor>" line per assignment, sorted by prefix.
# Short names drop the postal address and trailing legal suffixes (Inc., Co.,Ltd, GmbH & Co. KG,
# ...) deterministically; "Private" registrations are omitted. Needs curl and python3.
# Usage: scripts/update-oui.sh [path-to-oui.csv]   (a local CSV skips the download)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
out=src-tauri/src/vendor/oui.tsv
csv=${1:-}
if [ -z "$csv" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  csv=$tmp/oui.csv
  # The registry host rejects the default curl user agent.
  curl -fsSL -m 180 \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15' \
    -H 'Accept: text/csv,*/*' \
    -o "$csv" https://standards-oui.ieee.org/oui/oui.csv
fi
python3 -I - "$csv" "$out" <<'PY'
import csv, re, sys

# Trailing legal-form words, matched case-insensitively after stripping punctuation.
SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc",
    "llp", "lp", "gmbh", "ag", "kg", "sa", "sas", "sarl", "srl", "spa", "bv", "nv", "oy", "ab",
    "as", "aps", "plc", "pte", "pty", "sdn", "bhd", "kk", "ug", "ltda", "de", "cv", "sl", "oyj",
    "ohg", "mbh", "and", "the", "holdings", "holding", "group",
}

def short(name: str) -> str:
    name = re.sub(r"\s+", " ", name.replace("\t", " ")).strip()
    name = re.sub(r"([,;])(?=\S)", r"\1 ", name)  # "Co.,Ltd" -> "Co., Ltd"
    words = name.split(" ")
    while len(words) > 1:
        last = re.sub(r"[^a-z0-9]", "", words[-1].lower())
        if last in SUFFIXES or last == "":
            words.pop()
            continue
        break
    # Drop dangling separators left behind ("Foo &", "Foo,").
    return re.sub(r"[\s,.&/;-]+$", "", " ".join(words)) or name

rows = {}
with open(sys.argv[1], newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if r["Registry"] != "MA-L":
            continue
        prefix = r["Assignment"].strip().upper()
        org = r["Organization Name"].strip()
        if not re.fullmatch(r"[0-9A-F]{6}", prefix) or org.lower() == "private" or not org:
            continue
        rows[prefix] = short(org)
with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
    for p in sorted(rows):
        f.write(f"{p}\t{rows[p]}\n")
print(f"wrote {len(rows)} prefixes to {sys.argv[2]}")
PY
