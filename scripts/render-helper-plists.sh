#!/usr/bin/env bash
# Renders src-tauri/helper/*.plist.in into src-tauri/helper/rendered/*.plist for bundling.
# launchd does not expand "~" or $HOME in StandardOutPath, so the per-user app-data path is
# substituted at build time. The rendered files are git-ignored and never committed.
#
# The rendered plists therefore belong to the user who ran this script: the app compares the
# bundled StandardOutPath with its own data folder at runtime and reports the background item
# as "Unavailable in this build" for anyone else.
#
# Testing hooks (not for normal use): RENDER_OUT_DIR overrides the output folder.
set -euo pipefail
cd "$(dirname "$0")/../src-tauri/helper"
DATA_DIR="$HOME/Library/Application Support/com.anomali007.wifibtmonitor"

# Characters that would corrupt the sed substitution or the XML: refuse rather than guess.
# (Newline is checked separately; the other three are the sed delimiter, the sed "matched
# text" metacharacter, and the XML tag opener.)
case "$DATA_DIR" in
  *'#'* | *'&'* | *'<'* | *'\'*)
    echo "render-helper-plists: refusing a data path containing # & < or backslash" >&2
    exit 1 ;;
esac
if [[ "$DATA_DIR" == *$'\n'* ]]; then
  echo "render-helper-plists: refusing a data path containing a newline" >&2
  exit 1
fi

OUT_DIR="${RENDER_OUT_DIR:-rendered}"
mkdir -p "$OUT_DIR"
for f in *.plist.in; do
  out="$OUT_DIR/${f%.in}"
  # XML-escape the path (& and < are already excluded; > and quotes remain possible) and
  # substitute it with plain string search, not a regex or sed replacement, so no character in
  # the path is special. The path travels in the environment, not in the program text.
  DATA_DIR="$DATA_DIR" awk '
    function xml(s,   i, c, o) {
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == ">") o = o "&gt;"
        else if (c == "\"") o = o "&quot;"
        else if (c == "\047") o = o "&apos;"
        else o = o c
      }
      return o
    }
    BEGIN { d = xml(ENVIRON["DATA_DIR"]) }
    {
      out = ""; rest = $0
      while ((i = index(rest, "@DATA_DIR@")) > 0) {
        out = out substr(rest, 1, i - 1) d
        rest = substr(rest, i + 10)
      }
      print out rest
    }' "$f" > "$out"
  plutil -lint "$out" >/dev/null
done
ls "$OUT_DIR" | wc -l | tr -d ' ' | sed 's/$/ helper plists rendered/'
