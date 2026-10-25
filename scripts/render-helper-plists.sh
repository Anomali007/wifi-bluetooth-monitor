#!/usr/bin/env bash
# Renders src-tauri/helper/*.plist.in into src-tauri/helper/rendered/*.plist for bundling.
# launchd does not expand "~" or $HOME in StandardOutPath, so the per-user app-data path is
# substituted at build time. The rendered files are git-ignored and never committed.
set -euo pipefail
cd "$(dirname "$0")/../src-tauri/helper"
DATA_DIR="$HOME/Library/Application Support/com.anomali007.wifibtmonitor"
mkdir -p rendered
for f in *.plist.in; do
  out="rendered/${f%.in}"
  sed "s#@DATA_DIR@#${DATA_DIR}#g" "$f" > "$out"
  plutil -lint "$out" >/dev/null
done
ls rendered | wc -l | tr -d ' ' | sed 's/$/ helper plists rendered/'
