#!/usr/bin/env bash
# Public-repo guard. Fails (exit 1) on:
#   1. a MAC-shaped string in any tracked or untracked-but-not-ignored text file that is not
#      locally administered (02:xx:...) or all zero. Real scans contain neighbours' BSSIDs.
#   2. the placeholder salt "your_secret_salt" anywhere.
#   3. println!/eprintln!/dbg! in src-tauri/src outside test modules (scan data must never be
#      printed in a release build).
#   4. any raster image (png/jpg/jpeg/gif/webp/heic) outside src-tauri/icons/.
# Run from anywhere; it cds to the repo root. Prints a tally of checks run.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
checks=0
note() { printf 'FAIL: %s\n' "$*" >&2; fail=1; }

# Files to scan: tracked plus untracked-but-not-ignored, minus deleted ones and lockfiles.
files=""
while IFS= read -r f; do
  [ -f "$f" ] || continue
  if [ "$f" = "pnpm-lock.yaml" ] || [ "$f" = "src-tauri/Cargo.lock" ] || [ "$f" = "scripts/check-public-safety.sh" ]; then
    continue
  fi
  files="${files}${f}"$'\n'
done < <(git ls-files -co --exclude-standard)
files=${files%$'\n'}

# 1. MAC-shaped strings
checks=$((checks + 1))
mac_re='(^|[^0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}($|[^0-9A-Fa-f:-])'
while IFS= read -r f; do
  [ -n "$f" ] || continue
  grep -Iq . "$f" 2>/dev/null || continue   # skip binary / empty
  while IFS= read -r hit; do
    mac=$(printf '%s' "$hit" | grep -Eo '[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}' | head -1)
    norm=$(printf '%s' "$mac" | tr 'A-F-' 'a-f:')
    case "$norm" in
      02:*|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff) ;;
      *) note "MAC-shaped string in $f (not 02:xx / all-zero)"; ;;
    esac
  done < <(grep -E "$mac_re" "$f" || true)
done <<<"$files"

# 2. placeholder salt
checks=$((checks + 1))
if [ -n "$files" ] && printf '%s\n' "$files" | xargs grep -ln 'your_secret_salt' 2>/dev/null | grep -q .; then
  note '"your_secret_salt" found'
fi

# 3. print macros outside tests
checks=$((checks + 1))
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in src-tauri/src/*.rs|src-tauri/src/*/*.rs) ;; *) continue ;; esac
  awk -v F="$f" '
    /#\[cfg\(test\)\]|^mod (tests|live_tests)/ { intest = 1 }
    !intest && /(println|eprintln|dbg)!\(/ { printf "FAIL: %s:%d print macro outside a test module\n", F, NR > "/dev/stderr"; bad = 1 }
    END { exit bad }
  ' "$f" || fail=1
done <<<"$files"

# 4. raster images outside icons/
checks=$((checks + 1))
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    src-tauri/icons/*) ;;
    *.png|*.PNG|*.jpg|*.JPG|*.jpeg|*.JPEG|*.gif|*.webp|*.heic) note "image outside src-tauri/icons/: $f" ;;
  esac
done <<<"$files"

echo "public-safety: ${checks} checks ran over $(printf '%s\n' "$files" | grep -c .) files"
if [ "$checks" -lt 4 ]; then echo "FAIL: expected 4 checks" >&2; exit 1; fi
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "public-safety: OK"
