#!/usr/bin/env bash
# Build the `wbm` agent CLI / MCP server in release mode and COPY it into ~/bin.
#
#   scripts/install-cli.sh            # builds, installs ~/bin/wbm
#   scripts/install-cli.sh --force    # replace a ~/bin/wbm this script did not install
#   WBM_BIN_DIR=/some/dir scripts/install-cli.sh
#
# It copies the binary (so deleting the build directory cannot break the install, and a
# rebuild cannot change what agents run). It refuses to overwrite a `wbm` it did not install
# unless --force is given. It does NOT register the MCP server with any agent and edits no
# agent config: it prints the lines for you to run.
#
# Test hook: WBM_BUILT=/path/to/wbm skips the build and installs that binary.
set -euo pipefail

force=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "FAIL: unknown option $arg (try --help)" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${WBM_BIN_DIR:-$HOME/bin}"
target_dir="${CARGO_TARGET_DIR:-$root/src-tauri/target}"
dest="$bin_dir/wbm"
marker="$bin_dir/.wbm-installed.sha256"

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Is whatever sits at $dest something this script put there? Nothing there counts as ours.
#  - a regular file whose hash is the one recorded when we installed it, or
#  - a symlink into a cargo `release/wbm` (what the first version of this script made).
is_ours() {
  [ -e "$dest" ] || [ -L "$dest" ] || return 0
  if [ -L "$dest" ]; then
    case "$(readlink "$dest")" in */release/wbm) return 0 ;; *) return 1 ;; esac
  fi
  [ -f "$dest" ] && [ -f "$marker" ] && [ "$(sha "$dest")" = "$(cat "$marker")" ]
}

if ! is_ours && [ "$force" -ne 1 ]; then
  echo "FAIL: $dest exists and was not installed by this script; leaving it alone." >&2
  echo "      Move it away, or re-run with --force to replace it." >&2
  exit 1
fi

if [ -n "${WBM_BUILT:-}" ]; then
  built="$WBM_BUILT"
else
  echo "Building wbm (release)..."
  (cd "$root/src-tauri" && CARGO_TARGET_DIR="$target_dir" cargo build --release --bin wbm)
  built="$target_dir/release/wbm"
fi
[ -x "$built" ] || { echo "FAIL: $built was not produced" >&2; exit 1; }

mkdir -p "$bin_dir"
tmp="$dest.tmp.$$"
rm -f "$tmp"
cp "$built" "$tmp"
chmod 755 "$tmp"
# Replace atomically; a symlink at $dest is replaced, never followed.
rm -f "$dest"
mv -f "$tmp" "$dest"
sha "$dest" > "$marker"

# Prove the copy works and is the file we built before claiming success.
cmp -s "$built" "$dest" || { echo "FAIL: the installed file differs from the build" >&2; exit 1; }
"$dest" --version >/dev/null || { echo "FAIL: $dest does not run" >&2; exit 1; }
echo "Installed $dest ($("$dest" --version))"

case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "Note: $bin_dir is not on your PATH; use the full path below." ;;
esac

q_dest="$(printf '%q' "$dest")"
cat <<EOT

Next (you run these; this script changes no agent config):
  wbm status                                              # check it can read the app's database

Register the MCP server with Claude Code. Pick one:

  Read-only (recommended; 10 read tools, no way to change anything):
    claude mcp add wbm -- $q_dest mcp

  With edits (17 tools; edits that could hide an alert become requests you approve in the
  app under Settings, Agent requests; two safe ones apply at once and can be undone there):
    claude mcp add wbm -- $q_dest mcp --edits

Allowing mcp__wbm__* in Claude Code covers only the tools the server was started with, so the
read-only registration cannot be talked into editing by a permission rule alone.
EOT
