#!/usr/bin/env bash
# Build the `wbm` agent CLI / MCP server in release mode and link it into ~/bin.
#
#   scripts/install-cli.sh            # builds, links ~/bin/wbm
#   WBM_BIN_DIR=/some/dir scripts/install-cli.sh
#
# It does NOT register the MCP server with any agent and edits no agent config. To do that with
# Claude Code, run the line this script prints at the end yourself.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${WBM_BIN_DIR:-$HOME/bin}"
target_dir="${CARGO_TARGET_DIR:-$root/src-tauri/target}"

echo "Building wbm (release)..."
(cd "$root/src-tauri" && CARGO_TARGET_DIR="$target_dir" cargo build --release --bin wbm)

built="$target_dir/release/wbm"
[ -x "$built" ] || { echo "FAIL: $built was not produced" >&2; exit 1; }

mkdir -p "$bin_dir"
ln -sf "$built" "$bin_dir/wbm"

# Prove the link works before claiming success.
"$bin_dir/wbm" --version >/dev/null || { echo "FAIL: $bin_dir/wbm does not run" >&2; exit 1; }
echo "Linked $bin_dir/wbm -> $built ($("$bin_dir/wbm" --version))"

case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "Note: $bin_dir is not on your PATH; use the full path below." ;;
esac

cat <<EOF

Next (you run these; this script changes no agent config):
  wbm status                                  # check it can read the app's database
  claude mcp add wbm -- $bin_dir/wbm mcp      # register the MCP server with Claude Code
EOF
