#!/usr/bin/env bash
# Reads `vitest run` output on stdin, prints the tally, and fails when zero tests ran or any
# failed. A gate that ran nothing is not a pass.
set -euo pipefail
out=$(cat)
printf '%s\n' "$out"
line=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^ *Tests ' | tail -1 || true)
passed=$(printf '%s' "$line" | sed -n 's/.* \([0-9][0-9]*\) passed.*/\1/p')
failed=$(printf '%s' "$line" | sed -n 's/.* \([0-9][0-9]*\) failed.*/\1/p')
passed=${passed:-0}; failed=${failed:-0}
echo "TALLY: ${passed} passed / ${failed} failed"
if [ "$passed" -lt 1 ]; then echo "FAIL: vitest ran 0 tests" >&2; exit 1; fi
if [ "$failed" -ne 0 ]; then echo "FAIL: ${failed} test(s) failed" >&2; exit 1; fi
