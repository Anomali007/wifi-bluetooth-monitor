#!/usr/bin/env bash
# Reads `cargo test` output on stdin, prints the pass/fail tally, and fails when
# zero tests ran or any failed. A gate that ran nothing is not a pass.
set -euo pipefail
out=$(cat)
printf '%s\n' "$out"
passed=$(printf '%s\n' "$out" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | paste -sd+ - | bc)
failed=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) failed.*/\1/p' | paste -sd+ - | bc)
passed=${passed:-0}; failed=${failed:-0}
echo "TALLY: ${passed} passed / ${failed} failed"
if [ "$passed" -lt 1 ]; then echo "FAIL: cargo test ran 0 tests" >&2; exit 1; fi
if [ "$failed" -ne 0 ]; then echo "FAIL: ${failed} test(s) failed" >&2; exit 1; fi
