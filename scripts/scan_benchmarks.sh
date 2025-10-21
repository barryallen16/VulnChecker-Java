#!/usr/bin/env bash
# Scan the benchmark suites with the TriageMate Semgrep ruleset.
# Juliet is scanned one CWE directory at a time: a crash or timeout on a single
# file then costs one chunk instead of the whole run, and finished chunks resume.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANS="$ROOT/data/scans"
CONFIGS=(--config p/default --config p/security-audit --config p/owasp-top-ten)
FLAGS=(--json --quiet --timeout 30 --max-target-bytes 2000000 --metrics off --jobs 2)

mkdir -p "$SCANS/juliet"

if [ ! -s "$SCANS/owasp.json" ]; then
  echo "scanning owasp"
  ( cd "$ROOT/benchmarks/owasp" &&
    semgrep "${CONFIGS[@]}" "${FLAGS[@]}" -o "$SCANS/owasp.json" \
      src/main/java/org/owasp/benchmark/testcode ) || echo "owasp scan failed"
fi

scan_one() {
  local dir="$1" name out
  name="$(basename "$dir")"
  out="$SCANS/juliet/$name.json"
  [ -s "$out" ] && return 0
  echo "scanning juliet $name"
  ( cd "$ROOT/benchmarks/juliet" &&
    semgrep --config p/default --config p/security-audit --config p/owasp-top-ten \
      --json --quiet --timeout 30 --max-target-bytes 2000000 --metrics off --jobs 2 \
      -o "$out" "src/testcases/$name" ) || echo "juliet $name failed"
}
export -f scan_one
export ROOT SCANS

# 4 workers x 2 jobs each keeps the 8 cores busy without a memory spike.
find "$ROOT/benchmarks/juliet/src/testcases" -maxdepth 1 -type d -name 'CWE*' -print0 \
  | xargs -0 -P4 -I{} bash -c 'scan_one "$@"' _ {}
echo "scan complete"
