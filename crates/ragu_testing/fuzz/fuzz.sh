#!/usr/bin/env bash
# Run all fuzz targets. Defaults to 5 minutes each, sequential.
#
# Usage:
#   ./run_all.sh              # 5 min each, sequential
#   ./run_all.sh 60           # 1 min each, sequential
#   ./run_all.sh 300 -j       # 5 min each, parallel

set -euo pipefail
cd "$(dirname "$0")"

DURATION="${1:-300}"
PARALLEL="${2:-}"

TARGETS=(
  fuzz_poseidon_sponge
  fuzz_endoscalar
  fuzz_element_ops
  fuzz_revdot
  fuzz_fold_revdot
  fuzz_sxy_agreement
)

run_target() {
  local target="$1"
  echo "=== $target (${DURATION}s) ==="
  cargo +nightly fuzz run "$target" -- -max_total_time="$DURATION" 2>&1 \
    | tail -5
  echo
}

if [[ "$PARALLEL" == "-j" ]]; then
  for target in "${TARGETS[@]}"; do
    run_target "$target" &
  done
  wait
else
  for target in "${TARGETS[@]}"; do
    run_target "$target"
  done
fi

echo "=== done ==="
