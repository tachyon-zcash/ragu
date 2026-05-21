#!/usr/bin/env bash
# Run all fuzz targets. Defaults to 30 seconds each, sequential.
#
# Usage:
#   ./fuzz.sh                                 # 30s each, sequential
#   ./fuzz.sh 60                              # 1 min each, sequential
#   ./fuzz.sh 300 -j                          # 5 min each, parallel
#   DICT=1 ./fuzz.sh                          # Load dict.txt
#   ./fuzz.sh summarize <target> <file>       # Decode a corpus/crash input
#   ./fuzz.sh triage <file>                   # Triage a fuzz_soundness_cheat crash
#
# The DICT=1 path passes -dict=dict.txt to libFuzzer. Empirical comparison
# (60s on fuzz_element_ops): roughly flat coverage with a small features
# decrease; on fuzz_poseidon_sponge: small features and corpus increase.
# Worth trying for Poseidon-heavy targets in longer runs.
#
# The `summarize` subcommand runs the target binary on a single corpus or
# crash file with the DEBUG_INPUT env var set, which each fuzz target
# respects: instead of running the fuzz body, the target parses the input
# via Arbitrary, prints it via Debug, and exits. Useful for triaging
# crash artifacts without manually decoding bytes.
#
# The `triage` subcommand runs fuzz_soundness_cheat with TRIAGE_CHEAT=1,
# which walks the op stream tracking the cheated slot and reports how
# many downstream ops actually read it. A 0 count means the soundness
# signal is a "dead cheat" false positive.
#
# Regenerate dict.txt via:
#   cargo +nightly run --release --bin extract_dict > dict.txt

set -euo pipefail
cd "$(dirname "$0")"

# `summarize` subcommand: decode a single corpus/crash input via DEBUG_INPUT.
if [[ "${1:-}" == "summarize" ]]; then
  if [[ -z "${2:-}" || -z "${3:-}" ]]; then
    echo "Usage: ./fuzz.sh summarize <target> <corpus-or-crash-file>" >&2
    exit 1
  fi
  TARGET="$2"
  INPUT_FILE="$3"
  if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found: $INPUT_FILE" >&2
    exit 1
  fi
  DEBUG_INPUT=1 cargo +nightly fuzz run --fuzz-dir . "$TARGET" "$INPUT_FILE"
  exit
fi

# `triage` subcommand: walk the op stream of a fuzz_soundness_cheat crash
# input, report whether the cheated slot was read downstream.
if [[ "${1:-}" == "triage" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "Usage: ./fuzz.sh triage <crash-file>" >&2
    exit 1
  fi
  INPUT_FILE="$2"
  if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Input file not found: $INPUT_FILE" >&2
    exit 1
  fi
  TRIAGE_CHEAT=1 cargo +nightly fuzz run --fuzz-dir . fuzz_soundness_cheat "$INPUT_FILE"
  exit
fi

DURATION="${1:-30}"
PARALLEL="${2:-}"
DICT="${DICT:-}"

DICT_FLAG=""
if [[ -n "$DICT" ]]; then
  DICT_FLAG="-dict=dict.txt"
fi

TARGETS=(
  fuzz_poseidon_sponge
  fuzz_endoscalar
  fuzz_element_ops
  fuzz_revdot
  fuzz_fold_revdot
  fuzz_sxy_agreement
  fuzz_poseidon_differential
  fuzz_verify_reject
  fuzz_soundness_cheat
  fuzz_driver_metamorphic
  fuzz_witness_coverage
  fuzz_algebraic_identities
  fuzz_element_assertions
  fuzz_multipack
  fuzz_point_identities
  fuzz_consistent
  fuzz_io_roundtrip
)

run_target() {
  local target="$1"
  echo "=== $target (${DURATION}s) ==="
  cargo +nightly fuzz run --fuzz-dir . "$target" -- \
    $DICT_FLAG \
    -max_len=1024 \
    -max_total_time="$DURATION" \
    2>&1 | tail -5
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
