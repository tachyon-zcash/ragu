#!/usr/bin/env bash
# Run all fuzz targets. Defaults to 30 seconds each, sequential.
#
# Usage:
#   ./fuzz.sh                                 # 30s each, sequential, no ASAN
#   ./fuzz.sh 60                              # 1 min each, sequential
#   ./fuzz.sh 300 -j                          # 5 min each, parallel
#   DICT=1 ./fuzz.sh                          # Load dict.txt
#   ASAN=1 ./fuzz.sh                          # Re-enable AddressSanitizer
#   ./fuzz.sh summarize <target> <file>       # Decode a corpus/crash input
#   ./fuzz.sh triage <file>                   # Triage a fuzz_witness_cheat crash
#
# The DICT=1 path passes -dict=dict.txt to libFuzzer. Empirical comparison
# (60s on fuzz_element_ops): roughly flat coverage with a small features
# decrease; on fuzz_poseidon_sponge: small features and corpus increase.
# Worth trying for Poseidon-heavy targets in longer runs.
#
# By default this script passes `-s none` to cargo-fuzz, skipping
# AddressSanitizer for a large throughput win on simulator-heavy targets
# — measured ~70% on fuzz_witness_cheat (50k → 84k exec/s), ~30% on
# fuzz_poseidon_sponge, ~10% on fuzz_element_ops. ASAN catches memory
# bugs (UAF, OOB on unwise unsafe, leaks across `Simulator::simulate`
# closures); to opt back in, set ASAN=1. The weekly cron in
# `.github/workflows/fuzz-cron.yml` invokes `cargo +nightly fuzz run`
# directly and keeps ASAN regardless of this script's default. Crash
# artifacts found here should be reproduced under ASAN=1 before triaging
# to get proper allocation history.
#
# The `summarize` subcommand runs the target binary on a single corpus or
# crash file with the DEBUG_INPUT env var set, which each fuzz target
# respects: instead of running the fuzz body, the target parses the input
# via Arbitrary, prints it via Debug, and exits. Useful for triaging
# crash artifacts without manually decoding bytes.
#
# The `triage` subcommand runs fuzz_witness_cheat with TRIAGE_CHEAT=1,
# which walks the op stream tracking the cheated slot and reports how
# many downstream ops actually read it. A 0 count means the signal is a
# "dead cheat" false positive.
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

# `triage` subcommand: walk the op stream of a fuzz_witness_cheat crash
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
  TRIAGE_CHEAT=1 cargo +nightly fuzz run --fuzz-dir . fuzz_witness_cheat "$INPUT_FILE"
  exit
fi

DURATION="${1:-30}"
PARALLEL="${2:-}"
DICT="${DICT:-}"
ASAN="${ASAN:-}"

DICT_FLAG=""
if [[ -n "$DICT" ]]; then
  DICT_FLAG="-dict=dict.txt"
fi

# Default to no sanitizer for throughput. ASAN=1 opts back in for
# memory-bug coverage. See header comment for the trade-off.
SAN_FLAG="-s none"
if [[ -n "$ASAN" ]]; then
  SAN_FLAG=""
fi

TARGETS=(
  fuzz_poseidon_sponge
  fuzz_endoscalar
  fuzz_element_ops
  fuzz_circuit_witness
  fuzz_circuit_revdot_identity
  fuzz_staging
  fuzz_revdot
  fuzz_fold_revdot
  fuzz_sxy_agreement
  fuzz_poseidon_differential
  fuzz_verify_reject
  fuzz_witness_cheat
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
  cargo +nightly fuzz run --fuzz-dir . $SAN_FLAG "$target" -- \
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
