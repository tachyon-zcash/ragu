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
#   ./fuzz.sh cmin [target]                   # Minimize corpora in place (all targets if omitted)
#   ./fuzz.sh regress [target]                # Replay committed crash reproducers once each
#   ./fuzz.sh coverage [target]               # Corpus coverage report (union report if all targets)
#   ./fuzz.sh seeds [target] [seconds]        # Generate a local seed set from a short run
#   ./fuzz.sh census                          # Check the four target lists agree
#   ./fuzz.sh source-lint                     # Run no-execution circuit source lint
#
# Seeds: seeds/<target>/ is gitignored, local-only, and read-only to a run.
# Nothing is committed. This substrate's decoder is total — every byte slice
# is a valid program — so libFuzzer bootstraps any target from an empty
# corpus, and CI relies on the cron's durable corpus artifact rather than on
# seeds. They exist only to warm up a laptop run: `./fuzz.sh seeds` fuzzes
# into a scratch corpus, minimizes it, and copies the smallest survivors
# across.
# `./fuzz.sh census` is what CI runs to check every target is listed in
# fuzz.sh, and in both workflow matrices.
#
# Crash-regression inputs: when a fuzz run finds a real bug, commit the
# minimized reproducer to regressions/<target>/ (tracked in git, unlike
# corpus/ and seeds/). `./fuzz.sh regress` replays every committed
# reproducer once and fails on any crash; the cron does the same before
# each fuzz run.
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
# closures); to opt back in, set ASAN=1. The scheduled cron in
# `.github/workflows/fuzz-cron.yml` invokes `cargo "$NIGHTLY" fuzz run`
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
#   cargo "$NIGHTLY" run --release --bin extract_dict > dict.txt

set -euo pipefail
cd "$(dirname "$0")"

# Which nightly to build against. `+nightly` is whatever rustup calls nightly
# on this machine, which drifts and is regularly older than the workspace's
# MSRV — `cargo fuzz` then fails with "requires rustc 1.97" rather than
# anything about fuzzing. Set NIGHTLY to the pinned toolchain from
# `.github/actions/rust-nightly-setup/action.yml` to build exactly what CI
# builds:
#
#   NIGHTLY=+nightly-2026-05-23 ./fuzz.sh seeds
NIGHTLY="${NIGHTLY:-+nightly}"

TARGETS=(
  fuzz_poseidon_sponge
  fuzz_endoscalar
  fuzz_element_ops
  fuzz_circuit_witness
  fuzz_circuit_revdot_identity
  fuzz_witness_pinning
  fuzz_circuit_cheat
  fuzz_advice_patcher
  fuzz_internal_circuits
  fuzz_completeness
  fuzz_staging
  fuzz_revdot
  fuzz_fold_revdot
  fuzz_sxy_agreement
  fuzz_poseidon_differential
  fuzz_verify_reject
  fuzz_verify_reject_full
  fuzz_minimal_wire
  fuzz_compressed_wire
  fuzz_pcd_lifecycle
  fuzz_witness_cheat
  fuzz_driver_metamorphic
  fuzz_witness_coverage
  fuzz_algebraic_identities
  fuzz_element_assertions
  fuzz_multipack
  fuzz_point_identities
  fuzz_consistent
  fuzz_io_roundtrip
  fuzz_registry
)

# `source-lint` subcommand: parse production circuit/gadget source and apply
# the reviewed QA-local advisory baseline. The analyzer itself does not
# synthesize a circuit or invoke witness closures.
if [[ "${1:-}" == "source-lint" ]]; then
  exec cargo "$NIGHTLY" run --locked --bin circuit_lint -- --deny-advisories
fi

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
  DEBUG_INPUT=1 cargo "$NIGHTLY" fuzz run --fuzz-dir . "$TARGET" "$INPUT_FILE"
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
  TRIAGE_CHEAT=1 cargo "$NIGHTLY" fuzz run --fuzz-dir . fuzz_witness_cheat "$INPUT_FILE"
  exit
fi

# `census` subcommand: check the four places the target list is written down
# still agree.
if [[ "${1:-}" == "census" ]]; then
  exec ./check_targets.sh
fi

# `seeds` subcommand: generate a local seed set for one target, or for
# every target when none is given.
#
# Fuzzes into a scratch corpus (never the working one, so a local corpus is
# neither consumed nor polluted), minimizes it for coverage, and copies the
# smallest surviving inputs into seeds/<target>/. Small inputs are preferred
# because a seed's job is to be a cheap starting point, not a complete corpus:
# libFuzzer will grow it.
#
# The existing seeds are merged into the scratch corpus first, so regenerating
# never loses coverage a previous generation found.
if [[ "${1:-}" == "seeds" ]]; then
  SEED_SAN_FLAG="-s none"
  if [[ -n "${ASAN:-}" ]]; then
    SEED_SAN_FLAG=""
  fi
  if [[ -n "${2:-}" ]]; then
    SEED_TARGETS=("$2")
  else
    SEED_TARGETS=("${TARGETS[@]}")
  fi
  SEED_DURATION="${3:-30}"
  # How many inputs to keep per target. Enough to cover a target's branches
  # without committing a corpus: the cron accumulates the real one.
  SEED_KEEP="${SEED_KEEP:-8}"
  # A target that crashes while generating seeds is a finding, not a reason to
  # abandon the other twenty-six: collect them and report at the end.
  SEED_CRASHED=()
  for target in "${SEED_TARGETS[@]}"; do
    SCRATCH="$(mktemp -d)"
    trap 'rm -rf "$SCRATCH"' EXIT
    if [[ -d "seeds/$target" ]]; then
      find "seeds/$target" -type f -exec cp {} "$SCRATCH/" \;
    fi
    echo "=== seeds $target (${SEED_DURATION}s) ==="
    if ! cargo "$NIGHTLY" fuzz run --fuzz-dir . $SEED_SAN_FLAG "$target" "$SCRATCH" -- \
      -max_len=1024 \
      -max_total_time="$SEED_DURATION" 2>&1 | tail -3; then
      echo "=== $target: CRASHED while generating seeds ==="
      SEED_CRASHED+=("$target")
    fi
    cargo "$NIGHTLY" fuzz cmin --fuzz-dir . $SEED_SAN_FLAG "$target" "$SCRATCH" 2>&1 | tail -2 || true
    mkdir -p "seeds/$target"
    rm -f "seeds/$target"/*
    # Smallest first, then by name — libFuzzer names an input after its
    # content hash, so the set is stable across machines rather than
    # dependent on directory order. `wc -c` rather than `stat`, whose size
    # flag differs between BSD and GNU.
    while read -r _size file; do
      cp "$file" "seeds/$target/$(basename "$file")"
    done < <(
      find "$SCRATCH" -type f -exec sh -c 'echo "$(wc -c < "$1") $1"' _ {} \; \
        | sort -n -k1,1 -k2,2 | head -"$SEED_KEEP"
    )
    KEPT=$(find "seeds/$target" -type f | wc -l | tr -d ' ')
    echo "=== $target: $KEPT seeds written to seeds/$target/ ==="
    rm -rf "$SCRATCH"
    trap - EXIT
  done
  if [[ ${#SEED_CRASHED[@]} -gt 0 ]]; then
    echo "=== crashed during seed generation: ${SEED_CRASHED[*]} ===" >&2
    echo "Reproducers are under artifacts/<target>/." >&2
    exit 1
  fi
  exit
fi

# `cmin` subcommand: coverage-preserving corpus minimization, in place.
# Minimizes one target's corpus, or every target's when none is given.
# Uses `-s none` to reuse the default build cache; set ASAN=1 to match a
# sanitizer-enabled build instead.
if [[ "${1:-}" == "cmin" ]]; then
  CMIN_SAN_FLAG="-s none"
  if [[ -n "${ASAN:-}" ]]; then
    CMIN_SAN_FLAG=""
  fi
  if [[ -n "${2:-}" ]]; then
    CMIN_TARGETS=("$2")
  else
    CMIN_TARGETS=("${TARGETS[@]}")
  fi
  for target in "${CMIN_TARGETS[@]}"; do
    if [[ ! -d "corpus/$target" ]]; then
      echo "=== $target: no corpus, skipping ==="
      continue
    fi
    BEFORE=$(find "corpus/$target" -type f | wc -l | tr -d ' ')
    echo "=== cmin $target ($BEFORE inputs) ==="
    cargo "$NIGHTLY" fuzz cmin --fuzz-dir . $CMIN_SAN_FLAG "$target"
    AFTER=$(find "corpus/$target" -type f | wc -l | tr -d ' ')
    echo "=== $target: $BEFORE -> $AFTER inputs ==="
  done
  exit
fi

# `regress` subcommand: replay committed crash reproducers (one
# execution per file, no fuzzing) for one target or all targets.
# Any crash fails the run.
if [[ "${1:-}" == "regress" ]]; then
  REG_SAN_FLAG="-s none"
  if [[ -n "${ASAN:-}" ]]; then
    REG_SAN_FLAG=""
  fi
  if [[ -n "${2:-}" ]]; then
    REG_TARGETS=("$2")
  else
    REG_TARGETS=("${TARGETS[@]}")
  fi
  for target in "${REG_TARGETS[@]}"; do
    files=("regressions/$target"/*)
    if [[ ! -e "${files[0]:-}" ]]; then
      continue
    fi
    echo "=== regress $target (${#files[@]} inputs) ==="
    cargo "$NIGHTLY" fuzz run --fuzz-dir . $REG_SAN_FLAG "$target" "${files[@]}"
  done
  echo "=== regressions OK ==="
  exit
fi

# `coverage` subcommand: replay each target's corpus under a
# coverage-instrumented build (cargo fuzz coverage), then emit an
# llvm-cov per-file report to coverage/<target>/report.txt. When at
# least two targets are covered, also merges the profiles into a single
# union report at coverage/union-report.txt — the "which code does
# fuzzing reach at all" view. Requires llvm-tools-preview:
#   rustup component add llvm-tools-preview --toolchain nightly
if [[ "${1:-}" == "coverage" ]]; then
  HOST=$(rustc "$NIGHTLY" -vV | sed -n 's/^host: //p')
  TOOLS="$(rustc "$NIGHTLY" --print sysroot)/lib/rustlib/${HOST}/bin"
  if [[ ! -x "$TOOLS/llvm-cov" ]]; then
    echo "llvm-cov not found under $TOOLS" >&2
    echo "Install it with: rustup component add llvm-tools-preview --toolchain nightly" >&2
    exit 1
  fi
  has_input_files() {
    local dir="$1"
    [[ -d "$dir" ]] && [[ -n "$(find "$dir" -type f -print -quit)" ]]
  }
  # Keep the report focused on workspace code: drop registry deps, the
  # rust std sources, and the fuzz harness itself.
  IGNORE='(/\.cargo/|/rustc/|/\.rustup/|qa/fuzz/)'
  if [[ -n "${2:-}" ]]; then
    COV_TARGETS=("$2")
  else
    COV_TARGETS=("${TARGETS[@]}")
  fi
  FIRST_BIN=""
  PROFS=()
  OBJS=()
  for target in "${COV_TARGETS[@]}"; do
    dirs=()
    if has_input_files "corpus/$target"; then
      dirs+=("corpus/$target")
    fi
    if has_input_files "regressions/$target"; then
      dirs+=("regressions/$target")
    fi
    if has_input_files "seeds/$target"; then
      dirs+=("seeds/$target")
    fi
    if [[ ${#dirs[@]} -eq 0 ]]; then
      echo "=== $target: no corpus or seed inputs, skipping ==="
      continue
    fi
    echo "=== coverage $target ==="
    cargo "$NIGHTLY" fuzz coverage --fuzz-dir . -s none "$target" "${dirs[@]}"
    BIN="target/${HOST}/coverage/${HOST}/release/$target"
    PROF="coverage/$target/coverage.profdata"
    "$TOOLS/llvm-cov" report --instr-profile="$PROF" "$BIN" \
      --ignore-filename-regex="$IGNORE" > "coverage/$target/report.txt"
    tail -1 "coverage/$target/report.txt"
    PROFS+=("$PROF")
    if [[ -z "$FIRST_BIN" ]]; then
      FIRST_BIN="$BIN"
    else
      OBJS+=(-object "$BIN")
    fi
  done
  if [[ ${#PROFS[@]} -ge 2 ]]; then
    "$TOOLS/llvm-profdata" merge -sparse "${PROFS[@]}" -o coverage/union.profdata
    "$TOOLS/llvm-cov" report --instr-profile=coverage/union.profdata \
      "$FIRST_BIN" "${OBJS[@]}" \
      --ignore-filename-regex="$IGNORE" > coverage/union-report.txt
    echo "=== union (${#PROFS[@]} targets) ==="
    tail -1 coverage/union-report.txt
    echo "Union report: coverage/union-report.txt"
  fi
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

run_target() {
  local target="$1"
  echo "=== $target (${DURATION}s) ==="
  # First dir receives new units; seeds/<target> (when present) is a
  # local, read-only seed set merged in at startup so cold starts
  # never begin from an empty corpus.
  local dirs=("corpus/$target")
  if [[ -d "regressions/$target" ]]; then
    dirs+=("regressions/$target")
  fi
  if [[ -d "seeds/$target" ]]; then
    dirs+=("seeds/$target")
  fi
  mkdir -p "corpus/$target"
  cargo "$NIGHTLY" fuzz run --fuzz-dir . $SAN_FLAG "$target" "${dirs[@]}" -- \
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
