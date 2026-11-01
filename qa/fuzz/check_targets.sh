#!/usr/bin/env bash
# Census of the fuzz target list.
#
# The target list is written down in four places — `Cargo.toml`'s `[[bin]]`
# sections, `fuzz.sh`'s `TARGETS`, and the matrices of `fuzz-cron.yml` and
# `fuzz-coverage.yml` — and nothing kept them in step. A target added to
# `Cargo.toml` and forgotten in the cron is simply never fuzzed, silently and
# for as long as nobody counts.
#
# Seeds are deliberately not checked. This substrate's decoder is total —
# every byte slice is a valid program — so libFuzzer bootstraps any target
# from an empty corpus, and requiring committed seeds would mean 200 blobs in
# git that silently change meaning whenever a target's `Input` gains a field.
# The empty-coverage failure this census was written alongside is handled
# where it belongs, in `fuzz-coverage.yml`: a target that has produced a
# corpus before and has none now fails; one that has never been fuzzed
# reports that it has no data yet.
#
# Usage:
#   ./check_targets.sh          # census; non-zero exit on any mismatch

set -euo pipefail
cd "$(dirname "$0")"

CRON=../../.github/workflows/fuzz-cron.yml
COVERAGE=../../.github/workflows/fuzz-coverage.yml

fail=0
note() {
  echo "::error::$*" >&2
  fail=1
}

# `mapfile` would be the obvious reader, but it needs bash 4 and macOS still
# ships 3.2 as /bin/bash — this script has to run on a contributor's laptop as
# well as on the runner, so every list is read with a plain loop.

# The manifest is the source of truth: a target that is not a `[[bin]]` cannot
# be built at all. `extract_dict` and `circuit_lint` are tools, not fuzz targets.
manifest=()
while IFS= read -r line; do
  [ -n "$line" ] && manifest+=("$line")
done < <(sed -n 's/^name = "\(fuzz_[a-z0-9_]*\)"$/\1/p' Cargo.toml | sort)
if [ "${#manifest[@]}" -eq 0 ]; then
  note "no fuzz targets found in Cargo.toml — is the [[bin]] format still 'name = \"fuzz_...\"'?"
  exit 1
fi
echo "Cargo.toml declares ${#manifest[@]} fuzz targets."

# `fuzz.sh` lists them in its TARGETS array, one per line.
script=()
while IFS= read -r line; do
  [ -n "$line" ] && script+=("$line")
done < <(sed -n '/^TARGETS=(/,/^)/p' fuzz.sh | sed -n 's/^  \(fuzz_[a-z0-9_]*\)$/\1/p' | sort)

# Both workflows list them as matrix entries: "          - fuzz_name".
matrix_of() {
  sed -n 's/^          - \(fuzz_[a-z0-9_]*\)$/\1/p' "$1" | sort -u
}
cron=()
while IFS= read -r line; do
  [ -n "$line" ] && cron+=("$line")
done < <(matrix_of "$CRON")
coverage=()
while IFS= read -r line; do
  [ -n "$line" ] && coverage+=("$line")
done < <(matrix_of "$COVERAGE")

compare() {
  local what="$1"
  shift
  local -a have=("$@")
  local missing added
  missing=$(comm -23 <(printf '%s\n' "${manifest[@]}") <(printf '%s\n' "${have[@]}") | tr '\n' ' ')
  added=$(comm -13 <(printf '%s\n' "${manifest[@]}") <(printf '%s\n' "${have[@]}") | tr '\n' ' ')
  if [ -n "${missing// }" ]; then
    note "$what is missing: ${missing% } — those targets are never run there"
  fi
  if [ -n "${added// }" ]; then
    note "$what lists targets Cargo.toml does not build: ${added% }"
  fi
}

compare "fuzz.sh's TARGETS" "${script[@]}"
compare "fuzz-cron.yml's matrix" "${cron[@]}"
compare "fuzz-coverage.yml's matrix" "${coverage[@]}"

if [ "$fail" -eq 0 ]; then
  echo "=== target census OK: ${#manifest[@]} targets, all scheduled ==="
fi
exit "$fail"
