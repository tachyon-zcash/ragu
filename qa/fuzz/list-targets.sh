#!/usr/bin/env bash
# Print fuzz target names declared in Cargo.toml, one per line.
#
# cargo-fuzz stores each target as a `[[bin]]`. Auxiliary tools live in the
# same manifest, so this script includes only bin names with the `fuzz_`
# prefix.

set -euo pipefail
cd "$(dirname "$0")"

awk '
  /^\[\[bin\]\]/ {
    in_bin = 1
    next
  }

  /^\[/ {
    in_bin = 0
    next
  }

  in_bin && /^[[:space:]]*name[[:space:]]*=/ {
    name = $0
    sub(/^[^=]*=[[:space:]]*"/, "", name)
    sub(/".*/, "", name)
    if (name ~ /^fuzz_/) {
      print name
    }
    in_bin = 0
  }
' Cargo.toml
