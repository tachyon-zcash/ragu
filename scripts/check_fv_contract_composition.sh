#!/usr/bin/env bash
# Guard the audited Lean gadget-composition boundary.
#
# Every proof-carrying Ragu circuit currently exposes its implementation as a
# namespace-local `main`. Parents must call the packaged circuit value instead
# (`Child.circuit`, or `Core.mul`) so Clean inserts a real subcircuit and applies
# the packaged child contract. A qualified `.main` reference is the clearest
# accidental way to bypass that boundary, either in a parent circuit or in a
# parent proof.
set -euo pipefail
cd "$(dirname "$0")/.."

source_root='qa/fv/Ragu/Circuits'
expected_contract_builders=61
expected_helper_builders=1

contract_builders=$(grep -REc '^def main([[:space:](]|$)' "$source_root" \
  | awk -F: '{ total += $NF } END { print total + 0 }')
helper_builders=$(grep -Ec '^def loop([[:space:](]|$)' \
  "$source_root/Poseidon/Sponge.lean")

status=0
if [[ $contract_builders -ne $expected_contract_builders ]]; then
  echo "VIOLATION: expected ${expected_contract_builders} audited contract builders, found ${contract_builders}" >&2
  status=1
fi
if [[ $helper_builders -ne $expected_helper_builders ]]; then
  echo "VIOLATION: expected ${expected_helper_builders} audited helper builders, found ${helper_builders}" >&2
  status=1
fi

# Strip nested Lean block comments and line comments before looking for a
# qualified `.main`. This is intentionally a narrow accidental-drift lint; the
# Lean type checker remains the semantic authority for packaged subcircuits.
if ! awk '
function code_without_comments(line,    out, i, pair) {
  out = ""
  i = 1
  while (i <= length(line)) {
    pair = substr(line, i, 2)
    if (comment_depth > 0) {
      if (pair == "/-") {
        comment_depth++
        i += 2
      } else if (pair == "-/") {
        comment_depth--
        i += 2
      } else {
        i++
      }
    } else if (pair == "/-") {
      comment_depth++
      i += 2
    } else if (pair == "--") {
      break
    } else {
      out = out substr(line, i, 1)
      i++
    }
  }
  return out
}
{
  code = code_without_comments($0)
  if (code ~ /\.main([^[:alnum:]_'\''.]|$)/) {
    printf "VIOLATION: qualified circuit implementation reference at %s:%d: %s\n", \
      FILENAME, FNR, code > "/dev/stderr"
    bad = 1
  }
}
END { exit bad }
' $(find "$source_root" -name '*.lean' -type f | sort); then
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "Ragu FV contract composition: ${contract_builders} contract builder(s), ${helper_builders} helper builder(s); no qualified .main references."
fi
exit $status
