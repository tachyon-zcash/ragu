# Corpus and Triage

Corpora are not committed. Each target accumulates its own across scheduled
runs, cached per target and restored at the start of the next one — including
after a run that ended in a crash, so a crashing input never costs the corpus.
`./fuzz.sh cmin` minimizes them in place.

`dict.txt` is a libFuzzer dictionary of Ragu's field constants: the Poseidon
round constants and MDS matrices for both fields, plus special values, around
seven hundred entries. Regenerate it with

```bash
cargo +nightly run --release --bin extract_dict > dict.txt
```

It ships opt-in (`DICT=1`) rather than always-on, because it helps on
sponge-heavy targets and is roughly neutral elsewhere.

Fixed crashes leave their input in `regressions/`, replayed by
`./fuzz.sh regress` so that a fix cannot quietly come undone.

## Triage

Every target honors `DEBUG_INPUT=1`, which parses the input and prints its
`Debug` form instead of running the body — turning a crash artifact into
something readable:

```bash
DEBUG_INPUT=1 cargo +nightly fuzz run fuzz_element_ops \
  artifacts/fuzz_element_ops/crash-abc123
```

For the [under-constraint targets](oracles.md), `TRIAGE_CHEAT=1` additionally
reports how many downstream operations read the cheated wire. Zero reads is a
dead cheat; a high count means the cheat propagated and the constraints failed
to notice, which is the bug class worth chasing.

## What it has found

- Squeezing from an empty sponge violated a precondition.
- The native and circuit sponge APIs disagreed on that same case.
- `Tag::new(0)` divided by zero during registry construction.
