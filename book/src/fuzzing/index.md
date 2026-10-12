# Overview

Formal verification proves things about the circuits it covers, and the
[previous part](../fv/index.md) is explicit about how narrow that coverage is.
Fuzzing covers the rest, more weakly: a coverage-guided search for an input
that breaks an invariant, over the parts of the system no proof reaches yet.

The harness lives in `qa/fuzz`, built on
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). It is its own workspace
root, so the nightly toolchain and libFuzzer flags it needs stay out of the
main build. There are 28 targets, plus tools for extracting Ragu's field
constants into a fuzzer dictionary and linting circuit source without execution.

The harness enables `ragu_pcd`'s `unstable-fuzzing` feature in its own
`Cargo.toml`. This exposes `ragu_pcd::fuzzing`, the internal proof-corruption
and circuit-patcher interface. It is not part of the stable public API;
ordinary application dependencies do not need this feature.

## The shared substrate

Most targets are built on one module, `ragu_testing_fuzz::substrate`, layered
so each target takes only what it needs:

1. An op grammar over `Element` and `Boolean` gadget calls, with per-op
   capability flags so each target can carve out its own vocabulary.
2. A total byte decoder, so any input libFuzzer produces is a valid program —
   and `proptest` strategies over the same grammar, for deterministic tests
   under plain `cargo test`.
3. A driver-generic interpreter, run under `Simulator`, `Emulator`, or the
   patcher's recording driver.
4. A native `Fp` evaluator giving each op's true semantics, for differential
   oracles.
5. A wrapper making a generated program a registerable `Circuit`, for the
   constraint-level oracles.

Because the grammar and wire format are shared, so are the corpora: a mutation
that reaches deep circuit structure in one target reaches it in the others.

## Running it

```bash
cd qa/fuzz             # from the repository root
./fuzz.sh              # every target, 30s each, sequentially
./fuzz.sh 300 -j       # five minutes each, in parallel
./fuzz.sh regress      # replay every committed crash regression
./fuzz.sh cmin         # minimize the corpora in place
./fuzz.sh coverage     # per-target and union coverage reports
```

`DICT=1` loads the constant dictionary. `ASAN=1` re-enables AddressSanitizer,
off by default because it costs roughly 70% throughput on the simulator-heavy
targets — but worth turning on when triaging a crash.
