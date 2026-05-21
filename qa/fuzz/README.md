# `ragu_testing-fuzz`

cargo-fuzz harness for the Ragu project. 17 fuzz targets + 1 auxiliary
dictionary-extractor tool. Standalone workspace (the `[workspace]` table in
`Cargo.toml` makes this crate its own root) so nightly + libfuzzer flags
don't leak into the rest of the repo.

## Quick start

```bash
# Run every target for 30 seconds, sequentially.
./fuzz.sh

# Custom duration (seconds).
./fuzz.sh 300

# Parallel run (CPU fans will spin).
./fuzz.sh 60 -j

# With the field-element constant dictionary loaded.
DICT=1 ./fuzz.sh

# Run a single target directly.
cargo +nightly fuzz run fuzz_element_ops -- -max_total_time=60
```

## Targets

### Vec\<Op\>-style instruction-vector targets

Generate random `Vec<Op>` sequences of `Element`/`Boolean` gadget calls.
All four share an essentially identical `Op` enum and dispatch — see the
"why duplicated" note at the bottom.

| Target | What it catches |
|---|---|
| `fuzz_element_ops` | Completeness — random gadget compositions must not crash and must produce internally-consistent witnesses. The substrate. |
| `fuzz_witness_coverage` | Same as `fuzz_element_ops` plus a post-run witness-state hash spread across coverage branches. Biases the fuzzer toward distinct internal witness states. Opt-in POC (~28% throughput cost). |
| `fuzz_soundness_cheat` | Soundness — mid-stream replaces an element on the stack with a fresh allocation of a different value; matching final fingerprints under a cheat is a signal of an under-constrained gadget. |
| `fuzz_driver_metamorphic` | Differential — runs the same `Vec<Op>` through both `Simulator` and `Emulator<Wired<Fp>>`; wire values must match. Tests the model-vs-real-driver invariant. |

### Gadget-API property and identity targets

| Target | What it catches |
|---|---|
| `fuzz_algebraic_identities` | Random `Fp` pairs and a `Boolean`; checks ~16 gadget-level algebraic identities (commutativity, identity elements, distributivity, conditional-select). Catches broken gadget contracts. |
| `fuzz_element_assertions` | `enforce_zero`, `enforce_root_of_unity`, `invert_with` — assertion gadgets must accept valid inputs and reject invalid ones. |
| `fuzz_point_identities` | Pallas curve points `P = G * p_seed`. Tests group-law identities on the point gadget. |
| `fuzz_multipack` | `Boolean::multipack` — packing bits into `Element`s round-trips correctly. |
| `fuzz_consistent` | `Consistent` trait — internal invariants on gadgets hold for arbitrary inputs. |
| `fuzz_io_roundtrip` | `Write` trait — gadget serialize/deserialize via the IO buffer round-trips. |

### Primitive-level targets

| Target | What it catches |
|---|---|
| `fuzz_poseidon_sponge` | Random Absorb/Squeeze sequences through the circuit `Sponge`. Caught the squeeze-from-empty precondition bug. |
| `fuzz_poseidon_differential` | Native `NativeSponge` vs circuit `Sponge`; outputs must match. Caught the native↔circuit API asymmetry on squeeze-from-empty. |
| `fuzz_endoscalar` | Endoscalar (point × scalar) operations; has its own `special_scalar` table with `Fp::ZETA`. |
| `fuzz_revdot` | Reverse-dot-product primitive. |
| `fuzz_fold_revdot` | RevDot folding. |
| `fuzz_sxy_agreement` | `s(X, Y)` registry consistency. Caught `Key::new(0)` divide-by-zero. |

### Verifier robustness

| Target | What it catches |
|---|---|
| `fuzz_verify_reject` | Corrupt proof bytes via `fuzz_utils::Corruption`, assert verifier rejects. Uses `test_trivial_proof()` — tests verifier hardening, not soundness in the paper's sense. |

## Auxiliary tooling

### `extract_dict`

Not a fuzz target. Emits Ragu's field-element constants (Poseidon
`ROUND_CONSTANTS` + `MDS_MATRIX` for Fp and Fq, plus 16 special Fp/Fq
values — total ~704 entries) as a libFuzzer dictionary file at
`dict.txt`. Loaded into the mutation engine via the `DICT=1` flag.

Regenerate:

```bash
cargo +nightly run --release --bin extract_dict > dict.txt
```

The dictionary is mildly positive on Poseidon-heavy targets and roughly
neutral on element-ops targets, so it ships opt-in rather than always-on.

### `DEBUG_INPUT` env var

Every fuzz target respects a `DEBUG_INPUT=1` env var: instead of running
the fuzz body, it parses the input via `Arbitrary` and prints the
`Debug` representation, then exits. Useful for triaging a crash artifact:

```bash
DEBUG_INPUT=1 cargo +nightly fuzz run fuzz_element_ops \
  artifacts/fuzz_element_ops/crash-abc123
```

Or via the helper:

```bash
./fuzz.sh summarize fuzz_element_ops artifacts/fuzz_element_ops/crash-abc123
```

### `TRIAGE_CHEAT` env var (`fuzz_soundness_cheat` only)

When a soundness signal fires, distinguishing a real signal from a "dead
cheat" (cheated slot never read downstream) is important. Set
`TRIAGE_CHEAT=1` and pass a crash input file; the target will simulate
the op stream, track the cheated index, and report how many downstream
ops actually read it:

```bash
TRIAGE_CHEAT=1 cargo +nightly fuzz run fuzz_soundness_cheat \
  artifacts/fuzz_soundness_cheat/crash-abc123
```

If the count is 0, the soundness signal is probably a dead-cheat false
positive. If it's high, the cheat propagated but downstream constraints
were insensitive to it — that's the real bug class.

## CI

Two workflows in `.github/workflows/`:

- **`rust.yml`** runs `cargo +nightly check --bins` from this directory
  on every PR. Catches bitrot in the fuzz crate without actually running
  libFuzzer. Cache key includes `Cargo.toml`, `fuzz_targets/**/*.rs`,
  and `bin/**/*.rs`.

- **`fuzz-cron.yml`** runs every target via matrix-parallel for 5 hours
  each, weekly on Sundays at 00:00 UTC. Corpus persists across runs via
  `actions/cache`. Crashes upload as workflow artifacts with 30-day
  retention. Manual trigger via the Actions tab `workflow_dispatch`
  with override knobs for `duration` and `use_dict`.

## Why several targets duplicate the same `Op` enum

The four `Vec<Op>`-style targets (`fuzz_element_ops`,
`fuzz_witness_coverage`, `fuzz_soundness_cheat`,
`fuzz_driver_metamorphic`) each have a copy of the same `Op` enum and
dispatch — roughly 200 lines of mechanical duplication per file.

This is deliberate. cargo-fuzz expects `[[bin]]`-style fuzz targets, and
sharing a `src/lib.rs` between fuzz targets adds friction with the
cargo-fuzz workflow and the patch-table mirroring this crate already
needs. The duplication is annotated in each file (`Identical dispatch
logic to fuzz_element_ops and fuzz_soundness_cheat`) so future edits
propagate the same change everywhere.

## Patch table

This crate stands as its own workspace root (`[workspace]` in
`Cargo.toml`), so the repo-root `[patch.crates-io]` doesn't propagate
in. The same overrides are mirrored here. When the root patch set
changes, mirror the change here too — otherwise the fuzz build
resolves different versions than the rest of the workspace and ABI-
mismatches at link time.

## Background reading

- **PR #559** — original fuzz framework (8 targets).
- **PR #708** — extended framework: witness-mutation soundness, driver
  metamorphic, coverage augmentation, algebraic identities, field-
  element dictionary, plus housekeeping (`AllocRaw`, expanded
  `special_value`, `-max_len`, weekly cron). This PR.
- Talks/papers referenced in the PR descriptions for technique
  attribution (Aztec BigField, Aztec Noir/Brillig, TU Vienna Circus,
  zksecurity "Towards Fuzzing Zero-Knowledge Proof Circuits").
