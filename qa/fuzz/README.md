# `ragu_testing-fuzz`

cargo-fuzz harness for the Ragu project. 24 fuzz targets + 1 auxiliary
dictionary-extractor tool. Standalone workspace (the `[workspace]` table in
`Cargo.toml` makes this crate its own root) so nightly + libfuzzer flags
don't leak into the rest of the repo.

## Quick start

```bash
# Run every target for 30 seconds, sequentially. ASAN off by default
# (~70% throughput win on simulator-heavy targets).
./fuzz.sh

# Custom duration (seconds).
./fuzz.sh 300

# Parallel run (CPU fans will spin).
./fuzz.sh 60 -j

# With the field-element constant dictionary loaded.
DICT=1 ./fuzz.sh

# Re-enable AddressSanitizer for memory-bug coverage (slower, but
# required for triaging crash artifacts properly).
ASAN=1 ./fuzz.sh

# Run a single target directly.
cargo +nightly fuzz run fuzz_element_ops -- -max_total_time=60

# Replay all committed crash regressions once each.
./fuzz.sh regress

# Minimize each accumulated corpus in place.
./fuzz.sh cmin

# Generate per-target reports and a union coverage report locally.
./fuzz.sh coverage
```

## Targets

### Op-stream targets (shared substrate)

Decode the fuzzer's raw bytes into a program over a stack of
`Element`/`Boolean` gadget calls, via the shared
[`ragu_testing_fuzz::substrate`] op grammar. All consume the same decoder,
driver-generic synthesis dispatch, and (where applicable) native shadow —
see the "Shared substrate" note at the bottom.

[`ragu_testing_fuzz::substrate`]: src/substrate.rs

| Target | What it catches |
|---|---|
| `fuzz_element_ops` | Completeness — random gadget compositions must not crash and must produce internally-consistent witnesses. The canonical robustness consumer of the substrate. |
| `fuzz_witness_coverage` | Same as `fuzz_element_ops` plus a post-run witness-state hash spread across coverage branches. Biases the fuzzer toward distinct internal witness states. Opt-in POC (~28% throughput cost). |
| `fuzz_witness_cheat` | Mid-stream replaces an element on the stack with a fresh allocation of a different value (via the substrate's pre-op synthesis hook), then compares fingerprints against the honest run. A Simulator-robustness fuzzer; the constraint-side soundness oracles live in `fuzz_witness_pinning` / `fuzz_circuit_cheat` / `fuzz_advice_patcher` (below). |
| `fuzz_driver_metamorphic` | Differential — runs the same generated program through both `Simulator` and `Emulator<Wired<Fp>>`; wire values must match. Tests the model-vs-real-driver invariant. |

### Soundness / patcher targets

Constraint-side under-constraint oracles over generated
[`ragu_testing_fuzz::substrate`] circuits (issues #728, #793, #796). Each starts
from a satisfying witness, introduces a prover-style cheat, and demands the
constraint system reject it.

| Target | What it catches |
|---|---|
| `fuzz_witness_pinning` | Mutates one occupied coefficient of the assembled trace polynomial and demands the revdot identity reject it. The generated circuit is made fully-pinned (an `Anchor` per element) so every live coefficient is constrained — a survivor means the constraint system fails to pin that wire. |
| `fuzz_circuit_cheat` | Mutates one witness input, re-traces, and asserts the assembled constraint-identity verdict matches an independent native oracle (with a Simulator cross-check). The operational patcher whose "repair" is re-tracing. |
| `fuzz_advice_patcher` | Captures the emitted constraint graph through a recording driver, mutates free advice wires, and **repairs through the captured constraints** (not gadget logic) before comparing to the native shadow — catches under-constrained *advice* that re-trace-based repair masks. `PATCHER_SELFTEST=1` proves the oracle fires on a planted bug. |
| `fuzz_completeness` | Runs arbitrary witnesses through anchorless, value-infallible generated circuits; every such witness must be accepted, so rejection is an over-constraint signal independent of the patcher's bounded repair search. |

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
| `fuzz_sxy_agreement` | `s(X, Y)` registry consistency (`wxy == wx.eval(y) == wy.eval(x)`) over arbitrary generated circuits. Caught `Key::new(0)` divide-by-zero. |

### Verifier robustness

| Target | What it catches |
|---|---|
| `fuzz_verify_reject` | Corrupt proof bytes via `fuzz_utils::Corruption`, assert verifier rejects. Uses `test_trivial_proof()` — tests verifier hardening, not soundness in the paper's sense. |

### Circuit-pipeline targets

Higher-layer targets that drive full `Circuit::witness` → `trace::eval` →
`Registry::assemble_with_alpha` pipelines rather than calling gadgets
directly through `Simulator`. These close issue #709's Layer 1, 2, and 4
gaps.

| Target | What it catches |
|---|---|
| `fuzz_circuit_witness` | `Circuit::witness` pipeline correctness. The `Generated` arm drives arbitrary substrate programs against the native shadow; bespoke `BoolCircuit`, `PointCircuit`, `RoutineCircuit` (Routine via `Prediction::Unknown`), and `KnownRoutineCircuit` (`Prediction::Known`) arms cover gadget families the grammar does not generate (points, custom routines). Asserts Simulator output matches the native spec, `trace::eval` agrees with `Simulator` on accept/reject, and the `assemble_with_alpha` α-injection contract. |
| `fuzz_circuit_revdot_identity` | The canonical algebraic identity from `tests/mod.rs:158-187` — `r.revdot(r + r.dilate(z) + s(X,y) + t(X,z)) == circuit.ky(instance, y)` — over arbitrary generated circuits (accept direction; the rejection direction is `fuzz_witness_pinning`). Uses the public `Registry::circuit_y` for `s(X, y)`. |
| `fuzz_staging` | Full staging-system coverage: **Invariant A** (`rx.revdot(own_mask) == 0` per stage), **Invariant B** (combined revdot identity through `MultiStage::witness`), **final_mask** check on the bare assembled trace, plus structural **cross-mask** (rx coefficient positions stay within the stage's declared range — robust against adversarial witness/y) and `skip_gates`/`num_gates` hand-coded pins. Three variants exercise `Single2W`, `Single4W`, and `Chain2x4` (parent → child, exercising `skip_gates` recursion). |

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

### `TRIAGE_CHEAT` env var (`fuzz_witness_cheat` only)

When a soundness signal fires, distinguishing a real signal from a "dead
cheat" (cheated slot never read downstream) is important. Set
`TRIAGE_CHEAT=1` and pass a crash input file; the target will simulate
the op stream, track the cheated index, and report how many downstream
ops actually read it:

```bash
TRIAGE_CHEAT=1 cargo +nightly fuzz run fuzz_witness_cheat \
  artifacts/fuzz_witness_cheat/crash-abc123
```

If the count is 0, the soundness signal is probably a dead-cheat false
positive. If it's high, the cheat propagated but downstream constraints
were insensitive to it — that's the real bug class.

## CI

Three workflows in `.github/workflows/`:

- **`rust.yml`** runs `cargo test --lib` and `cargo check --bins` from this
  directory on every PR. This executes the substrate self-tests (the patcher
  engine's own tests, including its planted-bug selftest, run with the
  workspace in `ragu_testing`), then catches bitrot in every target without
  running libFuzzer. Cache keys include `Cargo.toml`, `fuzz_targets/**/*.rs`,
  and `bin/**/*.rs`.

- **`fuzz-cron.yml`** runs every target via matrix-parallel for 5 hours
  each on Sundays, Wednesdays, and Fridays at 00:00 UTC. Each target
  restores its latest corpus, replays committed crash regressions, extends
  the corpus, and saves it even when fuzzing finds a crash. Crash artifacts
  have 30-day retention. Manual runs can override `duration` and `use_dict`.

- **`fuzz-coverage.yml`** runs every Monday at 06:00 UTC, after the Sunday
  fuzz run. Each matrix job restores its target's latest accumulated corpus,
  includes any committed seeds, generates an `llvm-cov` per-file report,
  writes the headline totals to the job summary, and uploads the full report
  with 90-day retention.

## Shared substrate

The op-stream, soundness/patcher, and generated-circuit targets all build
on one shared module, [`ragu_testing_fuzz::substrate`], rather than the
per-target `Op` enum each used to copy. The substrate is layered so each
target consumes only what it needs:

1. **AST** — a unified `Op` grammar with per-op capability flags and
   `OpSet` masks; each target carves its vocabulary out of the union.
2. **Decoding** — a total byte decoder (for libFuzzer) with decode-time
   clamping, so the wire format and corpora are shared across targets,
   plus `proptest` strategies over the same AST for in-tree property tests
   under plain `cargo test`.
3. **Synthesis** — one driver-generic interpreter (run under `Simulator`,
   `Emulator`, and the patcher's recording driver).
4. **Native shadow** — an `Fp` evaluator mirroring each op's true
   semantics, for differential oracles.
5. **Circuit wrapper** — a generated program as a registerable `Circuit`
   (`ProgramCircuit`), with satisfying-witness `steer`ing, for the
   constraint-level oracles.

Living in this standalone fuzz crate's library lets the same grammar feed
both its libFuzzer binaries and deterministic `cargo test --lib` proptests.

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
  `special_value`, `-max_len`, weekly cron).
- **PR #794** (issues #728/#793/#796) — the patcher technique
  (`fuzz_witness_pinning`, `fuzz_circuit_cheat`, `fuzz_advice_patcher`)
  and the shared `ragu_testing_fuzz::substrate`: all op-stream targets migrated
  onto it, and the constraint-level targets generalized from the two fixed
  dummy circuits to arbitrary generated ones.
- Talks/papers referenced in the PR descriptions for technique
  attribution (Aztec BigField, Aztec Noir/Brillig, TU Vienna Circus,
  zksecurity "Towards Fuzzing Zero-Knowledge Proof Circuits").
