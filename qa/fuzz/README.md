# `ragu_testing-fuzz`

cargo-fuzz harness for the Ragu project. 28 fuzz targets + 2 auxiliary tools
(dictionary extraction and no-execution source linting). Standalone workspace (the `[workspace]` table in
`Cargo.toml` makes this crate its own root) so nightly + libfuzzer flags
don't leak into the rest of the repo.

The target list is written down in four places — `Cargo.toml`'s `[[bin]]`
sections, `fuzz.sh`'s `TARGETS`, and the matrices of `fuzz-cron.yml` and
`fuzz-coverage.yml`. `./fuzz.sh census` checks they agree; `rust.yml` runs it
on every pull request, so a target cannot be added and then quietly never
scheduled.

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

# Generate a local (gitignored) seed set to warm up a run.
./fuzz.sh seeds                    # every target, 30s each
./fuzz.sh seeds fuzz_element_ops 120

# Check the four target lists agree.
./fuzz.sh census

# Parse production circuit/gadget source without executing it.
./fuzz.sh source-lint
```

`+nightly` is whatever rustup calls nightly on the machine, which is
regularly older than the workspace MSRV — `cargo fuzz` then fails with
`requires rustc 1.97` rather than anything about fuzzing. Pin it to the
toolchain CI uses (from `.github/actions/rust-nightly-setup/action.yml`):

```bash
NIGHTLY=+nightly-2026-05-23 ./fuzz.sh seeds
```

## Circuit source lint

`circuit_lint` parses production Rust with `syn` without typechecking,
executing the code, synthesizing constraints, or invoking witness closures.
It reports narrowly scoped circuit-construction hazards:

| Code | Level | Finding |
|---|---|---|
| `RAGU001` | error | Discarded fallible driver or gadget result |
| `RAGU002` | error | Witness-assignment closure mutates captured state |
| `RAGU003` | error | Witness-observable state controls emitted operations |
| `RAGU004` | advisory | Driver-produced constraint value is discarded |
| `RAGU005` | advisory | Conditional arms emit different operation shapes |
| `RAGU006` | error | Reviewed baseline entry is stale |

Errors cannot be suppressed. `source-lint-baseline.txt` records only reviewed
`RAGU004`/`RAGU005` exceptions, keyed by exact rule, source path, line, and
rationale; moving or removing a finding makes its entry stale and fails the
gate. PR/push CI and the scheduled fuzz workflow run the same analyzer, with
the scheduled scan gating both the regular campaign and Saturday hardening.

This syntax pass cannot infer an unstated intended constraint and does not
expand macros or provide type-resolved HIR/MIR def-use analysis. Witness-free
source-shape comparison, synthesized-graph connectivity/rank checks, patcher
fuzzing, and fresh-witness replay remain complementary.

## Corpus durability

The fuzzing itself was never the broken part. `fuzz-cron.yml` runs every
target for five hours, three times a week, and libFuzzer generates its own
inputs — this substrate's decoder is *total*, so every byte slice is a valid
program and a cold start costs nothing but a little depth.

What broke was everything downstream of keeping the corpus. `corpus/` lived
only in the GitHub Actions cache, which evicts least-recently-used entries
once the repository hits its storage limit; this harness writes a fresh
run-scoped entry per target per campaign, three campaigns a week, so corpora
churned through that budget and disappeared. Two consequences, one of them
invisible:

- Every campaign restarted from a cold corpus, so runs never accumulated
  depth. Five hours of shallow fuzzing, repeatedly.
- `fuzz-coverage` had nothing to replay, reported "No corpus or seed inputs
  found ... skipping coverage", and **exited green**. Weeks of coverage
  reports were empty and looked passing — which is what hid the first point.

Two things now stand between that and a repeat:

- `fuzz-cron.yml` minimizes its corpus and uploads it as a **90-day
  artifact**. Artifacts are not subject to cache eviction, and
  `fuzz-coverage.yml` falls back to the most recent campaign's artifact when
  the cache misses. This is the load-bearing fix: it restores both the
  accumulation and the measurement.
- `fuzz-coverage.yml` distinguishes the two reasons a target can have no
  inputs. One whose campaign artifact exists but restored empty is **broken**
  and fails the job. One that has never produced a corpus has simply not been
  fuzzed yet, and reports that rather than failing.

### Why no committed seeds

An earlier cut of this work committed a seed corpus per target. It was
dropped, and the reasoning is worth keeping:

- Seeds are for formats where random bytes never survive the parser. Here
  decoding is total, so libFuzzer bootstraps any target from nothing. Eight
  tiny inputs add nothing to a five-hour campaign.
- They are a standing maintenance tax. When a target's `Input` gains a field,
  old seed bytes decode into something else entirely — and stale seeds do not
  fail loudly, they just quietly mean something different.
- Inputs genuinely worth keeping in git already have a home:
  `regressions/<target>/`, which the cron replays before every campaign.

`./fuzz.sh seeds [target] [seconds]` still exists for warming up a local run;
`seeds/` is gitignored.

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
constraint system reject it. The no-execution front end is described in
[Circuit source lint](#circuit-source-lint).

| Target | What it catches |
|---|---|
| `fuzz_witness_pinning` | Mutates one occupied coefficient of the assembled trace polynomial and demands the revdot identity reject it. The generated circuit is made fully-pinned (an `Anchor` per element) so every live coefficient is constrained — a survivor means the constraint system fails to pin that wire. |
| `fuzz_circuit_cheat` | Mutates one witness input, re-traces, and asserts the assembled constraint-identity verdict matches an independent native oracle (with a Simulator cross-check). The operational patcher whose "repair" is re-tracing. |
| `fuzz_advice_patcher` | Captures the emitted constraint graph through a recording driver, mutates free advice wires, and **repairs through the captured constraints** (not gadget logic) before comparing to the native shadow — catches under-constrained *advice* that re-trace-based repair masks. `PATCHER_SELFTEST=1` proves the oracle fires on a planted bug. |
| `fuzz_internal_circuits` | The patcher aimed at the **production internal recursion circuits**. Captures all five native circuits and the nested endoscaling steps from real fuses at four points — the Bootstrap base case, leaves, nodes, and a lopsided tree — paid once in libFuzzer's `init`. Before mutation, witness-free source-shape linting must match concrete synthesis; connectivity rejects isolated/floating subgraphs; bounded component rank checks reject movable derived wires with explicit skipped coverage; and `forced_by` requires the declared outputs to be constrained. A `Prepared` probe then pins declared inputs, mutates other free advice, and repairs through captured constraints. Any moved output is replayed through fresh synthesis and becomes a soundness signal only if that synthesis accepts the candidate witness. |
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
| `fuzz_revdot` | Reverse-dot-product primitive, at a fuzzer-chosen field and rank (see [Field and rank dispatch](#field-and-rank-dispatch)). Rank is not incidental here: `View`'s segments are clamped against `R::n()` and `revdot` pairs coefficients against a reversal whose length is the rank's, so a disagreement that only shows up at `n = 2048` was previously unreachable. |
| `fuzz_fold_revdot` | RevDot folding. |
| `fuzz_sxy_agreement` | `s(X, Y)` registry consistency (`wxy == wx.eval(y) == wy.eval(x)`) over arbitrary generated circuits. Caught `Key::new(0)` divide-by-zero. |

### Verifier robustness

| Target | What it catches |
|---|---|
| `fuzz_verify_reject` | Corrupts an honest **leaf** proof through the `fuzzing::corrupt::Corruption` vocabulary — any challenge, any bridge commitment, any header element or length, the circuit id, or an individual coefficient of any native or nested polynomial — and asserts the verifier never accepts a corruption that bound it. The cheap, high-throughput half. |
| `fuzz_verify_reject_full` | The same vocabulary against **fused** proofs: a `Hash2` over two leaves and a `Merge2` over two of those, whose accumulators the leaf case leaves degenerate. |
| `fuzz_pcd_lifecycle` | The whole lifecycle per input: a fuzzer-chosen registry size and tree shape, seeded from fuzzer-chosen witnesses, verified at every level, optionally rerandomized, then corrupted and required to be rejected. Seconds per iteration — a randomized integration test libFuzzer steers. |

Not every corruption obliges the verifier to reject: a proof's polynomials are
blinded, and moving a coefficient no claim binds is not forgery. `Proof::corrupt`
returns a `Binding` saying which case it is, derived rather than guessed, and
only `MustReject` is asserted. `crates/ragu_pcd/tests/corruption.rs` pins that
classification against real proofs, so a wrong one fails there rather than five
hours into a cron run.

These targets used to corrupt Ragu's synthesized dummy proof. That fixture is
the placeholder the internal Bootstrap step consumes, and `verify` rejects it
outright — so "the verifier did not accept the corrupted proof" held *before*
the corruption, and every assertion passed vacuously. Every fixture is now
built with `seed`/`fuse` and checked to verify before anything is corrupted.

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
| `fuzz_registry` | Registry construction past one circuit at index zero: a fuzzer-chosen sequence of circuits across all four `RegistryBuilder` categories, at a fuzzer-chosen rank. Asserts `finalize` concatenates by category rather than call order (the ordering `InternalCircuitIndex::ALL` depends on), that `xy(x,y).eval(w)`, `wy`, `wx` and `wxy` agree across the IFFT and cached-Lagrange paths — the same relation `verify.rs` checks on `native_registry_xy_poly` — that `circuit_y(i,y).eval(x) == circuit_xy(i,x,y)` at every index including the zero-polynomial padding above the circuit count, and that `finalize` returns `CircuitBoundExceeded` exactly one circuit past `R::num_coeffs()`. |

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
  the corpus, and saves it even when fuzzing finds a crash. It then minimizes
  the corpus and uploads it as a 90-day artifact — the durable copy, immune to
  the cache eviction that used to take corpora away. Crash artifacts have
  30-day retention. Manual runs can override `duration` and `use_dict`.

  Its resource ceilings are written down rather than inherited from
  libFuzzer's defaults (`-rss_limit_mb=4096`, `-malloc_limit_mb=2048`,
  `-timeout=120`). They are deliberately loose: this campaign is hunting
  logic bugs, and `fuzz_internal_circuits` can legitimately spend seconds on
  one input.

- **`fuzz-cron.yml`'s `hardening` job** runs on Saturdays at 00:00 UTC, a
  separate day so it never contends with the campaign for runners. Every
  target runs under two flavors for 15 minutes each:

  | Flavor | Build | Looks for |
  |---|---|---|
  | `careful` | `--careful` (const-UB and init checks over the debug-assertion std, ASan on) | UB and uninitialized reads that plain ASan links past |
  | `exhaustion` | `-s none`, `-rss_limit_mb=1024 -malloc_limit_mb=512 -timeout=30 -max_len=16384` | OOM and hangs |

  `exhaustion` turns the sanitizer *off* on purpose: ASan's shadow mapping
  inflates RSS several-fold, so under it a real allocation blowup is
  indistinguishable from sanitizer overhead and a memory ceiling means
  nothing. TSan is absent because `qa/fuzz` never enables `multicore`, so no
  target runs rayon; MSan is absent because it needs every dependency
  instrumented to avoid false positives, and the pinned curve and arithmetic
  crates are not. The sweep reads the campaign's corpus but never writes it,
  so corpus lineage stays single-writer. Manual runs opt in with
  `run_hardening` and can override `hardening_duration`.

- **`fuzz-coverage.yml`** runs every Monday at 06:00 UTC, after the Sunday
  fuzz run. Each matrix job assembles its inputs from the corpus cache, the
  cron's corpus artifact when the cache missed. A target whose artifact
  exists but restored empty **fails**; one that has never been fuzzed reports
  that it has no data yet. It generates an `llvm-cov` per-file
  report and a machine-readable `--summary-only` export, writes the headline
  totals to the job summary, and uploads both with 90-day retention.

  A final `union` job merges every target's summary. It reports the per-file
  best-of across targets — a documented *lower bound* on the true union, since
  shipping the profile and instrumented binary a real merge needs would be
  hundreds of megabytes per target — lists the workspace files no target
  reaches at all, and compares each target against
  `coverage-baseline.json`. A drop of more than the baseline's `tolerance`
  (default 2 percentage points) fails the job. Coverage going down is not
  automatically a bug, but it should not happen without somebody deciding it
  is fine:

  ```bash
  # Download the run's coverage-* artifacts into ./summaries, then:
  python3 qa/fuzz/coverage_union.py \
    --summaries summaries --baseline qa/fuzz/coverage-baseline.json --update
  ```

## Field and rank dispatch

Most of this harness was written against `Fp` and `TestRank`, for a good
reason: that is the cheap pair. `TestRank` is `R<7>` — `n = 32` gates, 128
coefficients — where `ProductionRank` is `R<13>`, `n = 2048` and 8192
coefficients, sixty-four times the vector length. Running every input at
production rank would cost most of the executions per second, and execution
count is what finds bugs.

The price was that the rank that actually ships, and the second field of the
cycle, were only exercised where a target named them outright: at audit time
**no** target used `ProductionRank` and only six mentioned `Fq`.

[`src/params.rs`](src/params.rs) makes both a fuzzer choice.
`with_rank!(choice, |R| { .. })` and `with_field!(choice, |F| { .. })`
monomorphize their body once per arm — necessary because `Rank` is a sealed
trait over a const-generic and the field is a compile-time type, so neither
can be picked by value at run time. A target opts in by wrapping its body and
adding a `RankChoice` / `FieldChoice` to its `Input`.

The rank draw is skewed: one byte in a sixteen-wide mid-range band selects
production. The band placement is deliberate and was learned the hard way —
the obvious `int_in_range(0..=15)? == 0` selected production rank on **46%**
of inputs rather than 6%, because libFuzzer's mutators emit `0x00` far more
often than chance. `0x00` and `0xff` are both common mutator output, so the
band avoids both. Even so the ratio is only nominal: a live fuzzer's byte
distribution is whatever coverage feedback drives it to. Measure it with the
target's own stats hook rather than assuming — `REGISTRY_STATS=1` on
`fuzz_registry` is the worked example.

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
