# PCD implementation map

This map is for reading the crate and for reviewing it. Each subprotocol lives
in one directory with its prover and verifier side by side, and the definitions
they share live below them in `protocol/`. These are private implementation
boundaries; the public API is unchanged.

| Directory | Holds |
| --- | --- |
| `header/`, `step/`, `profile/`, `pasta/` | What a proof claims, the steps that produce it, the proof shapes, the parameters. |
| `proof/` | Both proof forms: `Proof` and `Pcd`, `CompressedProof` and `CompressedPcd`. |
| `protocol/` | The definitions everything below shares: each side's canonical sizes and orders (`native/`, `nested/`), the stages a proof commits to (`native/stages/`, `nested/stages/`), revdot claims and their folding (`revdot/`), gadgets, and the transcript. |
| `ipa/` | The inner product argument: shared definitions in `mod.rs`, `prover.rs`, `verifier.rs`. |
| `fuse/` | The split-accumulation scheme: `prover/` constructs a proof from two children, `circuits/` constrain the reduction recursively, and `decider.rs` is the reference decider. |
| `compress/` | The decider restated over commitments, ending in one IPA opening per curve: shared definitions in each `mod.rs`, the two roles in `prover.rs` and `verifier.rs` at every level. |
| `wire/` | Byte encodings of both proof forms, and their decoding from untrusted input. |
| `test_support/` | Test-only instrumentation and fixtures. |

## Reading order

1. `lib.rs` and `application.rs`, then the entry points below.
2. `header/`, `step/` and `profile/`: what a proof claims and the shapes it takes.
3. `protocol/`, bottom-up. It imports nothing from `fuse/`, `compress/` or
   `wire/`; only its inline unit tests use `test_support/`.
4. `fuse/circuits/`: the constraints the recursive verifier enforces.
5. `fuse/decider.rs`: the plainest statement of what an accumulated proof must
   satisfy. It is a test oracle, compiled under `test-utils`.
6. The verifier side of `compress/` and `ipa/verifier.rs`: the production
   decider.
7. `wire/`: decoding untrusted bytes.

Soundness depends on everything except prover code: `fuse/prover/`, the
`prover.rs` files under `compress/` and `ipa/`, and `multicore.rs`, together with
`test_support/` and the tests. Apart from `ipa/mod.rs` re-exporting
`create_proof` for the public API, no module outside those prover paths
imports from them, so a soundness review can set them aside; they matter for
completeness and zero knowledge.

## Entry points

| Entry point | Implementation | Responsibility |
| --- | --- | --- |
| `ApplicationBuilder::finalize` | `application.rs` | Register the steps and internal circuits, derive the registry tags, and build or install the bootstrap proof. |
| `Application::seed` | `fuse/prover/seed.rs` | Fuse a leaf step against the bootstrap proof as both children. |
| `Application::rerandomize` | `fuse/prover/rerandomize.rs` | Fuse a proof through the internal rerandomization step. |
| `Application::fuse` | `fuse/prover/mod.rs`, `fuse/prover/orchestrator.rs` | Prepare the application step, then construct one accumulator proof from both children. |
| Recursive verification | `fuse/circuits/{native,nested}/` | Constrain the reduction of the children's claims into the parent's accumulated obligations. |
| `Application::compress` | `compress/prover.rs`, `compress/*/prover.rs` | Reduce accumulated obligations to polynomial openings and produce IPA proofs. |
| `Application::verify_compressed` | `compress/verifier.rs`, `compress/*/verifier.rs` | Decide final acceptance, including admission, transcript, reductions, batching, and both IPA openings. |
| IPA opening verification | `ipa/verifier.rs` | Verify an opening under the fixed polynomial-commitment parameters. |
| `Application::verify_uncompressed` | `fuse/decider.rs` | Check the accumulated obligations directly from the polynomials as a test oracle. |

## Following a fuse

`fuse/prover/orchestrator.rs` owns the chronological transcript schedule. It constructs
native and nested phase data, commits the bridge stages, absorbs their commitments,
and derives the challenges used by the next phase. Neither curve side runs an
independent complete fuse operation.

`fuse/prover/side.rs` defines the private `CurveSideFuse` interface. The providers
in `native/side.rs` and `nested/side.rs` select the field, commitment curve,
registry, challenge conversion, and claim layout. Shared phases construct the
registry restrictions and claims and perform both polynomial folding layers.
The interface has no transcript or RNG: the coordinator fixes when each phase
runs, and the concrete stage/bridge helpers commit its results before advancing
the transcript. Dispatch is static; no public custom-fuser registration API is
introduced.

The native provider retains the tracked commitment decomposition of its folded
`a` polynomial; the nested provider folds ordinary polynomials. Native
commitment MSMs, nested direct commitments, stage layouts, and circuit tracing
remain side-specific. The application step's preparation stays before `w`, and
the coordinator executes its circuit after `w`, at the same point in the
schedule.

Native and nested name the arithmetic context: `CircuitField` and `ScalarField`.
The commitment walks cross the cycle: a circuit operates on points whose base
field is its arithmetic field. A side's name does not identify which side's
polynomial commitments it verifies.

The side-local polynomial and witness computations live in
`fuse/prover/{native,nested}/`; cross-side stage construction lives in `bridge/`.
`trace/` executes the recursive verifier circuits and assembles their witness
polynomials. Constraint definitions live in `fuse/circuits/`; the stage
allocations they read live in `protocol/{native,nested}/stages/`, because the
prover, the circuits and the compressed instance all use them. A `witness`
method written against a generic `Driver` serves both tracing and constraint
synthesis; it is one definition of the stage, not a second implementation of
the relation.

For each obligation, follow its computation, stage commitment, transcript
challenge, enforcing circuit, parent binding, and terminal check. For example,
the inner-error prover computes quotient coefficients; the inner-error stage
allocates them; the collapse circuit checks the fold identity. Prover assertions
and cached values do not substitute for the constraints and bindings the verifier
checks. `unified.assert_complete()` remains a prover-time coverage assertion.

## Shared definitions

`proof/` holds both proof forms: `Proof` and `Pcd` in `uncompressed.rs`,
`CompressedProof` and `CompressedPcd` in `compressed.rs`; `wire/` holds their byte
encodings. `protocol/` holds each side's canonical component and claim orders,
the stages, the revdot claims and their folding, gadgets, and the transcript;
the compressed proof's instance is in `compress/instance/`. Prover extraction from a full proof and verifier
acceptance checks are separate implementations of operations on those types.
Stage gadgets are reused by tracing and constraint synthesis, so witness
generation agrees with the circuit relation.

`profile/` declares the proof shapes: the `Profile` trait and the built-in profiles
in `mod.rs`, extensions and the registry slots their hooks fill in `extension.rs`,
and the walk sizes in `shape.rs`.

The public `ipa` module (`ipa/mod.rs`) is the argument's public API: the shared
message, parameter, transcript, and MSM definitions live beside it in `ipa/`,
`create_proof` in `ipa/prover.rs`, and `verify_proof` in `ipa/verifier.rs`.

## Compatibility checks

Run the existing fixtures in check mode, without regenerating expected artifacts:

```sh
RAGU_FIXTURES=check cargo test --locked --release -p ragu_pcd --all-features --lib proof::fuse_fixture_tests -- --include-ignored
```

The prover cases compare proof-field digests, compressed bytes, and RNG tapes.
The verifier cases compare recorded transcript/MSM fingerprints and rejection
behavior. Passing both is bounded compatibility evidence for the pinned cases;
it does not prove equivalence for every input, profile, or feature configuration.
