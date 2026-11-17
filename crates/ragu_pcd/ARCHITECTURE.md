# PCD implementation map

The source tree separates proof construction, recursive verification constraints,
and terminal verification. Shared representations and algebra live in `protocol/`.
These are private implementation boundaries; the public API is unchanged.

| Entry point | Implementation | Responsibility |
| --- | --- | --- |
| `Application::fuse` | `prover/fuse/mod.rs` | Construct one accumulator proof from two children and an application step. |
| Recursive verification | `verifier/recursive/{native,nested}/` | Constrain the reduction of the children's claims into the parent's accumulated obligations. |
| `Application::compress` | `prover/compress/` | Reduce accumulated obligations to polynomial openings and produce IPA proofs. |
| `Application::verify_compressed` | `verifier/decider/compressed.rs` | Decide final acceptance, including admission, transcript, reductions, batching, and both IPA openings. |
| IPA opening verification | `verifier/ipa/` | Verify an opening under the fixed polynomial-commitment parameters. |
| `Application::verify_uncompressed` | `test_support/decider_uncompressed.rs` | Check the accumulated obligations directly from the polynomials as a test oracle. |

## Following a fuse

`prover/fuse/mod.rs` owns the chronological transcript schedule. It constructs
native and nested phase data, commits the bridge stages, absorbs their commitments,
and derives the challenges used by the next phase. Neither curve side runs an
independent complete fuse operation.

Native and nested name the arithmetic context: `CircuitField` and `ScalarField`.
The commitment walks cross the cycle: a circuit operates on points whose base
field is its arithmetic field. A side's name does not identify which side's
polynomial commitments it verifies.

The side-local polynomial and witness computations live in
`prover/fuse/{native,nested}/`; cross-side stage construction lives in `bridge/`.
`trace/` executes the recursive verifier circuits and assembles their witness
polynomials. Constraint definitions and stage allocations live in
`verifier/recursive/`. A `witness` method written against a generic `Driver` can
serve tracing and constraint synthesis; its directory identifies the verification
relation it defines, not a second implementation of that relation.

For each obligation, follow its computation, stage commitment, transcript
challenge, enforcing circuit, parent binding, and terminal check. For example,
the inner-error prover computes quotient coefficients; the inner-error stage
allocates them; the collapse circuit checks the fold identity. Prover assertions
and cached values do not substitute for the constraints and bindings the verifier
checks. `unified.assert_complete()` remains a prover-time coverage assertion.

## Shared definitions

`protocol/` holds proof messages, instances, canonical component and claim orders,
transcripts, and shared algebra. Prover extraction from a full proof and verifier
acceptance checks are separate implementations of operations on those types.
Stage gadgets are reused by tracing and constraint synthesis, so witness
generation agrees with the circuit relation.

The public `ipa` module is a compatibility facade. Its prover and verifier
implementations are under their respective role directories; message, parameter,
transcript, and MSM definitions remain shared.

## Compatibility checks

Run the existing fixtures in check mode, without regenerating expected artifacts:

```sh
RAGU_FIXTURES=check cargo test --locked --release -p ragu_pcd --all-features --lib proof::fuse_fixture_tests -- --include-ignored
```

The prover cases compare proof-field digests, compressed bytes, and RNG tapes.
The verifier cases compare recorded transcript/MSM fingerprints and rejection
behavior. Passing both is bounded compatibility evidence for the pinned cases;
it does not prove equivalence for every input, profile, or feature configuration.
