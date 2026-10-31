# A minimal fuse generalization for #288

This experiment starts at main commit
2ed70cf9ff883b61c01b9b12e28fabee4ead01d2 and addresses the duplication question in
[issue #288](https://github.com/tachyon-zcash/ragu/issues/288).

## The existing hierarchy

Current `Application::fuse` already coordinates both sides of the curve cycle.
It owns one native-field transcript and advances both sides through successive
commitment and challenge rounds. Its phase methods, such as `compute_s_prime`,
select each side's data and construct the bridges between them. Shared arithmetic
already lives in `internal::claims`, `internal::fold_revdot`, and `ragu_backend`.

That gives a useful hierarchy to extend:

```text
Application::fuse                 transcript and phase order
  compute_s_prime                side selection and bridge commitments
    SPrime<HostCurve>::compute    registry restrictions and commitments
    SPrime<NestedCurve>::compute  the same computation in the other field
```

The last two calls are the change demonstrated here. Later phases need their
own assessment of which computations have the same inputs and meaning.

## The working change

The Rust change is confined to `crates/ragu_pcd/src/fuse/_03_s_prime.rs`:

1. Replace the two copies of the s-prime data structure with `SPrime<G, R>`,
   where `G: Affine` determines the commitment curve and `G::Scalar` determines
   the polynomial field.
2. Keep `NativeSPrime<C, R>` and `NestedSPrime<C, R>` as aliases, so the later
   phases retain their existing signatures and field access.
3. Move the duplicated registry restriction and batched commitment computation
   into `SPrime::compute<B>`. Both instantiations use the selected backend.

The two calls differ in their supplied values:

| Input | Native | Nested |
| --- | --- | --- |
| Curve | `C::HostCurve` | `C::NestedCurve` |
| Polynomial field | `C::CircuitField` | `C::ScalarField` |
| Registry | native registry at `w` | nested registry at lifted `w` |
| Child evaluation points | child `x` values | lifted child `x` values |
| Generators | host generators | nested generators |

The generic computation receives evaluation points already in its scalar field.
The phase method performs the nested challenge conversion, then commits the
native points stage and the s-prime bridge in their existing order. The helper
uses static dispatch and needs neither a transcript nor an RNG.

## Where specialization belongs

`Application::fuse` remains the coordinator. A whole-side `fuse_curve_side`
method would need to yield at the shared transcript's commitment/challenge
boundaries: neither side can independently run its complete pipeline first.
An orchestration interface would therefore need to express phases and their
dependencies.

The existing code also has concrete asymmetries. Native `A` tracks a decomposition
to obtain its commitment from child commitments; nested `A` commits the folded
polynomial directly. Native circuits replay the transcript and bind nested
challenges. Bridges encode points across the fields, and the native and nested
claim sets have different layouts. These belong in their respective phase
methods and circuit modules.

For this first step, `Affine` and `Backend` express everything the common
computation needs. A private phase-level trait becomes useful when another
orchestration path actually needs to select between implementations. The next
small extraction to assess is the registry-at-`y` computation in
`_04_inner_error.rs`, with its challenge conversion and stage witnesses kept in
the phase method.

## Validation

The intended invariant is identical registry restrictions and commitments,
backend batching, challenge order, and RNG consumption. Existing nontrivial
recursive proving/compression tests, profile tests, and backend-equivalence tests
exercise the changed path. Their results are finite regression evidence. This
experiment generalizes one phase's computation and data; a complete
interchangeable side-fuser API would need additional work.

Validation completed with Rust 1.97.1:

- Library check: passed.
- Clippy with warnings denied: passed.
- Formatting with the repository's pinned nightly: passed.
- Nontrivial recursive proving/compression and profile integration tests:
  2 passed, 0 failed.
- Backend-equivalence suite: 19 passed, 0 failed, 0 ignored. The environment set
  `PROPTEST_CASES=2`, `PROPTEST_RNG_SEED=288`, and `RAYON_NUM_THREADS=4`.

Run from the worktree root:

```sh
cargo check -p ragu_pcd --lib --locked --offline
cargo clippy -p ragu_pcd --lib --locked --offline -- -D warnings
cargo +nightly-2026-05-23 fmt --all -- --config-path rustfmt.nightly.toml --check
RAYON_NUM_THREADS=4 cargo test --release -p ragu_pcd --locked --offline \
  --features multicore --test nontrivial --test profiles -- --test-threads=1
PROPTEST_CASES=2 PROPTEST_RNG_SEED=288 RAYON_NUM_THREADS=4 \
  cargo test --release -p ragu_pcd --locked --offline --features multicore \
  --lib backend_equivalence:: -- --test-threads=1
```
