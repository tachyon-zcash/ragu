# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Proof compression: `Application::compress`, `Application::verify_compressed`,
  `CompressedProof`, `CompressedPcd`, and the public `ragu_pcd::ipa` module.
- `Pcd::{data, proof, into_parts}` accessors.
- Online polynomial oracles: every proof stores `NUM_ONLINE_POLYNOMIALS`
  polynomials, a parameter of the protocol rather than of the header type; a
  header lists the kinds of polynomial its proofs carry, unit types
  implementing `OnlinePoly` or `Padding`, as `Header::OnlinePolyCommit`; a
  step prepares its output proof's through `Step::prepare` before its
  challenge is drawn, by kind, the constant one where it prepares nothing,
  and `Step::witness` opens its input or output proofs' polynomials by kind
  through
  `step::Oracles::{left, right, output}` at the challenge or at any wire,
  while `Oracles::staged` supplies the constraint-bound staged values. A slot
  a header leaves to padding cannot be opened, and an output slot a step leaves unopened is held
  to the constant one after its circuit. Ragu
  proves the openings in the step's own batch. What a slot means is the
  application's convention for the header, constrained by the producing
  steps' circuits. `Pcd::polynomials` reads a proof's polynomials back.
- Staged values: `Step::NUM_STAGED` and the values `Step::prepare` stages
  supply the values a step's checks at the challenge read but no header
  field contains. Ragu commits them in an application stage before the
  challenge; `Oracles::staged` hands them to `Step::witness`. A check at
  the challenge must read only values fixed before it. See the `ragu_pcd`
  changelog.
- Bridge hash: `Oracles::bridge_hash` gives a step the digest of its own last
  online commitment, and `Application::bridge_hash` computes it outside the
  circuit, for hash chains over polynomial commitments.

### Changed

- `Step::witness` takes the step's `Oracles` after the driver, and the
  application circuit's instance is prefixed by the challenge and the six
  online openings, followed by the bridge hash. Every proof carries two more
  online polynomials, the application stage and the bridge-hash stage, and
  their commitments; the native and nested walks grow by two and three
  steps (23 to 25, 26 to 29), and every step circuit reserves
  `ceil(n / 2)` gates for the largest `Step::NUM_STAGED` registered.
- For the Standard profile, the largest `HEADER_SIZE` the production rank
  `R<13>` fits drops from 103 to 96 elements: the challenge binders load the
  preamble, query and eval stages, which carry the online openings, the application stage and the
  children's bridge hashes. At 96 the largest binder uses all 2048 gates; a
  larger header fails `ApplicationBuilder::finalize` with
  `GateBoundExceeded`. Profiles with extensions can have a lower limit.
- Registry tags are supplied by the application from a randomness beacon;
  `ApplicationBuilder::finalize` requires them unless the test-only
  `insecure-test-registry-tag` feature is enabled.
- The PCD transcript tag is `ragu-pcd-v1`; proofs made under the placeholder
  tag do not verify. Compression has its own tag, `ragu-ipa-v1`.
- `ApplicationBuilder` and `Application` take a fourth type parameter
  `B: SelectableBackend`, defaulting to `ragu_backend::ReferenceBackend`.
- Random-number bounds use `rand 0.10`'s `CryptoRng` instead of
  `CryptoRngCore` on `seed`, `fuse`, `rerandomize` and `verify`.
- Header suffix `2` is reserved for the internal `Dummy` header; application
  suffixes begin at `3`.
- The base proof is built once in `finalize`; `seed` is an ordinary step
  against it. The bootstrap and decompression steps hold their output
  header's polynomial slots to the constant one, so the unit header and a
  decompressed header carry padding a prover cannot choose.

### Removed

- The in-tree arithmetic crates `ragu_arithmetic` and `ragu_pasta`. Fields,
  curves, FFTs, MSMs and the Poseidon permutation now come from Udon in Zakura
  Common (`zakura-udon`); baked Pasta parameters from `zakura-bento`.
- The `legacy-deps`, `modern-deps` and `native-msm` features.

### Fixed

- The mock verifier rejects proofs whose header suffix does not match the
  registered output for their application step.

### Migrating from the in-tree arithmetic crates

| Before | After |
| --- | --- |
| `ragu_arithmetic::Cycle`, `ragu_arithmetic::PoseidonPermutation` | `ragu_core::Cycle`, `ragu_core::PoseidonPermutation` |
| `ragu_pasta::{Pasta, PoseidonFp, PoseidonFq}` | `ragu_core::pasta::{Pasta, PoseidonFp, PoseidonFq}` |
| `pasta_curves::{Fp, Fq, Ep, Eq, EpAffine, EqAffine}` | `ragu_core::pasta::{Fp, Fq, Ep, Eq, EpAffine, EqAffine}` (Udon types) |
| `ragu_pasta::baked` (feature `ragu_pasta/baked`) | `ragu_pcd::pasta::baked()` (feature `ragu_pcd/baked`) |
| `ff::PrimeField`, `group::prime::PrimeCurveAffine` bounds | `udon::field::Field`, `udon::curve::Affine` |
| `rand_core::CryptoRngCore` | `rand::CryptoRng` |

Downstream crates that still depend on `zakura-pasta-curves` directly hold a
different `Fp` type from Ragu's; switch to the `ragu_core::pasta` aliases.

## [0.0.0] - 2025-03-15

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu-0.0.0
