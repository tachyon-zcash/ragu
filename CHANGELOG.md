# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Proof compression: `Application::compress`, `Application::verify_compressed`,
  `CompressedProof`, `CompressedPcd`, and the public `ragu_pcd::ipa` module.
- `Pcd::{data, proof, into_parts}` accessors.

### Changed

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
  against it.

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
