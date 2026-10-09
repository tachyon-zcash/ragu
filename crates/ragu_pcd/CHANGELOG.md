# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `ApplicationBuilder::register_bundle` to register two application
  `Step`s together in one proof. Each step binds the
  complete ordered tuple of circuit IDs as public inputs, checked by recursive
  and terminal verification.
- Added typed connections for bundle steps through `Step::Shared`.
  Both steps return the same gadget type; Ragu derives its layout,
  automatically binds every corresponding wire, and commits the shared values
  once per proof. Smaller bundles are padded internally, and staging and
  bonding claims enforce the connection in both verifier paths.
- Added sealed, static computational-backend selection between Ragu's reference
  and accelerated implementations, defaulting to
  `ragu_backend::ReferenceBackend`.
- Added `SelectableBackend::Verifier`, the backend whose kernels
  `Application::verify` consults, and support for
  `ragu_acceleration::AcceleratedProver`, which accelerates proving while
  verifying with the reference kernels.
- Added `RegistryTags::from_beacon` and `ApplicationBuilder::with_registry_tags`
  to supply both registry tags before finalization. Production callers must
  choose the values after fixing and publicly committing the complete application.

### Changed

- `Step` declares a `Shared` gadget type and returns that gadget from
  `witness`. Standalone steps declare `Shared = ()` and return `()`;
  `register`, `seed`, and `fuse` require this empty connection.
- Every proof carries two application circuits and the shared stage.
  `register(A)` registers the repeated bundle `(A, A)`: `seed` and `fuse` take
  the step alone and fill both slots with its one claim. Bundles are proved
  with `seed_bundle` and `fuse_bundle`, which take the steps' witnesses;
  proving requires both registered steps with matching headers and
  shared-stage values.
- Shared stages reserve gates only in split bundle steps. Standalone
  steps, bootstrap, and rerandomization retain their full circuit capacity;
  recursive and terminal verification select the lane checks from bound
  circuit IDs.
- Arithmetic and MSMs now use Udon from Zakura Common; the `native-msm`
  feature is no longer needed.
- Baked Pasta parameters are loaded through `ragu_pcd::pasta::baked`.

- PCD transcripts use `ragu-pcd-v3` for bundle-bound public inputs and
  bundle-only shared-stage lane checks. Proofs using previous protocol tags
  are incompatible.
- The `std` feature now enables the required `alloc` feature.
- Routed sparse polynomial evaluation, reverse-dot computations, registry
  evaluation, and polynomial commitments through the selected backend across
  proving and verification paths.
- `Application::verify` computes its acceptance kernels through the sealed
  `SelectableBackend::Verifier` of the selected backend rather than through
  the selected backend directly.

## [0.0.0] - 2025-11-05

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_pcd-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_pcd-0.0.0
