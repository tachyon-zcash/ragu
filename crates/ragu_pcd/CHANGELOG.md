# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added polynomial hooks: `StepCtx::witness_polynomial` commits a polynomial
  and hands the step a `PolyHandle`, `StepCtx::evaluate` evaluates it, and
  `StepCtx::enforce_poly_query` claims an opening the consuming fuse (or
  `verify`, for a root proof) discharges. The application declares its hook
  layout as `AppHooks<POLYS, QUERIES>`; the handles and query wires occupy a
  framework region of the application stage ahead of the step's `Shared`
  gadget, and the proof carries the witnessed polynomials for one fuse level.
- Added `Step::Shared`, the gadget a step stages: Ragu derives its layout,
  binds every wire of the returned gadget to the proof's application stage,
  and commits that stage once per proof beside the step's own polynomial.
  Stage and final-stage bonding claims hold the stage to its block in both
  verifier paths, so its commitment binds exactly the staged values.
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

- `Step::witness` takes a `StepCtx` in place of the bare driver, which it
  exposes as `ctx.dr` beside the hooks.
- `Step` declares a `Shared` gadget type and returns that gadget from
  `witness`. Steps that stage nothing declare `Shared = ()` and return `()`.
- Every proof carries an application stage sized by the largest registered
  `Shared` gadget. `ApplicationBuilder::register` queues each step and
  `finalize` constructs the circuits once that size is known; every step
  circuit reserves the stage's gates.
- Arithmetic and MSMs now use Udon from Zakura Common; the `native-msm`
  feature is no longer needed.
- Baked Pasta parameters are loaded through `ragu_pcd::pasta::baked`.

- PCD transcripts use `ragu-pcd-v2` for the application stage. Proofs using
  previous protocol tags are incompatible.
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
