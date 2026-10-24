# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `AcceleratedBackend`, initially inheriting all reference defaults.
- Added `AcceleratedProver`, which accelerates proving while `ragu_pcd`
  verifies with the reference kernels, and the `verifier` module that hosts
  verifier-consulted overrides.

### Changed

- Fuse uses backend-selected MSM batches and parallel error-term and polynomial
  evaluation scheduling.
- Compression error terms and per-claim verifier evaluations use Udon's scoped
  scheduler; the reference backend evaluates them serially.
- Independent Pasta MSMs share Udon's batch planner through `AcceleratedBackend`;
  `AcceleratedProver` forwards the same implementation.
- The arithmetic backend uses Udon. The `native-msm` feature is no longer needed.

## [0.0.0] - 2026-08-16

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_acceleration-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_acceleration-0.0.0
