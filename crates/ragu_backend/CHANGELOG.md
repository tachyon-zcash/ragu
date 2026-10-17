# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added the correctness-first `Backend` trait and `ReferenceBackend`.
- Added `Backend::msm_batch`, with an ordered fallback to separate `Backend::msm`
  calls that preserves individual MSM overrides.
- Added `Backend::for_each_mut`, with a serial default for independent work.
- Added `Backend::sparse_commit_batch` for independent polynomial commitments
  and `Backend::map` for ordered independent work with a lazy serial default.
- Added correctness-first sparse polynomial evaluation, reverse-dot,
  commitment, and registry evaluation backend methods.

## [0.0.0] - 2026-08-16

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_backend-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_backend-0.0.0
