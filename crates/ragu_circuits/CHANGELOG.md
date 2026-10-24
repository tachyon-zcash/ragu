# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added runtime-sized stages: `staging::stage_gates`, `stage_rx`, `stage_mask`
  and `final_stage_mask` lay out and mask a stage whose size is fixed when the
  registry is built rather than in the type, with the rank's bounds checked.
- Added iteration over the stored coefficients of sparse polynomials.
- Added `Tag::from_beacon` and `RegistryBuilder::with_tag` for caller-supplied
  tags chosen after the circuits are fixed. Finalization requires a tag;
  `insecure-test-registry-tag` enables a fixed fallback for tests only.

### Changed

- Temporarily replaced evaluation-based registry tags with caller-supplied tags.

- Renamed `registry::Key` to `registry::Tag` and `Registry::digest()` to
  `Registry::tag()`.

## [0.0.0] - 2025-07-29

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_circuits-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_circuits-0.0.0
