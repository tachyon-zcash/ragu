# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Rank` support for `R<14>` and `R<15>`, and the `AggregatorRank`
  alias for `R<15>`, for extension circuits that exceed the production rank's
  capacity. `ProductionRank` remains `R<13>`.
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
