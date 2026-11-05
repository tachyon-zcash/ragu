# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Rank` support for `R<14>` for extension circuits that exceed the
  production rank's capacity. `ProductionRank` remains `R<13>`.
- Added iteration over the stored coefficients of sparse polynomials.
- Added `RegistryBuilder::with_tag` under `test-utils`, a test seam that
  installs a tag in place of the derived one.

### Changed

- Registry tags are derived at finalization by hashing every registered
  wiring polynomial, written out as its nonzero monomials in canonical order,
  rather than by evaluating the registry polynomial at a handful of points.
  The tag is a function of the registered circuits alone.

- Renamed `registry::Key` to `registry::Tag` and `Registry::digest()` to
  `Registry::tag()`.

## [0.0.0] - 2025-07-29

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_circuits-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_circuits-0.0.0
