# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `decompose_bits`, which decomposes an element into its `n` low bits and so
  range-checks it below `2^n`.
- `Point::add_fixed_base_mul`, which adds `[k] base` for a constant `base` and
  the little-endian integer `k` of a slice of booleans, two bits per addition.
- `Point::x` and `Point::y`, the coordinates' elements.

## [0.0.0] - 2025-07-30

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_primitives-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_primitives-0.0.0
