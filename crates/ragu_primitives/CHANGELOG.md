# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added inversion advice for endoscaling. `Element::divide_with_advice` takes
  the inverse of its divisor from the prover and checks it before use;
  `GroupScaleAdvisor` and `group_scale_advice` compute a scaling's inverses
  with one batch inversion; `Endoscalar::group_scale_with_advice` and
  `HoistedEndoscalar::group_scale_with_advice` consume them. The constraints
  are those of `group_scale`.

## [0.0.0] - 2025-07-30

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_primitives-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_primitives-0.0.0
