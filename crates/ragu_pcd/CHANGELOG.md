# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added sealed, static computational-backend selection between Ragu's reference
  and accelerated implementations, defaulting to
  `ragu_backend::ReferenceBackend`.

### Changed

- Routed sparse polynomial evaluation, reverse-dot computations, registry
  evaluation, polynomial commitments, and native Poseidon through the selected
  backend across proving, native-witness, and verification paths.

## [0.0.0] - 2025-11-05

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_pcd-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_pcd-0.0.0
