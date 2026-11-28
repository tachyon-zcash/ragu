# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `msm_batch` for independent MSMs sharing a worker budget, and
  `for_each_mut` and `for_each_chunk_mut` for scoped work with original item
  and chunk indices.
- Added `msm_many` for a runtime-sized batch of independent MSMs and `join`
  for a pair of independent jobs.
- Added `PreparedMsm` for reusable Pasta bases, optionally with a table of
  precomputed fixed-base multiples, and `MsmWorkspace` for explicitly scoped
  MSM scratch.
- Added `WireStream` and its kind `WireStreamKind`: a gadget that is a run of
  wires whose number is known only at run time. Its traversal is that of an
  array of as many single wires.

### Changed

- **Fungibility is weaker.** A `Gadget` no longer has to hold the same number
  of wires in every instance. Fungibility is now substitution between
  instances that hold the same number of wires, and allocation determinism:
  the kind and the wires in traversal order give the gadget, with the number
  of wires as the only other input. This is what a driver that moves or
  memoizes a routine relies on. Every gadget that met the old definition
  meets this one.

## [0.0.0] - 2025-07-29

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_core-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_core-0.0.0
