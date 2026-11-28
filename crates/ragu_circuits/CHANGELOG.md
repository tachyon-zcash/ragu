# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Rank` support for `R<14>` and `R<15>`, and the `AggregatorRank`
  alias, which is `R<14>` as `WalletRank` now is: circuits that exceed that
  rank's capacity are cut into pages (`paging`) rather than proven at a
  larger rank.
- A paged circuit's pages call the routines the circuit calls
  (`Driver::routine`), each on the one page that holds its gates, so a
  routine has the same segment and fingerprint on a page as in the circuit.
  `Pages::check` holds the routines the pages call to the circuit's.
- Added `Blind`, the three coefficients of an rx polynomial that no wiring
  polynomial reads: `a[0]` of the SYSTEM gate, and `a[n - 1]` and `d[n - 1]`
  of the blind gate (`Rank::blind_gate`), the last gate of the rank.
  `Blind::random` draws all three. A field element converts into the `Blind`
  that holds it at `a[0]` and leaves the blind gate zero.
- Added runtime-sized stages: `staging::stage_gates`, `stage_rx`, `stage_mask`
  and `final_mask` lay out and mask a stage whose size is fixed when the
  registry is built rather than in the type, with the rank's bounds checked.
- Added iteration over the stored coefficients of sparse polynomials.
- Added `Stage::gate_ranges`, the gates of a stage and of every stage before
  it, for a registry to check a circuit's declared stages against.
- Added `RegistryBuilder::with_tag` under `test-utils`, a test seam that
  installs a tag in place of the derived one.
- Added `Registry::hashed_wxy_over_domain` under `test-utils`, a test seam
  that evaluates the registry polynomial from the monomials the tag hashed,
  for comparison with the wiring evaluators.

### Changed

- `WalletRank` is now `R<14>`, where it was `R<13>`: $2^{14}$ coefficients
  and up to 4,095 gates.
- The last gate of every rank is reserved as the blind gate. A circuit, a
  trace and a stage hold `n - 1` gates where they held `n`, and
  `Error::GateBoundExceeded` reports that limit. Stage masks and final masks
  leave the blind gate's `a` and `d` wires unconstrained and still hold its
  `b` and `c` wires to zero.
- `Trace::assemble`, `Registry::assemble_with_alpha`, `StageExt::rx`,
  `StageExt::rx_configured` and `staging::stage_rx` take
  `impl Into<Blind<F>>` where they took the alpha. `Registry::assemble`
  draws all three coefficients.
- Renamed `ProductionRank` to `WalletRank`, the rank wallets prove at,
  beside `AggregatorRank`.
- Registry tags are derived at finalization by hashing every registered
  wiring polynomial, written out as its nonzero monomials in canonical order,
  rather than by evaluating the registry polynomial at a handful of points.
  The tag is a function of the registered circuits alone.

- Renamed `registry::Key` to `registry::Tag` and `Registry::digest()` to
  `Registry::tag()`.
- Renamed `BondingObject` to `MaskObject` and
  `RegistryBuilder::register_bonding` to `register_mask`. Every such
  polynomial is a stage mask or a final mask.
- Removed `MultiStage::into_bonding_object`, which turned a circuit with no
  gates of its own into a bonding polynomial. Its one user, the nested
  loading circuit in `ragu_pcd`, is gone.
- Renamed `StageExt::mask` to `StageExt::stage_mask`, beside
  `StageExt::final_mask`, as the free functions `staging::stage_mask` and
  `staging::final_mask` are named.
- `MaskObject` is a concrete type over the rank alone, `MaskObject<R>`,
  where it boxed a wiring polynomial over a field and a lifetime. The
  functions that return one lose those two parameters.

## [0.0.0] - 2025-07-29

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_circuits-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_circuits-0.0.0
