# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added recursion profiles through `profile::{Profile, ProfiledCycle, Profiled,
  Standard, Aggregator, Shape}`. Profiles declare internal extension circuits,
  stages, statement and cross-cycle bindings, and endoscaling work, and a
  prover context (`ProverContext`) whose `Source` a decompression step supplies
  in place of the context's proof. The `Aggregator` profile, its
  `Decompression` context and `Application::decompress` sit behind the
  `unstable-aggregator` feature: they are not yet sound against a dishonest
  prover, since the decompression takes the wallet registry's evaluations and
  the nested curve's IPA's final generator from the prover. The host curve's
  is bound: the decompression step commits that IPA's challenge polynomial in
  its first output slot, and the extension holds its opening and commitment
  through the statement circuit's step binding (`profile::STEP_BINDING`) and
  the nested binding circuit's online slots (`Binding::online`).
  `Aggregator` is pinned for 4-element headers alone; other header sizes do
  not compile.
- Added `ApplicationBuilder::finalize_with` and `Application::context` for
  profile-specific prover context. The extension API is experimental while
  decompression is integrated. `finalize` checks a profile's declaration
  against what its hooks register: a staged circuit through
  `CircuitSlot::register_staged` and a stage's masks through
  `BondingSlot::register_mask` and `register_final_mask`; a bonding of another
  shape cannot be registered.
- Added optional `baked-aggregator` parameters through
  `pasta::baked_aggregator()`, sized for `AggregatorRank` (`R<15>`), the rank
  the aggregator profile proves at. Standard's `baked()` keeps its original
  `R<13>` tables and adds the stage reach past them (`pasta::STAGE_REACH`),
  including when the additional Aggregator parameters are enabled and loaded.
- Added sealed, static computational-backend selection between Ragu's reference
  and accelerated implementations, defaulting to
  `ragu_backend::ReferenceBackend`.
- Added `SelectableBackend::Verifier`, the backend whose kernels
  `Application::verify` consults, and support for
  `ragu_acceleration::AcceleratedProver`, which accelerates proving while
  verifying with the reference kernels.
- Added `RegistryTags::from_beacon` and `ApplicationBuilder::with_registry_tags`
  to supply both registry tags before finalization. Production callers must
  choose the values after fixing and publicly committing the complete application.
- Added `Application::verify_differential` under `test-utils`: checks a proof
  with both verifiers and asserts they agree, returning the uncompressed
  verdict. The adversarial test suites and the fuzz harness check every proof
  with both verifiers.
- Added an application stage: `Step::NUM_STAGED` and the values
  `Step::prepare` stages commit a step's staged values before its challenge
  $\zeta$ is drawn, and `Oracles::staged` hands them to `Step::witness` as
  wires bound to the committed stage. A check at $\zeta$ must read only
  values fixed before it; stage any other value it reads. Every step
  circuit reserves `ceil(n / 2)` gates for the largest `NUM_STAGED`
  registered, and the step circuits are constructed at `finalize`.
- Added `Header::OnlinePolyCommit`, the kinds of online polynomial a
  header's proofs carry, as a tuple of unit types implementing `OnlinePoly`
  or `Padding`, one per slot; `Step::prepare`, `HeaderInput::polynomial` and
  `Oracles::{left, right, output}` address a polynomial by its kind, which
  `Has` finds in the list at compile time, so a slot a header leaves to
  padding cannot be addressed, and the adapter holds every output slot a
  step leaves unopened to the constant one. `fuse` fails with
  `Error::InvalidWitness` if a step prepares a polynomial for an output
  slot it does not open. The bridge hash digests the last slot, so a
  header whose steps read it keeps the hashed kind last.
- Added `Pcd::commitments` and `Application::commit`: a proof's polynomial slot
  commitments, and the commitment of given coefficients, so that an
  application can recompute `Application::bridge_hash` outside the circuit.

### Changed

- Compressed proofs from earlier versions do not verify, in every profile.
  Compression challenges are endoscalar lifts of the transcript's squeezes,
  143 bits wide as the fuse's challenges are, so that a circuit over the
  other field can scale points by them. The transcript absorbs what lies in
  the scalar field, the host curve's points and the nested curve's scalars,
  as one nested-curve commitment per run of them, committed unblinded at the
  generators the run's stage takes in the proof's decompression at the
  aggregator rank, so that each challenge is a function of every message
  before it and a circuit over the circuit field absorbs the commitment as a
  point its verifier holds to that stage. The Standard fuse fixtures'
  compressed digests and verifier fingerprints pin both. Those generators lie
  past the Standard tables, so `baked()` carries the reach of them the runs
  take (`pasta::STAGE_REACH`), through `IpaCycle::nested_generator`, and
  serves a Standard application that compresses; the aggregator's own tables
  hold the same points.
- `CycleTranscript::new` commits each run of consecutive scalar-field values
  over the parameters' first nested generators, so a standalone IPA over
  `ipa` round-trips on either curve; the fuse opens its own transcript without
  run bases and the compression with its run stages'. Consecutive scalar-field writes share one commitment, where each
  was committed on its own before, so standalone transcripts from earlier
  versions do not replay.
- `ApplicationBuilder`, `Application`, and their proving, verification and
  compression methods now require `ProfiledCycle` rather than only `Cycle`.
  Custom cycles must select a profile; Pasta's implementation requires `baked`.
- Ordinary verification rejects malformed proof shapes before traversal.
  Compression returns `Error::InvalidWitness` for malformed shapes, and so do
  `Application::fuse` and `Application::rerandomize` for a child proof of
  another shape.
- Ordinary verification returns rejection for identity commitments used by
  claim targets or the bridge transcript, instead of an input error, while
  preserving application header-encoding errors.
- `Profile::check`, which finalization runs, refuses an empty profile name and
  a built-in profile's name on any other profile, since the name is what
  separates two profiles' registry tags under one beacon output and manifest
  digest. `Extension::is_consistent` requires each circuit's stage list to be
  strictly increasing, so that the stage whose final mask covers the circuit is
  the last it loads.
- Profile validation rejects zero endoscaling counts and counts whose product
  is at most four, which cannot produce convergent walk sizes. Binding
  documentation now makes declaration/circuit agreement a setup obligation
  rather than claiming a mismatch always rejects.
- `RegistryTags` fields are private. Direct construction from final `Tag::new`
  values is no longer supported; use `RegistryTags::from_beacon` and supply an
  independently trusted expected manifest digest to `with_registry_tags`.
- Fuse batches independent registry commitments and challenge binding partials
  through the selected backend. Its two error-term layers and child rx
  evaluations use ordered backend iteration, with a lazy serial default.
- Compressed verification batches the independent MSMs for its three derived
  fold commitments on each curve and its two recomputed nested stages through
  the selected verifier backend. Compression shares the fold-commitment batch.
- `RegistryTags` retains its setup manifest digest and exposes read-only tag
  accessors. `ApplicationBuilder::with_registry_tags` requires the receiver's
  expected manifest digest and returns an error on mismatch.
- Arithmetic and MSMs now use Udon from Zakura Common; the `native-msm`
  feature is no longer needed.
- Baked Pasta parameters are loaded through `ragu_pcd::pasta::baked`.

- Replaced the placeholder PCD transcript tag with `ragu-pcd-v1`. Proofs produced
  with the previous `FIXME` tag are incompatible with this protocol version.
- The `std` feature now enables the required `alloc` feature.
- Routed sparse polynomial evaluation, reverse-dot computations, registry
  evaluation, and polynomial commitments through the selected backend across
  proving and verification paths.
- `Application::verify` computes its acceptance kernels through the sealed
  `SelectableBackend::Verifier` of the selected backend rather than through
  the selected backend directly.
- `Application::verify`, the uncompressed verifier, is renamed to
  `Application::verify_uncompressed` and is now a test oracle behind the new
  `test-utils` feature, which `unstable-fuzzing` enables. Production
  verification compresses a proof with `Application::compress` and checks it
  with `Application::verify_compressed`.

## [0.0.0] - 2025-11-05

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_pcd-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_pcd-0.0.0
