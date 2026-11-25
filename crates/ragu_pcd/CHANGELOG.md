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
  in place of the context's proof. The unaudited `Aggregator` profile,
  its `Decompression` context and the decompression methods are public.
  Decompression takes the wallet registry's evaluations as claimed values of
  the profile's online batches, on restrictions its source meshes hold to
  the wallet application's registries, and holds the proof's circuit to the
  wallet registry's domain; a verifier of aggregator proofs so builds the
  aggregator over the wallet application. Both IPAs' final generators are
  bound, over round challenges fixed before the step's challenge: the
  decompression step stages the compression transcript's last squeeze, and
  the extension holds it to the squeeze it computes, through the step
  binding. The decompression step commits the host IPA's challenge
  polynomial in the native batch. Its opening is checked by the native
  extension and its commitment is bound through `Binding::native_online`. The nested
  curve's: every step commits that IPA's challenge polynomial as its online
  Fq polynomial (`Profile::online_fq_polynomials`), and exports its
  commitment and opening for the slots the profile's bindings name
  (`Binding::online` on the native binding, `Binding::openings` on the
  nested one), through `bind_endoscalar`'s and the nested `compute_v`'s
  instances; a proof and a compressed proof of such a profile carry them.
  `Profile::native_extension_rxs` is handed the step's six online openings.
  A step folds its own application claim, so in a profile with a statement
  circuit its `hashes_1` exports the step binding's staged digest after its
  output header and circuit id, and a proof and a compressed proof of such
  a profile carry them.
  A profile with a statement circuit reserves an application stage of at
  least one value, which the decompression step stages. A
  profile that names none, the Standard one included, exports nothing and
  its proofs are unchanged.
  `Aggregator` accepts header sizes from 1 through 195 field elements.
  `Application::decompress_with_polynomials` accepts coefficients for both
  wallet output slots and binds their commitments to the wallet proof. It
  refuses coefficients that do not commit to the wallet proof's commitments.
  `finalize_with` refuses an aggregator that does not register the
  wallet's own header type at every suffix the wallet's steps output.
  Under a profile whose decompression step pads its output slots,
  `finalize_with` refuses a step that outputs or reads a header naming an
  online polynomial.
- Added `ApplicationBuilder::finalize_with` and `Application::context` for
  profile-specific prover context. The extension API is experimental while
  decompression is integrated. `finalize` checks a profile's declaration
  against what its hooks register: a staged circuit through
  `CircuitSlot::register_staged` and a stage's masks through
  `MaskSlot::register_stage_mask` and `register_final_mask`; a mask of another
  shape cannot be registered.
- Added optional `baked-aggregator` parameters through
  `pasta::baked_aggregator()`, sized for `AggregatorRank` (`R<15>`), the rank
  the aggregator profile proves at. Standard's `baked()` keeps its original
  `R<13>` tables and adds the stage reach past them (`pasta::STAGE_REACH`),
  including when the additional Aggregator parameters are enabled and loaded.
- Added sealed, static computational-backend selection between Ragu's reference
  and accelerated implementations, defaulting to
  `ragu_acceleration::AcceleratedBackend` for both proving and verification.
- Added `SelectableBackend::Verifier`, the backend whose kernels
  `Application::verify_compressed` consults, and support for
  `ragu_acceleration::AcceleratedProver`, which accelerates proving while
  verifying with the reference kernels. `ragu_backend::ReferenceBackend`
  uses the reference kernels for both.
- Added the default `asm` feature for Udon's AArch64 field assembly.
- Added `ApplicationBuilder::with_commitment_tables`. Accelerated prover
  backends prepare the tables during finalization and reuse them for polynomial
  commitments over the application's lifetime.
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
- Added online polynomial batches through `profile::online`. A profile
  declares each field's batch as a `Layout` of polynomials, their commitment
  `Phase`s and their `Opening`s (`Profile::NATIVE_ONLINE`, `NESTED_ONLINE`),
  supplies its witnesses through `Profile::{native,nested}_online_inputs`,
  `_online_polynomials` and `_online_points`, and reads its wires from
  extension circuits listed in `Profile::{NATIVE,NESTED}_ONLINE_CONSUMERS`,
  traced through `Profile::{native,nested}_extension_rxs_with_online`.
- Added source-registry meshes: `Profile::{NATIVE,NESTED}_MESH` declare a
  `profile::online::mesh::Mesh` over a batch's slots, and
  `ApplicationBuilder::with_source_registries` captures the registries it
  restricts as `profile::online::source::SourceRegistry`s, or, without them,
  `Profile::source_registries` reads them off the profile's prover context;
  finalization refuses a builder and a context that both supply one for the
  same field.
  Each step carries both children's outgoing restrictions, and compression
  closes the root's. `Profile::{NATIVE,NESTED}_DOMAIN_INPUTS` name inputs the
  helper holds to the source registry's domain, and
  `Profile::{native,nested}_online_inputs` are handed the step's source.
- Added `Application::nested_registry`, beside `native_registry`.

### Changed

- `Application::rerandomize` fuses its input twice through the
  rerandomization step, each time with the application's bootstrap proof as
  the right child, and no longer keeps a seeded unit proof of its own for
  that. Under the Standard profile, its output is built to show nothing of
  the input beyond its header, the data it carries and its online
  polynomials. The method's documentation outlines the argument, which has
  not been audited, and what the caller must ensure. Applications whose
  users must not be told apart install one bootstrap proof for all of them
  with `ApplicationBuilder::with_bootstrap`.
- Every fuse draws three randomizers per side and three free coefficients
  for every trace and stage it commits (`ragu_circuits::Blind`), so a proof's
  folded `A` and `B` and batched `p` are uniformly random, and a commitment
  to one of its polynomials and two evaluations of it do not determine the
  rest. The exceptions are the challenge and bridge-hash stages and the `ab`
  bridge, which hold only values a parent shows anyway, and a profile's
  online and extension stages, which keep a single random coefficient. The
  fold lays the randomizer's claim out in every group and its half-claim in
  a last group of its own. A proof still shows its children's
  commitments, challenges and headers. The Standard profile's walks grow by
  two steps each (25 to 27, 29 to 31) and its fold from 91 to 95 native and
  79 to 83 nested claims. The proof and compressed-proof schemas move to
  version 4.
- The nested `collapse` circuit holds each point of the nested walk to its
  bridge-stage copy, where a separate claim, the loading circuit's, held them
  before. The nested registry loses that entry: under the Standard profile it
  holds 47 wiring polynomials where it held 48, the fold takes 82 nested
  claims where it took 83, and the nested batch 157 openings where it took
  158. Both registry tags change, so proofs and compressed proofs from
  earlier versions do not verify. The proof and compressed-proof schemas are
  unchanged.
- Renamed what the profile API called a bonding to a mask, since a stage
  mask and a final mask are the only kinds left: `BondingSlot` is `MaskSlot`,
  `Profile::register_native_bonding` and `register_nested_bonding` are
  `register_native_mask` and `register_nested_mask`, and
  `Extension::bondings` is `Extension::masks`.
- For the Standard profile, the largest `HEADER_SIZE` the wallet rank fits
  drops from 201 to 195 elements, since every circuit holds one gate fewer
  and the stages the challenge binders load carry the randomizers' values.
- Compressed proofs from earlier versions do not verify, in every profile.
  Compression challenges are endoscalar lifts of the transcript's squeezes,
  143 bits wide as the fuse's challenges are, so that a circuit over the
  other field can scale points by them. The transcript absorbs what lies in
  the scalar field, the host curve's points and the nested curve's scalars,
  as one nested-curve commitment per run of them, committed with a zero alpha at
  the generators the run's stage takes in the proof's decompression at the
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
  a built-in profile's name on any other profile. `Extension::is_consistent`
  requires each circuit's stage list to be strictly increasing, so that the
  stage whose final mask covers the circuit is the last it loads.
- Profile validation rejects zero endoscaling counts and counts whose product
  is at most four, which cannot produce convergent walk sizes. Binding
  documentation now makes declaration/circuit agreement a setup obligation
  rather than claiming a mismatch always rejects.
- `ApplicationBuilder::finalize` derives both registry tags from the registered
  circuits.
- `ApplicationBuilder` boxes a supplied bootstrap proof to reduce debug stack
  usage in long chains of `register` calls.
- Fuse batches independent registry commitments and challenge binding partials
  through the selected backend. Its two error-term layers and child rx
  evaluations use ordered backend iteration, with a lazy serial default.
- Compressed verification batches the independent MSMs for its three derived
  fold commitments on each curve and its two recomputed nested stages through
  the selected verifier backend. Compression shares the fold-commitment batch.
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
- Each step folds its own application claim, with its application trace and
  stage, instead of leaving it to its parent. A proof no longer carries its
  application trace, its application stage, its input headers or its online
  openings; its `hashes_1` exports its own output header and circuit id,
  which the parent holds its copies to. At the base case, `collapse` pins a
  step to the bootstrap circuit id and the unit output header. The proof and
  compressed-proof schemas move to version 3, and `Proof::encoded_len` and
  `CompressedProof::encoded_len` no longer take a header size.

## [0.0.0] - 2025-11-05

### Added

- Initial commit.

[unreleased]: https://github.com/tachyon-zcash/ragu/compare/ragu_pcd-0.0.0...HEAD
[0.0.0]: https://github.com/tachyon-zcash/ragu/releases/tag/ragu_pcd-0.0.0
