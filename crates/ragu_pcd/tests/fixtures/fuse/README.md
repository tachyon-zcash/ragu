# Fuse fixtures

Golden fixtures for the fuse pipeline and the compressed verifier, checked by
`tests/fuse_fixtures.rs` and by the `fuse fixtures` CI job. They pin the
outputs of selected `Application::fuse` executions and the transcript, MSMs,
and verdicts of selected `Application::verify_compressed` executions.
Changes to those executions fail CI.

The prover side follows the golden-proof harness of zakura-common's `sensei`
crate: the prover replays a committed randomness tape and must reproduce the
committed proof byte for byte, consuming exactly the tape. The verifier side
follows zakura-common's Halo2 and Orchard verifier fingerprints: the verifier
runs on each committed proof under a recorder, and its transcript schedule and
final MSMs must match the committed record.

## Profiles

The wallet's standard profile and the aggregator profile both check the same
fixtures in `standard/`. Until the aggregator's decompression circuits land,
the profile declares nothing and produces identical proofs, so storing a
second copy adds no coverage. Both profiles independently reproduce the
snapshots and check the verifier fingerprints and tampered proofs. When the
profiles diverge, the aggregator will need its own expected outputs.

## Scenarios

Six fixtures from a fixed tree of fuses over the harness's own steps
(`Seed`, `Merge`, `UnitLeft`, and `UnitRight`, which is registered but never
fused), at production rank with header size 4, on the baked Pasta parameters:

| Scenario      | Header  | Fuses                                   |
| ------------- | ------- | --------------------------------------- |
| `bootstrap`   | `()`    | the bootstrap step over two dummy proofs |
| `seed_a`      | `Value` | a seed with salt 13 over `bootstrap`      |
| `unit_left`   | `Value` | `UnitLeft` over `bootstrap` and `seed_a`   |
| `merge_ab`    | `Value` | `Merge` over `seed_a` and `seed_b`         |
| `merge_abcd`  | `Value` | `Merge` over `merge_ab` and `merge_cd`     |
| `rerandomize` | `Value` | the rerandomize step over `merge_abcd`     |

The sibling inputs `seed_b`, `seed_c`, `seed_d`, and `merge_cd` are still
proved from fixed seeds, preserving distinct children and the original tree.
They repeat the seed and first-level merge cases, so they have no separate
snapshots; the retained parent fixtures pin their effect on the proof.

The `bootstrap` scenario re-proves the bootstrap proof under the fixture
randomness and installs it in the application, since `finalize` proves it
under `StdRng`, whose output `Cargo.lock` pins but `rand`'s API does not, and
every seed fuses it as both children. The `rerandomize` tape also covers the
seeded trivial proof the step fuses against, which the application proves on
first use.

## Files

Each scenario has four files.

- `<scenario>.rng-u64s-le`: the randomness the fuse drew, as little-endian
  `u64` words. Checking replays it and fails if the prover asks for more or
  leaves any unused.
- `<scenario>.proof`: the header data, then the compressed proof, in the
  harness's own encoding: an eight-byte tag, canonical field and point
  encodings, little-endian `u32` lengths. It is a fixture format, not a wire
  format. The prover must reproduce these bytes, and the verifier must accept
  them as committed, without re-proving. Compression draws a megabyte of
  blinding per proof, too much to commit as a tape, so its randomness comes
  from the harness's frozen generator under a fixed seed and is pinned by its
  word count and these bytes.
- `<scenario>.digests`: `key = value` lines. One BLAKE2b-256 digest per
  primary field of the uncompressed proof, in declaration order, over the
  field's canonical bytes (every coefficient of a polynomial, zeros included);
  then `rng.fuse.words`, `rng.compress.words` and `proof.bytes`. The
  uncompressed proof is over ten megabytes at production rank, so this stands
  in for committing it. A mismatch names the fields that drifted, and the
  file's diff in a pull request reads as the list of stages a change touched.
- `<scenario>.fingerprint`: `key = value` lines recording the verifier's run
  on the `.proof`. `verifier.transcript` digests every point and scalar the
  transcript absorbed and every challenge it squeezed, in order;
  `verifier.absorbed` and `verifier.squeezed` split that stream, with counts,
  so a mismatch says whether the verifier read the proof differently or
  derived different challenges from the same reads. `verifier.msm.native` and
  `verifier.msm.nested` digest each curve's final IPA MSM, every scalar in
  evaluation order and every proof-dependent base, so they pin the
  coefficient structure the check assembles, not only that it vanished.

Alongside each fingerprint, the verifier test checks four tampered copies of
the proof, after the rejected captures beside zakura-common's Orchard
fingerprints: a wrong host-curve IPA scalar must fail the host MSM, a wrong
nested IPA scalar must pass the host MSM and fail the nested one, identity
stage commitments must be rejected before either MSM, and a wrong claimed
`v` must be rejected. These are checked, not committed.

The recorder lives in `src/ipa/fingerprint.rs`. Recording and event encoding
compile only for tests; production observation helpers are inline no-ops.
The helpers observe the cycle transcript's absorb, scalar and squeeze, and
the IPA MSM's evaluation, so the fingerprint is of the verifier's own code path.

The fixture workflow is called by Backend CI. Its result feeds the existing
required `backend-required` check, so a failed or cancelled fixture run blocks
merging. Other correctness and adversarial tests cover executions beyond this
fixed workload; matching these snapshots does not establish protocol soundness.

## Regenerating

After an intended change to the prover or the verifier, run

```console
RAGU_FIXTURES=write cargo test --release -p ragu_pcd --all-features --lib proof::fuse_fixture_tests
```

and review the diff before committing it. The `.digests` diff should name
exactly the stages a prover change was meant to touch, and the
`.fingerprint` diff the part of the verifier a verifier change was; a change
to `rng.fuse.words` means the randomness schedule moved. Only the standard
prover test writes the shared files, fingerprints included, since the verifier
test cannot read a proof that is still being written. Run the same command
without `RAGU_FIXTURES=write` afterwards to check both profiles. Fresh tapes and
sibling inputs come from the harness's SplitMix64 generator, which is not
cryptographically secure and exists only to make synthetic test data
reproducible; it must never produce a real proof.

The tests are ignored without `--release`: production-rank proving is
impractically slow in debug builds.
