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

Each profile's fixtures come in two families:

- `honest/`: the proofs the prover reproduces and the verifier accepts, with
  the verifier's run on each.
- `random/`: random proof strings of each honest proof's shape, which the
  verifier reads through to the host curve's MSM and rejects, with the
  verifier's run on each.

## Profiles

The wallet's standard profile checks the fixtures in `standard/` and the
aggregator profile those in `aggregator/`. The aggregator's proofs carry the
decompression circuits' polynomials, at the aggregator rank, run over the
canonical compressed proof of the wallet application the aggregator holds as
its context: the fixtures' own wallet application, its bootstrap proof
compressed under a fixed seed. Each profile reproduces its snapshots and checks
its verifier fingerprints, tampered proofs and random strings.

## Scenarios

Six fixtures from a fixed tree of fuses over the harness's own steps
(`Seed`, `Merge`, `UnitLeft`, and `UnitRight`, which is registered but never
fused), with header size 4, on the aggregator-rank Pasta parameters, which
the aggregator's decompression needs and whose prefix is the Standard tables; the wallet at
wallet rank and the aggregator at the aggregator rank:

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

## Honest files

Each scenario has four files in `honest/`.

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
  uncompressed proof is over ten megabytes at wallet rank, so this stands
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

## Random files

Each scenario has two files in `random/`.

- `<scenario>.proof`: a random proof string in the same encoding. It keeps
  the honest proof's shape and circuit id; everything else, header data
  included, is drawn from the harness's SplitMix64 generator under a fixed
  seed, points as random multiples of the generator. The values the verifier
  recomputes or solves for before its host MSM are then planted: the
  challenge-stage and `ab` bridge commitments, rebuilt from the challenges,
  headers and native commitments with the stage builders the verifier uses
  and checked against its stage check, and the host reduction's `q(r)`,
  solved from the reduction check's combined side, evaluated over a replay of
  the verifier's host transcript up to `r`. So the verifier reads the string
  through to the host MSM, which rejects it.
- `<scenario>.fingerprint`: the verifier's run on the string, in the same
  format, ending at the host MSM with `verifier.msm.native.identity = false`.
  Nothing short of a forged host opening reaches the nested side, so these
  pin the host side alone.

On an honest proof, every value the verifier recomputes from the headers,
the challenges and the registry agrees with whatever the proof carries in its
place, so a change in where the verifier sources one leaves the honest
fingerprints unchanged. On a random string the two disagree, so the change
mismatches instead of hiding behind honest structure. The random captures
claim only that the verifier's run matches and that the host MSM rejects.

The fabricator knows the discrete log of every point it draws. That is
harmless here: the strings are inputs the verifier must reject, not
forgeries, and the test checks that it does.

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
to `rng.fuse.words` means the randomness schedule moved. A random string
changes whenever the values planted in it move, which a change to the
verifier's recomputations does. Only the standard prover test writes the
shared files, fingerprints and random strings included, since the verifier
test cannot read a proof that is still being written. Run the same command
without `RAGU_FIXTURES=write` afterwards to check both profiles. Fresh tapes,
sibling inputs and random strings come from the harness's SplitMix64 generator, which is not
cryptographically secure and exists only to make synthetic test data
reproducible; it must never produce a real proof.

The tests are ignored without `--release`: wallet-rank proving is
impractically slow in debug builds.
