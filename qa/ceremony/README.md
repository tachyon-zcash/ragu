# Example registry tag ceremony

This directory contains QA tooling and example records for the temporary
registry-collision workaround in [#78](https://github.com/tachyon-zcash/ragu/issues/78).
The API change is temporary setup-time tag injection. The manifest format,
OpenTimestamps service, Bitcoin beacon, and block-selection rule below are
choices for exercising that API in QA, not a production ceremony specification.
Consumers can use their own setup procedure while satisfying the
[sampling requirement](../../book/src/guide/configuration.md#registry-tags).

This example commits to the complete setup of both registries before the
Bitcoin beacon output is known. `registry_tags` derives the tags from the
beacon bytes and `X = SHA-256(setup.manifest)`. The manifest binds the actual
code, dependency, and public-parameter artifacts by SHA-256 content digests.
The Rust `manifest_digest` argument receives `X`.
For Git-based source snapshots, include their full commit IDs in `provenance`.
These IDs are covered by the manifest digest and timestamp along with the
artifact digests. Hashing a SHA-1 commit ID again does not strengthen its
binding to the code contents.

## Prepare the manifest

Freeze the entire application and Ragu codebase at identified revisions first.
Hash the complete source snapshots. Create the ceremony records separately
afterward: the manifest, timestamp proof, beacon record, and derived tags refer
to those frozen snapshots and are not part of them.

Copy [setup.manifest.example.json](setup.manifest.example.json) to `setup.json`
in a new ceremony directory. Replace every placeholder with the exact setup;
expand the example lists and maps as needed. Record application steps in
registration order and all inputs that determine their circuits. Values
already fixed by committed code can refer to an artifact, path, and item in
that code instead of being repeated. Include every remaining build and setup
choice.

The example records keep digests and reproduction details, without storing
source archives or parameter binaries. For a Git snapshot, hash the archive
stream directly:

```sh
git archive --format=tar <source-commit> | shasum -a 256
```

This covers the snapshot's contents, including the book. Record how each
input can be reconstructed in `artifacts`, along with its SHA-256 digest.
Registry dependencies can be bound through a hashed `Cargo.lock` whose
`checksum` entries are SHA-256 digests of the crate archives. Dependencies
without those checksums need separate content digests. Hash generated public
parameter bytes and identify their generator and encoding in the frozen code.
A filename or Git commit ID does not replace a content digest.

The `baked` feature and `pasta::baked()` retain Standard's original $2^{13}$
vector generators per curve. The optional `baked-aggregator` feature adds
separate $2^{15}$ tables loaded by `pasta::baked_aggregator()`. Enabling or
loading those tables does not enlarge Standard's parameters. A setup that uses
the larger parameters must hash and record that selected artifact and feature
configuration in its own manifest. Existing frozen records remain descriptions
of their original artifacts; do not rewrite them for a new configuration.

For `ragu-setup-manifest-v1`, use JSON objects, arrays, strings, integers,
booleans, and null; duplicate object keys and floating-point numbers are
not allowed. Canonical bytes are the ASCII output of Python's `json.dumps`
with `sort_keys=True`, `ensure_ascii=True`, and `separators=(",", ":")`,
followed by one LF byte. Array order is preserved. These are this format's
encoding rules, including for any additional setup fields.

Run the canonicalizer from the repository root, using a new record directory:

```sh
python3 qa/ceremony/manifest.py path/to/setup.json > path/to/setup.manifest
shasum -a 256 path/to/setup.manifest | cut -d ' ' -f 1 > path/to/manifest_digest.txt
```

The helper rejects missing setup fields, unresolved placeholders, malformed
digests, duplicate keys, floating-point numbers and profile/label mismatches.
Its output follows the
v1 canonical encoding above. These are description checks; the setup procedure
must still match artifact contents and deployed configuration to the record,
and authenticate the public commitment and beacon.

## Profiles and verified setups

Every new description names `setup.profile.name` and its `definition` in the
frozen source. `standard` uses the existing labels `ragu_pcd native registry`
and `ragu_pcd nested registry`. `aggregator` appends ` (aggregator)` to each.
The current QA tools support these two built-in profiles; other profiles need
an application-specific derivation using their compiled `RegistryTags<C>` type.

Record other setups whose keys, tags or parameters the profile fixes at setup
in `setup.verified_setups`, using their profile, approved `manifest_sha256`
and `record_sha256`. The latter binds the approved record containing the
beacon and final native/nested tags, not just the pre-keyed description.
For example, a future Aggregator that verifies Standard compressed proofs must
pin that Standard setup in its own description. Use an empty list when no
other setup is fixed as a parameter. Those dependency parameters must already
be fixed in the outer setup's complete description before its tags are sampled.
Recording a dependency does not authenticate it or implement its verifier circuit.

The profile name alone is not a setup identity. Changes to circuit order,
staging, ranks, application inputs, public parameters, dependencies or transcript
rules change the committed description and require fresh tags after that
changed description is fixed. Do not finalize an Aggregator production manifest
or ceremony until its actual circuits and configuration have landed and frozen.

## Timestamp and derive

The example uses the following steps after freezing the manifest, including
the beacon selection rule and derivation labels:

1. Run `ots stamp setup.manifest` and keep `setup.manifest.ots`. Once a
   calendar transaction confirms, run `ots upgrade setup.manifest.ots`.
2. Run `ots verify setup.manifest.ots` against a configured Bitcoin Core
   node. Use the earliest **verified** attestation height `N`. `ots info`
   displays metadata but does not verify the timestamp.
3. Wait for block `N + 100` and record its hash `B` from more than one source.
   A future Bitcoin block provides unpredictability after commitment, not
   unbiasability; this assumes miners do not selectively withhold blocks or
   reorganize the chain to bias the tags.
4. Derive the tags below, then record the inputs, outputs, and timestamp proof
   together so the derivation can be reproduced.

With `B` and `X` both expressed as hex, run from the repository root:

```sh
cargo run -p ragu_ceremony --bin registry_tags -- --profile standard B X
```

Select `--profile aggregator` for an Aggregator record. Omitting the flag
retains the legacy Standard behavior. `continue.sh` reads the profile and labels
from the frozen manifest, checks its Bitcoin/N+100 policy before external
calls, and passes the profile to the derivation command. Old Standard v1 records
without a profile field remain readable without rewriting their bytes.

Keep the canonical manifest, timestamp proof, beacon selection record, and
resulting tag pair together, with access to the referenced source and inputs.
A changed description needs a fresh ceremony; do not reuse a known beacon
output to regenerate these records.

To check a record, match the artifact digests to the setup, recompute `X`,
verify the timestamp, check block `N + 100`'s hash independently, and repeat
the tag derivation.

Pin the approved `X` in the receiver's configuration. Pass it separately to
`ApplicationBuilder::with_registry_tags(tags, &expected_manifest_digest)?`.
The API rejects a different manifest and preserves the final derived tag values.
Artifact and ceremony verification remain the setup procedure's responsibility.

## Example record

Each `dry-run-<commit>/` directory is a flat record named after its source
revision. `RECORD.md` describes the setup and status; `commit.txt` records the
full source commit ID. `setup.manifest` and `manifest_digest.txt` add the
complete setup commitment to the original `attestation.txt`, `beacon.txt`,
and `tags.txt` fields.

Run the record's `./continue.sh` to timestamp the manifest and, once its
attestation is verified and the beacon block exists, derive the tags. The
proof is `setup.manifest.ots`, created when the manifest is timestamped.
An explicit block-height argument exercises a dry run without the ordering
guarantee. Pending fields are marked as such; they are not usable setup tags.

The shared [continue.sh](continue.sh) implements this example. Run its offline
regressions and the description checks with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s qa/ceremony -p 'test_*.py'
cargo test --release -p ragu_ceremony --bin registry_tags
```

`fixtures/` contains canonical, explicitly test-only Standard and Aggregator
descriptions, their SHA-256 digests, and independently computed tag vectors.
These are not deployment records or completed ceremonies. Their tests exercise
profile selection, canonicalization and changes to setup choices; they do not
supply production parameters or establish beacon provenance.
