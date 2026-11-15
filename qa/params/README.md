# Poseidon parameter provenance

The Poseidon tables ragu runs with — `udon`'s, in the Udon repository's `crates/udon/src/poseidon/` at the
revision this workspace pins — are roughly
700 hand-transcribable field elements that no fingerprint or differential test
can validate. Every test downstream of them is generic in whatever the tables
happen to contain. Replacing a constant changes the golden fixture digests, so
the fixtures notice the change, but nothing there says which tables are right.
Their only external authority is the script that generated them.

`check_poseidon_params.py` regenerates the tables and compares (it finds the pinned
`udon` through `cargo metadata`, or takes `--udon-dir`):

```sh
python3 qa/params/check_poseidon_params.py
```

Each field is checked three ways, and all three must agree:

* the committed Rust tables;
* `reference/`, the verbatim stdout of the real Sage script at ragu's own
  parameters — see `reference/PROVENANCE.md` for the revision, invocation, and
  digests;
* `poseidon_params.py`, a pure-Python port of the Grain LFSR part of
  `generate_parameters_grain.sage`, which regenerates the tables from scratch
  on every run.

The Sage output is the authority; the port is what makes the check cheap enough
to run on every commit. Sage is not a CI dependency — its result is checked in.

## Calibration

A reimplementation of a generator is worth only as much as its own validation,
so the port is measured against real Sage output twice over. At `t = 5` it is
compared against `reference/`, produced by the script itself at exactly the
parameters ragu ships. At `t = 3` it is compared against halo2's P128Pow5T3
tables from the same script. The Fp instance is Orchard's deployed nullifier
permutation; Fq is halo2's companion Pasta-field instance. Point the check at a
halo2 checkout for that pass:

```sh
python3 qa/params/check_poseidon_params.py --halo2-dir path/to/halo2
```

CI runs the ragu pass. The halo2 pass is a developer-side check for when the
port is touched, and evidence that the port tracks the script across parameter
sets rather than at one point. Supplying `--halo2-dir` requires both parameter
files to be present; a missing or incomplete checkout fails the check.

## What is and isn't covered

Covered: the round constants exactly, including the Grain rejection sampling,
and the MDS matrix.

The port does not implement `algorithm_1/2/3`, the reference's MDS security
filter, which decides whether a Cauchy candidate is *accepted*; it emits the
first candidate. That costs nothing here: the port's matrix equals the pinned
Sage output's for both fields, and the reference resamples on rejection, so
the first candidate is the one it accepted. (The `Result Algorithm` lines in
the Sage output are not evidence of this — the script re-runs the filter on
the matrix it returns, so they read `True` whatever it rejected on the way.)
A future parameter set landing on a later candidate would show up as a
port/Sage disagreement rather than passing silently.

Not covered, deliberately: whether these parameters are *good* — round counts
against the known attacks, MDS security. That is the reference script's
judgement and the Poseidon literature's, not this check's. This answers only
"are the committed tables what the recorded command produces".

## The other half

Parameters being genuine says nothing about the permutation consuming them
correctly. That is pinned separately, in
`crates/ragu_primitives/src/poseidon/tests/`, against halo2's permutation test
vectors — see `gen_halo2_vectors.py`, which vendors them. The two checks are
complementary and neither implies the other:

| | pinned by |
| --- | --- |
| the constants ragu ships | this directory, against the generator |
| the permutation applying them | halo2's vectors, in `ragu_primitives` |
