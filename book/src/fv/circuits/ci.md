# CI Integration

The CI formal verification workflow helps developers check whether the formal
verification pipeline runs successfully.

At its core, the workflow tests the extraction evaluators, checks generated and
trust-boundary artifacts, builds the Lean development in `qa/fv`, and runs both
the deterministic and randomized Rust-to-Lean comparisons.

Concretely, it first runs `cargo run --locked -p lean_extraction -- check`,
which enforces that the checked-in generated Lean files — the
`Ragu/Instances.lean` import root and the `Ragu/Fingerprint/Instances.lean`
instance list — are up to date with respect to the exporter's target table. This
forces a handwritten formal-instance module to exist for every export target.

After that, CI builds the Lean project: this checks that the formal-instance
files, the circuit reimplementations, and the associated proofs still compile
together. The build is run with `--wfail`, so Lean warnings (and in particular
`sorry`s) are treated as failures.

```admonish warning
Concretely, the Lean build step builds every module under `qa/fv/Ragu/` (the
library uses a glob), so a file that no aggregator imports cannot silently
escape CI.
```

CI then runs the [fingerprint equivalence check](./fingerprint.md): it
compares the canonical trace digests printed by
`cargo run --locked -p lean_extraction -- fingerprint` against the ones computed
in Lean from the `Clean` reimplementations
(`lake env lean --run Ragu/Fingerprint/Main.lean`), and fails on any mismatch.
If the Rust circuit code changes the extracted operations or outputs, CI fails
until the Lean reimplementation is updated to match (and its proofs repaired).

Finally, CI generates and prints a fresh 32-byte seed and runs the
[direct randomized polynomial check](./polynomial-fingerprint.md) at two
domain-separated points. The Rust side runs each real gadget with the
four-slot `EvaluationDriver`; Lean evaluates the corresponding handwritten
model without consuming the Rust trace. Their exact headers and four field
accumulators must match for all 57 enrolled instances. The explicit printed
seed makes failures reproducible, while generating it after checkout prevents
source changes from targeting a permanently fixed public point.

Independent, hand-written Lean checks should be imported through `Ragu.Lemmas`,
not through the Rust extraction exporter.
