# CI integration

The CI formal verification workflow helps developers check whether the formal verification pipeline runs successfully.

At its core, the workflow runs the extraction exporter and then builds the Lean development in `fv/lean`.
Concretely, it first runs `cargo run --locked -p lean_extraction -- check`, which enforces that the checked-in exported Lean files are up to date with respect to the current Rust exporter.
If the Rust circuit code changes the extracted operations or outputs, CI fails until the exported Lean artifacts are regenerated and committed.

After that, CI builds the Lean project with `leanprover/lean-action`: this checks that the formal-instance files, the circuit reimplementations, and the associated proofs still compile together.
The build is run with `--wfail`, so Lean warnings (and in particular `sorry`s) are treated as failures.

> [!WARNING]
> Concretely, the Lean build step checks everything imported by the top-level library file `fv/lean/Ragu.lean`.
> The Lean build step will not notice files that are not imported.

Independent, hand-written Lean checks should be imported through `Ragu.Contrib`, not through the Rust extraction exporter.
