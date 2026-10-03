# Summary

[Introduction](introduction.md)
[Proof-carrying data](concepts/pcd.md)

---

- [Part I: User Guide]()
  - [Requirements](guide/requirements.md)
  - [Getting Started](guide/getting_started.md) <!-- todo -->
  - [Drivers](guide/drivers/index.md)
    - [Witness Data](guide/drivers/witness.md)
    - [Linear Expressions](guide/drivers/linear.md)
    - [Concrete Drivers](guide/drivers/concrete.md)
  - [Gadgets](guide/gadgets/index.md)
    - [Simple Gadgets](guide/gadgets/simple.md)
    - [The GadgetKind Trait](guide/gadgets/gadgetkind.md)
    - [The Kind! Macro](guide/gadgets/kind.md)
    - [Conversion](guide/gadgets/conversion.md)
    - [Demotion](guide/gadgets/demotion.md) <!-- todo -->
  - [Routines](guide/routines.md)
  - [Primitives](guide/primitives/index.md) <!-- todo -->
    - [Allocation](guide/primitives/allocation.md) <!-- todo -->
    - [Simulator](guide/primitives/simulator.md) <!-- todo -->
  - [Writing Circuits](guide/writing_circuits.md) <!-- todo -->
  - [Configuration](guide/configuration.md) <!-- todo -->
  - [Step Capacity and Proving Cost](guide/capacity.md)
- [Part II: Protocol Design]()
  - [Overview](protocol/index.md) <!-- todo -->
  - [Preliminaries]()
    - [Cryptographic Assumptions](protocol/prelim/assumptions.md) <!-- todo -->
    - [Notation](protocol/prelim/notation.md) <!-- todo -->
    - [Structured Vectors](protocol/prelim/structured_vectors.md) <!-- todo -->
    - [Nested Commitment](protocol/prelim/nested_commitment.md) <!-- todo -->
    - [Bulletproofs IPA](protocol/prelim/bulletproofs.md) <!-- todo -->
    - [Transcript](protocol/prelim/transcript.md) <!-- todo -->
  - [Core Construction]()
    - [Arithmetization](protocol/core/arithmetization.md) <!-- todo -->
    - [NARK](protocol/core/nark.md) <!-- todo -->
    - [Split-Accumulation Schemes](protocol/core/accumulation/index.md) <!-- todo -->
      - [PCS Batched Evaluation](protocol/core/accumulation/pcs.md) <!-- todo -->
      - [Wiring Consistency](protocol/core/accumulation/wiring.md) <!-- todo -->
      - [Revdot Product](protocol/core/accumulation/revdot.md) <!-- todo -->
  - [Extensions]()
    - [Registry Polynomial](protocol/extensions/registry.md) <!-- todo -->
    - [Endoscalars](protocol/extensions/endoscalar.md) <!-- todo -->
    - [Staging](protocol/extensions/staging.md) <!-- todo -->
  - [Recursion](protocol/recursion/index.md)
    - [Public Inputs](protocol/recursion/public_inputs.md)
    - [Compression](protocol/recursion/compression.md)
  - [Analysis](protocol/analysis.md) <!-- todo -->
  - [Local (Sean's Corner!)]()
    - [Arithmetization](protocol/local/arithmetization.md)
    - [Wiring and Instance Polynomials](protocol/local/wiring.md)
- [Part III: Implementation]()
  - [Architecture Overview](implementation/arch.md) <!-- todo -->
  - [Documenting Circuit Code](implementation/circuit-code-documentation.md)
  - [Circuits](implementation/circuits.md) <!-- todo -->
  - [Routines](implementation/routines.md) <!-- todo -->
  - [Polynomial Management](implementation/polynomials.md) <!-- todo -->
  - [PCD Step and Proofs](implementation/proofs.md) <!-- todo -->
  - [Staging](implementation/staging.md) <!-- todo -->
  - [Drivers]()
    - [Writing Custom Drivers](implementation/drivers/custom.md) <!-- todo -->
- [Part IV: Formal Verification]()
  - [Scope](fv/index.md)
  - [The Clean Framework](fv/clean/index.md)
    - [The Circuit Monad](fv/clean/circuit.md)
    - [A Tiny Multiplication Circuit](fv/clean/mul.md)
    - [Provable Types and Structs](fv/clean/provable.md)
    - [Expressions and Environment](fv/clean/expression.md)
    - [Operations](fv/clean/operations.md)
    - [Formal Circuits](fv/clean/formal.md)
    - [A Full Example](fv/clean/example.md)
    - [Compile-Time Parameters](fv/clean/parameters.md)
  - [Verified Circuits](fv/circuits/index.md)
    - [Extraction](fv/circuits/extraction.md)
    - [Inputs, Outputs, and Serialization](fv/circuits/serialization.md)
    - [Composable Gadget Contracts](fv/circuits/contracts.md)
    - [Fingerprint Equivalence Check](fv/circuits/fingerprint.md)
    - [Direct Randomized Polynomial Check](fv/circuits/polynomial-fingerprint.md)
    - [Assumptions](fv/circuits/assumptions.md)
    - [CI Integration](fv/circuits/ci.md)
- [Part V: Fuzzing]()
  - [Overview](fuzzing/index.md) <!-- todo -->
  - [Oracles](fuzzing/oracles.md) <!-- todo -->
  - [Targets](fuzzing/targets.md) <!-- todo -->
  - [Corpus and Triage](fuzzing/corpus.md) <!-- todo -->
  - [Scheduled Runs](fuzzing/scheduled.md) <!-- todo -->

---

# Appendices

- [Bootle16 v.s. R1CS](appendix/cs.md) <!-- todo -->
- [Related Work](appendix/related.md) <!-- todo -->
- [SNARKs](appendix/snarks.md) <!-- todo -->
- [Terminology](appendix/terminology.md) <!-- todo -->
