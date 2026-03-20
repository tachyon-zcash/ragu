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
  - [Routines](guide/routines.md)
  - [The Primitives Standard Library](guide/standard_library.md) <!-- todo -->
  - [Writing Circuits](guide/writing_circuits.md) <!-- todo -->
  - [Configuration](guide/configuration.md) <!-- todo -->
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
  - [Recursion]()
    - [Public Inputs](protocol/recursion/public_inputs.md) <!-- todo -->
  - [Analysis](protocol/analysis.md) <!-- todo -->
- [Part III: Implementation]()
  - [Architecture Overview](implementation/arch.md) <!-- todo -->
  - [Circuits](implementation/circuits.md) <!-- todo -->
  - [Routines](implementation/routines.md) <!-- todo -->
  - [Polynomial Management](implementation/polynomials.md) <!-- todo -->
  - [PCD Step and Proofs](implementation/proofs.md) <!-- todo -->
  - [Staging](implementation/staging.md) <!-- todo -->
  - [Drivers]()
    - [Writing Custom Drivers](implementation/drivers/custom.md) <!-- todo -->

---

# Appendices

- [Bootle16 v.s. R1CS](appendix/cs.md) <!-- todo -->
- [Related Work](appendix/related.md) <!-- todo -->
- [SNARKs](appendix/snarks.md) <!-- todo -->
- [Terminology](appendix/terminology.md) <!-- todo -->
