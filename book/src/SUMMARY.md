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
  - [Construction](protocol/construction/index.md)
    - [Arithmetization](protocol/construction/arithmetization.md)
      - [Wiring and Instance Polynomials](protocol/construction/wiring.md)
      - [Stages and Bonding Polynomials](protocol/construction/staging.md)
      - [Registry](protocol/construction/registry.md)
    - [Curve Cycle](protocol/construction/cycle.md)
    - [Setup](protocol/construction/setup.md)
    - [Proof](protocol/construction/proof.md)
    - [Claims and Fold](protocol/construction/claims.md)
    - [Batched Opening](protocol/construction/batch.md)
    - [Walks](protocol/construction/walks.md)
    - [Stage Contents](protocol/construction/stage_contents.md)
    - [Internal Circuits](protocol/construction/internal_circuits.md)
    - [Protocol](protocol/construction/protocol.md)
    - [Fuse](protocol/construction/fuse.md)
    - [Base Case](protocol/construction/base_case.md)
    - [Decider](protocol/construction/decider.md)
  - [The Refinement Ladder](protocol/ladder/index.md)
    - [Rung 0: A Verifier of the Whole History](protocol/ladder/rung_00.md)
    - [Rung 1: One Node, One Equation](protocol/ladder/rung_01.md)
    - [Rung 2: Commitments and Three Expensive Jobs](protocol/ladder/rung_02.md)
    - [Rung 3: An Accumulator of Carried Claims](protocol/ladder/rung_03.md)
    - [Rung 4: A Merge of Two Revdot Claims](protocol/ladder/rung_04.md)
    - [Rung 5: One Quotient Instead of a Matrix of Cross Terms](protocol/ladder/rung_05.md)
    - [Rung 6: A Fold in Two Layers](protocol/ladder/rung_06.md)
    - [Rung 7: Evaluation Checks for the Folded Polynomials](protocol/ladder/rung_07.md)
    - [Rung 8: The Registry and the Merge of Wiring Claims](protocol/ladder/rung_08.md)
    - [Rung 9: One Quotient Test for Many Openings](protocol/ladder/rung_09.md)
    - [Rung 10: One Opening, Carried Forward](protocol/ladder/rung_10.md)
    - [Rung 11: A Second Curve and a Second Accumulator](protocol/ladder/rung_11.md)
    - [Rung 12: A Verifier Split Across Circuits by Stages](protocol/ladder/rung_12.md)
    - [Rung 13: Challenges Hashed Inside the Circuits](protocol/ladder/rung_13.md)
    - [Rung 14: Bindings of Claims to the Statement](protocol/ladder/rung_14.md)
    - [Rung 15: The Decider at the Root](protocol/ladder/rung_15.md)
    - [Rung 16: Compression of the Decider's Checks](protocol/ladder/rung_16.md)
    - [The Ladder at a Glance](protocol/ladder/glance.md)
    - [Assumptions of the Argument](protocol/ladder/assumptions.md)
  - [Fuse IOP](protocol/iop.md)
  - [Compression](protocol/recursion/compression.md)
  - [Decompression](protocol/recursion/decompression.md)
  - [Analysis](protocol/analysis.md) <!-- todo -->
  - [Poly Oracle](protocol/poly-oracle.md) <!-- todo -->
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

---

# Appendices

- [Bootle16 v.s. R1CS](appendix/cs.md) <!-- todo -->
- [Related Work](appendix/related.md) <!-- todo -->
- [SNARKs](appendix/snarks.md) <!-- todo -->
- [Terminology](appendix/terminology.md) <!-- todo -->

---

# Recycle Bin

- [NARK](recycle/nark.md) <!-- todo -->
- [Split-Accumulation Schemes](recycle/accumulation.md) <!-- todo -->
- [Wiring Consistency](recycle/wiring_consistency.md) <!-- todo -->
- [Nested Commitment](recycle/nested_commitment.md) <!-- todo -->
- [Bulletproofs IPA](recycle/bulletproofs.md) <!-- todo -->
- [Endoscalars](recycle/endoscalar.md) <!-- todo -->
