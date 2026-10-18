# Assumptions
## Assumptions for the Ragu Formal Verification to be mathematically meaningful

The Ragu Formal Verification relies on some assumptions.

- The extraction is correct
    - The semantics of the Ragu Driver operations are correctly captured, and
      are correctly translated into Clean operations (i.e., the extracted
      operations and the Ragu circuit are semantically equivalent)
    - The inputs/outputs serialization is done correctly and done
      deterministically
    - The Rust extraction and Lean extraction use the same ordering of elements
      during serialization of structures
    - The circuit instance is defined correctly and is coherent with the goal of
      the FV

- The fingerprint equivalence check is meaningful
    - Equality of operation traces and output expressions suffices to fully
      characterize semantic equivalence of circuits
    - The Rust and Lean implementations of the canonical encoding both realize
      the documented encoding, and the encoding is injective
    - SHA-256 is collision resistant
    - Agreement of the traces at the canonical input vector implies agreement at
      all inputs (the reimplementations do not special-case the canonical input)

- The direct randomized polynomial check is meaningful
    - The Rust and Lean implementations realize the documented versioned
      challenge derivation, slot mapping, ordering, and accumulator equations
    - SHA-256 behaves as independent random-oracle outputs on the
      domain-separated challenge inputs
    - A Rust/Lean disagreement gives a nonzero polynomial whose degree is no
      greater than the checked structural bound
    - The fresh CI seed is generated after the compared revision is fixed and
      is supplied unchanged to both evaluators

- The assumptions and specification properties suffice to fully characterize the
  circuit within the scope of the FV (e.g., we could prove a Spec that does not
  imply some real-world broader property we care about)

- The lean "core" statements are correct
    - the formal instance in lean is correct
    - the Clean core statements about circuit semantics and subcircuit
      composition are correct
    - the Lean elaborater creates an internal representation of the statement
      (to be checked together with the proof term by the Lean kernel) in a way
      that keeps the correct intention

- The logical foundation is not contradictory
    - The Lean kernel theory and implementation are sound.
    - Each theorem's transitive axioms stay within its declared trust budget.
      `#print axioms <theoremName>` lists them, and `Ragu.Meta.TrustBoundary`
      enforces the budget during the build. The standard theorem tier permits
      `propext`, `Classical.choice`, and `Quot.sound`.
    - The concrete Pasta endoscaling theorems additionally reuse the existing
      CompElliptic group-order certificates `Pallas.q_nsmul_Gpt` and
      `Vesta.p_nsmul_Gpt`, as appropriate for the curve. Those certificates
      use `native_decide` and therefore trust compiled evaluation. Each
      dependent endpoint names the exact certificate it uses. The integer
      bounds and affine/group bridge introduce no additional native
      certificates or axioms. The Pasta primality results are proved theorems,
      not assumed primality axioms.

## Assumptions for the Ragu Formal Verification to be useful

### General Remarks

Any gaps between the reality and the formalization can render the Ragu Formal
Verification to be useless. Also, any gaps between expectations (yours or
others', documented or undocumented, conscious or unconscious) and the
formalization can render the Ragu Formal Verification to be useless.

Lean theorems mean that any model of Lean type theory that satisfies all the
assumptions, arguments and hypotheses of the theorem also satisfies the
conclusion of the theorem. The Lean theorems in this project talk about field
elements. In order to use the Lean theorems to reason about the implementation,
the field elements in Lean need to correspond to field elements in the
implementation. The field elements in the implementation might exist verbatim in
the memory (of the prover or the verifier), in the network, or only conceptually
accessible through commitment schemes. When the same variable is used multiple
times in a Lean statement, all occurrences of the same variables need to
correspond to the same field element in the implementation.

Lean and other proof assistants that are based on intuitionistic and classical
logic suffer from a problem called
[explosivity](https://plato.stanford.edu/archives/fall2017/entries/logic-paraconsistent/).
From a contradiction about any topic, it is possible to prove all true and false
statements. For this reason, when any one of arguments or hypotheses is false, a
theorem in Lean does not carry any guarantees.

Because of explosivity, approximations do not work well with Lean and other
proof assistants. Just because a situation looks close to satisfy the hypotheses
of a theorem, that doesn't mean that the situation is close to satisfy the
conclusion of the theorem. The logic behind Lean and other proof assistants does
not have the notion of degree of falsehood so any tiny gap between the reality
and the formalization can be used to prove things that are utterly wrong. If a
situation doesn't satisfy all hypotheses of a Lean theorem, the Lean theorem
doesn't apply to the situation.

It is difficult to list all potential gaps between the reality and the
formalization. The same holds for potential gaps between the expectations (yours
or others', documented or undocumented, conscious or unconscious) and the
formalization. The potential gaps listed are just some typical examples and not
to be taken as exhaustive.

Future changes might introduce new gaps.

### Overview

Anything other than the verified circuit is out of scope.

If values in the circuit are copied somewhere else, the soundness theorems of
the Ragu Formal Verification results don't tell the verifier anything about the
copied values. The soundness theorems might not be applicable because of missing
constraints on the inputs and the outputs of the circuit. The verifier needs to
be sure of the Lean assumptions of the circuit soundness without relying on the
circuit. The prover needs to be sure of the Lean assumptions of the circuit
completeness without relying on the circuit.

The completeness theorem in the Ragu Formal Verification does not guarantee that
the honest prover implementation does produce a proof that passes the
verification. The Ragu Formal Verification does not prove any theorems about the
Rust implementation of anything. The completeness results in Ragu Formal
Verification just talk about the `witness` operations in the Lean code. The Lean
`witness` operations are not compared against extractions from Rust.

### Assumptions about implementation

Everything in the Rust source, the Rust compiler, the hardware, and the physical
and social level is out of scope of formal verification. The mathematical theory
behind the protocol is mostly out of scope. For example, the cryptographic
reductions and the cryptographic assumptions are out of scope. The Rust
implementation might behave in a nondeterministic way so that it might sometimes
or always use different constraints from the constraints that it exports.

The implementation of the circuit proof system (both theory and implementation)
needs to be sound for the soundness result of Ragu Formal Verification to be
useful. The soundness of the backend proof system (both theory and
implementation) is required. Bugs in libraries, Fiat-Shamir issues (hash
function is not random oracle, forgetting transcript elements for Fiat-Shamir),
bugs in the prover & verifier implementations, incorrect compilation of the
circuit, incorrect field arithmetics, bugs in the Rust compiler, bugs in the
Rust source code, bugs in operating system, hardware bugs, issues around using
GPUs, advances in cryptoanalysis, powerful enough quantum computers and
breakdowns of laws of physics (like elsewhere the examples are not exhaustive)
can all render the soundness result of Ragu Formal Verification to be useless.

The completeness result of Ragu Formal Verification has similar limitations.
Moreover, since the completeness result is only useful when it's combined with
availability of the whole system including the prover, the verifier, the
communication between them and actors who operate on these.

### Assumptions about deployment and protocol

Issues in deployment and integration can render the Ragu Formal Verification
useless. Availability or integrity issues in the prover or the verifier in
software, hardware, building, energy supply, network connectivity or operations,
can render the Ragu Formal Verification useless. The same can be said for
communication between the prover and the verifier, and the system that use the
result that the verifier produces. The result of formal verification is not
useful when the user of the prover fails to identify the honest prover
implementation with the correct public key, or when the system that uses the
result of the verifier fails to identify the verifier implementation with the
correct verification key. Operational security of parties who operate
cryptography is assumed. Leaks of secrets and UI issues can bypass Ragu Formal
Verification results.

Ragu Formal Verification does not cover issues in the protocol. Ragu Formal
Verification results do not address MEV, front-running, replay attacks or
similar issues.
