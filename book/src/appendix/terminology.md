# Terminology

## Protocol concepts

| Concept | Term | Reference |
|---------|------|-----------|
| Computation organized around a transition predicate; each step consumes prior instances and produces a new one | **Proof-carrying data (PCD)** | [Concepts: PCD](../concepts/pcd.md) |
| Restricted PCD where each step consumes a single predecessor, forming a linear chain | **Incrementally verifiable computation (IVC)** | [Concepts: PCD](../concepts/pcd.md) |
| Non-interactive argument with a succinct instance but potentially linear-size witness | **NARK** | [NARK chapter](../protocol/core/nark.md) |
| Succinct non-interactive argument of knowledge; the proof is much smaller than the computation and fast to verify | **SNARK** | [Appendix: SNARKs](snarks.md) |
| Deferral of expensive verification by folding claims into an accumulator eventually checked by a decider | **Accumulation scheme** | [Accumulation](../protocol/core/accumulation/index.md) |
| Accumulation variant separating the succinct instance from the linear-size witness | **Split accumulation** | [Accumulation](../protocol/core/accumulation/index.md) |
| Application-defined state carried through PCD steps; specifies the output gadget type | **Header** | [Concepts: PCD](../concepts/pcd.md) |
| Discriminant allowing headers to be distinguished by semantic value | **Suffix** | [Concepts: PCD](../concepts/pcd.md) |
| Final verifier that runs the deferred expensive check on accumulated claims | **Decider** | [Accumulation](../protocol/core/accumulation/index.md) |

## Arithmetization

| Concept | Term | Reference |
|---------|------|-----------|
| Multiplication checks $\v{a}_i \cdot \v{b}_i = \v{c}_i$ and $\v{c}_i \cdot \v{d}_i = 0$ over four wires $(A, B, C, D)$ | **Gate** | [Arithmetization](../protocol/local/arithmetization.md) |
| Fixed linear form on wires that must equal an instance value | **Constraint** | [Arithmetization](../protocol/local/arithmetization.md) |
| Value a constraint requires a linear form to equal (zero or public input) | **Instance** | [Arithmetization](../protocol/local/arithmetization.md) |
| Assignment of field values to wires satisfying all gates and constraints | **Witness** | [Arithmetization](../protocol/local/arithmetization.md) |
| Assignment of field values to every wire, encoding as polynomial $r(X)$ | **Trace** | [Arithmetization](../protocol/local/arithmetization.md) |
| Polynomial specified by four vectors $(\v{a}, \v{b}, \v{c}, \v{d})$ with the coefficient layout defined in the [arithmetization chapter](../protocol/local/arithmetization.md) | **Structured polynomial** | [Arithmetization](../protocol/local/arithmetization.md) |
| Bivariate polynomial $s(X, Y)$ encoding all circuit constraints; fixed by the circuit definition | **Wiring polynomial** | [Wiring](../protocol/local/wiring.md) |
| First gate; ensures the ONE wire equals 1 | **SYSTEM gate** | [Wiring](../protocol/local/wiring.md) |

## Registry, Stage, and Circuit Terminology Mapping

| Concept | Term | Code Reference |
|---------|------|----------------|
| Defines stage structure; specifies wire range and corresponds with a stage polynomial that represents a partial trace | **Stage** | `preamble::Stage` |
| Input data for a stage | **Stage witness** | `Stage::witness()` |
| Well-formedness check for a stage; $s$ polynomial enforcing independence (for multi-stage circuits, these masks are batched in the revdot check) | **Stage mask** | `Stage::mask()` or `Stage::final_mask()` |
| Circuit using staged traces | **Multi-stage circuit** | `MultiStageCircuit` |
| Combined witness across all stages | **Multi-stage witness** | implicit, concatenation of stage witness |
| Combined $r(X) = a(X) + b(X) + \cdots + f(X)$ | **Multi-stage trace polynomial $r(X)$** | implicit, sum of all `Stage::rx()` |
| Collection of circuits indexed by $\omega^i$; $m(W, X, Y)$ interpolating wiring polynomials | **Registry** | `Registry`, `RegistryBuilder` |

## Polynomial operations

| Concept | Term | Notation |
|---------|------|----------|
| Pair-wise product of two vectors | **Hadamard product** | $\v{a} \circ \v{b}$ |
| Inner product | **Dot product** | $\dot{\v{a}}{\v{b}}$ |
| Dot product with one vector reversed: $\dot{\v{a}}{\rv{b}}$ | **Revdot product** | $\revdot{\v{a}}{\v{b}}$ |
| Reversed coefficient vector | **Reversal** | $\rv{p}$ |
| Transformation $p(zX)$ via Hadamard product with powers of $z$ | **Dilation** | [Notation](../protocol/prelim/notation.md) |

## Proof lifecycle

| Concept | Term | Reference |
|---------|------|-----------|
| Large proof string used during recursive fusion; linear-size witness attached | **Uncompressed proof** | [Concepts: PCD](../concepts/pcd.md) |
| Succinct proof for transmission; orders of magnitude smaller than uncompressed | **Compressed proof** | [Concepts: PCD](../concepts/pcd.md) |
| Recursive composition of proofs along a PCD tree | **Fuse** | [Architecture](../implementation/arch.md) |
| Post-fuse transformation producing a fresh proof of the same certified data | **Rerandomization** | [Concepts: PCD](../concepts/pcd.md) |
