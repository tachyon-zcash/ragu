# Scope

Ragu's soundness rests on its circuits constraining exactly what they are meant
to constrain. A gadget that assigns a wire but never constrains it still
produces proofs that verify, and nothing in the prover objects, because an
honest prover never exercises the gap. Tests sample the input space and
[fuzzing](../fuzzing/index.md) searches it, but a search that finds nothing has
not shown that there is nothing to find. A machine-checked proof has.

This part documents that proof effort: the framework the proofs are written in,
how a Rust circuit is connected to a Lean theorem about it, and — because this
matters more than the theorems themselves — what those theorems do and do not
say. The work is carried out with
[Clean](https://github.com/Verified-zkEVM/clean), a Lean 4 framework for
zero-knowledge circuits developed by the Verified zkEVM project, in
collaboration with [zkSecurity](https://zksecurity.xyz/).

## Two properties

Every verified circuit carries a proof of two properties, stated against
explicit assumptions on its inputs and an explicit specification of its
intended behavior.

**Soundness** says that any witness satisfying the circuit's constraints also
satisfies the specification. This is the direction that rules out
under-constrained circuits, and it is the direction a malicious prover attacks.

**Completeness** says that for inputs satisfying the assumptions, an honest
prover can always produce a satisfying witness. This rules out over-constrained
circuits, which are a liveness problem rather than a soundness one.

Both are conditional on the assumptions, and an assumption the caller does not
actually establish is a hole in the argument rather than a detail. The
[assumptions](circuits/assumptions.md) chapter is the honest accounting of
those conditions, and it is the chapter to read before quoting any result from
this part.

## What is verified today

Verification currently covers the gadget layer: 57 concrete circuit instances,
each one a specific instantiation at a fixed prime field with all compile-time
parameters made concrete.

- **Field elements** — multiplication, squaring, allocation, inversion,
  division by a nonzero element, zero and equality tests, root-of-unity
  enforcement, invertible allocation, enforcement, and re-establishment, and
  folding at four arities.
- **Curve points** — allocation and contract re-establishment on both curves
  of the cycle, doubling, incomplete addition, incomplete double-and-add, and
  conditional endomorphism application and negation.
- **Booleans** — allocation, conjunction, conditional selection, conditional
  equality enforcement, and contract re-establishment.
- **Endoscalars** — allocation, extraction, lifting, and radix-3 group
  scaling, in both the plain form and the hoisted form that reads its digit
  products from stage wires, plus the contract that pins those product wires.
- **Poseidon** — the permutation at the deployed Pasta parameters on both
  fields, and the sponge in several distinct control-flow shapes:
  single-block hashing on each field, uniform blocks across a rate boundary,
  a ragged final block, absorption after a squeeze, repeated squeezes, and
  the save/resume path.
- **Horner evaluation** at three arities, plus the trailing-constant $k(Y)$
  form.
- **Nonzero banks** at three arities, and the core multiplication gate.

Every one of these is proved without `sorry`, and the Lean build runs with
`--wfail` so that an admitted goal fails CI rather than passing quietly. The
axioms each theorem depends on can be listed with `#print axioms`; the
assumptions chapter records which ones appear and what trusting them costs.

## What is not verified

Everything above the gadget layer. The internal recursion circuits, the
accumulation scheme, the staging system, and the protocol as a whole have no
Lean theorems about them.

Some of the gadget layer has nothing to verify rather than something unproved,
and the distinction matters when reading the list above as a coverage claim.
Demotion (`promotion.rs`) strips witness data through a driver whose every
method is unreachable, and the serialization surface (`io.rs`) moves wires
without emitting constraints; a reimplementation of either would prove a
theorem about no constraints. What they are not exempt from is *trust*: the
extractor relies on this serialization to read wires in and out, so a bug there
would change what every other theorem is about.

The `Consistent` implementations are the one place this boundary is easy to
misread. `Boolean`, `Point`, and `Invertible` each re-establish their wire
contracts by allocating a fresh gadget and constraining it equal to the
existing wires — real constraints, emitted where the staging machinery
substitutes wires — and the re-establishment instances above cover exactly
that trace. `Nonzero`'s implementation is `Element::enforce_invertible`, which
is covered under that name.

Neither is any Rust code verified: the proofs are about
circuits extracted from Rust, not about the Rust implementation that extracted
them, and not about the prover and verifier that run the protocol. The
cryptographic assumptions underlying the construction are out of scope by
construction — no proof assistant establishes that the discrete logarithm
problem is hard.

The [assumptions](circuits/assumptions.md) chapter states these boundaries
precisely, including the ways a gap between the formalization and reality makes
a theorem inapplicable rather than merely approximate.

## How the connection is made

Rust circuits and Lean proofs are joined without either side being translated
into the other. Separately from the real Rust gadget, the circuit is
reimplemented in Clean, compositionally and in idiomatic Lean, and the
soundness and completeness theorems are proved about that reimplementation.
CI ties them together in two ways: an exact digest compares the symbolic
extraction trace, and a fresh randomized polynomial check directly runs the
production gadget and independently evaluates the Lean model. Both comparisons
must agree for every enrolled instance.

The exported artifact never has to be rendered into Lean source, the proofs get
the full compositional structure of Clean to work with, and disagreements in
the enrolled driver-level constraints or outputs are detected subject to the
documented exact-hash and randomized-evaluation assumptions. Witness generation
and the deployed backend remain separate obligations. The direct path shares
only a versioned writes-as-polynomials evaluation specification rather than a
complete symbolic Rust trace. The
[Clean](clean/index.md) chapter covers the framework; the
[verified circuits](circuits/index.md) chapter covers extraction, the digest
and randomized checks, and the CI wiring.

## Where this is going

The gadget layer is the foundation for the result that matters: **one layer of
recursion**. Verifying a step circuit that verifies a proof is qualitatively
harder than verifying a multiplication gadget, since the specification is
itself a statement about the proof system, and it is the point at which formal
verification starts to say something about Ragu as a recursive proof system
rather than about its parts.

Beyond that sits an open question about what the security model should even be.
Knowledge soundness for PCD is argued by exhibiting an extractor that recovers
a witness from a convincing prover, and the cost of that extractor grows with
recursion depth — an extractor exponential in the depth is a real bound, but a
weak one. Mina addressed this by adopting
[chain extractability](https://minaprotocol.com/wp-content/uploads/technicalWhitepaper.pdf),
a weaker but more practical model than full knowledge soundness. Whether Ragu
should follow, or whether straightline extraction gives a tighter bound, is
undecided; the answer changes what a formalization of recursion should be
proving.

```admonish note
The knowledge extractor of the security argument and the extraction driver of
the next chapter are unrelated things that share a name. The former is a
hypothetical algorithm in a soundness proof; the latter is a Rust driver that
logs circuit operations.
```
