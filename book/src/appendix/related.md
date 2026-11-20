# Related Work

Ragu builds on a decade of progress in recursive proof composition. This
section surveys the systems and techniques most relevant to its design,
grouped by the role they play.

## Accumulation and folding schemes

Ragu avoids verifying a full proof inside the recursive circuit.
Instead, the verifier defers expensive checks by folding claims
into an _accumulator_ that can later be checked by a decider.

[**Halo [BGH19]**](https://eprint.iacr.org/2019/1021) introduced this
idea as _nested amortization_. The prover witnesses the claimed output of
the IPA verifier and reduces old and new instances together via a random
spot check, turning an expensive linear-time verification into a
lower-cost in-circuit accumulator update. Ragu's accumulation scheme
descends directly from this construction.

[**BCMS20**](https://eprint.iacr.org/2020/499) formalized the idea as
_accumulation schemes_, separating the accumulator object from the
underlying proof system. Claims can be inserted cheaply; the expensive
check is deferred to a _decider_.

[**Split accumulation [BCLMS20]**](https://eprint.iacr.org/2020/1618)
refined the model by separating instance (public, succinct) from witness
(private, linear-size). This separation allows Ragu to use a NARK
rather than a full SNARK during recursion: the verifier only processes the
succinct instance, and the prover carries the witness forward until the
decider runs.

[**Nova [KS21]**](https://eprint.iacr.org/2021/370) presented a related
formalization called _folding schemes_, which merge NP statements directly
without invoking a (S)NARK verifier during accumulation. Nova folds
R1CS instances using a single random challenge per step, achieving
minimal in-circuit cost. Its IVC variant replaces per-step SNARK
generation with a single folding operation.

[**Hypernova [KS23]**](https://eprint.iacr.org/2023/573) extended Nova
to support non-uniform computations (where the circuit changes between
steps). Ragu borrows the post-processing technique from Halo, adapted to
the non-uniform PCD model as in Hypernova, to support many circuits in
the computational graph with diminishing overhead.

[**Protostar [BC23]**](https://eprint.iacr.org/2023/620) generalized
folding to richer constraint systems (including custom gates and lookup
arguments) by folding error terms alongside witnesses. Ragu instead
opts for a simpler arithmetization without custom gates or lookups,
trading per-gate expressiveness for a larger number of smaller circuits.

## Arithmetization

[**BCCGP16**](https://eprint.iacr.org/2016/263) introduced the
constraint-system approach that underpins Bulletproofs-style
arithmetic circuits. Ragu's simple R1CS-like arithmetization
follows from this lineage: the prover commits to a witness
vector and proves that it satisfies a set of quadratic
constraints, with verification relying on inner-product
arguments rather than pairings.

## Curve-cycle recursion

Recursive proof systems over elliptic curves must perform scalar
arithmetic natively in the circuit's field. When the curve's scalar field
differs from the circuit field, this arithmetic becomes non-native and
expensive.

The _Pasta curves_ (Pallas and Vesta) form a 2-cycle: each curve's
scalar field is the other's base field. Ragu evaluates its primary and
secondary circuits on opposite sides of the cycle, avoiding non-native
field arithmetic in most operations.

[**CycleFold [KS23b]**](https://eprint.iacr.org/2023/1192) refined
curve-cycle recursion by splitting the non-native group operations into
a secondary circuit on the companion curve. Ragu adopts a
CycleFold-inspired design to eliminate the remaining non-native
arithmetic that arises during accumulation.

## Polynomial commitment schemes

Ragu uses Pedersen vector commitments with a modified
[Bulletproofs [BBBPWM17]](https://eprint.iacr.org/2017/1066)-style
inner product argument for polynomial evaluation proofs. This choice
avoids a trusted setup and retains the linear homomorphism needed for
accumulation. The [SHPLONK [BDFG20]](https://eprint.iacr.org/2020/081)
batching technique reduces the number of IPA openings when multiple
polynomials are queried at different points.

Pairing-based alternatives, including KZG-based PlonK-family systems
and Groth16, offer constant-size proofs and effectively constant-time
verification, but require a trusted setup ceremony and do not support
transparent recursion on a curve cycle.

## Earlier PCD constructions

The first practical PCD systems composed pairing-based SNARKs over
cycles of pairing-friendly curves. Beyond the trusted-setup cost
described above, these systems required much larger curves with
complicated assumptions. Ragu accepts linear-time verification in
exchange for transparent setup and compatibility with the smaller,
deployment-ready Pasta curves.

## Ragu's position

Ragu occupies a specific point in the design space: transparent
(ECDLP-based, no trusted setup), curve-cycle native (Pasta curves,
CycleFold-inspired recursion), built on split accumulation with a
simple R1CS-like arithmetization (no custom gates or lookups), and
supporting non-uniform PCD over univariate polynomials without
verification keys.

The combination of IPA commitments and an algebraic hash
(Poseidon) means Ragu does not require FFTs or polynomial
multiplications of the size of a circuit except at uncommon protocol
boundaries, as the in-circuit verifier only processes succinct
accumulator instances and field-native hashes. The only FFTs of a fuse
interpolate one restriction of each registry over that registry's
domain, whose size is on the order of the number of registered
circuits. This is in sharp contrast to the
hand-optimized PlonK-based arithmetization used in Halo2, which
relies on FFT-intensive polynomial IOPs.

For verification-cost estimates against the existing Orchard
deployment, see the [Analysis](../protocol/analysis.md) chapter.
