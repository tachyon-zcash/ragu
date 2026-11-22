# Overview

Ragu implements the ECDLP-based recursive SNARK construction from
[Halo [BGH19]](https://eprint.iacr.org/2019/1021) with some simplifications
and adaptations based on modern techniques from the literature of
[accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370)
in the years that followed. The main _external_ ingredients of Ragu are:

* Univariate polynomial commitments via linearly homomorphic Pedersen vector
  commitments and a modified
  [Bulletproofs [BBBPWM17]](https://eprint.iacr.org/2017/1066)-style inner
  product argument (IPA) similar to the construction deployed in
  [`halo2`](https://github.com/zcash/halo2).
    * Realized using the
      [Pasta curve cycle](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)
      designed for and deployed in Zcash's
      [Orchard protocol](https://zcash.github.io/orchard/).
    * Incorporating
      [SHPLONK [BDFG20]](https://eprint.iacr.org/2020/081) multi-point
      polynomial queries.
* Simple R1CS-like arithmetization based on the
  [[BCCGP16]](https://eprint.iacr.org/2016/263) lineage of argument
  systems, though considerably simplified compared to the original Halo
  protocol.
* Support for
  [split accumulation [BCLMS20]](https://eprint.iacr.org/2020/1618)
  techniques to improve performance and simplify the construction.
* [CycleFold](https://eprint.iacr.org/2023/1192)-inspired recursion design
  for eliminating unnecessary non-native field arithmetic.
* Pre-processing is avoided using the _post_-processing technique from Halo,
  adapted to the non-uniform PCD model (as in
  [Hypernova](https://eprint.iacr.org/2023/573)). Many circuits can be
  supported in the computational graph with diminishing overhead,
  verification keys are unnecessary, and pre-computations done by the prover
  are negligible in time and memory usage.
* Prolific use of [Poseidon](https://eprint.iacr.org/2019/458) for the purposes of
  Fiat-Shamir transformations.

Ragu's design is informed by practical requirements for its deployment in
Zcash as part of [Project Tachyon](https://tachyon.z.cash/). We seek a
performance profile that is comparable to the existing proofs deployed in the
[Orchard protocol](https://zcash.github.io/orchard/) (based on the
[`halo2`](https://github.com/zcash/halo2) crate). We would also prefer
compatibility with the
[Pasta](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)
elliptic curves (used for signing in hardware wallets, for example) as
deployed in Orchard.

## Reading Routes {#reading-routes}

Several chapters of this part describe the same protocol, each for a different
question.

| Question | Chapter |
|---|---|
| Why does the protocol have these components? | [The Refinement Ladder](ladder/index.md) starts from a verifier that checks everything and makes one change per rung. |
| What happens during a fuse? | The [Fuse PIOP](iop.md) follows one fuse round by round, and its [contract](iop.md#iop-contract) says what a fuse establishes. |
| What is the exact representation, order or circuit contract? | [Construction](construction/index.md) is the reference that the other chapters link. |
| What is assumed, and what is left open? | [Assumptions of the Argument](ladder/assumptions.md) lists both. |
| How does a root proof reach a verifier, or an aggregator? | [Compression](recursion/compression.md) and [Decompression](recursion/decompression.md). |

## ECDLP-based Protocol

Tachyon will need _small_ recursive proof sizes for deployment in Zcash,
given our existing [Zerocash](https://eprint.iacr.org/2014/349)-based
protocol. Given the current state-of-the-art, this essentially limits us to
ECDLP-based constructions with our existing payment protocol
architecture.[^postquantum] Our existing protocol (Orchard) uses the
cryptography needed already, and much of it has been deployed in production
in things like hardware wallets.

[^postquantum]: We have [reduced concern](https://seanbowe.com/blog/zcash-and-quantum-computers/) (in the medium term) for post-quantum _soundness_ risks.

Our strong desire to avoid a trusted setup limits us to vector (and
polynomial) commitment schemes based on the modified
[inner product argument](https://eprint.iacr.org/2017/1066) from
Bulletproofs, in order to achieve succinctness. Avoiding expensive
verification time (with respect to group arithmetic) involves reducing the
maximum size of the committed vectors—this requires a careful trade-off with
prover performance and implementation complexity, but can be achieved thanks
to the fact that Pedersen commitments are linearly homomorphic.

## First-class Polynomial Oracles

Ragu internally uses an accumulation scheme (heavily based on Halo), which
provides the best recursion performance of known ECDLP-based constructions.
Because we already perform general accumulation operations internally (in
particular, folding claims about polynomial commitments) we can easily expose
polynomial oracle queries to applications.

As an example heavily used in Tachyon, the ability for applications to query
(arbitrary) polynomial commitments can be used to construct
[dynamic memory checking protocols](https://eprint.iacr.org/2024/979). Ragu
embraces _univariate_ polynomial commitment schemes (rather than multilinear
schemes) because the construction we present can largely avoid polynomial
multiplications and encoding witnesses in the Lagrange basis _without_ using
the sum-check protocol.

## Simple Circuit Model

The requirement for smaller committed vectors requires either splitting up
our recursive SNARK protocol into many separate circuits (corresponding to
different portions of the witness) _or_ requires extensive use of clever
optimizations like custom high-degree gates, or worse, a combination of the
two. Considering that Ragu is a PCD-based scheme anyway, we attempt to
_maximize_ along the dimension of having many (smaller) circuits, and
_minimize_ along the dimension of arithmetization complexity.

This has led to two fundamental design decisions:

* **Simple arithmetizations.** The central protocol uses a simple R1CS-like
  arithmetization based on the
  [[BCCGP16]](https://eprint.iacr.org/2016/263) lineage of argument
  systems, with a cost model similar to that of QAP-based SNARKs like
  [[Groth16]](https://eprint.iacr.org/2016/260). Notably, there is no need
  to _materialize_ sparse R1CS matrices or expensive QAP reductions; it
  supports unlimited fan-in addition gates, and the polynomials encoding the
  circuit can be synthesized directly. There are no custom gates and no
  lookup arguments, though individual applications can implement more exotic
  cryptographic schemes based on the first-class polynomial oracle support.
* **Non-uniform circuits.** Ragu embraces a non-uniform circuit model which
  allows the prover to switch between any number of hundreds (or thousands)
  of circuits within the computational graph at any point in the PCD tree.
  This is done without the use of verification keys, using the
  _post-processing_ technique originally presented in Halo. Due to the
  relatively small cost of supporting many circuits, circuits can optimize
  for being decomposed into as few (smaller) separate circuits that
  "communicate" along the PCD tree, rather than individually being more
  efficient due to aggressive optimization techniques and arithmetizations.


-----

STUFFING THIS HERE TEMPORARILY:::


## Cycles of Elliptic Curves {#cycles}

The first practical realizations of PCD used recursive SNARKs built using
pairing-friendly elliptic curves. In these earlier protocols the SNARK verifier
was asymptotically efficient—usually constant-time, regardless of the complexity
of the statement being checked. Because of this, proof verifiers could be
encoded alongside the transition predicates they certified, and the recursive
circuit converged to a finite size, enabling PCD.

There remained some efficiency concerns with this approach. Earlier recursive
SNARK constructions were instantiated over [cycles of elliptic
curves](https://eprint.iacr.org/2014/595) to minimize the expensive non-native
field arithmetic needed by the SNARK verifier, which itself still had to be
encoded into an arithmetic circuit. The resulting constructions, while barely
practical, required a mixture of very large elliptic curves, complicated
cryptographic assumptions, and (notably) trusted setups.

## Accumulation and Folding Schemes {#accumulation-and-folding}

[Halo] introduced a new technique for realizing IVC using recursive SNARKs,
observing that in some SNARKs the most expensive (and especially linear-time)
portions of the verifier circuit could be continually deferred in a process
referred to as "nested amortization." In short, the prover in each IVC step
could witness the _claimed_ output of an expensive verifier check (as advice)
and the statement could embed this claim into the instance. Then, through the
use of a special non-interactive protocol, two or more instances of these claims
could be reduced together into a single claim in each IVC step.

This was realized in two separate ways:

1. Halo avoided the linear-time cost of evaluating a large bivariate public
polynomial $s(X, Y)$ needed to verify the SNARK by taking a claimed commitment
to $S = s(X, y)$ as advice, and encoding the claim $(S, y)$ in the instance. In
each step, a parallel protocol (involving a multivariate consistency check)
could be applied to reduce claimed commitments together via random spot
validation. As a result, all _prior_ evaluations of $s$ could be established
with high probability just by checking the _final_ claim encoded in the
instance.
2. The SNARK (and the amortization process for $s$) both relied on a polynomial
commitment scheme constructed using the inner product argument, which requires a
linear-time group polynomial evaluation $G = g_\mathbf{u}(\mathbf{X})$ to
verify. But because $g_\mathbf{u}(\mathbf{X}) = \com(g_\mathbf{u}(X))$ is a
linearly homomorphic commitment to a succinct polynomial $g_\mathbf{u}$, the
claim $(G, \mathbf{u})$ could be embedded into the instance and multiple such
claims could be merged in each step through random spot checks.

Halo's technique was later modularized as an [accumulation
scheme](https://eprint.iacr.org/2020/499) for PCD. In this interpretation, each
step of PCD involves adding SNARKs to an _accumulator_ object. The accumulator,
which is analogous to the claim encoded in Halo's recursive SNARK instance, can
be _decided_ at any point with a (possibly expensive) verification operation
that determines the correctness of all the inserted SNARKs by induction. The
insertion protocol, which mirrors nested amortization's probabilistic reduction
step, remains comparatively cheap to verify. The accumulation scheme
formalization resembles what actually occurs in the more familiar setting of
batch verification.

The original formalization of accumulation schemes assumed that the accumulator
(instance) was sufficient to create and verify insertion transcripts. In a
follow-up work, the same authors presented a generalization called [split
accumulation] (as opposed to the original so-called _atomic_ accumulation) which
considered a separate witness only required by the accumulation prover and
decider, _not_ the accumulation verifier. This generalization expanded the set
of protocols that could function for the purpose of PCD, including NARKs
(non-succinct SNARKs). Later formalizations such as [folding schemes] present a
related alternative that purely involves merging NP statements themselves,
without the use of any (S)NARK verifier during accumulation.

[Halo]: https://eprint.iacr.org/2019/1021
[folding schemes]: https://eprint.iacr.org/2021/370
[split accumulation]: https://eprint.iacr.org/2020/1618
