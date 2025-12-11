# Proof-Carrying Data

**Proof-Carrying Data (PCD)** is a cryptographic primitive that allows data to
be bundled together with a proof of its correctness. Unlike traditional
[verifiable computation]—in which something like a SNARK is _attached_ to a
piece of data to demonstrate its integrity—new PCD can take as input prior
proofs along with the data they certify. This enables reasoning about an entire
history of previously verified steps, supporting incremental, continual
verification of computation rather than a single, one-shot proof.

This primitive is especially useful in distributed systems: nodes can pass data
around along with evidence of how it is computed, allowing things like entire
blockchain histories to be verified using only a snapshot of the _current_ state
in the form of PCD.

[verifiable computation]: https://en.wikipedia.org/wiki/Verifiable_computing

## IVC vs. PCD

**Incrementally Verifiable Computation (IVC)**, introduced by Valiant in his
2007 [master's thesis](https://iacr.org/archive/tcc2008/49480001/49480001.pdf),
recursively composes non-interactive proofs of knowledge. It can be viewed as a
special, linear-chain instance of what was later
[formalized](http://people.csail.mit.edu/tromer/papers/pcd.pdf) as
Proof-Carrying Data by Tromer and Chiesa in 2010.

IVC deals with linear chains of computation:

```
Step 1 → Step 2 → Step 3 → Step 4
```

At each step, the prover takes as input the previous proof and the data
representing the current state of the computation, verifies that proof, and
outputs new state data together with a fresh proof attesting to the correctness
of this state transition.

PCD generalizes this to tree-structured computations:

```
        Step 3
       /      \
    Step 2a   Step 2b
       \      /
        Step 1
```

Here, the PCD produced in **Step 1** is used as input to two independent steps
(**Step 2a** and **Step 2b**) and the results are used as input for a third
**Step 3**. This illustrates the scalability that makes PCD powerful:
computational integrity is established inductively, and can be computed in
parallel.

```admonish info title="Ragu's Approach"
Ragu provides a PCD framework in which every step is uniformly treated as an
arity-2 node in a PCD tree, always accepting two proofs as input. This simplifies
the design at the cost of reduced flexibility and performance in situations where
only IVC (linear-chain) semantics are necessary.
```

## Accumulation and Folding Schemes

[Halo] introduced a new technique for realizing recursive SNARKs whereby full
verification of previous proofs is continually collapsed at each step, expanding
the space of protocols that could be used to build PCD. This technique was later
formalized and generalized as an [accumulation
scheme](https://eprint.iacr.org/2020/499) (or [folding
scheme](https://eprint.iacr.org/2021/370)).

```admonish info title="Ragu's Approach"
Ragu implements a construction very similar to the original Halo protocol, with
some performance improvements and simplifications that emerged immediately after
its publication.
```

[Halo]: https://eprint.iacr.org/2019/1021

-----

# TODO:

-----

## Recursive Proof Composition

Ragu's power comes from its ability to prove statements about proofs themselves. This recursive property enables:

- **Incremental verification**: Each step verifies previous steps without re-executing them
- **Proof aggregation**: Multiple computations can be combined into a single proof
- **Unbounded computation**: Chain together arbitrarily many steps while keeping verification time logarithmic

The technical details of how this works involve specialized cryptographic primitives and accumulation schemes, but as a library user, you primarily interact with this through Ragu's API for creating, folding, and compressing proofs.

## The Cost Model: Compression vs. Folding

Ragu operates with a single proof structure that can exist in two different modes:

**Uncompressed proofs** (split-accumulation form):
- Non-succinct: size scales with the circuit size
- Large witness data, but inexpensive to generate
- Efficiently "folded" together using accumulation
- This is the natural mode for recursive computation

**Compressed proofs** (IPA-based succinct form):
- Succinct: size is logarithmic in the circuit size
- More expensive to create (compression step)
- More expensive to verify (dominated by linear-time multi-scalar multiplication)
- Optimal for bandwidth-constrained scenarios (e.g., blockchain transactions)

**When to compress:** The key is to operate in uncompressed mode during recursion and only compress at specific boundary conditions. For example, when broadcasting a proof on-chain, you compress to optimize for bandwidth. During intermediate computation steps where you'll continue folding proofs together, keep them uncompressed.

Note that compressed proofs can also be "decompressed" back into the accumulation form when needed for further folding.
