# Nested Commitments

Ragu uses a
[curve cycle](https://zcash.github.io/halo2/background/curves.html#cycles-of-curves).
Concretely, we use
[Pallas/Vesta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)
where each curve's scalar field is the other's base field.

- Vesta has base field $\F_q$ and scalar field $\F_p$
- Pallas has base field $\F_p$ and scalar field $\F_q$

During recursive proofs, you often need to commit to data that lives in the 
"wrong" field — for example, representing Vesta points (with $\F_q$ coordinates)
inside an $\F_p$ circuit.

A **nested commitment** solves this by wrapping a commitment from one curve in
a commitment on the other:

* Encode the coordinates of the original commitment points as a polynomial
* Commit to that polynomial with coefficients in the foreign field
* The resulting (nested) commitment point has coordinates in the native field

### Example

You're in an $\F_p$ circuit with witness polynomial $\v{a}\in\F^n$ and need to
hash a commitment $A$ (Vesta point with $\F_q$ coordinates)
into the [transcript](./transcript.md).
Even with algebraic hash function, you can't hash $\F_q$ elements natively 
in $\F_p$ and non-native arithmetic is expensive.

<p align="center">
  <img src="../../assets/nested_commitment.svg" alt="nested_commitment" />
</p>

The *nested commitment* $\mathring{A}$ cryptographically binds the original data 
while being native to the $\F_p$ circuit. 

### Deferred Operations

Nested commitments only bind the original data, but doesn't translate any
intended operation over. 
If we want to operate on the original commitment $A\in\G_{host}$ (say $s\cdot A$),
we can't constrain such operation natively in $\F_p$ circuit that only receives
$\mathring{A}\in\F_p^2$ as non-deterministic advice/witness.
Instead, we _defer_ these group operations to the other field $\F_q$ 
during the recursion since they witness the coordinate representation of
$A\in\G_{host}$ and can enforce scalar multiplication natively.
Additionally, we need to transfer the scalar $s\in\F_p$ across the circuits,
with the help of [endoscalars](../extensions/endoscalar.md) so that scalar
multiplication in $\F_q$ circuit becomes efficient _endoscaling_.
The $\F_q$ circuit will generate a proof which itself will be recursively
(partial-) verified by an $\F_p$ circuit in the next recursion step.

Furthermore, define $A(X)\in\F_q[X]$ the _partial witness polynomial_ (a.k.a.
[staging polynomial](../extensions/staging.md)) that encodes $A$.
Since $A(X)$ is only a partial witness of the $\F_q$ circuit,
we need to further enforce the consistency between its commitment $\mathring{A}$
and the overall witness polynomial commitment $R\in\G_{nested}=\com(r(X)\in\F_q[X])$.
Both $\mathring{A}$ and $R$ are available to the next $\F_p$ circuit step.

<p align="center">
  <img src="../../assets/defer.svg" alt="defer_example" />
</p>

Ensuring this consistency checks constitutes two _well-formedness_ requirements:
1. $A(X)$ doesn't overlap with other partial-witness (e.g. $B(X)$)
2. Their commitments adds up to the overall witness polynomial commitment 
(e.g. $R=\mathring{A} + \mathring{B}$)

The first statement is checked via a revdot product as part of the $\F_q$ circuit;
the second statement is checked in-circuit as part of the "next $\F_p$" circuit.
See details in the [staging section](../extensions/staging.md).

In each PCD step, both curves work together simultaneously in a cycle-fold inspired
design. The $\F_p$ recursion circuit handles proof/accumulator merging and uses
nested commitments $\mathring{A}, \mathring{B},\ldots$ as non-deterministic advice
to hash into the transcript. Concurrently, the $\F_q$ circuit performs the deferred
group operations over the original commitments $A, B\in\G_{host}$ and checks part 1
of the well-formedness of the partial witness polynomials underlying these nested
commitments. Finally, part 2 of the well-formedness is enforced within the $\F_p$
recursion circuit, verifying that the "partial/multi-staged" commitments add up
to the overall witness commitment.

To summarize, deferred operations for the next recursion step include:
- Verify that partial witness polynomials (a.k.a. _staging polynomials_) are well-formed
- Verify any deferred group operations (e.g. endoscaling) were computed correctly
