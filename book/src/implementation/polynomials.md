# Polynomial Management

Polynomials are the core data representation in Ragu. Every wire
allocation, every constraint, and every proof component is ultimately
encoded as a polynomial. How coefficients are stored, accessed,
and combined directly affects
both the efficiency of synthesis and the correctness of the proving
pipeline. This page explains the two polynomial representations Ragu
uses, how they relate to each other, and how they flow through the
system from circuit synthesis to proof construction.

## Structured Representation {#structured}

The `structured::Polynomial<F, R>` type stores coefficients in four
sparse vectors `(u, v, w, d)`, each of length at most $n$ where
$n = 2^{R-2}$ for a given `Rank` parameter $R$. These four vectors
encode the polynomial

$$
p(X) = \sum_{i=0}^{n-1} \Big(
    w_i X^{i}
  + v_i X^{2n-1-i}
  + u_i X^{2n+i}
  + d_i X^{4n-1-i}
\Big)
$$

which has degree at most $4n - 1$ but only $4n$ potentially nonzero
coefficients. This split layout mirrors the structure of the witness
polynomial: the $u$, $v$, and $w$ vectors correspond to the $a$, $b$,
and $c$ wire vectors described in [Circuits](circuits.md), and $d$
provides additional capacity used in backward-perspective operations.

The structured representation is the natural format during circuit
synthesis. Drivers populate individual coefficient positions as they
process `alloc`, `mul`, and `enforce_zero` calls, and the sparse
storage avoids allocating a full $4n$-element vector when only a
fraction of positions are nonzero.

Key operations on structured polynomials include `eval(z)` for
polynomial evaluation, `dilate(z)` for the transformation
$p(X) \to p(zX)$, `commit()` for Pedersen-style commitments, and
`fold()` for linear combination during accumulation.

## Unstructured Representation {#unstructured}

The `unstructured::Polynomial<F, R>` type stores coefficients as a
dense `Vec<F>` of length `R::num_coeffs()` (i.e., $2^R = 4n$) in
standard monomial basis: the $i$-th element is the coefficient of
$X^i$. It implements `Deref<Target = [F]>`, so slicing with
`&poly[..]` provides direct access to the coefficient array.

Unstructured polynomials are used when the full coefficient vector
is needed rather than the sparse four-vector decomposition. This
arises in two main contexts: commitments where the polynomial must
be evaluated against a full set of generators, and final arithmetic
operations (such as constructing the $f$ and $p$ polynomials during
proving) where the structured layout would add unnecessary
complexity.

Converting between representations is straightforward. Calling
`.unstructured()` on a structured polynomial produces the equivalent
unstructured polynomial by scattering the four sparse vectors into
their correct monomial positions. The reverse direction is not
provided as a method, since unstructured polynomials need not have
the sparse structure that the four-vector layout requires.

## Forward and Backward Perspectives {#perspectives}

Structured polynomials offer two _perspectives_ via the `forward()`
and `backward()` methods. Each returns a `View` that provides mutable
access to three of the four internal vectors, labeled `(a, b, c)`:

- **Forward perspective** maps `a -> u`, `b -> v`, `c -> w`. This is
  the natural view during witness synthesis, where the $a$, $b$, $c$
  wire vectors correspond directly to the structured polynomial's
  $u$, $v$, $w$ storage.
- **Backward perspective** maps `a -> v`, `b -> u`, `c -> d`. This
  reversed mapping aligns with the coefficient ordering needed for
  the revdot product.

These views are zero-copy: they borrow the underlying vectors
without allocation. The dual-perspective design means that the same
polynomial can serve both as a witness polynomial (accessed through
the forward view) and as the reversed operand in a revdot
computation (accessed through the backward view), without copying or
reordering data.

The `revdot` method on structured polynomials computes the reversed
inner product

$$
\revdot{p}{q} = \sum_i (u_i \cdot v'_i + v_i \cdot u'_i
  + w_i \cdot d'_i + d_i \cdot w'_i)
$$

where the primed vectors belong to the second operand. This identity
exploits the fact that the forward view of one polynomial naturally
aligns with the backward view of another, making the reversed inner
product a direct dot product over the four vector pairs. The revdot
product is central to the
[accumulation scheme](../protocol/core/accumulation/revdot.md)
and appears throughout verification.

## Wiring Polynomials {#wiring}

Individual arithmetic circuits are defined by the
[structured vector](../protocol/prelim/structured_vectors.md)
$\v{s} \in \F^{4n}$ that describes the
[linear constraints](../protocol/core/arithmetization.md#linear-constraints)
enforced over the witness, given a concrete choice of random
challenge $y$. This vector is the coefficient vector of a special
polynomial

$$
s(X, Y) = \sum\limits_{j=0}^{4n - 1} Y^j \Big(
      \sum_{i = 0}^{n - 1} (\v{u})_{i,j} X^{2n - 1 - i}
    + \sum_{i = 0}^{n - 1} (\v{v})_{i,j} X^{2n + i}
    + \sum_{i = 0}^{n - 1} (\v{w})_{i,j} X^{4n - 1 - i}
\Big)
$$

at the restriction $Y = y$. This is known as the "wiring
polynomial."

The `CircuitObject` trait provides three methods for evaluating
the wiring polynomial under different driver contexts. The `sxy`
method evaluates $s(x, y)$ at concrete field elements. The `sx`
method fixes $X = x$ and returns an unstructured polynomial in
$Y$. The `sy` method fixes $Y = y$ and returns a structured
polynomial in $X$. These partial evaluations are computed by the
synthesis drivers during proving, and the choice of which
evaluation to use depends on the stage of the protocol.

The `enforce_zero` and `mul` driver operations produce terms in
the wiring polynomial. Each `enforce_zero` call creates a
[linear constraint](../protocol/core/arithmetization.md#linear-constraints)
that forces a linear combination of wires to equal zero,
contributing a new $Y^j$ term. Each `mul` call creates a
[multiplication constraint][multiplication constraint] $ab = c$,
allocating the corresponding powers $(X^{2n+i}, X^{2n-1-i}, X^i)$.

## Synthesis {#synthesis}

Ragu directly synthesizes circuit code into (partial) evaluations
of the reduced wiring polynomial. **This synthesis process is
procedural.** Any
contiguous sequence of `enforce_zero` and `mul` operations is
defined by the polynomials $g, h \in \F[X, Y]$ and transforms
$s(X, Y)$ into $s'(X, Y)$ where for some $i, j$

$$
s'(X, Y) = s(X, Y) + Y^j (X^i g(X, Y) + h(X, Y)).
$$

Here, only $h(X, Y)$ varies depending on wires not allocated
within that sequence of operations. In many cases, $h$ is either
extremely sparse (and so trivial to compute as necessary) or is
used in multiple repeated sequences. Any repeated sequence produces
the same $g$ polynomial by definition, and so its evaluation can
be fully memoized for future invocations of an identical sequence
of operations by scaling by $X^i Y^j$.

## The Gate Polynomial {#gate-polynomial}

The gate polynomial $t(X, Z)$ encodes the structure of
multiplication constraints in the circuit. It is defined as

$$
t(X, Z) = -\sum_{i=0}^{n-1} X^{4n-1-i}
  \big(Z^{2n-1-i} + Z^{2n+i}\big)
$$

and captures the relationship between the $a$, $b$, and $c$ wire
positions that must satisfy pairwise product constraints. The NARK
verifier uses partial evaluations of $t$ to check gate
satisfaction without examining each multiplication gate
individually.

The `Rank` trait provides three methods for evaluating $t$. The
`tz(z)` method fixes $Z = z$ and returns a structured polynomial
in $X$. The `tx(x)` method fixes $X = x$ and returns a structured
polynomial in $Z$. The `txz(x, z)` method evaluates $t$ at
concrete field elements, returning a single field value. These
partial evaluations appear in the
[NARK](../protocol/core/nark.md) verification equations, where
the verifier checks that the prover's witness satisfies the
circuit's multiplication constraints.

## Polynomials in Proofs {#polynomials-in-proofs}

Polynomials flow through every stage of proof construction. Each
component of the `Proof` type carries polynomials alongside
blinding factors and commitments on both the host and nested
curves. The proof stages — Preamble, SPrime, ErrorN, ErrorM, AB,
Query, F, Eval, and P — each contain structured or unstructured
polynomials depending on their role in the protocol.

Structured polynomials appear in components that carry witness
data or accumulated error terms. For example, the Preamble stage
holds the native and nested witness polynomials as
`structured::Polynomial` values, and the ErrorN and ErrorM stages
carry accumulated error polynomials in structured form. The AB
stage contains the $a$ and $b$ polynomials as structured
polynomials along with the scalar $c$.

Unstructured polynomials appear where the protocol requires full
monomial-basis representations. The SPrime stage holds registry
polynomials as `unstructured::Polynomial` values, the F stage
contains the $f$ polynomial in unstructured form, and the P stage
holds the final $p$ polynomial whose evaluation at the challenge
point $u$ is checked during verification.

Each polynomial that has an associated blinding factor and
commitment is verified during `Application::verify()` by
recomputing the commitment from the polynomial and blind and
checking it against the stored commitment point. For a detailed
walkthrough of the proof structure and verification logic, see
[PCD Step and Proofs](proofs.md).

## Further Reading {#further-reading}

The protocol pages provide the mathematical foundations for the
constructions described here:
[Structured Vectors](../protocol/prelim/structured_vectors.md)
defines the vector decomposition,
[Arithmetization](../protocol/core/arithmetization.md) introduces
the constraint model, and the
[Accumulation](../protocol/core/accumulation/index.md) pages
explain how revdot claims are folded. The
[Architecture Overview](arch.md) maps these concepts to their
crate locations, and [Circuits](circuits.md) describes the witness
structure from which synthesis begins.

[multiplication constraint]: ../protocol/core/arithmetization.md#multiplication-constraints
