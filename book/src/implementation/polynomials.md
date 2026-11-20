# Polynomial Management

Ragu's prover works primarily with polynomials: constructing them from
circuit descriptions, multiplying them via FFTs, and decomposing their
products into forms the verifier can check. This chapter covers the
wiring polynomial that encodes an arithmetic circuit, the synthesis
process that builds it incrementally, and the low-level polynomial
utilities in [`udon`] that support these operations.

## Wiring Polynomials

Individual arithmetic circuits are defined by the
[structured vector](../protocol/construction/arithmetization.md)
$\v{s} \in \F^{4n}$ that describes the
[constraints](../protocol/construction/arithmetization.md)
enforced over the witness, given a concrete choice of random challenge $y$.
This vector is the coefficient vector of a special polynomial

$$
s(X, Y) = \sum\limits_{j=0}^{4n - 1} Y^j \sum_{i = 0}^{n - 1} \Big(
      u^{a}_{i,j} X^{2n + i}
    + u^{b}_{i,j} X^{2n - 1 - i}
    + u^{c}_{i,j} X^{4n - 1 - i}
    + u^{d}_{i,j} X^{i}
\Big)
$$

at the restriction $Y = y$, where $u^{a}_{i,j}$ is the weight of the wire
$\v{a}_i$ in the $j$-th constraint, and likewise for the other three wires.
This is known as the "wiring polynomial." Each weight sits at the monomial
that the revdot product pairs with its wire's monomial in the trace; see the
[layout](../protocol/construction/wiring.md#layout).

## Synthesis {#synthesis}

Ragu will directly synthesize circuit code into (partial) evaluations of
the reduced wiring polynomial. There are two operations that influence this
polynomial:

* `enforce_zero` creates a
  [constraint](../protocol/construction/arithmetization.md)
  that enforces that a linear combination of wires must equal zero. This
  produces a new term in $Y^j$ for some unused $j$.
* `mul` creates new wires $(a, b, c)$ that must satisfy a
  [gate]
  $ab = c$. This allocates (or assigns) the corresponding powers
  $(X^{2n + i}, X^{2n - 1 - i}, X^{4n - 1 - i})$ for some unused $i$. The
  gate's fourth wire $d$, at $X^i$, stays zero unless circuit code claims it
  through the lower-level `gate` operation.

**Importantly, this synthesis process is procedural.** Any contiguous
sequence of `enforce_zero` and `mul` operations that begins at gate $i$ and
constraint $j$ is defined by polynomials $g_1, g_2, h$ and transforms
$s(X, Y)$ into $s'(X, Y)$, where

$$
s'(X, Y) = s(X, Y)
  + Y^j \big( X^i g_1(X, Y) + X^{-i} g_2(X^{-1}, Y) + h(X, Y) \big).
$$

The powers of the $a$ and $d$ wires ascend with the gate index and those of
the $b$ and $c$ wires descend, so the terms over wires allocated within the
sequence split into a part $g_1$ that moves with $X^i$ and a part $g_2$ that
moves with $X^{-i}$. Only $h(X, Y)$ varies depending on wires not allocated
within that sequence of operations. In many cases, $h$ is either extremely
sparse (and so trivial to compute as necessary) or is used in multiple
repeated sequences. Any repeated sequence produces the same $g_1$ and $g_2$
by definition, and so their evaluations could be memoized for future
invocations of an identical sequence of operations, scaling one by
$X^i Y^j$ and the other by $X^{-i} Y^j$. [Routines](routines.md) are the
unit of this reuse. The evaluators do not memoize yet.

[gate]: ../protocol/construction/arithmetization.md

## Polynomial Arithmetic

The synthesis machinery above relies on standard polynomial operations
provided by the [`udon`] crate. These operate on coefficient
vectors in ascending
degree order: the slice $[c_0, c_1, \ldots, c_n]$ represents the
polynomial
$c_0 + c_1 X + \cdots + c_n X^n$.

### Evaluation and Inner Products

[`evaluate_iter`] evaluates a polynomial at a point using Horner's method over
any `Field`; [`evaluate`] is its Pasta slice counterpart. Generic inner
products $\langle \v{a}, \v{b} \rangle$ use `Field::sum_of_products_slice`
for equal-length slices and `Field::sum_of_product_pairs` for reversed or
noncontiguous inputs; [`dot`] and [`dot_iter`] expose the same Pasta kernels
directly. These helpers provide the scalar operations underlying polynomial
evaluation and inner-product checks.

[`udon`]: https://docs.rs/crate/zakura-udon/0.1.0/source/
[`evaluate`]: https://docs.rs/crate/zakura-udon/0.1.0/source/src/polynomial/evaluation.rs
[`evaluate_iter`]: https://docs.rs/crate/zakura-udon/0.1.0/source/src/polynomial/evaluation.rs
[`dot`]: https://docs.rs/crate/zakura-udon/0.1.0/source/src/field/pasta/products/mod.rs
[`dot_iter`]: https://docs.rs/crate/zakura-udon/0.1.0/source/src/field/pasta/products/mod.rs
