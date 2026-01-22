# Polynomial Management

## Wiring Polynomials

Individual arithmetic circuits are defined by the [structured vector](../protocol/prelim/structured_vectors.md) $\v{s} \in \F^{4n}$ that describes the [linear constraints](../protocol/prelim/cs.md) enforced over the witness, given a concrete choice of random challenge $y$. This vector is the coefficient vector of a special polynomial

$$
s(X, Y) = \sum\limits_{j=0}^{4n - 1} Y^j \Big(
      \sum_{i = 0}^{n - 1} (\v{u})_{i,j} X^{2n - 1 - i}
    + \sum_{i = 0}^{n - 1} (\v{v})_{i,j} X^{2n + i}
    + \sum_{i = 0}^{n - 1} (\v{w})_{i,j} X^{4n - 1 - i}
\Big)
$$

at the restriction $Y = y$. This is known as the "wiring polynomial."

## Synthesis

Ragu will directly synthesize circuit code into (partial) evaluations of the reduced wiring polynomial. There are two operations that influence this polynomial:

* `enforce_zero` creates a [linear constraint](../protocol/prelim/cs.md#linear-constraints) that enforces that a linear combination of wires must equal zero. This produces a new term in $Y^j$ for some unused $j$.
* `mul` creates new wires $(a, b, c)$ that must satisfy a [multiplication constraint](../protocol/prelim/cs.md#multiplication-constraints) $ab = c$. This allocates (or assigns) the corresponding powers $(X^{2n + i}, X^{2n - 1 - i}, X^i)$ for some unused $i$.

**Importantly, this synthesis process is procedural.** Any contiguous sequence of `enforce_zero` and `mul` operations is defined by the polynomials $g, h \in \F[X, Y]$ and transforms $s(X, Y)$ into $s'(X, Y)$ where for some $i, j$

$$
s'(X, Y) = s(X, Y) + Y^j (X^i g(X, Y) + h(X, Y)).
$$

Here, only $h(X, Y)$ varies depending on wires not allocated within that sequence of operations. In many cases, $h$ is either extremely sparse (and so trivial to compute as necessary) or is used in multiple repeated sequences. Any repeated sequence produces the same $g$ polynomial by definition, and so its evaluation can be fully memoized for future invocations of an identical sequence of operations by simply scaling by $X^i Y^j$.

