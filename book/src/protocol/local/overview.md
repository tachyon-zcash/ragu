# Overview

Ragu's arithmetic circuits over $\F$ consist of $n$ **gates** each on four wires
$\v{a}_i, \v{b}_i, \v{c}_i, \v{d}_i \in \F$ enforcing both $\v{a}_i \cdot \v{b}_i =
\v{c}_i$ and $\v{c}_i \cdot \v{d}_i = 0$, and $4n$ **constraints** each
enforcing that a fixed linear combination of all wires equals an **instance**
value—either zero, or a **public input** value. A valid **witness** determines
an assignment of field values to every wire satisfying all constraints, also
called the **trace** of execution for the circuit. The protocol convinces a
verifier that a valid trace exists (and thus also a valid witness for the
statement) given some instance.

The trace $\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$ is encoded as a **trace
polynomial** $r(X)$, represented in the $4n$-dimensional space of **structured
polynomials**.

```admonish info title="Structured polynomials"
A structured polynomial $p(X)$, of degree $< 4n$, is specified by four vectors
$\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$:

$$
p(X) = \sum_{i=0}^{n-1} \left(
  \v{c}_i\, X^{i} +
  \v{b}_i\, X^{2n-1-i} +
  \v{a}_i\, X^{2n+i} +
  \v{d}_i\, X^{4n-1-i}
\right)
$$

Reading the $4n$ coefficients from lowest to highest degree, the coefficient
vector is the concatenation $\v{c} \| \rv{b} \| \v{a} \| \rv{d}$, where
$\rv{x}$ denotes the reversal of $\v{x} \in \F^n$. Reversing the full
coefficient vector yields another structured polynomial with
$\v{a} \leftrightarrow \v{b}$ and $\v{c} \leftrightarrow \v{d}$ swapped —
structured polynomials are closed under reversal of their coefficients.

The **revdot product** $\revdot{\v{p}}{\v{q}} = \dot{\v{p}}{\rv{q}}$ is the
dot product of one structured polynomial with the reversal of another:

$$
\revdot{\v{p}}{\v{q}} = \dot{\v{a}_p}{\v{b}_q} + \dot{\v{b}_p}{\v{a}_q}
  + \dot{\v{c}_p}{\v{d}_q} + \dot{\v{d}_p}{\v{c}_q}
$$

The reversal closure swaps $\v{a} \leftrightarrow \v{b}$ and
$\v{c} \leftrightarrow \v{d}$, so revdot naturally cross-multiplies these
pairs.
```

The trace polynomial $r(X)$ is a structured polynomial whose coefficient vector
is of this precise form, i.e. $\v{r} = \v{c} \| \rv{b} \| \v{a} \| \rv{d}$. When
we revdot between the trace $r(X)$ and its dilation $r(Xz)$ for some $z \in \F$,
it expands into two weighted sums:

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}}
= \sum_{i=0}^{n-1} \v{a}_i \cdot \v{b}_i \left( z^{2n-1-i} + z^{2n+i} \right)
+ \sum_{i=0}^{n-1} \v{c}_i \cdot \v{d}_i \left( z^{i} + z^{4n-1-i} \right)
$$

The equation

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t}} = 0
$$

enforces the gate equations, where the correction vector $\v{t}$ is determined
by $z$ such that
$\revdot{\v{r}}{\v{t}} = -\sum_i \v{c}_i(z^{2n-1-i} + z^{2n+i})$
for all $\v{r}$. Expanding gives

$$
\sum_{i=0}^{n-1} (\v{a}_i \cdot \v{b}_i - \v{c}_i)(z^{2n-1-i} + z^{2n+i})
+ \sum_{i=0}^{n-1} \v{c}_i \cdot \v{d}_i (z^{i} + z^{4n-1-i}) = 0
$$

This is a polynomial identity in $z$. The two sums occupy disjoint monomial
ranges, and so each gate's coefficient must vanish independently: the first
enforces $\v{a} \circ \v{b} = \v{c}$, and the second enforces $\v{c} \circ \v{d}
= \v{0^n}$. Schwartz–Zippel guarantees that checking at a single random $z$
suffices with overwhelming probability.

The circuit's constraints, each requiring a fixed linear combination of wires to
equal an instance value, can be similarly collapsed into a single revdot check.
Given a (sparse) instance vector $\v{k} \in \F^{4n}$, the $j$-th constraint can
be written $\revdot{\v{r}}{\v{s_j}} = \v{k}_j$ where the structured vector
$\v{s_j}$ encodes the constraint's wire weights at the revdot complements of the
trace monomials.

Given some value $y \in \F$, we can stack all $4n$ constraints into a structured vector $\v{s}$:

$$
\begin{array}{rrl}
\sum\limits_{j=0}^{4n - 1} y^j \revdot{\v{r}}{\v{s_j}}& &=  \\
\revdot{\v{r}}{\v{s}}& &= \langle \v{k}, \v{y^{4n}} \rangle
\end{array}
$$

If any constraint is violated, the sum will disagree with $\v{k}$ as a
low-degree polynomial in $y$, so a random $y$ detects the violation with
overwhelming probability.

Ragu combines these checks into a single revdot equation that establishes both
with high probability for random $y, z \in \F$:

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t} + \v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$$

This combined equation is sound because all the terms of
$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t}}$
are linearly independent (in $z$) from $\revdot{\v{r}}{\v{s}}$ except at the
coefficient for $z^0$, where the combined check yields
$$
c_0 d_0 + \revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}.
$$
Meanwhile, the $z^{4n - 1}$ coefficient gives
$$
\v{d}_0 \v{c}_0 = 0
$$
and substituting into the $z^0$ coefficient gives
$\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}$, which is exactly the
constraint check. In any case, Ragu defines $\v{s}_0 = 0$ for all circuits (the
$d_0$ wire does not participate in any constraints), so this boundary condition
is only theoretical.
