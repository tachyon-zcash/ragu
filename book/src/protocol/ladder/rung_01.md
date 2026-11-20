# Rung 1: One Node, One Equation

**Problem.** Re-executing a step consists of many small unrelated checks. A
check can only be deferred or merged once it has a single algebraic form.

**Refinement.** Express each step as an
[arithmetic circuit](../construction/arithmetization.md) and collapse the
circuit's checks into one revdot equation.

A circuit has $n$ gates, each with four wires
$\v{a}_i, \v{b}_i, \v{c}_i, \v{d}_i$ subject to

$$
\v{a}_i \v{b}_i = \v{c}_i, \qquad \v{c}_i \v{d}_i = 0 .
$$

It also has linear **constraints**, fewer than $4n$ of them. Constraint $j$
requires a fixed linear combination of wires to equal the entry $\v{k}_j$ of the
**instance vector** $\v{k}$. That vector holds a leading $1$, then the circuit's
public outputs in reverse order, then zeros. The last position, $j = 4n - 1$, is
reserved for a term that [rung 14](rung_14.md) adds.

The wire values are packed into the **trace polynomial**

$$
r(X) = \sum_{i=0}^{n-1} \left( \v{c}_i X^{i} + \v{a}_i X^{2n-1-i} + \v{b}_i X^{2n+i} + \v{d}_i X^{4n-1-i} \right).
$$

Under revdot this layout pairs each $\v{a}_i$ with $\v{b}_i$ and each $\v{c}_i$
with $\v{d}_i$. Three public polynomials complete the picture:

- The [**wiring polynomial**](../construction/wiring.md)
  $s(X, Y) = \sum_j u_j(X) Y^j$, where $u_j$ is chosen so that $\revdot{r}{u_j}$
  is the linear combination checked by constraint $j$. It is fixed by the
  circuit.
- The **instance polynomial** $k(Y) = \sum_j \v{k}_j Y^j$. The outputs
  $o_0, \ldots, o_{\ell-1}$ are stored as $\v{k}_j = o_{\ell-j}$, which gives
  the Horner form $k(Y) = o_0 Y^{\ell} + \cdots + o_{\ell-1} Y + 1$. A verifier
  evaluates it in one pass over the outputs.
- The **correction polynomial**
  $t(X, z) = -\sum_{i=0}^{n-1} X^{4n-1-i} \left( z^{2n-1-i} + z^{2n+i} \right)$.

For challenges $y$ and $z$, the circuit's
[combined check](../construction/arithmetization.md#combinedcheck) is

$$
\revdot{r}{r(zX) + s(X, y) + t(X, z)} = k(y).
$$

Each term of the right-hand argument does one job. Pairing $r$ with its dilation
$r(zX)$ produces

$$
\sum_i \v{a}_i \v{b}_i (z^{2n-1-i} + z^{2n+i}) + \sum_i \v{c}_i \v{d}_i (z^{i} + z^{4n-1-i}).
$$

The correction $t$ subtracts $\v{c}_i$ from each $\v{a}_i \v{b}_i$, turning the
first sum into the gate residuals $\v{a}_i \v{b}_i - \v{c}_i$. The term
$s(X, y)$ contributes $\sum_j y^j$ times the left side of constraint $j$, and
$k(y)$ is the same combination of the right sides.

**Why it holds.** Fix the trace before $y$ and $z$ are drawn. The difference
between the two sides is a polynomial in $(y, z)$ built from the individual gate
and constraint residuals, placed on monomials arranged so that the polynomial is
zero only if every residual is. If any gate or constraint fails, the difference
is nonzero with total degree at most $4n - 1$. For $y$ and $z$ uniform on $S$,
the pair $(y, z)$ is a root with probability at most $(4n - 1) / |S|$.

Gate $0$ is reserved as the
[`SYSTEM` gate](../construction/wiring.md#system-gate). Its $\v{d}_0$ wire is
the constant `ONE`: the constraint at $Y^0$ forces $\v{d}_0 = \v{k}_0 = 1$, and
the gate equation then forces $\v{c}_0 = 0$. A consequence used later is that
every circuit's wiring polynomial satisfies $s(X, 0) = 1$.

**Still owed.** The verifier still holds the whole trace, computes a revdot of
length $4n$ and evaluates $s$, once per node of the tree.

The arithmetization is implemented in the `ragu_circuits` crate.
