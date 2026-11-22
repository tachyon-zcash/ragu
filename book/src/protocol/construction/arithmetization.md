# Arithmetization {#arithmetization}

Ragu's arithmetic circuits over $\F$ consist of $n$ **gates** on four wires
$\v{a}_i, \v{b}_i, \v{c}_i, \v{d}_i \in \F$, with each gate enforcing both
$\v{a}_i \v{b}_i = \v{c}_i$ and $\v{c}_i \v{d}_i = 0$.[^whydwires] In addition,
there are $4n$ **constraints**, each requiring a fixed linear form on all the
wires to equal an **instance** value (either zero, or a **public
input**).[^why4n] A valid **witness** determines an assignment of field values
to every wire that satisfies all gates and constraints; this assignment is also
called the **trace** of execution.

For a given instance, the trace $\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$ is encoded
as a **trace polynomial** $r(X)$, represented in the $4n$-dimensional space of
**structured polynomials**.

```admonish info title="Structured polynomials"
A structured polynomial $p(X)$, of degree $< 4n$, is specified by four vectors
$\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$:

$$
p(X) = \sum_{i=0}^{n-1} \left(
  \v{c}_i\, X^{i} +
  \v{a}_i\, X^{2n-1-i} +
  \v{b}_i\, X^{2n+i} +
  \v{d}_i\, X^{4n-1-i}
\right)
$$

Reading the $4n$ coefficients from lowest to highest degree, the coefficient
vector is the concatenation $\v{c} \| \rv{a} \| \v{b} \| \rv{d}$, where
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
is of this precise form, i.e. $\v{r} = \v{c} \| \rv{a} \| \v{b} \| \rv{d}$. We
write $\v{z^{4n}} = (1, z, \ldots, z^{4n-1})$ for the vector of powers of
$z \in \F$ and $\circ$ for the entrywise product, so that
$\v{r} \circ \v{z^{4n}}$ is the coefficient vector of the dilation $r(zX)$. When
we revdot between the trace $r(X)$ and its dilation, it expands into two
weighted sums:

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}}
= \sum_{i=0}^{n-1} \v{a}_i \v{b}_i \left( z^{2n-1-i} + z^{2n+i} \right)
+ \sum_{i=0}^{n-1} \v{c}_i \v{d}_i \left( z^{i} + z^{4n-1-i} \right)
$$

The equation

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t}} = 0
$$

is equivalent, as an identity in $z$, to the gate equations, where the
correction vector $\v{t}$ is uniquely determined by $z$ such that
$\revdot{\v{r}}{\v{t}} = -\sum_i \v{c}_i(z^{2n-1-i} + z^{2n+i})$
for all $\v{r}$.[^t-def] Expanding gives

$$
\sum_{i=0}^{n-1} (\v{a}_i \v{b}_i - \v{c}_i)(z^{2n-1-i} + z^{2n+i})
+ \sum_{i=0}^{n-1} \v{c}_i \v{d}_i (z^{i} + z^{4n-1-i}) = 0
$$

Viewed as a polynomial in $z$, the left-hand side has two sums over disjoint
monomial ranges. Vanishing of this polynomial forces each monomial coefficient
to zero: the first sum requires $\v{a} \circ \v{b} = \v{c}$, the second requires
$\v{c} \circ \v{d} = \v{0^n}$. Its monomials span $z^0, \ldots, z^{4n-1}$, so by
Schwartz–Zippel, if this polynomial is nonzero then for uniformly random
$z \in \F$ the probability that it vanishes is at most $(4n-1)/|\F|$.

The constraints can be similarly collapsed into a single revdot check. Given an
instance vector $\v{k} \in \F^{4n}$, the $j$-th constraint can be written
$\revdot{\v{r}}{\v{u_j}} = \v{k}_j$, where $\v{u_j} \in \F^{4n}$ encodes the
$j$-th constraint's wire weights at the revdot complements of the trace
monomials. Given $y \in \F$, we can stack all $4n$ constraints into a structured
vector $\v{s} = \sum_{j=0}^{4n-1} y^j \v{u_j}$. For a valid trace, linearity of
revdot gives:

$$
\revdot{\v{r}}{\v{s}}
= \sum_{j=0}^{4n-1} y^j \revdot{\v{r}}{\v{u_j}}
= \sum_{j=0}^{4n-1} y^j \v{k}_j
= \dot{\v{k}}{\v{y^{4n}}}
$$

If any constraint is violated, the two sides differ as polynomials in $y$ of
degree at most $4n-1$, so by Schwartz–Zippel a uniformly random $y$ detects the
violation except with probability at most $(4n-1)/|\F|$.

## Combined Check {#combinedcheck}

Ragu combines these checks into a single equation:

$$
\boxed{\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t} + \v{s}} = \dot{\v{k}}{\v{y^{4n}}}}
$$

Viewed as a polynomial in $z$, the gate check spans every power of $z$ while the
constraint check is $z$-independent (since $\v{s}$ depends only on $y$). As a
polynomial identity in $z$, the $z^{4n-1}$ coefficient gives $\v{c}_0 \v{d}_0 =
0$ and the $z^0$ coefficient gives $\v{c}_0 \v{d}_0 + \revdot{\v{r}}{\v{s}} =
\dot{\v{k}}{\v{y^{4n}}}$, which together recover the constraint check
$\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}$.

For uniformly random $(y, z) \in \F^2$, failure of the combined identity to
expose a violated gate or constraint relation occurs with probability at most
$(4n-1)/|\F|$.[^sz-combined]

Later pages state this check on polynomials rather than on coefficient vectors.
With $s(X, y)$ and $t(X, z)$ the polynomials whose coefficient vectors are
$\v{s}$ and $\v{t}$, and $k(Y)$ the polynomial whose coefficient vector is
$\v{k}$, it reads

$$
\revdot{r}{\, r(zX) + s(X, y) + t(X, z)} = k(y),
$$

where the revdot product of two polynomials is that of their coefficient
vectors. Of the three polynomials, $s(X, Y)$ is fixed by the circuit and $k(Y)$
by the instance; both are the subject of
[Wiring and Instance Polynomials](wiring.md). The correction polynomial
$t(X, Z)$ depends on neither, and is the same for every circuit of $n$ gates.

[^sz-combined]: By linearity of revdot, the combined discrepancy decomposes
    additively as $E(Y, Z) = G(Z) + C(Y)$, where $G(Z) := \revdot{\v{r}}{\v{r}
    \circ \v{Z^{4n}} + \v{t}}$ is the gate discrepancy and $C(Y) :=
    \revdot{\v{r}}{\v{s}} - \dot{\v{k}}{\v{Y^{4n}}}$ is the constraint
    discrepancy, each of degree $\leq 4n-1$ in its own variable. If any gate or
    constraint fails, $G \not\equiv 0$ or $C \not\equiv 0$. A nonzero $G$ has a
    nonzero coefficient at a positive power of $Z$, since each gate residual
    appears at one, and $C$ has no such term. The sum $E$ is therefore a
    nonzero bivariate polynomial of total degree $\leq 4n-1$. By
    Schwartz–Zippel, a uniformly random $(y, z) \in \F^2$ is a root with
    probability at most $(4n-1)/|\F|$. This bound is
    achieved, e.g., by a constraint-only failure where $C(Y)$ has $4n-1$
    distinct roots.

[^whydwires]: The $\v{d}$ wires arise from the revdot product's pairing of
    $\v{a} \leftrightarrow \v{b}$ and $\v{c} \leftrightarrow \v{d}$. The gate
    equation $\v{c}_i \v{d}_i = 0$ forces $\v{d}_i = 0$ whenever $\v{c}_i \ne
    0$, which is typical; at gates where $\v{c}_i = 0$ it is a free wire that
    can carry additional witness data. Strictly speaking, no circuit requires
    the $\v{d}$ wires for its arithmetization, but they must appear in the
    revdot-based reduction regardless, and they _are_ sometimes useful.

[^why4n]: The constraint vectors $\v{u_j}$ are the $Y$-coefficients of a
    bivariate wiring polynomial $s(X, Y) = \sum_j u_j(X) Y^j$ (see
    [Wiring and Instance Polynomials](wiring.md)); the vector $\v{s}$ above is
    the coefficient vector of its restriction $s(X, y)$ at $Y = y$. Since
    $s(X, Y)$ must fit within the structured polynomial space in each variable,
    the number of constraints is at most $4n$. Reducing a general R1CS instance
    to a Ragu circuit takes just over $3n$ constraints in the worst case
    (closer to $2n$ in favorable cases), leaving headroom for public inputs.

[^t-def]: The $\v{d}$-component of $\v{t}$ (which pairs with the trace's
    $\v{c}$ wires under revdot) is set so that revdot yields
    $\sum_i -\v{c}_i(z^{2n-1-i} + z^{2n+i})$, the correction that turns the
    dilation expansion's bare $\v{a}_i\v{b}_i$ products into the
    $\v{a}_i\v{b}_i - \v{c}_i$ gate residuals. (The other components of
    $\v{t}$ are $\v{0}^n$.) Explicitly,
    $$t(X, Z) = -\sum_{i=0}^{n-1} X^{4n-1-i}(Z^{2n-1-i} + Z^{2n+i})$$
    defines the correction polynomial such that $\v{t}$ is the coefficient
    vector of the univariate restriction $t(X, z)$.
    At $z = 0$ it vanishes, $t(X, 0) = 0$, and for $z \neq 0$ the two sums
    regroup as geometric series in $Xz$ and $X/z$:
    $$-t(X, z) = X^{3n} z^n \sum_{k=0}^{n-1} (Xz)^k + X^{3n} z^{3n-1} \sum_{k=0}^{n-1} (X/z)^k.$$
