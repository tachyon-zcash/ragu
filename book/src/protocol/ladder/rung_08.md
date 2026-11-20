# Rung 8: The Registry and the Merge of Wiring Claims

**Problem.** [Rung 7](rung_07.md) needs the value at $(x, y)$ of the wiring
polynomial of every circuit and mask whose claim is folded. Evaluating a wiring
polynomial costs time linear in the circuit's size, and there are many circuits:
every application step, and several dozen internal ones. The prover also chooses
which step ran at each node, and that choice must be confined to the registered
steps.

**Refinement, part one.** Gather every wiring polynomial into one
[**registry polynomial**](../construction/registry.md#registry-polynomial)
$m(W, X, Y)$ that interpolates them over a domain of roots of unity, in which
each index $j$ is assigned a
[point](../construction/registry.md#registry-domain) $\omega_j$:

$$
m(\omega_j, X, Y) = s_j(X, Y).
$$

All the values [rung 7](rung_07.md) needs are then evaluations of a single
univariate polynomial, the restriction $m(W, x, y)$, at domain points. This
fixes the wiring claim of [rung 3](rung_03.md). Its instance is
$([m(W, x, y)], x, y)$, and it asserts that the commitment is to the registry
restricted at $X = x$ and $Y = y$. Given a true wiring claim, each $s_j(x, y)$
is an opening of $[m(W, x, y)]$ at $\omega_j$.

**Refinement, part two.** The two children bring wiring claims at their own
points, $(x^{(0)}, y^{(0)})$ and $(x^{(1)}, y^{(1)})$. The fuse needs one at its
own $(x, y)$. It gets there by
[changing one coordinate at a time](../construction/batch.md#registry-chain),
committing each intermediate restriction before the challenge that fixes the
next coordinate:

| Commitments Already Fixed | Challenge Drawn | Restriction Committed Next |
| --- | --- | --- |
| the children's $[m(W, x^{(0)}, y^{(0)})]$ and $[m(W, x^{(1)}, y^{(1)})]$ | $w$ | $m(w, x^{(0)}, Y)$ and $m(w, x^{(1)}, Y)$ |
| those two commitments | $y$ | $m(w, X, y)$ |
| that commitment | $x$ | $m(W, x, y)$ |

Neighboring restrictions must agree where they overlap, which gives five
equalities:

$$
\begin{aligned}
m(W, x^{(0)}, y^{(0)})\big|_{W = w} &= m(w, x^{(0)}, Y)\big|_{Y = y^{(0)}}, \\
m(W, x^{(1)}, y^{(1)})\big|_{W = w} &= m(w, x^{(1)}, Y)\big|_{Y = y^{(1)}}, \\
m(w, x^{(0)}, Y)\big|_{Y = y} &= m(w, X, y)\big|_{X = x^{(0)}}, \\
m(w, x^{(1)}, Y)\big|_{Y = y} &= m(w, X, y)\big|_{X = x^{(1)}}, \\
m(w, X, y)\big|_{X = x} &= m(W, x, y)\big|_{W = w}.
\end{aligned}
$$

Each equality is a pair of openings of two different commitments to one shared
value. The code names a restriction after its fixed coordinates: `registry_wx0`
and `registry_wx1`, `registry_wy`, and `registry_xy`.

**Why it holds.** Follow a false child claim through the chain. Suppose the left
child's polynomial is not $m(W, x^{(0)}, y^{(0)})$. It was fixed before $w$, so
its value at $w$ is wrong unless $w$ is a root of the difference. The first
equality then forces the committed stand-in for $m(w, x^{(0)}, Y)$ to be wrong
at $y^{(0)}$, so it is the wrong polynomial. It was fixed before $y$, so it is
wrong at $y$ unless $y$ is a root. The same reasoning carries the error through
the restriction in $X$ and the challenge $x$, and the last equality forces the
new committed restriction to be wrong at $w$. A false input yields a false
output unless one of $w$, $y$, $x$ is a root of a nonzero polynomial of degree
below $4n$.

The order matters at every link. Suppose the left child's polynomial is the
correct one plus the constant $1$, and the prover may choose the intermediate
restriction in $Y$ after seeing $y \ne y^{(0)}$. It commits to

$$
m(w, x^{(0)}, Y) + \frac{Y - y}{y^{(0)} - y}.
$$

This matches the false value at $y^{(0)}$ and the true value at $y$. Every later
restriction can be honest, all five equalities pass, and the false claim is
gone.

The last equality tests the new committed restriction at $w$, a point its
committer already knew. That is enough to carry an error forward and is not
enough to establish that it is $m(W, x, y)$. The new wiring claim stays a claim.
The next fuse tests it at a fresh $w$ of its own and carries it forward again,
and at the root the decider settles it by evaluating the registry itself at a
fresh point.

The circuit identifier a proof names must be a point of the registry's domain. A
fuse's own [`hashes_1`](../construction/internal_circuits.md#hashes-1) circuit
enforces this for the identifier of the fuse's step circuit, and the decider or
the verifier of a compressed proof checks the identifier that it reads from the
root. Every domain point carries some wiring polynomial, and
[rung 12](rung_12.md) explains why a point that does not carry a circuit cannot
satisfy a circuit claim.

**Still owed.** Ten more openings from the five equalities, the openings of
$[m(W, x, y)]$ at each $\omega_j$, and the new wiring claim itself.
