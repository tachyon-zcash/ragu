# Rung 9: One Quotient Test for Many Openings

**Problem.** By now the native side of a fuse owes
[172 opening claims](../construction/batch.md#native-openings): each child's
accumulated opening $p(u) = v$ at that child's own $u$; the ten registry
openings; the children's $A^{(i)}$ and $B^{(i)}$ and the new $A$ and $B$; every
child trace and stage polynomial at $xz$, and the two polynomials of the fuse's
own step circuit; $m(W, x, y)$ at the domain point of every circuit and mask in
use; and the six openings that a step's circuit may ask for
([rung 0](rung_00.md)). Claim $i$ says that
$h_{\sigma(i)}(\xi_i) = v_i$, where $h_0, \ldots, h_{J-1}$ are the polynomials
that the claims name, each listed once, and $\sigma(i)$ names the one that
claim $i$ is about.

A claim $h(\xi) = v$ is true exactly when $(h(X) - v) / (X - \xi)$ is a
polynomial. Summing those quotients without weights is unsound, because errors
can cancel. Take two claims about the zero polynomial at a common point, with
the false values $v_0 = 1$ and $v_1 = -1$: the two quotients sum to zero.

**Refinement.** After all $L$ claims are fixed, draw $\alpha$. The prover
commits to

$$
f(X) = \sum_{i=0}^{L-1} \alpha^{L-1-i} \, \frac{h_{\sigma(i)}(X) - v_i}{X - \xi_i}.
$$

An honest prover forms each quotient with the true value $h_{\sigma(i)}(\xi_i)$
in place of $v_i$, so that $f$ is a polynomial whatever is claimed. Then draw
$u$. The prover sends the value $e_j$ of each $h_j$ at $u$, and the verifier
computes what $f(u)$ must be:

$$
v_f = \sum_{i=0}^{L-1} \alpha^{L-1-i} \, \frac{e_{\sigma(i)} - v_i}{u - \xi_i}.
$$

**Why it holds.** The two challenges have different jobs. Group the false claims
by evaluation point. At one such point, the pole of the weighted sum has a
residue that is a nonzero polynomial in $\alpha$ of degree below $L$. Unless
$\alpha$ is one of its roots, the sum is a rational function with a real pole
and equals no polynomial. The committed $f$ is a polynomial fixed before $u$, so
after clearing denominators the two differ by a nonzero polynomial of bounded
degree, and $u$ exposes the difference unless it is a root. Sending $f$ after
$u$ would let the prover fit a constant to the one tested point.

The formula for $v_f$ divides by $u - \xi_i$, so the test is undefined when $u$
equals one of the evaluation points. The protocol treats that case as a failure.
The circuit that computes $v_f$ constrains every $u - \xi_i$ to have an inverse,
and no satisfying trace exists when one of them is zero. Every $\xi_i$ is fixed
before $u$ is drawn, so this happens with probability at most the number of
distinct points divided by $|S|$. The outcome is a rejection, so it costs the
honest prover a negligible chance of failing and gives a cheating prover
nothing. [Rung 5](rung_05.md) needed no such rule, because its formulas never
divide by a challenge.

**Still owed.** The test consumed $f(u)$ and every $e_j$, none of which has been
verified. They are all openings at the same point $u$.
