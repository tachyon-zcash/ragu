# Rung 5: One Quotient Instead of a Matrix of Cross Terms

**Problem.** The correction for $M$ claims should have about $M$ terms, not
$M^2$, and should take one round.

**Refinement.** Interpolate the claims and
[fold](../construction/claims.md#fold) by evaluation. Assign claim $i$ the
interpolation node $i \in \{0, \ldots, M - 1\}$, let $\ell_i(T)$ be the Lagrange
basis on those nodes, and let $Z_M(T) = \prod_i (T - i)$. Define

$$
a(T) = \sum_i \ell_i(T) \, a_i, \qquad
b(T) = \sum_i \ell_i(T) \, b_i, \qquad
c(T) = \sum_i \ell_i(T) \, c_i .
$$

At node $i$ the expression $\revdot{a(T)}{b(T)} - c(T)$ equals claim $i$'s
error. If every claim is true it vanishes on all the nodes, so it is divisible
by $Z_M$:

$$
\revdot{a(T)}{b(T)} - c(T) = Z_M(T) \, Q(T), \qquad \deg Q \le M - 2 .
$$

The prover sends the $M - 1$ coefficients of $Q$. An honest prover computes them
with the actual products $\revdot{a_i}{b_i}$ in place of the $c_i$, which gives
the same $Q$ when the claims are true and keeps the division exact when they are
not. A challenge $\mu$ is then drawn, and the merged claim is

$$
a' = a(\mu), \qquad b' = b(\mu), \qquad c' = c(\mu) + Z_M(\mu) \, Q(\mu).
$$

Both vectors use the same weights $\ell_i(\mu)$, and one challenge suffices.

**Why it holds.** For whatever $Q$ the prover sent, let

$$
E(T) = \revdot{a(T)}{b(T)} - c(T) - Z_M(T) \, Q(T).
$$

Since $Z_M$ vanishes on the nodes, $E(i)$ is claim $i$'s error regardless of
$Q$. The quotient can change $E$ between the nodes and nowhere else. A false
claim therefore makes $E$ a nonzero polynomial of degree at most $2M - 2$, and
the merged claim is true only if $\mu$ is one of its roots, which happens with
probability at most $(2M - 2) / |S|$ for $\mu$ uniform on $S$.

Sending $Q$ late breaks this. Given $\mu$ off the nodes, the constant polynomial
$Q = \bigl(\revdot{a(\mu)}{b(\mu)} - c(\mu)\bigr) / Z_M(\mu)$ repairs the
equation at that one point.

A challenge that lands on a node needs no special handling. The weights then
select that node's claim and $Z_M(\mu) = 0$. The formulas contain no division by
$\mu - i$, and the event is already counted among the roots of $E$.

The identity is the one used by
[ProtoGalaxy](https://eprint.iacr.org/2023/1106), specialized to revdot claims.

**Still owed.** The verifier's work per fold is now linear in $M$. The prover
still computes all $M^2$ revdot products to assemble $Q$, which is too slow for
a single fold over every claim.
