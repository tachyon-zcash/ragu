# Rung 7: Evaluation Checks for the Folded Polynomials

**Problem.** Write $\lambda_i$ for the **fold weight** of claim $i$, the product
of its weight within its group at $\mu$ and its group's weight at $\mu'$. The
folded claim is about $A = \sum_i \lambda_i a_i$ and $B = \sum_i \lambda_i b_i$.
Checking $[A] = \sum_i \lambda_i [a_i]$ directly costs about a hundred scalar
multiplications inside a circuit. For $B$ the direct check is not available at
all: for a circuit claim, $b_i = r_i(zX) + s_i(X, y) + t(X, z)$ is derived from
the trace and was never committed.

**Refinement.** The prover commits to $A$ and $B$. A challenge $x$ is then
drawn, and the two identities are tested at a point:

$$
A(xz) = \sum_i \lambda_i \, a_i(xz), \qquad B(x) = \sum_i \lambda_i \, b_i(x).
$$

The claims being folded come in [three kinds](../construction/claims.md#claims),
and each kind supplies its terms differently.

| Kind | $a_i$ | $b_i$ | Target |
| --- | --- | --- | --- |
| Raw | a child's accumulated $A$ | the same child's accumulated $B$ | that child's $c$ |
| Circuit | the trace $r_i$ of an internal circuit that a child ran, or of the fuse's own step circuit | $r_i(zX) + s_i(X, y) + t(X, z)$ | the circuit's $k(y)$ |
| Bonding ([rung 12](rung_12.md)) | the polynomials held to one linear check, such as a mask, combined by powers of $z$ | that check's $s_i(X, y)$ | $0$ |

For a circuit claim, $b_i(x) = r_i(xz) + s_i(x, y) + t(x, z)$. This is why $A$
is tested at $xz$ and not at $x$: both identities then consume the same
evaluations $r_i(xz)$. The circuits require $x$ and $z$ to be nonzero, and with
$z \ne 0$ the point $xz$ is as unpredictable as $x$. The value $t(x, z)$ is a
pair of geometric series that the verifier computes itself.

**Why it holds.** The commitments $[A]$ and $[B]$ are fixed before $x$. If
either committed polynomial differs from the intended combination, the
difference is a nonzero polynomial of degree below $4n$, and $x$ is a root with
probability at most $(4n - 1) / |S|$.

**Still owed.** The check has traded group arithmetic for two new kinds of
unverified scalar:

- evaluations of committed polynomials, such as $r_i(xz)$, $A(xz)$ and $B(x)$,
  which are opening claims;
- the wiring values $s_i(x, y)$, one for each circuit and each mask that a
  folded claim refers to.

The [`compute_v`](../construction/internal_circuits.md#native-compute-v) circuit
performs this check.
