# The Refinement Ladder

Ragu builds [proof-carrying data](../../concepts/pcd.md) (PCD) from an
accumulation scheme. An accumulation scheme never verifies a proof in full while
the computation is still growing. It performs the cheap parts of verification,
restates the expensive parts as short *claims*, and merges claims so that their
number stays fixed. Only the final recipient pays for an expensive check, and
pays once.

This makes the finished protocol hard to read from the code. Almost every
component exists because a simpler design owed a check it could not afford, or
because deferring that check opened a gap. These chapters rebuild the protocol
as a ladder. [Rung 0](rung_00.md) is a verifier that checks everything directly.
Each later rung makes one change and records what is owed afterwards. The top of
the ladder is the protocol implemented in the `ragu_pcd` crate. The
[Construction](../construction/index.md) section specifies it as far as the
decider of [rung 15](rung_15.md), the [Fuse PIOP](../iop.md) follows one fuse
round by round, and [Compression](../recursion/compression.md) gives the
protocol of [rung 16](rung_16.md).

Each rung has the same four parts:

- **Problem**: what the construction so far cannot afford, or fails to
  guarantee.
- **Refinement**: the change.
- **Why it holds**: what stops a false claim from surviving the change.
- **Still owed**: the obligations that remain, which later rungs take up.

The answer under "why it holds" has the same shape on most rungs. The prover
fixes some object by committing to it. A challenge is drawn afterwards. If a
claim is false, some polynomial determined before the challenge is nonzero, and
the check fails unless the challenge is one of its roots. A nonzero polynomial
of degree $d$ has at most $d$ roots, so a challenge drawn uniformly from a set
$S$ misses the error with probability at most $d / |S|$. The order of commitment
and challenge is therefore part of every rung, and several rungs include a small
example of what breaks when the order is reversed. Until [rung 11](rung_11.md) a
challenge can be taken to range over the whole field. That rung introduces
challenges that range over a smaller set, which is why the bounds are written
with $|S|$.

The order of the rungs is expository, not historical. Rungs [1](rung_01.md)
through [12](rung_12.md) describe challenges as values sent by an interactive
verifier. [Rung 13](rung_13.md) replaces that verifier with a hash function.

The description covers the standard profile over the Pasta curves. Where another
chapter covers a rung's components in more depth, the rung links to it. After
the last rung, [The Ladder at a Glance](glance.md) tabulates what each rung
defers, and [Assumptions of the Argument](assumptions.md) lists what the
argument rests on.

## Notation

All arithmetic is over a prime field $\F$. A circuit has $n$ gates, and every
polynomial that the protocol commits to has $4n$ coefficients, so its degree is
below $4n$. At the wallet rank $4n = 2^{13}$.

The **revdot** product of two coefficient vectors is the dot product of one with
the reversal of the other:

$$
\revdot{a}{b} = \sum_{j=0}^{4n-1} a_j \, b_{4n-1-j}.
$$

Equivalently, it is the coefficient of $X^{4n-1}$ in the product $a(X) b(X)$. It
is linear in each argument. These chapters write a polynomial and its
coefficient vector with the same letter. Bold letters are kept for the wire
vectors of [rung 1](rung_01.md), as in
[Arithmetization](../construction/arithmetization.md).

A **commitment** to a polynomial is a Pedersen vector commitment to its
coefficients under fixed generators,

$$
[a] = \sum_{j=0}^{4n-1} a_j \, G_j .
$$

Commitments are linearly homomorphic: $[a] + \rho [b] = [a + \rho b]$. They are
binding if no nontrivial linear relation among the generators is known.

The variables $X$, $Y$ and $W$ belong to the circuit polynomials introduced in
rungs [1](rung_01.md) and [8](rung_08.md). The variable $T$ is used only for
interpolating across claims. Lowercase letters
$w, x, y, z, \mu, \mu', \alpha, u, \beta$ are challenges and match the names in
the code. The letters $\rho$ and $\nu$ stand for a scalar or a challenge that is
local to one argument.
