# Rung 4: A Merge of Two Revdot Claims

**Problem.** Merge the claims $(a_0, b_0, c_0)$ and $(a_1, b_1, c_1)$ into one.
The natural attempt takes a challenge $\rho$ and sets $a' = a_0 + \rho a_1$,
$b' = b_0 + \rho b_1$ and $c' = c_0 + \rho^2 c_1$. Revdot is bilinear, so

$$
\revdot{a'}{b'} = \revdot{a_0}{b_0} + \rho \, c_{\times} + \rho^2 \revdot{a_1}{b_1},
\qquad c_{\times} = \revdot{a_0}{b_1} + \revdot{a_1}{b_0}.
$$

The naive target omits the cross term $c_{\times}$, so the scheme rejects honest
provers. With scalars in place of vectors: the true claims $1 \cdot 1 = 1$ and
$2 \cdot 2 = 4$ fold at $\rho = 1$ to $3 \cdot 3 = 9$, while the naive target is
$5$.

**Refinement.** The prover sends $c_{\times}$ before $\rho$ is drawn, and the
target becomes $c' = c_0 + \rho \, c_{\times} + \rho^2 c_1$.

**Why it holds.** For whatever $c_{\times}$ the prover sent, the error
$\revdot{a'}{b'} - c'$ is a polynomial in $\rho$ of degree at most two whose
constant coefficient is the first claim's error and whose leading coefficient is
the second's. If either claim is false the polynomial is nonzero, and $\rho$ is
a root with probability at most $2 / |S|$. The value $c_{\times}$ controls only
the middle coefficient. If it could be sent after $\rho$, the prover would solve
one linear equation for it and pass for every $\rho \ne 0$.

**Still owed.** The repair does not extend cheaply to many claims in one round.
With powers of a single challenge as weights, $a' = \sum_i \rho^i a_i$ and
$b' = \sum_i \rho^i b_i$, the claimed value $c_i$ shares the coefficient of
$\rho^{2i}$ with every cross term $\revdot{a_j}{b_{j'}}$ that has $j + j' = 2i$.
A prover who supplies those cross terms can hide claim $i$'s error among them. A
one-round merge of $M$ claims needs weights that keep cross terms off the
monomials of the claimed values, such as $a' = \sum_i \rho^i a_i$ and
$b' = \sum_j \nu^j b_j$ under two challenges $\rho$ and $\nu$. That leaves
$M^2 - M$ cross terms, each sent, hashed and consumed inside a circuit, and a
fuse merges on the order of a hundred claims.

The alternative is to merge two claims at a time. A binary tree of such merges
needs only $M - 1$ cross terms, but about $\log_2 M$ rounds, each with its own
commitment and challenge. [Rung 5](rung_05.md) reaches the smaller count in a
single round.

The verifier must also learn that $[a']$ and $[b']$ are the right combinations
of the input commitments, which [rung 7](rung_07.md) takes up.
