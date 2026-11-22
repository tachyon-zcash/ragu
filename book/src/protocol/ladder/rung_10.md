# Rung 10: One Opening, Carried Forward

**Problem.** Authenticate the $J$ values $e_j$ and the value of $f$ at $u$
without $J + 1$ separate openings.

**Refinement.** After the $e_j$ are fixed, draw $\beta$ and
[combine](../construction/batch.md#batch-structure) everything by Horner's rule,
starting from $f$:

$$
\begin{aligned}
p(X) &= \beta^{J} f(X) + \sum_{j=0}^{J-1} \beta^{J-1-j} \, h_j(X), \\
v &= \beta^{J} v_f + \sum_{j=0}^{J-1} \beta^{J-1-j} \, e_j .
\end{aligned}
$$

The fuse's new opening claim is $(P, u, v)$, with the commitment $P = [p]$
computed as

$$
P = \beta^{J} [f] + \sum_{j=0}^{J-1} \beta^{J-1-j} \, [h_j].
$$

**Why it holds.** If some $h_j(u) \ne e_j$, or $f(u) \ne v_f$, then $p(u) - v$
is a nonzero polynomial in $\beta$ of degree at most $J$, and the claim
$p(u) = v$ is true only if $\beta$ is one of its roots. [Rung 11](rung_11.md)
explains why $\beta$ is drawn from a smaller set than the challenges before it.

The implementation folds one more polynomial into $p$, a
[batch randomizer](../construction/batch.md#batch-randomizer) that no claim
names. It is one more $h_j$ with its own $e_j$, and the argument is unchanged.

This is the third claim of the accumulator. The children's opening claims were
among the $L$ inputs, so every opening owed anywhere in the subtree has been
reduced to this one. The scalar half, the computation of $v$, runs in the
`compute_v` circuit.

**Still owed.** The claim is about $P$, and $P$ is a combination of $J + 1$
elliptic curve points weighted by powers of $\beta$. Something has to perform
that group arithmetic and prove it did.

With this rung the accumulation scheme is complete on paper: three kinds of
claim, and a merge for each that turns false inputs into a false output. The
remaining rungs make the verifier of those merges something that circuits can
run.
