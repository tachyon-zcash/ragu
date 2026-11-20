# Rung 6: A Fold in Two Layers

**Problem.** Prover time for one fold over all claims grows with the square of
their number.

**Refinement.** Arrange the claims in $N$
[groups](../construction/claims.md#fold-groups) of $M$ slots, padding with zero
claims. Fold every group at $\mu$, each with its own quotient, all sent before
$\mu$. Then fold the $N$ group results at a second challenge $\mu'$, with an
outer quotient sent before $\mu'$. The result is the new revdot claim of the
accumulator, about polynomials $A$ and $B$ with the value $c$.

The number of quotient coefficients carried is $N (M - 1) + (N - 1) = MN - 1$,
the same as for a single fold over all $MN$ slots. The prover's revdot products
drop from $(MN)^2$ to $N M^2 + N^2$. The standard profile uses 14 groups of 7
for its native claims and 10 groups of 8 for its nested claims
([rung 11](rung_11.md)).

**Why it holds.** A false claim makes its group's result false unless $\mu$ is a
root of that group's error polynomial, and a false group result makes the final
claim false unless $\mu'$ is a root of the outer one. All groups share $\mu$.
That costs nothing in the analysis, because a union bound over the groups does
not need their failure events to be independent.

The code calls the quotient coefficients "error terms" and commits the native
ones in the `inner_error` and `outer_error` stages. The
[`collapse`](../construction/internal_circuits.md#native-collapse) circuit
recomputes $c$ from the claims' targets, the $N$ inner quotients and the outer
quotient.

**Still owed.** The scalar $c$ is now checked. The commitments $[A]$ and $[B]$
are not.
