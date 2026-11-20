# Rung 13: Challenges Hashed Inside the Circuits

**Problem.** There is no interactive verifier. The circuits that verify a merge
must also be convinced that each challenge was drawn after the commitments it
tests.

**Refinement.** Apply the Fiat-Shamir transformation. A
[Poseidon sponge](../construction/cycle.md#transcript) over $\F_p$, initialized
with the tag `ragu-pcd-v1`, absorbs one bridge commitment per
[round](../construction/protocol.md#rounds) and is squeezed for that round's
challenges. Each bridge commitment is the nested commitment
([rung 11](rung_11.md)) of a stage holding the native commitments produced in
that round, together with the scalars the nested side contributes to it.

| Absorbed Bridge | Objects Fixed | Challenges Squeezed | Use |
| --- | --- | --- | --- |
| `BridgePreamble` | the children's commitments; the polynomials the fuse's step circuit may query, and the values it stages | $w$ | registry restriction in $W$ ([rung 8](rung_08.md)); the step circuit's challenge $\zeta$ ([rung 0](rung_00.md)) |
| `BridgeSPrime` | the step circuit's trace; the `preamble` stage, with the children's public values and the fuse's own output header and openings; $[m(w, x^{(0)}, Y)]$ and $[m(w, x^{(1)}, Y)]$ | $y$, $z$ | every circuit and bonding claim (rungs [1](rung_01.md), [12](rung_12.md)); restriction in $Y$ |
| `BridgeInnerError` | the inner quotients; $[m(w, X, y)]$ | $\mu$ | first fold layer ([rung 6](rung_06.md)) |
| `BridgeOuterError` | the outer quotient | $\mu'$ | second fold layer |
| `BridgeAB` | $[A]$ and $[B]$ | $x$ | folded-polynomial check ([rung 7](rung_07.md)); restriction in $X$ |
| `BridgeQuery` | every claimed evaluation; $[m(W, x, y)]$ | $\alpha$ | weighting the quotients ([rung 9](rung_09.md)) |
| `BridgeF` | $[f]$ | $u$ | the quotient test |
| `BridgeEval` | every evaluation at $u$ | `pre_beta` | the final combination ([rung 10](rung_10.md)) |

The second bridge fixes the `preamble` stage after $w$, because that stage
holds what the step circuit outputs at $\zeta = w$. The children's public
values in it are fixed by $w$ all the same. The commitments of a child's traces
are absorbed before $w$, a trace determines the instance that its circuit
exposes, and the fold at $y$ takes its targets from these values
([rung 14](rung_14.md)), so a value that differs from what the traces fix makes
the fold fail, except with small probability. The exception is the base case of
that rung, where the final comparison of the fold is waived.

The table lists the native side. The nested side's commitments are fixed by the
same bridges. A commitment of the nested side has coordinates in $\F_p$, so it
sits in a native stage, and that stage's commitment is among the native
commitments in the next bridge absorbed. Each such commitment is fixed by the
bridge that the table gives for its native counterpart, with two exceptions:
$[m_q(w_q, X, y_q)]$ is fixed by `BridgeAB`, and $[m_q(W, x_q, y_q)]$ by
`BridgeF`. The first still precedes $x$, as [rung 8](rung_08.md) requires. The
second follows $\alpha_q$, and [rung 11](rung_11.md) explains why that is sound.

Two internal circuits,
[`hashes_1`](../construction/internal_circuits.md#hashes-1) and
[`hashes_2`](../construction/internal_circuits.md#hashes-2), recompute this
transcript from the bridge commitments and expose the resulting challenges. The
other internal circuits that take a challenge as a field element read it from
the same shared public instance, called the
[**unified instance**](../construction/proof.md#native-unified). The sponge
state is handed from the first hashing circuit to the second through a stage.

The nested circuits run no transcript. Their challenges are the lifts of the
native ones ([rung 11](rung_11.md)), written into a
[**challenge stage**](../construction/stage_contents.md#challenge-stage) beside
one other value, the base-case sign of [rung 14](rung_14.md). That stage is
committed with $\v{a}_0 = 0$, so its commitment is a fixed combination of
generators weighted by its contents. The native `bind_challenges` circuits
recompute that combination from the transcript's challenges, which ties the
nested side's challenges to the hash.

One challenge cannot be bound this way within the same fuse. The binding
circuits keep their running sums in the `eval` stage, and `pre_beta` is squeezed
only after that stage is committed. The fuse therefore exports the combination
without its $\beta_q$ term, and the parent's `bind_beta` circuit adds the term
and compares the result with the commitment the parent uses. The root has no
parent, so the decider recomputes the root's whole challenge stage from the
challenges and the root's circuit identifier, which determines the sign, and
compares.

Extracting an endoscalar from a transcript output requires the output's
canonical value to be below $2^{254}$. A uniform element of $\F_p$ misses that
range with probability about $2^{-129}$. All nine challenges are lifted, so all
nine must meet the condition, and the circuits cannot be satisfied otherwise.
For the first eight the prover takes the transcript as it comes, and the fuse
fails if one of them is out of range. For `pre_beta` the prover commits the
`eval` stage and its bridge again, each with a fresh $\v{a}_0$, and squeezes
again until the condition holds. Each attempt is a further hash query and counts
as one when bounding a cheating prover's chances.

**Why it holds.** In the random oracle model, each squeezed challenge is uniform
and independent of everything absorbed before it, which restores the order of
commitment and challenge that the earlier rungs assumed. Treating Poseidon as a
random oracle is an assumption of the protocol, not something the construction
proves.

The sponge does not length-prefix the absorbed messages. The sequence above is
fixed by the circuit code, so a prover cannot add or drop an element without
changing what the hashing circuits recompute.

**Still owed.** The challenges are now bound to commitments. Nothing yet binds
the commitments, or the targets of the claims, to the statement being proved.
