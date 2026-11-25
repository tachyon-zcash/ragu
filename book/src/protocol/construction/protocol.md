# Protocol {#protocol}

A fuse is a public-coin protocol of eight rounds, made non-interactive by the
[transcript](cycle.md#transcript). The [Fuse PIOP](../iop.md) gives the
messages and checks of each round in full, and the
[fuse procedure](fuse.md#procedure) gives the prover's steps. Here they are
reduced to a schedule.

In each round the prover fixes objects on both sides, and the transcript
absorbs one point of $\E_p$ that commits to all of them: the commitment of a
[bridge stage](stage_contents.md#nested-stages). The bridge stage holds the
commitments of the native objects of the round. It holds the round's nested
objects directly when they are scalars. When they are commitments, it holds the
commitment of the native points stage that carries them. One absorbed point
therefore fixes both sides.

## Rounds {#rounds}

| Round | Native Objects Fixed | Nested Objects Fixed | Absorbed | Challenge |
|---|---|---|---|---|
| 1 | $o_0$, $o_1$; `ApplicationStage` | every nested commitment of both children, in `PointsBinding` and `PointsPreamble`; the children's native commitments and nested instances, in `BridgePreamble` | $R_q[\texttt{BridgePreamble}]$ | $w$ |
| 2 | the step circuit's polynomial `Application`; `Preamble`: the children's instances, output headers and indices, and the fuse's own output header, index and openings; $m(w, x^{(i)}, Y)$; $a_\star$, $b_\star$ | $m_q(w_q, x_q^{(i)}, Y)$, $a_{q,\star}$, $b_{q,\star}$, in `PointsRegistryWx` | $R_q[\texttt{BridgeSPrime}]$ | $y$, $z$ |
| 3 | $\text{quo}_{g,k}$, $c_\star$, in `InnerError`; $m(w, X, y)$ | $\text{quo}_{q,g,k}$, $c_{q,\star}$, in `BridgeInnerError` | $R_q[\texttt{BridgeInnerError}]$ | $\mu$ |
| 4 | $\text{quo}'_k$, $\text{col}_g$, the child targets and the saved transcript state, in `OuterError` | $\text{quo}'_{q,k}$, $\text{col}_{q,g}$, in `BridgeOuterError` | $R_q[\texttt{BridgeOuterError}]$ | $\mu'$ |
| 5 | $A$, $B$ | $A_q$, $B_q$, $m_q(w_q, X, y_q)$, in `PointsAb` | $R_q[\texttt{BridgeAB}]$ | $x$ |
| 6 | the claimed values, in `Query`; $m(W, x, y)$ | the nested claimed values, in `BridgeQuery` | $R_q[\texttt{BridgeQuery}]$ | $\alpha$ |
| 7 | $f$, $p_\star$ | $f_q$, $m_q(W, x_q, y_q)$, $p_{q,\star}$, in `PointsF` | $R_q[\texttt{BridgeF}]$ | $u$ |
| 8 | the evaluations at $u$ and the three partial sums of the [challenge stage](stage_contents.md#challenge-stage) commitment, in `Eval` | the evaluations at $u_q$, in `BridgeEval` | $R_q[\texttt{BridgeEval}]$ | $\text{pre\_beta}$ |

A row gives three things that should be kept apart. The objects of its second
and third columns are fixed before its challenge is drawn. The transcript
absorbs the one point of its fourth column and nothing else. Whether an object
is still in the proof afterwards is a separate question, which the
[proof page](proof.md#stored-derived) answers: a fuse discards the two
polynomials of its step circuit's trace, the restrictions in $Y$ and in $X$,
$f$, $f_q$ and its randomizers.

After the last challenge the prover sends a final message, which no challenge
follows:

- $p$ and $P$, with the nested walk that computes $P$: the `EndoscalarStage`,
  the `PointsStage` and the $31$ `EndoscalingStep` polynomials;
- $p_q$ and $P_q$, with the native walk: the `PointsWalk` stage and the $27$
  `EndoscalingStep` polynomials;
- the `ChallengeStage`;
- the polynomials of the ten native internal circuits other than the
  endoscaling steps, and of the nested `Collapse` and `ComputeV`.

The prover computes the commitment of the `BridgeHash` stage in round 1,
together with the point that it hashes, and the transcript does not absorb that
commitment. Round 1 fixes the point, which `BridgePreamble` also holds, but not
the [free coefficients of the stage](stage_contents.md#bridge-hash).

The prover draws its [fold randomizers](claims.md#randomizer) and
[batch randomizers](batch.md#batch-randomizer) before round 1. Their commitments
enter the transcript with the objects that they are folded or batched with: the
fold randomizers in round 2, and the batch randomizers in round 7.

Round 2 is where the step's circuit runs. Its challenge $\zeta$ is $w$, so its
polynomial and the `preamble` stage, which holds its output header, openings
and `BridgeHash` commitment coordinates, cannot be fixed in round 1. They are
fixed before $y$ and $z$, the challenges at which the claim of the step circuit
is folded. The `preamble`
stage also holds the children's instances, which
[$w$ already fixes](stage_contents.md#native-preamble) through the children's
commitments.

In round 8 the prover repeats its message, with fresh free coefficients in the
`Eval` and `BridgeEval` stages, until the challenge is below $2^{254}$, so that
$\text{pre\_beta}$ has an endoscalar. The other eight challenges are not
retried. If one of them is $2^{254}$ or more, the fuse fails.[^large]

[^large]: Each of the eight has probability about $2^{-129}$ of being that
    large.

## Challenge Roles {#challenge-roles}

| Challenge | Use | Follows |
|---|---|---|
| $w$ | the point at which the registry is restricted and the children's $m(W, x^{(i)}, y^{(i)})$ are opened; the step's $\zeta$ | every commitment of the children, and the step's own online polynomials and staged values |
| $y$ | combines the constraints of every claim; the point at which `registry_wx` is opened | $m(w, x^{(i)}, Y)$, the step circuit's polynomial, the `preamble` stage and the fold randomizers |
| $z$ | combines the gate equations of every circuit claim and the polynomials of every mask claim | the same |
| $\mu$ | first-layer fold | the first-layer quotients and the target $c_\star$ |
| $\mu'$ | second-layer fold | the second-layer quotients and collapsed values |
| $x$ | $B$, the children's $B^{(i)}$ and $b_\star$ are opened at $x$, and $A$, $A^{(i)}$, $a_\star$, every child rx polynomial and the two polynomials of the step circuit at $xz$; `registry_wy` is opened at $x$ | $A$, $B$ and $m(w, X, y)$ |
| $\alpha$ | combines the openings into $f$ | every claimed value and $m(W, x, y)$ |
| $u$ | the single point at which every batched polynomial is evaluated | $f$ and the batch randomizer |
| $\text{pre\_beta}$ | its lifts $\beta$, $\beta_q$ combine the batched polynomials into $p$, $p_q$, and both walks use its endoscalar | the evaluations at $u$ and $u_q$ |

The nested side uses the lift of each challenge for the same purpose. Two of its
commitments are fixed later than their native counterparts.
$[m_q(w_q, X, y_q)]$ is held in `PointsAb`, so it follows $\mu$ and $\mu'$. It
still precedes $x$, and it is opened at $x_q$. $[m_q(W, x_q, y_q)]$ is
held in `PointsF`, so it follows $\alpha$ and precedes $u$. Only its claimed
values, in `BridgeQuery`, precede $\alpha$, and the
[batched opening](batch.md#batch-structure) accounts for that.

## Checks {#checks}

A verifier of the interactive protocol would check the following.

| | Check | Enforced By |
|---|---|---|
| 1 | The step circuit is satisfied by the step's trace. | no circuit; it is a [claim](claims.md#native-claims) of this fuse's own fold |
| 2 | The challenges are the transcript's. | `hashes_1`, `hashes_2` |
| 3 | The targets of the claims are computed from the children's instances and, for the step circuit, from the fuse's own values. | `hashes_1` for $k_{\text{uni}}$ and $k_{\text{bridge}}$, `collapse` for $k_{\text{app}}$ and $k_{\text{cv}}$, `Collapse` for $k_q$ |
| 4 | On each side, the collapsed values and $c$ satisfy the [fold relations](claims.md#fold). | `collapse`, `Collapse` |
| 5 | On each side, $v$ is the [batch formula](batch.md#batch-structure) over the claimed values and evaluations, with $A(xz)$ and $B(x)$ recomputed from the children's opened values. | `compute_v`, `ComputeV` |
| 6 | $P$ and $P_q$ are the outputs of the two [walks](walks.md) over the commitments fixed in earlier rounds. | `endoscaling_step`, `bind_endoscalar`; `EndoscalingStep`, `Collapse`, `ComputeV` |
| 7 | The native walk consumed, for each child, the nested commitments that the child's native instance fixes, and the nested walk consumed the native commitments that the bridge stages hold. | `bind_beta`; `Collapse` |
| 8 | The challenge stage holds the lifts of the transcript's challenges. | `bind_challenges`, completed one level up by the [binding chain](stage_contents.md#challenge-stage) |
| 9 | A fuse that takes the [base case](base_case.md#confinement) has the index of `Bootstrap`, the unit output header and padding output slots. | `collapse` |

In practice, no party runs this verifier during a fuse. Checks 2 to 9 are
constraints of the [circuits](internal_circuits.md) named beside them, and the
fuse produces the traces of those circuits. The statements that those circuits
are satisfied are revdot claims, and they form the fuse's
[frontier](proof.md#frontier). Check 1 is a revdot claim too, and the fuse folds
it into its new raw claim with the claims of the children.

After the fuse, three things remain to be established on each side:

- the frontier claims of the fuse;
- the new raw claim $\revdot{A}{B} = c$, which now stands for check 1 as well;
- the new batched opening $p(u) = v$ against $P$, and that the stored
  restriction is $m(W, x, y)$.

A parent's fuse folds the first two into its own raw claim, and opens $p$ and
the restriction in its own batch. For the root, the [decider](decider.md)
settles all three. It checks the frontier claims, the restriction and the
commitment $P$, and it derives $c$ and $v$ from the polynomials, so that the raw
claim and the batched opening hold by construction.
