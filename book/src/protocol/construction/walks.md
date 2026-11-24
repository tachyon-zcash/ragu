# Walks {#walks}

The commitment $P$ of a [batched polynomial](batch.md) is a linear combination
of other commitments, with powers of $\beta$ as scalars. Computing it takes
group arithmetic on one curve, which is native arithmetic for circuits over the
other field. Each side therefore computes the other side's $P$, by an
**endoscaling walk**. The one other place where a commitment is recomputed
across the cycle is the [challenge stage](stage_contents.md#challenge-stage).

Let $e = \text{endo}(\text{pre\_beta})$ be the
[endoscalar](cycle.md#endoscalars) of the last challenge, so that
$\beta = \text{lift}_p(e)$ and $\beta_q = \text{lift}_q(e)$.

A walk is Horner's rule over its points, with one endoscaling by $e$ for each
point after the first, and it is divided among circuits that perform at most
four endoscalings each. An endoscaling by a [hoisted](cycle.md#endoscalars)
endoscalar costs $433$ gates, so a circuit of $n = 2^{11}$ gates has room for
four and not for five.

## Nested Walk {#nested-walk}

The nested walk runs in circuits over $\F_q$ and folds $122$ points of $\E_q$
into $P$. The points are $C_0 = [f]$ and $C_{j+1} = [\psi_j]$ for the
[native batched polynomials](batch.md#native-p) $\psi_0, \dots, \psi_{120}$.

$$I_{-1} = C_0, \qquad I_s = \beta^4 \cdot I_{s-1} + \sum_{t=0}^{3} \beta^{3-t} \cdot C_{4s+t+1} \quad (s = 0, \dots, 29),$$

$$I_{30} = \beta \cdot I_{29} + C_{121}, \qquad P = I_{30} = \sum_{k=0}^{121} \beta^{121-k} \cdot C_k.$$

The last line takes in the one point that remains after $30$ lines of four.

The `EndoscalarStage` holds $e$, and the `PointsStage` holds every $C_k$ and
every **interstitial** $I_s$. Both are committed after $\text{pre\_beta}$ is
drawn, so [`Collapse`](internal_circuits.md#nested-collapse) binds the walk's
inputs to earlier commitments: each $C_k$ must equal a field of a bridge stage
that the transcript absorbed.

| Point $k$ | $C_k$ | Bridge-Stage Field |
|---|---|---|
| 0 | $[f]$ | `BridgeF.native_f` |
| $1 + 52i + t$, $t < 48$ | $R^{(i)}[\cdot]$ in [rx order](setup.md#rx-order) | the child's field of that name in `BridgePreamble` |
| $49 + 52i$, $50 + 52i$ | $[A^{(i)}]$, $[B^{(i)}]$ | `stashed_ab_a`, `stashed_ab_b` |
| $51 + 52i$ | $[m(W, x^{(i)}, y^{(i)})]$ | `stashed_registry_xy` |
| $52 + 52i$ | $P^{(i)}$ | `stashed_p` |
| 105, 106 | $[m(w, x^{(0)}, Y)]$, $[m(w, x^{(1)}, Y)]$ | `BridgeSPrime.registry_wx0`, `.registry_wx1` |
| 107 | $R[\texttt{Application}]$ | `BridgeSPrime.native_application` |
| 108 | $R[\texttt{ApplicationStage}]$ | `BridgePreamble.application_stage` |
| 109 | $[m(w, X, y)]$ | `BridgeInnerError.registry_wy` |
| 110, 111 | $[A]$, $[B]$ | `BridgeAB.a`, `.b` |
| 112 | $[m(W, x, y)]$ | `BridgeQuery.registry_xy` |
| 113, 114 | $[a_\star]$, $[b_\star]$ | `BridgeSPrime.randomizer_a`, `.randomizer_b` |
| 115 | $[p_\star]$ | `BridgeF.native_mask` |
| 116 to 119 | $O^{(0)}_0, O^{(0)}_1, O^{(1)}_0, O^{(1)}_1$ | the children's `stashed_online_commitments` |
| 120, 121 | $O_0$, $O_1$ | `BridgePreamble.online_commitments` |

Three kinds of circuit check the walk.

- Each `EndoscalingStep(s)` checks one line of the recurrence.
- `Collapse` checks that every point of the `PointsStage` is on the curve, that
  every $C_k$ equals its bridge-stage field in the table above, that the
  `EndoscalarStage` holds bits and their products, and that the exported $E_8$
  equals $I_{30}$.
- `ComputeV` checks that the lift of the `EndoscalarStage` endoscalar equals the
  $\beta_q$ of the challenge stage.

## Native Walk {#native-walk}

The native walk runs in circuits over $\F_p$ and folds $108$ points of $\E_p$
into $P_q$. The points are $C_{q,0} = [f_q]$ and $C_{q,j+1} = [\psi_{q,j}]$ for
the [nested batched polynomials](batch.md#nested-p).

$$I_{q,-1} = C_{q,0}, \qquad I_{q,s} = \beta_q^4 \cdot I_{q,s-1} + \sum_{t=0}^{3} \beta_q^{3-t} \cdot C_{q,4s+t+1} \quad (s = 0, \dots, 25),$$

$$I_{q,26} = \beta_q^3 \cdot I_{q,25} + \beta_q^2 \cdot C_{q,105} + \beta_q \cdot C_{q,106} + C_{q,107}, \qquad P_q = I_{q,26} = \sum_{k=0}^{107} \beta_q^{107-k} \cdot C_{q,k}.$$

The last line takes in the three points that remain after $26$ lines of four.

Unlike the nested walk, the native walk reads its points from the stages in
which they were first committed, so it has no second copy to compare. Each of
those stages is fixed before the challenges of this fuse at which its points
are opened, with one exception: $[m_q(W, x_q, y_q)]$ is fixed after $w_q$ and is
opened at $w_q$. A parent opens that commitment at its own $w_q$ instead.

| Point $k$ | $C_{q,k}$ | Held In |
|---|---|---|
| 0 | $[f_q]$ | `points::FStage` |
| $1 + 49i + t$, $t < 35$ | $R_q^{(i)}[\cdot]$ of `EndoscalingStep(0..=30)`, `Collapse`, `ComputeV`, `EndoscalarStage`, `PointsStage` | `points::PreambleStage` |
| $36 + 49i + t$, $t < 9$ | $R_q^{(i)}[\cdot]$ of the nine bridge stages | `points::BindingStage` |
| $45 + 49i$ | $R_q^{(i)}[\texttt{ChallengeStage}]$ | `points::BindingStage` |
| $46 + 49i$, $47 + 49i$ | $[A_q^{(i)}]$, $[B_q^{(i)}]$ | `points::BindingStage` |
| $48 + 49i$ | $[m_q(W, x_q^{(i)}, y_q^{(i)})]$ | `points::BindingStage` |
| $49 + 49i$ | $P_q^{(i)}$ | `points::BindingStage` |
| 99, 100 | $[m_q(w_q, x_q^{(0)}, Y)]$, $[m_q(w_q, x_q^{(1)}, Y)]$ | `points::RegistryWxStage` |
| 101 | $[m_q(w_q, X, y_q)]$ | `points::AbStage` |
| 102, 103 | $[A_q]$, $[B_q]$ | `points::AbStage` |
| 104 | $[m_q(W, x_q, y_q)]$ | `points::FStage` |
| 105, 106 | $[a_{q,\star}]$, $[b_{q,\star}]$ | `points::RegistryWxStage` |
| 107 | $[p_{q,\star}]$ | `points::FStage` |

The `points::WalkStage` holds $e$ with its products and the interstitials
$I_{q,s}$. Three kinds of circuit check the walk.

- Each `endoscaling_step[s]` checks one line of the recurrence.
- `bind_endoscalar` checks that every walk input is on the curve, that the
  `WalkStage` holds the hoisted $\text{endo}(\text{pre\_beta})$, and that
  $I_{q,26}$, $[A_q]$, $[B_q]$ and $[m_q(W, x_q, y_q)]$ equal their slots of the
  [native unified instance](proof.md#native-unified).
- `bind_beta` checks each child's $14$ points in `points::BindingStage` against
  that child's native unified instance.

### Fixing Order {#fixing-order}

A native points stage is committed as soon as its points exist, and its
commitment is placed in the next bridge stage that the transcript absorbs.

| Points | Native Stage | Carried By | Fixed Before |
|---|---|---|---|
| every nested commitment of both children | `points::BindingStage`, `points::PreambleStage` | `BridgePreamble` | $w$ |
| $[m_q(w_q, x_q^{(i)}, Y)]$, $[a_{q,\star}]$, $[b_{q,\star}]$ | `points::RegistryWxStage` | `BridgeSPrime` | $y$ |
| $[m_q(w_q, X, y_q)]$, $[A_q]$, $[B_q]$ | `points::AbStage` | `BridgeAB` | $x$ |
| $[m_q(W, x_q, y_q)]$, $[f_q]$, $[p_{q,\star}]$ | `points::FStage` | `BridgeF` | $u$ |
| $e$, $I_{q,0}, \dots, I_{q,26}$ | `points::WalkStage` | none in this fuse | committed after $\text{pre\_beta}$ |

The commitment of the `WalkStage` and the commitments of this fuse's own nested
polynomials are fixed one level up. A parent places $R[\texttt{PointsWalk}]$ in
its `BridgePreamble` stage, as the child's `points_walk`, and the nested
commitments in its own `points::BindingStage` and `points::PreambleStage`.
