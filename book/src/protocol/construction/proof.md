# Proof {#proof}

An uncompressed proof stores its polynomials in full, so that a parent can fold
and open them and the decider can check them directly. Its contents are an
accumulator, a pending trace and auxiliary data.

## Accumulator {#accumulator}

Each side of the cycle has an
[accumulator](index.md#accumulator-pending-trace) with
three components.

| Component | Native | Nested |
|---|---|---|
| revdot claim | $A, B \in \F_p[X]$ with $[A], [B] \in \E_q$ | $A_q, B_q \in \F_q[X]$ with $[A_q], [B_q] \in \E_p$ |
| batched opening | $p \in \F_p[X]$ with $P \in \E_q$, opened at $u$ | $p_q \in \F_q[X]$ with $P_q \in \E_p$, opened at $u_q$ |
| registry restriction | $m(W, x, y)$ and its commitment | $m_q(W, x_q, y_q)$ and its commitment |

The third component is stored as a polynomial. The fuse that made the proof
does not establish that it is the registry's restriction, so until a parent or
the decider tests it, it is a [candidate](batch.md#registry-candidates) for
that restriction.

The values that the accumulator claims are derived from the polynomials and are
not stored:

$$c = \revdot{A}{B}, \qquad v = p(u), \qquad c_q = \revdot{A_q}{B_q}, \qquad v_q = p_q(u_q).$$

The two online polynomials $o_0, o_1$ and their commitments $O_0, O_1$ are
stored with the accumulator. A parent opens them as its left or right slots, and
they are part of no revdot claim.

## Pending Trace {#pending-trace}

The [pending trace](index.md#accumulator-pending-trace) holds circuit
polynomials and stage polynomials.

| Side | Circuit Polynomials | Stage Polynomials |
|---|---|---|
| native, 48 | `Hashes1`, `Hashes2`, `Collapse`, `ComputeV`, `BindChallenges(0..=3)`, `BindBeta`, `BindEndoscalar`, `EndoscalingStep(0..=26)` | `Preamble`, `InnerError`, `OuterError`, `Query`, `Eval`, `PointsBinding`, `PointsPreamble`, `PointsRegistryWx`, `PointsAb`, `PointsF`, `PointsWalk` |
| nested, 45 | `EndoscalingStep(0..=30)`, `Collapse`, `ComputeV` | `EndoscalarStage`, `PointsStage`, `BridgePreamble`, `BridgeHash`, `BridgeSPrime`, `BridgeInnerError`, `BridgeOuterError`, `BridgeAB`, `BridgeQuery`, `BridgeF`, `BridgeEval`, `ChallengeStage` |

Each polynomial is stored with its commitment, $R[\cdot] \in \E_q$ for a native
one and $R_q[\cdot] \in \E_p$ for a nested one. A fuse draws the
[free coefficients](wiring.md#blind-gate) of each uniformly at random, except
those of the three nested stages that the
[stage table](stage_contents.md#nested-stages) lists with fixed ones.

The [step circuit](setup.md#step-circuit) is not in the pending trace. Its trace
depends on no challenge of the fuse after $w$, so the fuse folds the claim about
it into its own accumulator, and the proof keeps neither of the two polynomials
of that trace.

## Auxiliary Data {#auxiliary}

A parent or the decider computes the target of each claim of the pending
trace from a public instance. The commitments in an instance and the values
$c$ and $v$ are derived from the polynomials of the proof. The auxiliary data
are the other values of the instances, and `bridge_alpha`.

| Field | Content | Part Of |
|---|---|---|
| `circuit_id` | native registry index of the step's circuit | the instance of `hashes_1`, as $\omega_{\text{id}}$ |
| challenges | $w, y, z, \mu, \mu', x, \alpha, u, \text{pre\_beta} \in \F_p$ | the [native unified instance](#native-unified); the [nested](#nested-unified) one holds the lifts of $x$, $y$ and $u$ |
| `nested_challenges_partial` | a point of $\E_p$, defined with the [challenge stage](stage_contents.md#challenge-stage) | the native unified instance |
| `bridge_alpha` | an element of $\F_q$ whose square is the $\v{a}_0$ of the `BridgeAB` stage | none; $r_q[\texttt{BridgeAB}]$ is [derived](#stored-derived) from it |

The proof has no field for a header. Its output header is recomputed from the
data that a `Pcd` carries beside the proof, and its input headers and online
openings entered the claim about its step circuit, which its own fuse folded.
The [`preamble`](stage_contents.md#native-preamble) stage, which the pending
trace keeps, still holds a copy of all three headers and of the openings.

## Stored and Derived {#stored-derived}

Every commitment in the proof is redundant with its polynomial, and the
[decider](decider.md#decider-checks) checks it against that polynomial. In
practice, the prover forms some of the commitments without committing.

- $[A]$ is formed as a linear combination of the children's commitments and of
  $R[\texttt{Application}]$, $R[\texttt{ApplicationStage}]$ and
  $[a_\star]$, and $[B]$ by committing $B$.
- $P$ and $P_q$ are the outputs of the two [walks](walks.md), not commitments
  computed from $p$ and $p_q$.

One polynomial is derived: $r_q[\texttt{BridgeAB}]$ is the
[stage polynomial](staging.md#stage-polynomial) over $[A]$, $[B]$ and
$R[\texttt{PointsAb}]$ with $\v{a}_0 = \texttt{bridge\_alpha}^2$.[^whysquared]
The stage holds nothing but commitments that the proof already has, so storing
`bridge_alpha` is enough to rebuild its polynomial.

[^whysquared]: The code gives each derived bridge stage a distinct power of
    `bridge_alpha`. `BridgeAB` is the only such stage, and takes the second
    power.

The proof does not store the quotient polynomials $f$ and $f_q$ of the
[batched openings](batch.md#batch-structure), or the
[restrictions](batch.md#registry-chain) `registry_wx0`, `registry_wx1` and
`registry_wy` of either side, or the two polynomials of the step circuit's
trace, or the fuse's [randomizers](claims.md#randomizer). Those exist only
during the fuse.

A proof is **well formed** when it holds $4$ `BindChallenges` polynomials, $27$
native and $31$ nested `EndoscalingStep` polynomials, with as many commitments.

## Native Unified Instance {#native-unified}

The native internal circuits share one public instance, the native **unified
instance**, of $25$ **slots** and $39$ wires $U_1, \dots, U_{39}$. A point takes
two wires. Each slot is covered by exactly one circuit, which computes or
receives it. Coverage alone does not constrain a received value to the
commitment it names.

| Slot | Wires | Value | Covered By |
|---|---|---|---|
| `bridge_preamble_commitment` | 1, 2 | $R_q[\texttt{BridgePreamble}]$ | `hashes_1` |
| `bridge_hash_commitment` | 3, 4 | $R_q[\texttt{BridgeHash}]$ | `hashes_1` |
| `w` | 5 | $w$ | `hashes_1` |
| `bridge_s_prime_commitment` | 6, 7 | $R_q[\texttt{BridgeSPrime}]$ | `hashes_1` |
| `y`, `z` | 8, 9 | $y$, $z$ | `hashes_1` |
| `bridge_inner_error_commitment` | 10, 11 | $R_q[\texttt{BridgeInnerError}]$ | `hashes_1` |
| `mu` | 12 | $\mu$ | `hashes_2` |
| `bridge_outer_error_commitment` | 13, 14 | $R_q[\texttt{BridgeOuterError}]$ | `hashes_2` |
| `mu_prime` | 15 | $\mu'$ | `hashes_2` |
| `c` | 16 | $c$ | `collapse` |
| `bridge_ab_commitment` | 17, 18 | $R_q[\texttt{BridgeAB}]$ | `hashes_2` |
| `x` | 19 | $x$ | `hashes_2` |
| `bridge_query_commitment` | 20, 21 | $R_q[\texttt{BridgeQuery}]$ | `hashes_2` |
| `alpha` | 22 | $\alpha$ | `hashes_2` |
| `bridge_f_commitment` | 23, 24 | $R_q[\texttt{BridgeF}]$ | `hashes_2` |
| `u` | 25 | $u$ | `hashes_2` |
| `bridge_eval_commitment` | 26, 27 | $R_q[\texttt{BridgeEval}]$ | `hashes_2` |
| `pre_beta` | 28 | $\text{pre\_beta}$ | `hashes_2` |
| `v` | 29 | $v$ | `compute_v` |
| `nested_challenges_partial` | 30, 31 | see [challenge stage](stage_contents.md#challenge-stage) | `bind_challenges[3]` |
| `nested_p_commitment` | 32, 33 | $P_q$ | `bind_endoscalar` |
| `nested_a_commitment` | 34, 35 | $[A_q]$ | `bind_endoscalar` |
| `nested_b_commitment` | 36, 37 | $[B_q]$ | `bind_endoscalar` |
| `nested_registry_xy_commitment` | 38, 39 | $[m_q(W, x_q, y_q)]$ | `bind_endoscalar` |

In particular, `hashes_1` exposes `bridge_hash_commitment` without absorbing
it. Before $y$, `BridgeSPrime` fixes the native preamble's copy of its
coordinates. Native `collapse` equates that copy with the unified point. A
parent's `bind_beta`, or the terminal verifier for a root, binds that point to
the `BridgeHash` stage commitment.

The instance polynomial of a circuit whose public output is this instance alone
is

$$k_{\text{uni}}(Y) = \text{Horner}_Y[U_1, \dots, U_{39}, 0, 1].$$

The zero before the trailing one is a suffix. It distinguishes an internal
circuit from a step circuit, in which the coefficient of $Y^1$ is a header
suffix and is never zero.

One circuit writes more than the instance. The public output of `hashes_1` also
carries the output header of its fuse and the domain point
$\omega_{\text{id}}$ of the fuse's `circuit_id`:

$$k_{\text{bridge}}(Y) = \text{Horner}_Y[U_1, \dots, U_{39}, \text{hdr}_O, \omega_{\text{id}}, 0, 1].$$

These are the header and the index that the fuse's own
[application claim](claims.md#native-targets) was folded with. A parent has its
own copies of them, as an input header of its step and as the child's index,
and binds the copies to this instance when it folds the child's `hashes_1`
claim. Each header is thus checked once by the fuse that produced it and once
by the fuse that consumes it.

The target of a `compute_v` claim is carried separately, as $k_{\text{cv}}$,
because a profile can add to that circuit's public output. The standard profile
adds nothing, so that

$$k_{\text{cv}}(Y) = k_{\text{uni}}(Y).$$

A parent holds each child's instance in its `preamble` stage. We write $U^{(i)}$
for the wires of child $i$'s instance and give the slots of that instance the
same superscript, as in $w^{(i)}$, $c^{(i)}$ and $v^{(i)}$.

## Nested Unified Instance {#nested-unified}

The two nested instance circuits, `Collapse` and `ComputeV`, share the nested
unified instance, of five scalars and $16$ points of $\E_q$.

| Slot | Value | Constrained By |
|---|---|---|
| `c` | $c_q$ | `Collapse` |
| `v` | $v_q$ | `ComputeV` |
| `x`, `y`, `u` | $x_q$, $y_q$, $u_q$ | `Collapse` |
| `exported` | $E_0, \dots, E_{15}$ | `Collapse` |

The exported points are the native commitments that a parent's nested walk
consumes. The bridge stages of this fuse hold each of them except $P$, which is
the output of this fuse's own nested walk.

| $j$ | $E_j$ | Bound Stage Value |
|---|---|---|
| 0 | $R[\texttt{Preamble}]$ | `BridgeSPrime.native_preamble` |
| 1 | $R[\texttt{InnerError}]$ | `BridgeInnerError.native_inner_error` |
| 2 | $R[\texttt{OuterError}]$ | `BridgeOuterError.native_outer_error` |
| 3 | $R[\texttt{Query}]$ | `BridgeQuery.native_query` |
| 4 | $R[\texttt{Eval}]$ | `BridgeEval.native_eval` |
| 5 | $[A]$ | `BridgeAB.a` |
| 6 | $[B]$ | `BridgeAB.b` |
| 7 | $[m(W, x, y)]$ | `BridgeQuery.registry_xy` |
| 8 | $P$ | the last interstitial of `PointsStage` |
| 9 | $R[\texttt{PointsBinding}]$ | `BridgePreamble.native_points_binding` |
| 10 | $R[\texttt{PointsPreamble}]$ | `BridgePreamble.native_points_preamble` |
| 11 | $R[\texttt{PointsRegistryWx}]$ | `BridgeSPrime.native_points_registry_wx` |
| 12 | $R[\texttt{PointsAb}]$ | `BridgeAB.native_points_ab` |
| 13 | $R[\texttt{PointsF}]$ | `BridgeF.native_points_f` |
| 14, 15 | $O_0$, $O_1$ | `BridgePreamble.online_commitments` |

With each point written as its two coordinates,

$$k_q(Y) = \text{Horner}_Y[c_q, v_q, x_q, y_q, u_q, E_0, \dots, E_{15}, 1].$$

There is no zero suffix, because the nested registry holds no step circuit.

A parent holds each child's nested instance in its `BridgePreamble` stage, as
$c_q^{(i)}, v_q^{(i)}, x_q^{(i)}, y_q^{(i)}, u_q^{(i)}$ and
$E^{(i)}_0, \dots, E^{(i)}_{15}$.
