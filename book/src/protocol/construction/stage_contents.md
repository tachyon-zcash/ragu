# Stage Contents {#stage-contents}

A fuse commits most of its data in [stages](staging.md#stages): whatever several
of its circuits read, and whatever must be fixed before a challenge is drawn.
The contents of each stage are listed in wire order. **Fields that only a
profile hook fills are omitted from the tables on this page.**

A field of type point is a curve point and takes two values, its $x$ coordinate
and then its $y$ coordinate. A count is in units of the field's type, so a point
counts once. Native stages hold points of $\E_p$, and nested stages hold points
of $\E_q$.

The challenges in the tables are those that a proof
[stores](proof.md#auxiliary). The [protocol](protocol.md#challenge-roles) gives
the role of each.

## Native Stages {#native-stages}

The native stages form a tree rooted at `points::BindingStage`, with three
chains from the root to a leaf. On the gate axis the chains are as follows,
where $h = \lceil (3H + 93) / 2 \rceil$ is the number of gates of the
`preamble` stage.

```text
gate  0       1..28                 29..28+h  29+h..47+h   48+h..89+h
      SYSTEM  points::BindingStage  preamble  outer_error  inner_error

gate  0       1..28                 29..28+h  29+h..107+h  108+h..167+h
      SYSTEM  points::BindingStage  preamble  query        eval

gate  0       1..28                 29..94                 95..96           97..99   100..101  102..245
      SYSTEM  points::BindingStage  points::PreambleStage  RegistryWxStage  AbStage  FStage    WalkStage
```

A circuit reserves the gates of one chain, as far as its last stage, and its own
polynomial begins at the next gate. Two stages that no chain shares, such as
`preamble` and `points::PreambleStage`, are never reserved by the same circuit,
so they may occupy the same gates.

| Stage | Parent | Values | First Gate |
|---|---|---|---|
| `points::BindingStage` | none | 56 | 1 |
| `preamble` | `points::BindingStage` | $3H + 93$ | 29 |
| `outer_error` | `preamble` | 38 | $29 + h$ |
| `inner_error` | `outer_error` | 84 | $48 + h$ |
| `query` | `preamble` | 157 | $29 + h$ |
| `eval` | `query` | 120 | $108 + h$ |
| `points::PreambleStage` | `points::BindingStage` | 132 | 29 |
| `points::RegistryWxStage` | `points::PreambleStage` | 4 | 95 |
| `points::AbStage` | `points::RegistryWxStage` | 6 | 97 |
| `points::FStage` | `points::AbStage` | 4 | 100 |
| `points::WalkStage` | `points::FStage` | 287 | 102 |

In gate order, `outer_error` precedes `inner_error`, although it is committed
later. A circuit whose last stage is `outer_error` therefore does not reserve
the gates of `inner_error`.

Every native stage polynomial has a uniformly random $\v{a}_0$. That of `eval`
is drawn again on each attempt at $\text{pre\_beta}$, since a new value changes
the commitment that the transcript absorbs, and with it the challenge.

### `points::BindingStage` {#points-binding}

The stage holds, for child $0$ and then child $1$, the $14$ points of the child
that the parent must check against the child's
[native unified instance](proof.md#native-unified).

| Field | Type | Count | Value |
|---|---|---|---|
| `bridges` | point | 9 | $R_q^{(i)}[\cdot]$ of `BridgePreamble`, `BridgeHash`, `BridgeSPrime`, `BridgeInnerError`, `BridgeOuterError`, `BridgeAB`, `BridgeQuery`, `BridgeF`, `BridgeEval` |
| `challenges` | point | 1 | $R_q^{(i)}[\texttt{ChallengeStage}]$ |
| `a`, `b` | point | 2 | $[A_q^{(i)}]$, $[B_q^{(i)}]$ |
| `registry_xy` | point | 1 | $[m_q(W, x_q^{(i)}, y_q^{(i)})]$ |
| `p` | point | 1 | $P_q^{(i)}$ |

### `preamble` {#native-preamble}

The stage holds what each child exposes to the fuse that consumes it, for
child $0$ and then for child $1$.

| Field | Type | Count | Value |
|---|---|---|---|
| `output_header` | element | $H$ | the child's output header $\text{hdr}^{(i)}_O$; for child $0$ this is $\text{hdr}_L$, for child $1$ it is $\text{hdr}_R$ |
| `circuit_id` | element | 1 | $\omega^{(i)}_{\text{id}}$, the domain point of the child's `circuit_id` |
| `unified` | 14 points, 11 elements | 39 values | $U^{(i)}$ |

It then holds three values of the fuse's own step, in the field `own`.

| Field | Type | Count | Value |
|---|---|---|---|
| `output_header` | element | $H$ | $\text{hdr}_O$ |
| `circuit_id` | element | 1 | $\omega_{\text{id}}$, the domain point of the fuse's `circuit_id` |
| `online` | element | 12 | the fuse's six openings $(\xi_s, \eta_s)$ |

The stage is committed after $w$, because the output header and the openings
are what the step circuit produces at $\zeta = w$. The `BridgeSPrime` stage
carries its commitment, so the stage is fixed before $y$. That is early enough
for the fuse's own values, which enter a claim that is folded at $y$.

The children's values are needed sooner: the
[registry chain](batch.md#registry-chain) at $w$ reads a child's $x^{(i)}$ and
$y^{(i)}$, and a step circuit can read an input header at $\zeta$. These wires
are committed after $w$, yet $w$ already fixes them. The commitments of each
child's traces are in `BridgePreamble`, which $w$ absorbs, and a committed trace
determines its instance polynomial. The fuse folds the children's claims at
$y$ with [targets](claims.md#native-targets) computed from these wires. A wire
that differs from the value that the child's traces fix therefore makes a
target the value of another polynomial, and the fold fails except with
probability at most the degree of that polynomial over $|\F_p|$. The
[base case](base_case.md#waived) does not enforce the children's claims, and
there no later check relies on these values.

### `outer_error` {#native-outer-error}

| Field | Type | Count | Value |
|---|---|---|---|
| `error_terms` | element | 13 | $\text{quo}'_0, \dots, \text{quo}'_{12}$, the layer-2 quotient coefficients |
| `collapsed` | element | 14 | $\text{col}_0, \dots, \text{col}_{13}$ |
| `left`, `right` | element | 6 | per child: the `unified`, `unified_bridge` and `compute_v_bridge` [targets](claims.md#native-targets) |
| `sponge_state` | element | 5 | the transcript state saved after absorbing $R_q[\texttt{BridgeInnerError}]$ |

The target of the step circuit's claim is not held here. The
[`collapse`](internal_circuits.md#native-collapse) circuit computes it from the
`preamble` stage and uses it directly.

The saved state lets [`hashes_2`](internal_circuits.md#hashes-2) resume the
transcript where [`hashes_1`](internal_circuits.md#hashes-1) stops, so that the
replay is split between the two circuits.

### `inner_error` {#native-inner-error}

The stage holds one field, `error_terms`: the $14 \cdot 6$ elements
$\text{quo}_{g,k}$ for $g < 14$ and $k < 6$, which are the layer-1 quotient
coefficients. The quotients and collapsed values are defined with the
[fold](claims.md#fold).

### `query` {#native-query}

| Field | Type | Count | Value |
|---|---|---|---|
| `fixed_registry` | element | 53 | $m(\omega_j, x, y)$ for $j = 0, \dots, 52$ |
| `registry_wxy` | element | 1 | $m(w, x, y)$ |
| `registry_xy_at_circuit_id` | element | 1 | $m(\omega_{\text{id}}, x, y)$ |
| `application_at_xz`, `application_stage_at_xz` | element | 2 | $r{[\texttt{Application}]}(xz)$, $r{[\texttt{ApplicationStage}]}(xz)$ |
| `left.rx`, `right.rx` | element | $2 \cdot 46$ | $r^{(i)}{[\cdot]}(xz)$ in native [rx order](setup.md#rx-order) |
| `a_poly_at_xz` | element | 2 | $A^{(i)}(xz)$ |
| `b_poly_at_x` | element | 2 | $B^{(i)}(x)$ |
| `child_registry_xy_at_current_w` | element | 2 | $m(w, x^{(i)}, y^{(i)})$ |
| `current_registry_wy_at_child_x` | element | 2 | $m(w, x^{(i)}, y)$ |

The fields of each child are consecutive, with its $46$ `rx` values first: all
$50$ values of child $0$, then all $50$ of child $1$.

### `eval` {#native-eval}

Every evaluation is at $u$. The first $114$ values are the evaluations of the
polynomials [folded into $p$](batch.md#native-p), in the same order.

| Field | Type | Count | Value |
|---|---|---|---|
| `left`, `right` | element | $2 \cdot 50$ | per child: $r^{(i)}{[\cdot]}(u)$ in rx order, then $A^{(i)}(u)$, $B^{(i)}(u)$, $m(u, x^{(i)}, y^{(i)})$, $p^{(i)}(u)$ |
| `registry_wx0`, `registry_wx1` | element | 2 | $m(w, x^{(0)}, u)$, $m(w, x^{(1)}, u)$ |
| `application`, `application_stage` | element | 2 | $r{[\texttt{Application}]}(u)$, $r{[\texttt{ApplicationStage}]}(u)$ |
| `registry_wy` | element | 1 | $m(w, u, y)$ |
| `a_poly`, `b_poly` | element | 2 | $A(u)$, $B(u)$ |
| `registry_xy` | element | 1 | $m(u, x, y)$ |
| `online` | element | 6 | the six slot polynomials at $u$ |
| `partials` | point | 3 | the partial sums of the [challenge stage](#challenge-stage) commitment |

### Points Stages {#points-stages}

The [native walk](walks.md#native-walk) folds $101$ points.
`points::BindingStage` holds $28$ of them, and the first four stages of the
table below hold the other $73$. `points::WalkStage` holds the walk's endoscalar
and its interstitials.

| Stage | Field | Value |
|---|---|---|
| `points::PreambleStage` | `points` | per child, $33$ points: $R_q^{(i)}[\cdot]$ of `EndoscalingStep(0..28)`, `Collapse`, `ComputeV`, `EndoscalarStage`, `PointsStage` |
| `points::RegistryWxStage` | `registry_wx0`, `registry_wx1` | $[m_q(w_q, x_q^{(0)}, Y)]$, $[m_q(w_q, x_q^{(1)}, Y)]$ |
| `points::AbStage` | `registry_wy`, `a`, `b` | $[m_q(w_q, X, y_q)]$, $[A_q]$, $[B_q]$ |
| `points::FStage` | `registry_xy`, `f` | $[m_q(W, x_q, y_q)]$, $[f_q]$ |
| `points::WalkStage` | `endoscalar` | the $143$ bits and $94$ products of $\text{endo}(\text{pre\_beta})$ |
| | `interstitials` | $I_{q,0}, \dots, I_{q,24}$, the walk's $25$ intermediate points |

## Nested Stages {#nested-stages}

The nested stages form one chain.

| Stage | Values | First Gate | $\v{a}_0$ |
|---|---|---|---|
| `EndoscalarStage` | 237 | 1 | random |
| `BridgeHash` | 2 | 120 | zero |
| `PointsStage` | 288 | 121 | random |
| `BridgePreamble` | 228 | 265 | random |
| `BridgeSPrime` | 10 | 379 | random |
| `BridgeInnerError` | 74 | 384 | random |
| `BridgeOuterError` | 21 | 421 | random |
| `BridgeAB` | 6 | 432 | $\texttt{bridge\_alpha}^2$ |
| `BridgeQuery` | 145 | 435 | random |
| `BridgeF` | 4 | 508 | random |
| `BridgeEval` | 102 | 510 | random, drawn again on each attempt at $\text{pre\_beta}$ |
| `ChallengeStage` | 20 | 561 | zero |

The parent of each stage is the stage above it in the table. The nine stages
named `Bridge...` are the **bridge stages**. They hold native commitments, and
the transcript absorbs the commitment of each of them except `BridgeHash`.

### `EndoscalarStage` and `PointsStage` {#nested-points}

| Stage | Field | Value |
|---|---|---|
| `EndoscalarStage` | `endoscalar` | the $143$ bits and $94$ products of $\text{endo}(\text{pre\_beta})$ |
| `PointsStage` | `initial` | $C_0 = [f]$ |
| | `inputs` | $C_1, \dots, C_{114}$ |
| | `interstitials` | $I_0, \dots, I_{28}$ |

The points $C_k$ and $I_s$ belong to the [nested walk](walks.md#nested-walk).

### `BridgeHash` {#bridge-hash}

A step circuit is over $\F_p$, and the coordinates of $O_1$, the commitment of
the step's own second online polynomial, lie in $\F_q$. The `BridgeHash` stage
gives the step a digest of $O_1$ in its own field. The stage holds $O_1$ and
nothing else: the $x$ coordinate of $O_1$ is the wire $\v{a}_{120}$, at degree
$2n - 121$, and its $y$ coordinate is the wire $\v{d}_{120}$, at degree
$4n - 121$. The honest prover commits the stage with $\v{a}_0 = 0$, so that its
commitment is a function of $O_1$ alone,

$$R_q[\texttt{BridgeHash}] = \v{a}_{120} \cdot G_{2n - 121} + \v{d}_{120} \cdot G_{4n - 121},$$

with $G$ the generators of $\E_p$. This commitment, a point of $\E_p$, is the
**bridge hash** of $O_1$, and its two coordinates are the wires $(h_x, h_y)$ of
the [step circuit](setup.md#step-circuit).[^whysecond]

[^whysecond]: The stage sits between the `EndoscalarStage`, whose size the
    endoscalar encoding fixes, and the `PointsStage`, so that its gates, and
    with them the two generators, do not move when the walk or the preamble
    grows.

The stage mask does not force $\v{a}_0$ to zero, so an accepted commitment binds
$O_1$ without having to be this canonical one.

### `BridgePreamble` {#bridge-preamble}

| Field | Type | Count | Value |
|---|---|---|---|
| `native_points_binding` | point | 1 | $R[\texttt{PointsBinding}]$ |
| `native_points_preamble` | point | 1 | $R[\texttt{PointsPreamble}]$ |
| `online_commitments` | point | 2 | $O_0$, $O_1$ |
| `application_stage` | point | 1 | $R[\texttt{ApplicationStage}]$ |
| `left`, `right` | 52 points, 5 elements each | 2 | the two children, below |

For child $i$:

| Field | Type | Count | Value |
|---|---|---|---|
| `hashes_1`, `hashes_2`, `collapse`, `compute_v` | point | 4 | $R^{(i)}[\cdot]$ of the circuit of that name |
| `bind_challenges` | point | 4 | $R^{(i)}[\texttt{BindChallenges}(k)]$ |
| `bind_beta`, `bind_endoscalar` | point | 2 | $R^{(i)}[\texttt{BindBeta}]$, $R^{(i)}[\texttt{BindEndoscalar}]$ |
| `endoscaling_steps` | point | 25 | $R^{(i)}[\texttt{EndoscalingStep}(s)]$ |
| `points_walk` | point | 1 | $R^{(i)}[\texttt{PointsWalk}]$ |
| `stashed_preamble` to `stashed_online_commitments` | point | 16 | $E^{(i)}_0, \dots, E^{(i)}_{15}$ in the order `preamble`, `inner_error`, `outer_error`, `query`, `eval`, `ab_a`, `ab_b`, `registry_xy`, `p`, `points_binding`, `points_preamble`, `points_registry_wx`, `points_ab`, `points_f`, `online_commitments` |
| `nested` | element | 5 | $c_q^{(i)}, v_q^{(i)}, x_q^{(i)}, y_q^{(i)}, u_q^{(i)}$ |

The $16$ stashed points and the five scalars are the child's
[nested unified instance](proof.md#nested-unified). Together, the other $36$
points and the $16$ stashed ones are the child's $46$ native rx commitments,
$[A^{(i)}]$, $[B^{(i)}]$, $[m(W, x^{(i)}, y^{(i)})]$, $P^{(i)}$, $O^{(i)}_0$ and
$O^{(i)}_1$.

The stage holds the commitment of the fuse's application stage and not that of
the native `preamble` stage, which does not exist until the step circuit has
run.

### Later Bridge Stages {#bridge-stages}

| Stage | Field | Type | Count | Value |
|---|---|---|---|---|
| `BridgeSPrime` | `registry_wx0`, `registry_wx1` | point | 2 | $[m(w, x^{(0)}, Y)]$, $[m(w, x^{(1)}, Y)]$ |
| | `native_preamble` | point | 1 | $R[\texttt{Preamble}]$ |
| | `native_application` | point | 1 | $R[\texttt{Application}]$ |
| | `native_points_registry_wx` | point | 1 | $R[\texttt{PointsRegistryWx}]$ |
| `BridgeInnerError` | `native_inner_error` | point | 1 | $R[\texttt{InnerError}]$ |
| | `registry_wy` | point | 1 | $[m(w, X, y)]$ |
| | `error_terms` | element | $10 \cdot 7$ | $\text{quo}_{q,g,k}$, the nested layer-1 quotient coefficients |
| `BridgeOuterError` | `native_outer_error` | point | 1 | $R[\texttt{OuterError}]$ |
| | `error_terms` | element | 9 | $\text{quo}'_{q,k}$, the nested layer-2 quotient coefficients |
| | `collapsed` | element | 10 | $\text{col}_{q,g}$ |
| `BridgeAB` | `a`, `b` | point | 2 | $[A]$, $[B]$ |
| | `native_points_ab` | point | 1 | $R[\texttt{PointsAb}]$ |
| `BridgeF` | `native_f` | point | 1 | $[f]$ |
| | `native_points_f` | point | 1 | $R[\texttt{PointsF}]$ |

`BridgeSPrime` carries the two commitments that the step circuit's run
produces: that of the circuit's own polynomial, and that of the native
`preamble` stage. The transcript absorbs the stage before $y$ and $z$, the
challenges at which the claim of the step circuit is folded.

### `BridgeQuery` {#bridge-query}

| Field | Type | Count | Value |
|---|---|---|---|
| `native_query` | point | 1 | $R[\texttt{Query}]$ |
| `registry_xy` | point | 1 | $[m(W, x, y)]$ |
| `fixed_registry` | element | 46 | $m_q(\omega_{q,j}, x_q, y_q)$ for $j = 0, \dots, 45$ |
| `registry_wxy` | element | 1 | $m_q(w_q, x_q, y_q)$ |
| `left.rx`, `right.rx` | element | $2 \cdot 43$ | $r_q^{(i)}{[\cdot]}(x_q z_q)$ in nested rx order |
| `a_poly_at_xz` | element | 2 | $A_q^{(i)}(x_q z_q)$ |
| `b_poly_at_x` | element | 2 | $B_q^{(i)}(x_q)$ |
| `child_registry_xy_at_current_w` | element | 2 | $m_q(w_q, x_q^{(i)}, y_q^{(i)})$ |
| `current_registry_wy_at_child_x` | element | 2 | $m_q(w_q, x_q^{(i)}, y_q)$ |

As on the native side, the fields of each child are consecutive, with its `rx`
values first.

### `BridgeEval` {#bridge-eval}

Every evaluation is at $u_q$. The $100$ values after the first field are the
evaluations of the polynomials [folded into $p_q$](batch.md#nested-p), in the
same order.

| Field | Type | Count | Value |
|---|---|---|---|
| `native_eval` | point | 1 | $R[\texttt{Eval}]$ |
| `left`, `right` | element | $2 \cdot 47$ | per child: $r_q^{(i)}{[\cdot]}(u_q)$ in rx order, then $A_q^{(i)}(u_q)$, $B_q^{(i)}(u_q)$, $m_q(u_q, x_q^{(i)}, y_q^{(i)})$, $p_q^{(i)}(u_q)$ |
| `registry_wx0`, `registry_wx1` | element | 2 | $m_q(w_q, x_q^{(0)}, u_q)$, $m_q(w_q, x_q^{(1)}, u_q)$ |
| `registry_wy` | element | 1 | $m_q(w_q, u_q, y_q)$ |
| `a_poly`, `b_poly` | element | 2 | $A_q(u_q)$, $B_q(u_q)$ |
| `registry_xy` | element | 1 | $m_q(u_q, x_q, y_q)$ |

### `ChallengeStage` {#challenge-stage-layout}

The stage holds ten scalars, each on the wire $\v{a}$ of its own gate. The zero
on each wire $\v{d}$ brings the stage to twenty values.

| Position | Value |
|---|---|
| 0 to 7 | $w_q, y_q, z_q, \mu_q, \mu'_q, x_q, \alpha_q, u_q$ |
| 8 | the base-case sign $\sigma$: $+1$ in the [base case](base_case.md), $-1$ otherwise |
| 9 | $\beta_q$ |

### Challenge Stage Commitment {#challenge-stage}

The nested circuits do not replay the transcript. They read their challenges
from the `ChallengeStage`, and the native side forces that stage to hold the
lifts of the transcript's challenges by recomputing its commitment.

The stage is committed with $\v{a}_0 = 0$, so that its commitment is a function
of its ten values alone and a native circuit can recompute it. The value at
[position](#challenge-stage-layout) $\iota$ of the stage is the
wire $\v{a}_{561 + \iota}$, at the coefficient of degree
$2n - 1 - (561 + \iota) = 2n - 562 - \iota$. With $G$ the generators of $\E_p$,
we write $\Gamma_\iota = G_{2n - 562 - \iota}$ for the generator of position
$\iota$. Then, with
$(\chi_0, \dots, \chi_7) = (w, y, z, \mu, \mu', x, \alpha, u)$,

$$R_q[\texttt{ChallengeStage}] = \sum_{\iota=0}^{7} \chi_{\iota,q} \cdot \Gamma_\iota + \sigma \cdot \Gamma_8 + \beta_q \cdot \Gamma_9.$$

The point is assembled in pieces. Each of the four `bind_challenges` circuits
adds two terms, and the running sums pass from one circuit to the next through
the `eval` stage. That stage is committed before $\text{pre\_beta}$ is drawn,
and the fuse's own circuits leave out the term of $\beta_q$, which a parent's
`bind_beta` adds.

$$\text{partial}_k = \sum_{\iota=0}^{2k+1} \chi_{\iota,q} \cdot \Gamma_\iota \quad (k = 0, 1, 2),$$

$$\texttt{nested\_challenges\_partial} = \sum_{\iota=0}^{7} \chi_{\iota,q} \cdot \Gamma_\iota + \sigma \cdot \Gamma_8.$$

The three partial sums are in the `eval` stage. The last sum is a slot of the
native unified instance.

The stage's contents are bound by the following chain.

1. This fuse's four `bind_challenges` circuits recompute
   `nested_challenges_partial` from the challenges in the native unified
   instance, endoscaling each constant generator by the challenge's bits. The
   last of them takes the sign $\sigma$ from the headers.
2. The parent holds this fuse's native unified instance in its `preamble` stage,
   bound by the targets of this fuse's native claims.
3. The parent's `bind_beta` adds
   $\text{lift}_q(\text{endo}(\text{pre\_beta}^{(i)})) \cdot \Gamma_9$ to the
   partial and equates the sum with the point `challenges` of its
   `points::BindingStage`.
4. The parent's native walk folds that same point into its $P_q$.
5. The parent's nested batch opens $r_q^{(i)}[\texttt{ChallengeStage}]$ against
   $P_q$.
6. The opened value enters the $a$ sides of this fuse's `Collapse` and
   `ComputeV` claims in the parent's fold.

The stage has $\v{a}_0 = 0$ and the commitment scheme is binding, so those
claims are about the polynomial that holds the transcript's lifts and the
header's sign. The root has no parent: the [decider](decider.md) recomputes the
root's challenge stage polynomial, with the sign that the root's `circuit_id`
[determines](base_case.md#confinement), and compares coefficients.
