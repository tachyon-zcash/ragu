# Internal Circuits {#internal-circuits}

The checks of a fuse are split across fixed internal circuits on each side. A
circuit reads its inputs from [stages](stage_contents.md) and exposes a
[unified instance](proof.md#native-unified), and its claim joins the fuse's
frontier. The one circuit that an application supplies is the
[step circuit](setup.md#step-circuit), and the fuse folds the claim of that
circuit itself.

Two predicates recur, and each has the value one when it holds and zero
otherwise. The native [base-case](base_case.md) predicate reads the suffixes of
the two child output headers from the `preamble` stage,

$$\text{base} = \left( \text{hdr}_L[H - 1] = 2 \right) \wedge \left( \text{hdr}_R[H - 1] = 2 \right),$$

and the nested one reads the sign of the challenge stage,
$\text{base}_q = (\sigma = 1)$.

A circuit **decomposes** a challenge by allocating $254$ bits
$b_0, \dots, b_{253}$, constraining $\sum_i 2^i b_i$ to equal the challenge, and
keeping the low $143$ as its [endoscalar](cycle.md#endoscalars). A challenge of $2^{254}$ or more makes
the circuit unsatisfiable.

## Native Circuits {#native-circuits}

| Circuit | Index | Last Stage | Loaded Enforced | Loaded Unenforced |
|---|---|---|---|---|
| `hashes_1` | 0 | `outer_error` | | `preamble`, `outer_error` |
| `hashes_2` | 1 | `outer_error` | | `outer_error` |
| `collapse` | 2 | `inner_error` | `outer_error`, `inner_error` | `preamble` |
| `compute_v` | 3 | `eval` | `preamble` | `query`, `eval` |
| `bind_challenges[k]` | $4 + k$ | `eval` | | `preamble`, `query`, `eval` |
| `bind_beta` | 8 | `preamble` | | `points::BindingStage`, `preamble` |
| `bind_endoscalar` | 9 | `points::WalkStage` | the five points input stages | `points::WalkStage` |
| `endoscaling_step[s]` | $10 + s$ | `points::WalkStage` | | all six points stages |

A circuit reserves the gates of every stage on the path from the root to its
last stage, whether or not it loads them. Its own polynomial is confined by the
[final mask](staging.md#masks) of its last stage.

Among the gadgets that these stages hold, a curve point has a contract to
enforce: it lies on the curve and is not the identity. The
[enforced](staging.md#stage-polynomial) loads of the table cover the points of `preamble` and of the five points input stages. The
partial sums of `eval` and the interstitials of `points::WalkStage` are loaded
unenforced only, and each is equated with a point computed in circuit.

The hoisted endoscalar of `points::WalkStage` also has a contract, that its
wires are bits and their products. Item 2 of
[`bind_endoscalar`](#bind-endoscalar) covers it.

Every circuit below except `endoscaling_step` has the native unified instance in
its public output, and constrains only the slots listed for it on the
[proof page](proof.md#native-unified).

### `hashes_1` {#hashes-1}

The circuit replays the transcript as far as $z$ and checks two targets of each
child. Public output: [$k_{\text{bridge}}$](proof.md#native-unified), over the
unified instance and the fuse's own $\text{hdr}_O$ and $\omega_{\text{id}}$ of
the `preamble` stage.

The absorbed points are named by their slots of the
[native unified instance](proof.md#native-unified). Each slot holds the
commitment $R_q[\cdot]$ of the bridge stage of the same name, and the
[rounds](protocol.md#rounds) give the schedule that this circuit and `hashes_2`
replay.

1. $\omega_{\text{id}}$, the fuse's own index in the `preamble` stage, raised
   to the size of the native registry domain equals one. This places the index
   of the step circuit in the domain, which is
   [all that an index has to do](registry.md#registry-kinds). A child's index
   needs no check here: the child's own `hashes_1` made it, and
   $k^{(i)}_{\text{bridge}}$ binds this fuse's copy to the child's.
2. Start the transcript. Absorb `bridge_preamble_commitment` and squeeze $w$.
3. Allocate `bridge_hash_commitment` as a curve point. The transcript does not
   absorb it.
4. Absorb `bridge_s_prime_commitment` and squeeze $y$, then $z$.
5. For each child, recompute $k^{(i)}_{\text{uni}}(y)$ and
   $k^{(i)}_{\text{bridge}}(y)$ from the `preamble` wires at this $y$ and equate
   them with the `outer_error` wires.
6. Absorb `bridge_inner_error_commitment`, save the transcript state, and equate
   it with `outer_error.sponge_state`.

### `hashes_2` {#hashes-2}

The circuit replays the rest of the transcript, from $\mu$ to
$\text{pre\_beta}$. Public output: $k_{\text{uni}}$.

1. Resume the transcript from `outer_error.sponge_state` and squeeze $\mu$.
2. Absorb `bridge_outer_error_commitment` and squeeze $\mu'$.
3. Absorb `bridge_ab_commitment` and squeeze $x$.
4. Absorb `bridge_query_commitment` and squeeze $\alpha$.
5. Absorb `bridge_f_commitment` and squeeze $u$.
6. Absorb `bridge_eval_commitment` and squeeze $\text{pre\_beta}$.

### `collapse` {#native-collapse}

The circuit computes the target of the step circuit's claim, confines the
[base case](base_case.md) and checks both layers of the
[fold](claims.md#fold). Public output: $k_{\text{uni}}$. Let
$\text{tgt}_0, \dots, \text{tgt}_{97}$ be the
[native targets](claims.md#native-claims) in claim order, built from the wires
$c^{(i)}$ of the `preamble` stage, the value of item 1 and the target wires of
the `outer_error` stage, with ones at the endoscaling positions and zeros at
the bonding and padding positions.

1. Compute [$k_{\text{app}}(y)$](claims.md#native-targets) from the `preamble`
   stage, with $w$ and $R_q[\texttt{BridgeHash}]$ read from the unified
   instance. This is $\text{tgt}_2$, and no stage holds it.
2. For each child, the `compute_v_bridge` target of the `outer_error` stage
   equals the `unified` target, since
   [$k_{\text{cv}} = k_{\text{uni}}$](proof.md#native-unified).
3. If $\text{base}$ holds, the fuse is the [bootstrap](base_case.md#confinement):
   $\omega_{\text{id}}$ is the domain point of `Bootstrap`, $\text{hdr}_O$ is
   the encoding of the unit header, and each output slot has $\xi_s = w$ and
   $\eta_s = 1$.
4. For each group $g < 14$, the wire $\text{col}_g$ of the `outer_error` stage
   equals

   $$\sum_{j < 7} \ell^{(7)}_j(\mu) \, \text{tgt}_{7g+j} + V^{(7)}(\mu) \sum_{k < 6} \text{quo}_{g,k} \, \mu^k.$$

5. Compute, over those wires,

   $$c^\ast = \sum_{g < 14} \ell^{(14)}_g(\mu') \, \text{col}_g + V^{(14)}(\mu') \sum_{k < 13} \text{quo}'_k \, \mu'^k$$

   and enforce $(1 - \text{base}) \cdot (c - c^\ast) = 0$.

Items 1, 2 and 4 are enforced in the [base case](base_case.md#waived) too. Only
the equality of item 5 is waived there, and item 3 constrains nothing outside
it.

### `compute_v` {#native-compute-v}

The circuit checks the [batched opening](batch.md): it recomputes the values of
the folded polynomials and computes $v$. Public output:
[$k_{\text{cv}}$](proof.md#native-unified), which is $k_{\text{uni}}$.

1. The $28$ points of the two child instances in the `preamble` stage are curve
   points.
2. $\text{pre\_beta}$ is decomposed, giving $e$.
3. $t(x, z)$ is computed as two geometric sums, as in the closed form given with
   the [arithmetization](arithmetization.md#combinedcheck). The computation uses
   the inverses of $x$ and $z$, so the circuit requires $x \ne 0$ and $z \ne 0$.
4. $\text{ax}$ and $\text{bx}$ are computed as on the
   [batch page](batch.md#ax-bx).
5. For each of the $70$ opening points $\rho$ an inverse $d_\rho$ is allocated
   with $d_\rho \cdot (u - \rho) = 1$. The points are $u^{(i)}$, $y^{(i)}$ and
   $x^{(i)}$ for each child, $w$, $x$, $y$, $xz$, $\omega_{\text{id}}$, the $53$
   constants $\omega_j$, and the six $\xi_s$.
6. $v$ is computed by the [batch formula](batch.md#batch-structure) over the
   $172$ native openings and the $114$ evaluations of the `eval` stage, with
   $\beta = \text{lift}_p(e)$ computed in circuit.

Item 5 makes the circuit unsatisfiable when $u$ equals an opening point.

The six online openings $(\xi_s, \eta_s)$ are wires of the `preamble` stage,
the same wires that `collapse` reads for $k_{\text{app}}(y)$. The step circuit
is thereby held to the openings that this batch proves.

### `bind_challenges[k]` {#bind-challenges}

The four circuits recompute the commitment of the nested challenge stage from
the native challenges, two challenges per circuit. Public output:
$k_{\text{uni}}$. Circuit $k$ handles the challenges $\chi_{2k}$ and
$\chi_{2k+1}$ of $(w, y, z, \mu, \mu', x, \alpha, u)$, with the notation of the
[challenge stage commitment](stage_contents.md#challenge-stage).

1. Each of the two challenges is decomposed, and the constant generator
   $\Gamma_\iota$ is endoscaled by it, giving
   $\text{term}_\iota = \chi_{\iota,q} \cdot \Gamma_\iota$.
2. For $k < 3$:
   $\text{partial}_{k-1} + \text{term}_{2k} + \text{term}_{2k+1} = \text{partial}_k$,
   where $\text{partial}_{-1}$ is absent.
3. For $k = 3$:

   $$\text{partial}_2 + \text{term}_6 + \text{term}_7 + \sigma \cdot \Gamma_8 = \texttt{nested\_challenges\_partial},$$

   with $\sigma = +1$ if $\text{base}$ holds and $\sigma = -1$ otherwise.

### `bind_beta` {#bind-beta}

The circuit ties each child's points in `points::BindingStage` to that child's
unified instance, and completes the child's challenge stage commitment. Public
output: $k_{\text{uni}}$. The circuit constrains no slot of its own instance.
For each child $i$, with $\mathcal{B}^{(i)}$ the child's block of
`points::BindingStage`:

1. the nine points `bridges` of $\mathcal{B}^{(i)}$ equal the nine bridge
   commitments of $U^{(i)}$, in order;
2. $\text{pre\_beta}^{(i)}$ is decomposed, and

   $$\mathcal{B}^{(i)}.\texttt{challenges} = U^{(i)}.\texttt{nested\_challenges\_partial} + \beta_q^{(i)} \cdot \Gamma_9;$$

3. the points `p`, `a`, `b` and `registry_xy` of $\mathcal{B}^{(i)}$ equal the
   slots `nested_p_commitment`, `nested_a_commitment`, `nested_b_commitment` and
   `nested_registry_xy_commitment` of $U^{(i)}$.

### `bind_endoscalar` {#bind-endoscalar}

The circuit ties the native walk to the unified instance: the walk's endoscalar
to $\text{pre\_beta}$, and its output and three of its inputs to their slots.
Public output: $k_{\text{uni}}$.

1. All $101$ points of the [native walk](walks.md#native-walk) are curve points.
2. $\text{pre\_beta}$ is decomposed, its endoscalar is hoisted, and the result
   equals the `endoscalar` of the `WalkStage`, wire by wire.
3. $I_{q,24}$ equals `nested_p_commitment`. The points `a` and `b` of
   `points::AbStage` equal `nested_a_commitment` and `nested_b_commitment`. The
   point `registry_xy` of `points::FStage` equals
   `nested_registry_xy_commitment`.

### `endoscaling_step[s]` {#native-endoscaling-step}

The circuit checks one line of the native walk's recurrence. Public output: a
single zero, so $k(Y) = 1$.

1. Start from $I_{q,s-1}$, or from $[f_q]$ when $s = 0$.
2. For $t = 0, \dots, 3$, endoscale the running point by the `WalkStage`
   endoscalar and add $C_{q,4s+t+1}$.
3. The result equals $I_{q,s}$.

This circuit relies on the bits and the curve membership that `bind_endoscalar`
enforces.

## Nested Circuits {#nested-circuits}

| Circuit | Index | Last Stage | Loaded |
|---|---|---|---|
| `EndoscalingStep(s)` | $s$ | `PointsStage` | `EndoscalarStage`, `PointsStage` |
| `Collapse` | 29 | `ChallengeStage` | all twelve stages |
| `ComputeV` | 30 | `ChallengeStage` | all twelve stages |
| `Loading` | 45 | `BridgeEval` | `PointsStage`, `BridgePreamble`, `BridgeSPrime`, `BridgeInnerError`, `BridgeAB`, `BridgeQuery`, `BridgeF` |

Every nested stage is loaded unenforced. `Collapse` re-emits the two contracts
that the nested walk depends on, in its items 1 and 2.

### `EndoscalingStep(s)` {#nested-endoscaling-step}

The circuit checks one line of the nested walk's recurrence. Public output:
empty, so $k(Y) = 1$.

1. Start from $I_{s-1}$, or from $C_0$ when $s = 0$.
2. For $t = 0, \dots, 3$, endoscale the running point by the `EndoscalarStage`
   endoscalar and add $C_{4s+t+1}$. The last circuit, $s = 28$, stops after
   $t = 1$.
3. The result equals $I_s$.

### `Collapse` {#nested-collapse}

The circuit checks both layers of the nested fold, and ties the exported points
of the nested unified instance to the stages that hold them. Public output: the
[nested unified instance](proof.md#nested-unified). Let
$\text{tgt}_{q,0}, \dots, \text{tgt}_{q,79}$ be the
[nested targets](claims.md#nested-claims) in claim order, computed in circuit
from the `BridgePreamble` stage at the $y_q$ of the challenge stage.

1. All $144$ points of the `PointsStage` are curve points.
2. The `EndoscalarStage` holds $143$ bits and the $94$ products of those bits.
3. The slots `x`, `y` and `u` equal the challenge stage's $x_q$, $y_q$ and
   $u_q$.
4. The point of the `BridgeHash` stage equals $O_1$ in `BridgePreamble`.
5. Each exported $E_j$ equals the stage value listed for it on the
   [proof page](proof.md#nested-unified).
6. For each group $g < 10$, the wire $\text{col}_{q,g}$ of the
   `BridgeOuterError` stage equals

   $$\sum_{j < 8} \ell^{(8)}_j(\mu_q) \, \text{tgt}_{q,8g+j} + V^{(8)}(\mu_q) \sum_{k < 7} \text{quo}_{q,g,k} \, \mu_q^k.$$

7. Compute, over those wires,

   $$c_q^\ast = \sum_{g < 10} \ell^{(10)}_g(\mu'_q) \, \text{col}_{q,g} + V^{(10)}(\mu'_q) \sum_{k < 9} \text{quo}'_{q,k} \, {\mu'_q}^k$$

   and enforce $(1 - \text{base}_q) \cdot (c_q - c_q^\ast) = 0$.

No nested circuit constrains $\sigma$. It is fixed from the native side through
the [challenge stage commitment](stage_contents.md#challenge-stage).

### `ComputeV` {#nested-compute-v}

The circuit checks the nested batched opening. Public output: the nested unified
instance. The circuit constrains only the slot `v`. `Collapse` constrains the
other slots, and the two claims take [one target](claims.md#nested-targets).

1. $t(x_q, z_q)$ is computed as in the native [`compute_v`](#native-compute-v),
   which requires $x_q \ne 0$ and $z_q \ne 0$.
2. $\text{ax}_q$ and $\text{bx}_q$ are computed as on the
   [batch page](batch.md#ax-bx).
3. For each of the $56$ opening points $\rho$ an inverse $d_\rho$ is allocated
   with $d_\rho \cdot (u_q - \rho) = 1$. The points are $u_q^{(i)}$, $y_q^{(i)}$
   and $x_q^{(i)}$ for each child, $w_q$, $x_q$, $y_q$, $x_q z_q$, and the $46$
   constants $\omega_{q,j}$.
4. The lift of the `EndoscalarStage` endoscalar, computed in circuit, equals the
   challenge stage's $\beta_q$.
5. $v_q$ is computed by the [batch formula](batch.md#batch-structure) over the
   $150$ nested openings and the $100$ evaluations of the `BridgeEval` stage.

Item 4 binds the endoscalar that the nested walk used to $\text{pre\_beta}$: a
parent's `bind_beta` binds the challenge stage's $\beta_q$, and a lift
[determines its endoscalar](cycle.md#endoscalars).

### `Loading` {#loading}

`Loading` is registered as a [stripped circuit](staging.md#stripped) and has no
polynomial of its own. Its constraints are the $115$ point equalities in the
table of the [nested walk](walks.md#nested-walk): each input of the
`PointsStage` equals its bridge-stage field, and the initial point equals
`BridgeF.native_f`. It is claimed as a bonding claim over the sum of the seven
stages that it loads.
