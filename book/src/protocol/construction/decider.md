# Decider {#decider}

The **decider** checks a root proof, which no parent folds. It holds every
polynomial of that proof and tests the accumulator and the frontier directly, at
points that it samples. In the implementation the decider is
[`Application::verify_uncompressed`](ragu_pcd::Application::verify_uncompressed),
a test oracle. **Production verification compresses the proof first, which is
out of scope for this section.**

The input is a proof $\pi$ with the data $\delta$ of its output header. The
decider derives $c$, $v$, $c_q$ and $v_q$ from the polynomials, and it
recomputes or compares everything else that it reads, with one exception:
`nested_challenges_partial` enters $U$ as stored, and the `bind_challenges`
claims of check 4 hold it to the challenges.

## Checks {#decider-checks}

The decider samples $\tau_w, \tau_y, \tau_z, \tau_r \in \F_p$ and
$\tau_{q,w}, \tau_{q,y}, \tau_{q,z}, \tau_{q,r} \in \F_q$ uniformly. The nested
samples are fresh field elements, not lifts. The decider accepts when all of the
following hold.

1. $\pi$ is [well formed](proof.md#stored-derived).
2. `circuit_id` names a point of the native registry domain.
3. Each of the nine challenges has an endoscalar.
4. Every claim of the [native list for a single proof](#single-proof) holds at
   $(\tau_y, \tau_z)$.
5. Every claim of the [nested list for a single proof](#single-proof) holds at
   $(\tau_{q,y}, \tau_{q,z})$.
6. Each stored registry restriction agrees with its registry at a random point:
   the stored native restriction, evaluated at $\tau_w$, equals
   $m(\tau_w, x, y)$, and the stored nested restriction, evaluated at
   $\tau_{q,w}$, equals $m_q(\tau_{q,w}, x_q, y_q)$.

7. $r_q[\texttt{ChallengeStage}]$ equals, coefficient by coefficient, the stage
   polynomial with $\v{a}_0 = 0$ over
   $(w_q, y_q, z_q, \mu_q, \mu'_q, x_q, \alpha_q, u_q)$, the sign $\sigma$
   and $\beta_q$. The sign is $+1$ when `circuit_id` is the index of
   `Bootstrap` and $-1$ otherwise.
8. For the $52$ pairs $(\phi_i, \Phi_i)$ of a native polynomial and its stored
   commitment,

   $$\sum_{i=0}^{51} \tau_r^{51-i} \cdot \Phi_i = \Big[ \sum_{i=0}^{51} \tau_r^{51-i} \, \phi_i \Big].$$

   The polynomials are the $46$ rx polynomials, $A$, $B$, $m(W, x, y)$, $p$,
   $o_0$ and $o_1$.
9. The same holds with $\tau_{q,r}$ for the $47$ nested pairs: the $43$ rx
   polynomials, $A_q$, $B_q$, $m_q(W, x_q, y_q)$ and $p_q$.
10. The values `a` and `b` read from $r[\texttt{PointsAb}]$ and `registry_xy`
    read from $r[\texttt{PointsF}]$ are the coordinates of $[A_q]$, $[B_q]$ and
    $[m_q(W, x_q, y_q)]$.
11. Replaying the eight absorptions of the [rounds](protocol.md#rounds) over the
    stored bridge commitments yields the nine stored challenges. A bridge
    commitment equal to the identity is rejected.
12. $r_q[\texttt{BridgeAB}]$ equals, coefficient by coefficient, the stage
    polynomial over $[A]$, $[B]$ and $R[\texttt{PointsAb}]$ with
    $\v{a}_0 = \texttt{bridge\_alpha}^2$.
13. The [registry values and current-fuse evaluations](#stage-values) that the
    query and evaluation stages claim are correct.

Checks 8 and 9 include $P = [p]$ and $P_q = [p_q]$.

Each randomized check can pass when what it tests is false, with a probability
that is bounded as follows.

- A circuit claim of check 4 or 5 whose trace violates a gate or a constraint
  holds at the sampled point with probability at most $(4n - 1)/|\F|$, the
  bound of the [combined check](arithmetization.md#combinedcheck), with $\F$
  the field of the side.
- A bonding claim over a list of $L$ polynomials, one of which violates a
  constraint, holds with probability at most
  [$(4n - 2 + L)/|\F|$](claims.md#claims). The longest list has $26$ entries on
  the native side and $29$ on the nested side.
- A stored restriction that is not that of the registry passes check 6 with
  probability at most $(4n - 1)/|\F|$, since the two differ by a polynomial of
  degree at most $4n - 1$.
- A stored commitment that is not the commitment of its polynomial passes
  check 8 with probability at most $51/|\F_p|$, and check 9 with probability
  at most $46/|\F_q|$.[^rlc]

[^rlc]: By the linearity of the commitment, check 8 says that
    $\sum_i \tau_r^{51-i} \cdot (\Phi_i - [\phi_i])$ is the identity. The group
    has prime order, so this is a polynomial in $\tau_r$ of degree at most
    $51$, and it is nonzero when some $\Phi_i$ differs from $[\phi_i]$.

## Claims of a Single Proof {#single-proof}

The single-proof lists are the [claim lists](claims.md) with one proof in place
of two children. A sum on an $a$ side is unchanged, and a Horner list has one
entry per named polynomial instead of two.

The native list has $51$ claims: the $35$ internal circuits and $16$ of the
$18$ bondings. It has no claim for the step circuit and none for the two
bonding polynomials of the application stage. The proof's own fuse folded those
three claims, and the proof does not hold their polynomials. The native raw
claim is omitted as well, because its target $c$ is derived from the
polynomials that it would test. The targets are computed from $\pi$, with $U$
assembled from the stored commitments, the stored challenges,
`nested_challenges_partial` and the derived $c$ and $v$.

The target of `hashes_1` is [$k_{\text{bridge}}(\tau_y)$](proof.md#native-unified)
over $U$, the output header that the decider was given, and the domain point
of `circuit_id`:

$$\text{Horner}_{\tau_y}[U_1, \dots, U_{39}, \text{hdr}(\delta), \omega_{\text{id}}, 0, 1].$$

This claim is what holds the proof to $\delta$. The root's `hashes_1` exports
the header and the index that the root's step-circuit claim was folded with, and
the decider stands where a parent would, with its own copy of each.

The target of each of the other nine circuits with the
[unified instance](proof.md#native-unified), `compute_v` among them, is
$k_{\text{uni}}(\tau_y)$. The target of each `endoscaling_step` is $1$, and the
target of each bonding claim is $0$.

Check 2 keeps the index that the decider reads, here and in the
[stage values](#stage-values), inside the domain in which the root's `hashes_1`
placed its own copy.

The nested list has $47$ claims: the raw claim, the $29$ endoscaling steps,
`Collapse`, `ComputeV` and the $15$ bondings. The raw claim is included and
holds by construction. The target of `Collapse` and `ComputeV` is
$k_q(\tau_{q,y})$ over the proof's own
[nested instance](proof.md#nested-unified), with $E_0, \dots, E_{15}$ read from
the stored native commitments.

## Stage Values {#stage-values}

The decider reads wires out of stage polynomials and compares them with values
that it computes. The children's $x^{(i)}$ and $y^{(i)}$ are read from
$r[\texttt{Preamble}]$, and their nested $x_q^{(i)}$, $y_q^{(i)}$ from
$r_q[\texttt{BridgePreamble}]$. The point $\omega_{\text{id}}$ is that of the
proof's `circuit_id`.

| Stage Wire | Native Value | Nested Value |
|---|---|---|
| `fixed_registry` at $j$ | $m(\omega_j, x, y)$ | $m_q(\omega_{q,j}, x_q, y_q)$ |
| `registry_wxy` | $m(w, x, y)$ | $m_q(w_q, x_q, y_q)$ |
| `child_registry_xy_at_current_w` | $m(w, x^{(i)}, y^{(i)})$ | $m_q(w_q, x_q^{(i)}, y_q^{(i)})$ |
| `registry_xy_at_circuit_id` | $m(\omega_{\text{id}}, x, y)$ | none |
| `current_registry_wy_at_child_x` | $m(w, x^{(i)}, y)$ | $m_q(w_q, x_q^{(i)}, y_q)$ |
| `registry_wx0`, `registry_wx1` in the evaluation stage | $m(w, x^{(i)}, u)$ | $m_q(w_q, x_q^{(i)}, u_q)$ |
| `registry_wy` in the evaluation stage | $m(w, u, y)$ | $m_q(w_q, u_q, y_q)$ |
| `a_poly`, `b_poly` in the evaluation stage | $A(u)$, $B(u)$ | $A_q(u_q)$, $B_q(u_q)$ |
| `registry_xy` in the evaluation stage | $m(u, x, y)$ | $m_q(u_q, x_q, y_q)$ |

The native wires are in $r[\texttt{Query}]$ and $r[\texttt{Eval}]$, and the
nested ones in $r_q[\texttt{BridgeQuery}]$ and $r_q[\texttt{BridgeEval}]$. The
proof does not store the restrictions `registry_wx` and `registry_wy`, so their
claimed values are checked against the registry instead.

## Scope {#decider-scope}

The decider does not recompute either walk, does not rebuild $p$ from $f$ and
the batched polynomials, and does not check a child's opened values one by one.
The walks and the opened values are constrained by the fuse's own circuits, and
checks 4 and 5 establish that those circuits are satisfied. The walks constrain
the commitments $P$ and $P_q$, and checks 8 and 9 hold $p$ and $p_q$ to them.

The decider does not examine the children's claims or the claim of the root's
step circuit. They were folded into $(A, B)$ and $(A_q, B_q)$. The `collapse`
and `Collapse` claims of checks 4 and 5 bind the derived $c$ and $c_q$ to the
fold of the targets, and the `compute_v` and `ComputeV` claims, with the root's
batched openings, bind the folded polynomials to the
[claim lists](batch.md#ax-bx).

The decider waives nothing for the [base case](base_case.md#bootstrap). It only
reads the sign of check 7 from `circuit_id`.
