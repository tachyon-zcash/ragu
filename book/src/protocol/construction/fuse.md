# Fuse {#fuse}

The procedure of [`Application::fuse`](ragu_pcd::Application::fuse) follows the
[rounds](protocol.md#rounds) of the protocol.

The inputs are a registered step with its witness, two children
$(\pi^{(0)}, \delta^{(0)})$ and $(\pi^{(1)}, \delta^{(1)})$, each a proof with
the data of its output header, and a source of randomness. The output is a proof
$\pi$ with the data of the step's output header.

The **stage of** a list of contents is the
[stage polynomial](staging.md#stage-polynomial) over those contents with a fresh
uniformly random $\v{a}_0$, unless a value is given. The **trace of** a circuit
is its assembled polynomial, which also takes a fresh random $\v{a}_0$. A
commitment is computed from its polynomial unless stated otherwise.

## Procedure {#procedure}

For the prover's messages, transcript challenges, and verifier checks on both
curves, see the [detailed Fuse PIOP](../iop.md).

### Before the First Round {#fuse-start}

1. Reject unless both children are [well formed](proof.md#stored-derived).
2. Sample `bridge_alpha` from $\F_q$ and start the
   [transcript](cycle.md#transcript).

### Round 1 {#fuse-round-1}

3. Set `circuit_id` to the step's registry index, $\text{hdr}_L$ to
   $\text{hdr}(\delta^{(0)})$ and $\text{hdr}_R$ to $\text{hdr}(\delta^{(1)})$.
4. Run the step's first phase to obtain $o_0$, $o_1$ and the staged values.
   Reject if either online polynomial is zero or has more than $4n$
   coefficients, or if the step stages other than the number of values it
   declares. Set $r[\texttt{ApplicationStage}]$ to the stage of the staged
   values.
5. Set $r[\texttt{PointsBinding}]$ and $r[\texttt{PointsPreamble}]$ to the
   stages of the children's nested commitments: $14$ per child in the first and
   $33$ per child in the second.
6. Set $r_q[\texttt{BridgePreamble}]$ to the
   [stage](stage_contents.md#bridge-preamble) of this fuse's native commitments
   so far and of the two children. Set $r_q[\texttt{BridgeHash}]$ to the stage
   of $O_1$ with $\v{a}_0 = 0$.
7. Absorb $R_q[\texttt{BridgePreamble}]$ and squeeze $w$.

### Round 2 {#fuse-round-2}

8. Run the step circuit with $\zeta = w$. Set $r[\texttt{Application}]$ to its
   trace and record $\text{hdr}_O$ and the six openings. Reject if the circuit
   encodes input headers other than $\text{hdr}_L$ and $\text{hdr}_R$.
9. Set $r[\texttt{Preamble}]$ to the [stage](stage_contents.md#native-preamble)
   of the two children and of the fuse's own $\text{hdr}_O$, `circuit_id` and
   openings.
10. Compute $m(w, x^{(i)}, Y)$ and $m_q(w_q, x_q^{(i)}, Y)$ for both children,
    with their commitments.
11. Set $r[\texttt{PointsRegistryWx}]$ to the stage of the two nested
    commitments, and $r_q[\texttt{BridgeSPrime}]$ to the stage of the two native
    commitments, $R[\texttt{Preamble}]$, $R[\texttt{Application}]$ and
    $R[\texttt{PointsRegistryWx}]$.
12. Absorb $R_q[\texttt{BridgeSPrime}]$ and squeeze $y$, then $z$.

### Round 3 {#fuse-round-3}

13. Build the $91$ [native claims](claims.md#native-claims) at $(y, z)$ and the
    $79$ [nested claims](claims.md#nested-claims) at $(y_q, z_q)$.
14. Compute the [first-layer quotients](claims.md#fold-layer-1)
    $\text{quo}_{g,k}$ and $\text{quo}_{q,g,k}$.
15. Compute $m(w, X, y)$ and $m_q(w_q, X, y_q)$, with their commitments.
16. Set $r[\texttt{InnerError}]$ to the stage of the $\text{quo}_{g,k}$. Set
    $r_q[\texttt{BridgeInnerError}]$ to the stage of $R[\texttt{InnerError}]$,
    $[m(w, X, y)]$ and the $\text{quo}_{q,g,k}$.
17. Absorb $R_q[\texttt{BridgeInnerError}]$. Save the transcript state. Squeeze
    $\mu$.

### Round 4 {#fuse-round-4}

18. Fold each group on both sides to $a'_g$, $b'_g$.
19. Compute the six child [targets](claims.md#native-targets), the target
    $k_{\text{app}}(y)$ of the step circuit's claim and the collapsed values
    $\text{col}_g$, and the nested collapsed values $\text{col}_{q,g}$.
20. Compute the [second-layer quotients](claims.md#fold-layer-2) $\text{quo}'_k$
    and $\text{quo}'_{q,k}$.
21. Set $r[\texttt{OuterError}]$ to the stage of the $\text{quo}'_k$, the
    $\text{col}_g$, the six child targets and the saved transcript state. Set
    $r_q[\texttt{BridgeOuterError}]$ to the stage of $R[\texttt{OuterError}]$,
    the $\text{quo}'_{q,k}$ and the $\text{col}_{q,g}$.
22. Absorb $R_q[\texttt{BridgeOuterError}]$ and squeeze $\mu'$.

### Round 5 {#fuse-round-5}

23. Compute $A$ and $B$. Form $[A]$ as the
    [linear combination](claims.md#fold-schedule) of the children's commitments,
    $R[\texttt{Application}]$ and $R[\texttt{ApplicationStage}]$.
24. Compute $A_q$ and $B_q$.
25. Set $r[\texttt{PointsAb}]$ to the stage of $[m_q(w_q, X, y_q)]$, $[A_q]$ and
    $[B_q]$. Set $r_q[\texttt{BridgeAB}]$ to the stage of $[A]$, $[B]$ and
    $R[\texttt{PointsAb}]$ with $\v{a}_0 = \texttt{bridge\_alpha}^2$.
26. Absorb $R_q[\texttt{BridgeAB}]$ and squeeze $x$.

### Round 6 {#fuse-round-6}

27. Evaluate $m(\omega_j, x, y)$ over the native registry domain and interpolate
    $m(W, x, y)$. Compute the remaining claimed values of the
    [`query` stage](stage_contents.md#native-query).
28. Do the same on the nested side for the
    [`BridgeQuery` stage](stage_contents.md#bridge-query), obtaining
    $m_q(W, x_q, y_q)$.
29. Set $r[\texttt{Query}]$ to the stage of the native claimed values. Set
    $r_q[\texttt{BridgeQuery}]$ to the stage of $R[\texttt{Query}]$,
    $[m(W, x, y)]$ and the nested claimed values.
30. Absorb $R_q[\texttt{BridgeQuery}]$ and squeeze $\alpha$.

### Round 7 {#fuse-round-7}

31. Compute $f$ over the $172$ [native openings](batch.md#native-openings) and
    $f_q$ over the $150$ [nested openings](batch.md#nested-openings), with $[f]$
    and $[f_q]$.
32. Set $r[\texttt{PointsF}]$ to the stage of $[m_q(W, x_q, y_q)]$ and $[f_q]$.
    Set $r_q[\texttt{BridgeF}]$ to the stage of $[f]$ and $R[\texttt{PointsF}]$.
33. Absorb $R_q[\texttt{BridgeF}]$ and squeeze $u$.

### Round 8 {#fuse-round-8}

34. Lift the eight challenges so far. Compute the sign $\sigma$ from
    $\text{hdr}_L$ and $\text{hdr}_R$. Compute the three partial sums and
    `nested_challenges_partial` of the
    [challenge stage commitment](stage_contents.md#challenge-stage).
35. Evaluate the $114$ native batched polynomials at $u$ and the $100$ nested
    ones at $u_q$.
36. Repeat until $\text{pre\_beta} < 2^{254}$: set $r[\texttt{Eval}]$ to the
    stage of the native evaluations and the partial sums; set
    $r_q[\texttt{BridgeEval}]$ to the stage of $R[\texttt{Eval}]$ and the nested
    evaluations; on a copy of the transcript, absorb $R_q[\texttt{BridgeEval}]$
    and squeeze $\text{pre\_beta}$.
37. Set $r_q[\texttt{ChallengeStage}]$ to the stage of the eight lifts, $\sigma$
    and $\beta_q$ with $\v{a}_0 = 0$.

### Final Message {#fuse-final}

38. Compute $p$. Run the [nested walk](walks.md#nested-walk) over the $115$
    native commitments: set $r_q[\texttt{EndoscalarStage}]$ and
    $r_q[\texttt{PointsStage}]$ to their stages and
    $r_q[\texttt{EndoscalingStep}(s)]$ to the trace of each endoscaling step.
    Set $P$ to the last interstitial.
39. Compute $p_q$. Run the [native walk](walks.md#native-walk) over the $101$
    nested commitments: set $r[\texttt{PointsWalk}]$ to its stage and
    $r[\texttt{EndoscalingStep}(s)]$ to the trace of each endoscaling step. Set
    $P_q$ to the last interstitial.
40. Assemble the [native unified instance](proof.md#native-unified) with
    $c = \revdot{A}{B}$ and $v = p(u)$. Compute the traces of `hashes_1`,
    `hashes_2`, `collapse`, `compute_v`, the four `bind_challenges`, `bind_beta`
    and `bind_endoscalar`.
41. Assemble the [nested unified instance](proof.md#nested-unified) with
    $c_q = \revdot{A_q}{B_q}$ and $v_q = p_q(u_q)$. Compute the traces of
    `Collapse` and `ComputeV`.
42. Compute every commitment not yet computed and output $\pi$. The proof keeps
    the accumulator, the frontier and the auxiliary data of the
    [proof page](proof.md). It does not keep $r[\texttt{Application}]$ or
    $r[\texttt{ApplicationStage}]$, and it has no field for the three headers
    or the openings, which remain only as values of the `preamble` stage.

## Inputs of the Step Circuit {#step-circuit-inputs}

Item 8 is the only place where the step's own logic runs after a challenge.
Of what the step circuit reads, the staged values and the six online slot
polynomials are fixed before item 7 draws $w$. The staged values are committed
in item 6, with the application stage. The six online slot polynomials are the
children's four and the step's own two, and `BridgePreamble` holds all six
commitments.

The step's witness is not fixed. A value that the circuit takes from it after
$\zeta$ is drawn is the prover's choice given $\zeta$. A step therefore has to
[stage](setup.md#application-stage) every value that its checks at $\zeta$
read, other than the openings and the fields of its input headers.

The bridge hash is the commitment of a stage that holds $O_1$. Item 6 fixes
$O_1$, but the transcript does not absorb the commitment of that stage, so the
[$\v{a}_0$ of the stage](stage_contents.md#bridge-hash), and with it the bridge
hash, is not fixed before $w$. The honest prover sets $\v{a}_0 = 0$.

The input headers are committed only in item 9, with the `preamble` stage, but
[$w$ already fixes them](stage_contents.md#native-preamble): each is the output
header that a child's committed `hashes_1` trace exports.
