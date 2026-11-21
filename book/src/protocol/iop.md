# Fuse PIOP {#fuse-iop}

This chapter gives the [Fuse procedure](construction/fuse.md) in more detail
as a public-coin polynomial interactive oracle proof (PIOP) between a prover
$\mathcal{P}$ and a verifier $\mathcal{V}$. Each round gives the prover's
message, the bridge commitment Ragu absorbs, and the verifier's challenge.
The counts use the [Standard layout](construction/index.md) for uncompressed
proofs.

## Preliminaries {#iop-preliminaries}

The notation is that of the [curve cycle](construction/cycle.md#notation).

- $\F_p$ is the native field and $\F_q$ the nested field. A subscript $q$
  marks a nested object. If the canonical integer for $\chi \in \F_p$ is
  below $2^{254}$, its [endoscalar](construction/cycle.md#endoscalars)
  is its low $143$ bits.
  The nested side uses $\chi_q = \text{lift}_q(\text{endo}(\chi))$.
- In the PIOP, $[\phi]$ denotes an oracle for a polynomial with at most $4n$
  coefficients, where $n$ is the number of gates at the circuit's rank. In
  Ragu it denotes the
  [Pedersen vector commitment](construction/cycle.md#commitments) to those
  coefficients. For a circuit or stage $S$, $r[S]$ is its own
  polynomial and $R[S]=[r[S]]$. Unless a round specifies a value, the prover
  samples each new stage's free wire $\v{a}_0$ uniformly in its field.
- A [revdot claim](construction/claims.md#claims) $(a,b;\ \text{tgt})$ asserts
  $\revdot{a}{b}=\sum_{d=0}^{4n-1} a_d b_{4n-1-d}=\text{tgt}$. For a circuit
  with trace $r$ at registry index $j$, $a=r$ and
  $b(X)=r(zX)+s_j(X,y)+t(X,z)$. Here $s_j(X,y)=m(\omega_j,X,y)$ is the
  circuit's [wiring polynomial](construction/registry.md) and $t$ is the
  [gate correction polynomial](construction/arithmetization.md#combinedcheck).
  For a [bonding claim](construction/staging.md#bonding), $a$ is a Horner
  fold of traces at $z$, $b=s_j(X,y)$, and the target is zero. For nested
  `Loading`, let $L_i$ be the sum of child $i$'s seven stage polynomials.
  Its claim uses $a=z_q L_0+L_1$.
- $\ell^{(M)}_j$ and $V^{(M)}$ are the Lagrange basis and vanishing polynomials
  on the nodes $0, \dots, M - 1$, as in the
  [fold](construction/claims.md#fold-groups).
- An [accumulator](construction/proof.md#accumulator) on each side is
  $\bigl(([A], [B], c),\ (P, u, v),\ ([m(W, x, y)], x, y)\bigr)$. It is valid
  when $\revdot{A}{B} = c$, $P = [p]$ with $p(u) = v$, and the stored
  restriction is $m(W, x, y)$.

## Protocol in Detail {#iop-protocol}

Both parties use the application's two registries and public parameters.
The prover has two uncompressed child proofs with their polynomials and
output header data, and a registered step with its witness.

For each child $i \in \{0, 1\}$, the verifier has the
[native unified instance](construction/proof.md#native-unified) $U^{(i)}$, the
[nested unified instance](construction/proof.md#nested-unified), the encoded
output header $\text{hdr}^{(i)}_O$, and the registry point
$\omega^{(i)}_{\text{id}}$.
The verifier has oracle access to the children's polynomials. Each instance
supplies that child's accumulator values $c,v$ and points $u,x,y$ on its side.

Fuse folds the children's claims on both curves. The native fold also includes
the current step's circuit claim and its two bonding claims. Fuse outputs the
step's header and one accumulator per curve.

On each **Challenge** line, $\mathcal{V}$ sends the indicated field elements,
drawn uniformly from $\F_p$. Ragu derives them from one
[Poseidon transcript](construction/cycle.md#transcript) tagged `ragu-pcd-v1`.
It absorbs the named bridge commitment, affine $x$ coordinate then $y$,
and squeezes the challenges in order. Replay rejects an identity point.
Each raw squeeze must be below $2^{254}$ to supply its nested lift. Only
the final squeeze is retried.
The [schedule](construction/protocol.md#rounds) lists what each bridge fixes.

Before the first round, $\mathcal{P}$ checks that both child proofs have the
[shape the profile expects](construction/proof.md#stored-derived) and samples
`bridge_alpha` uniformly from $\F_q$.

### Round 1. Commit the step's polynomials and staged values {#iop-round-1}

1. The registered step determines the registry index $\text{id}$.
   The prover encodes each child's output header data as $\text{hdr}^{(i)}_O$.
   It runs the step's first phase to obtain the two
   online polynomials for polynomial oracle access ($o_0, o_1$) and the
   staged values.
   It aborts if either polynomial is zero or has more than $4n$
   coefficients, or if the step returns a different number of staged values
   than it declares. It places those values in the
   [application stage](construction/setup.md#application-stage) polynomial
   $r[\texttt{ApplicationStage}]$.
2. $\mathcal{P}$ sends $[o_0]$, $[o_1]$ and $R[\texttt{ApplicationStage}]$.
   `BridgePreamble` also binds both children's nested instances and their
   commitments on both curves. All six slot polynomials and the staged values
   are fixed before $w$. A private value read only from the step's witness
   can still depend on $w$.
3. **Challenge.** Absorb $R_q[\texttt{BridgePreamble}]$ and squeeze $w$.

### Round 2. Run the step and restrict the registries {#iop-round-2}

1. $\mathcal{P}$ runs the [step circuit](construction/setup.md#step-circuit)
   with $\zeta = w$ and the children's output header data. The prover rejects
   unless the encoded input headers returned by the circuit satisfy
   $\text{hdr}_L = \text{hdr}^{(0)}_O$ and $\text{hdr}_R = \text{hdr}^{(1)}_O$.
   The prover obtains the circuit's own polynomial $r[\texttt{Application}]$,
   with a uniformly random $\v{a}_0$, the encoded output header $\text{hdr}_O$,
   and one opening $(\xi_s, \eta_s)$ per slot $s$.
   The six slots, numbered $0$ to $5$, hold
   $o^{(0)}_0, o^{(0)}_1, o^{(1)}_0, o^{(1)}_1, o_0, o_1$.
   The step can open each slot once. Its adapter opens the rest at $w$ and
   enforces $\eta_s=1$ for each output slot it opens this way.
2. $\mathcal{P}$ sends $R[\texttt{Application}]$, $\omega_{\text{id}}$,
   $\text{hdr}_O$ and $(\xi_s, \eta_s)_{s < 6}$. For each child $i$ it also
   sends $[m(w, x^{(i)}, Y)]$ and $[m_q(w_q, x_q^{(i)}, Y)]$, the two
   registry restrictions in the free variable $Y$.
   The [`Preamble` stage](construction/stage_contents.md#native-preamble)
   records the step's domain point, output header and openings, and each
   child's native instance, output header and domain point. The proof stores
   the step's integer index $\text{id}$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeSPrime}]$ and squeeze $y$, then $z$.

The [bridge hash](construction/stage_contents.md#bridge-hash) is the point
$R_q[\texttt{BridgeHash}]$ with coordinates $(h_x,h_y)$. Round 1 fixes the
stage's input $[o_1]$. Its $\v{a}_0$ is still free when $w$ is drawn, although
the honest prover uses zero. `BridgeSPrime` then binds both coordinates
through the application trace before $y$ and $z$.

### Round 3. Commit the group quotients {#iop-round-3}

1. $\mathcal{P}$ forms the $91$
   [native claims](construction/claims.md#native-claims) at $(y,z)$ and pads
   the list to $98$ entries $(a_k,b_k;\ \text{tgt}_k)$.

   - $k=i$ holds child $i$'s raw claim $(A^{(i)},B^{(i)};\ c^{(i)})$.
   - $k=2$ holds the step's circuit claim at $\text{id}$, with trace
     $r[\texttt{Application}]+r[\texttt{ApplicationStage}]$ and target
     $k_{\text{app}}(y)$.
   - $k=3+2j+i$ holds child $i$'s circuit claim for internal circuit $j<35$.
     Its trace is its own polynomial plus the stages it loads.
   - $k=38+j$ holds the bonding claim at index $35\le j<53$, with target zero.
     For $j<51$, take each polynomial in the list for $j$ from the left child
     and then the right. Indices $51$ and $52$
     constrain $r[\texttt{ApplicationStage}]$ and $r[\texttt{Application}]$,
     respectively.
   - Each remaining entry, $91\le k<98$, holds $(0,0;\ 0)$.

   The $79$ [nested claims](construction/claims.md#nested-claims) at
   $(y_q,z_q)$ occupy $80$ entries with padding. The list has the
   raw claims at $k = i$, the circuit claim of child $i$'s nested internal
   circuit $j$ at $k = 2 + 2j + i$ for $j < 31$, the bonding claims at
   $k = 33 + j$ for $31 \le j < 46$, and one zero claim.
2. Both fold layers compute their quotients by interpolation. For $L$ pairs
   $(a_j,b_j)$, let $a(T)$ and $b(T)$ interpolate the two sides at the
   nodes $0,\ldots,L-1$.
   $$a(T)=\sum_{j<L}\ell_j^{(L)}(T)\,a_j,\qquad
     b(T)=\sum_{j<L}\ell_j^{(L)}(T)\,b_j.$$
   The quotient $q(T)$ satisfies
   $$V^{(L)}(T)\,q(T)=\revdot{a(T)}{b(T)}
      -\sum_{j<L}\ell_j^{(L)}(T)\,\revdot{a_j}{b_j}.$$
   Revdot acts on the coefficients in $X$. The sum uses the actual products
   at the nodes, so the difference vanishes there and $q$ has at most
   $L-1$ coefficients.

   In the first layer, split the list into $N$ groups of $M$ claims, with
   $(M,N)=(7,14)$ native and $(8,10)$ nested. Group $g$ uses the $L=M$
   pairs at indices $Mg+j$, in order. Write its quotient as
   $\text{quo}_g(T)=\sum_{k<M-1}\text{quo}_{g,k}T^k$ on the native side
   and $\text{quo}_{q,g}(T)$ on the nested side.
3. $\mathcal{P}$ sends $(\text{quo}_{g,k})$, $(\text{quo}_{q,g,k})$ and
   $[m(w, X, y)]$.
4. **Challenge.** Absorb $R_q[\texttt{BridgeInnerError}]$ and squeeze $\mu$.

### Round 4. Fold each group and commit the outer quotients {#iop-round-4}

1. For each group $g$, $\mathcal{P}$ computes
   $a'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, a_{Mg+j}$,
   $b'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, b_{Mg+j}$ and
   $$\text{col}_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{Mg+j} + V^{(M)}(\mu) \, \text{quo}_g(\mu),$$
   using the claim targets for the collapsed value $\text{col}_g$.
   The outer quotient uses the $L=N$ pairs $(a'_g,b'_g)$ in group order
   and their actual products $\revdot{a'_g}{b'_g}$ at the nodes. Write it as
   $\text{quo}'(T)=\sum_{k<N-1}\text{quo}'_kT^k$. On the nested side,
   $\mu_q$ gives the folded pairs, collapsed values $\text{col}_{q,g}$ and
   outer quotient $\text{quo}'_q$.
2. $\mathcal{P}$ sends $(\text{quo}'_k)$, $(\text{col}_g)$, $(\text{quo}'_{q,k})$
   and $(\text{col}_{q,g})$. The step claim contributes $k_{\text{app}}(y)$,
   including the bridge-hash coordinates, to the first native group.
   The compiled [`OuterError` stage](construction/stage_contents.md#native-outer-error)
   records three targets per child, $k_{\text{uni}}^{(i)}(y)$,
   $k_{\text{bridge}}^{(i)}(y)$ and $k_{\text{cv}}^{(i)}(y)$. It also holds
   the sponge state saved after absorbing $R_q[\texttt{BridgeInnerError}]$
   and before squeezing $\mu$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeOuterError}]$ and squeeze $\mu'$.

### Round 5. Commit the folded polynomials {#iop-round-5}

1. With $\text{wt}_{Mg+j} = \ell^{(N)}_g(\mu') \, \ell^{(M)}_j(\mu)$,
   $\mathcal{P}$ computes $A = \sum_k \text{wt}_k \, a_k$ and
   $B = \sum_k \text{wt}_k \, b_k$, and $A_q$, $B_q$ with $\mu_q, \mu'_q$.
2. $\mathcal{P}$ sends $[A]$, $[B]$, $[A_q]$, $[B_q]$ and
   $[m_q(w_q, X, y_q)]$. `PointsAb` holds that restriction's commitment,
   followed by $[A_q]$ and $[B_q]$. `BridgeAB` holds $[A]$, $[B]$ and
   $R[\texttt{PointsAb}]$, with $\v{a}_0=\texttt{bridge\_alpha}^2$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeAB}]$ and squeeze $x$.

### Round 6. Claim the opening values {#iop-round-6}

1. Use the [172 native openings](construction/batch.md#native-openings)
   $(\phi_i, \rho_i)_{i < 172}$ and the
   [150 nested openings](construction/batch.md#nested-openings)
   $(\phi_{q,i}, \rho_{q,i})_{i < 150}$ in table order. Each opening has a
   claimed value $\vartheta_i$ or $\vartheta_{q,i}$. The children's batched
   openings use $v^{(i)}$ and $v_q^{(i)}$ from their instances. The native
   slot openings use the recorded $\eta_s$.
2. In the [registry chain](construction/batch.md#registry-chain), each pair
   below shares one claimed value.

   - Each child's $m(W, x^{(i)}, y^{(i)})$ at $w$ and the fuse's
     $m(w, x^{(i)}, Y)$ at $y^{(i)}$.
   - For each child $i$, $m(w, x^{(i)}, Y)$ at $y$ and $m(w, X, y)$ at $x^{(i)}$.
   - $m(w, X, y)$ at $x$ and $m(W, x, y)$ at $w$.

   The nested registry uses the same pairs with the nested polynomials and
   points.
3. $\mathcal{P}$ sends $[m(W,x,y)]$ and the $157$ native and $141$ nested
   query values, counting each shared value once. From these component
   evaluations and the fold weights, $\mathcal{V}$ derives the claimed
   $A(xz),B(x)$ and $A_q(x_qz_q),B_q(x_q)$.
4. **Challenge.** Absorb $R_q[\texttt{BridgeQuery}]$ and squeeze $\alpha$.
   The bridge fixes the claimed values on both curves before $\alpha$.

### Round 7. Commit the batched quotients {#iop-round-7}

1. $\mathcal{P}$ forms each quotient using the polynomial's actual value at
   its opening point.
   $$\begin{aligned}
   f(X)&=\sum_{i<172}\alpha^{171-i}\frac{\phi_i(X)-\phi_i(\rho_i)}{X-\rho_i},\\
   f_q(X)&=\sum_{i<150}\alpha_q^{149-i}
     \frac{\phi_{q,i}(X)-\phi_{q,i}(\rho_{q,i})}{X-\rho_{q,i}}.
   \end{aligned}$$
   The verifier uses the claimed values $\vartheta_i,\vartheta_{q,i}$ to
   check $v,v_q$.
2. $\mathcal{P}$ sends $[f]$, $[f_q]$ and $[m_q(W, x_q, y_q)]$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeF}]$ and squeeze $u$.
   `BridgeQuery` fixed the nested restriction's claimed values before $\alpha$.
   `BridgeF` fixes its commitment $[m_q(W,x_q,y_q)]$ after $\alpha$ and
   before $u$.
   The [batching argument](construction/batch.md#batch-structure) tracks this
   restriction through the output accumulator.

### Round 8. Evaluate the batch entries {#iop-round-8}

1. Let $\psi_j$ and $\psi_{q,j}$ denote the native and nested batch entries.
   Both batches start with child $0$, then child $1$. For each
   child, list that side's circuit and stage polynomials in
   [rx order](construction/setup.md#rx-order), then the child's $A$, $B$,
   registry restriction and $p$. Append the current fuse's entries in this
   order.

   - The [native entries](construction/batch.md#native-p) are
     $m(w,x^{(0)},Y)$, $m(w,x^{(1)},Y)$,
     $r[\texttt{Application}]$, $r[\texttt{ApplicationStage}]$, $m(w,X,y)$,
     $A$, $B$, $m(W,x,y)$, then the six slot polynomials in slot order.
   - The [nested entries](construction/batch.md#nested-p) are
     $m_q(w_q,x_q^{(0)},Y)$,
     $m_q(w_q,x_q^{(1)},Y)$, $m_q(w_q,X,y_q)$, $A_q$, $B_q$, $m_q(W,x_q,y_q)$.

   Write $j(i)$ and $j_q(i)$ for the batch indices named by native and nested
   opening $i$. Multiple openings of one entry share its index. Equal
   polynomials in distinct slots or children keep separate indices.
2. $\mathcal{P}$ sends $\epsilon_j = \psi_j(u)$ for $j < 114$ and
   $\epsilon_{q,j} = \psi_{q,j}(u_q)$ for $j < 100$. `Eval` also holds the
   running sums after the first two, four and six lifts in the
   [challenge stage commitment](construction/stage_contents.md#challenge-stage).
3. **Challenge.** The last squeeze is $\text{pre\_beta}$. The compiled prover
   keeps the evaluations at $u$ and $u_q$ fixed. On each attempt it samples
   fresh $\v{a}_0$ coefficients for `Eval` and `BridgeEval`, absorbs the new
   $R_q[\texttt{BridgeEval}]$ into a copy of the transcript state after $u$,
   and squeezes $\text{pre\_beta}$. It keeps the stages from the first
   squeeze below $2^{254}$. An out-of-range squeeze in an earlier round
   aborts the fuse.
4. Set $\beta = \text{lift}_p(\text{endo}(\text{pre\_beta}))$ and
   $\beta_q = \text{lift}_q(\text{endo}(\text{pre\_beta}))$. The compiled
   `ChallengeStage` holds the eight nested lifts through $u_q$, the base-case
   sign ($+1$ if both input headers have suffix $2$, $-1$ otherwise), and
   $\beta_q$. Each occupies an $\v{a}$ wire with its $\v{d}$ wire zero,
   and $\v{a}_0=0$. The native `bind_challenges` circuits compute
   `nested_challenges_partial` from the eight challenges and the headers. A
   parent's `bind_beta` adds the $\beta_q$ term and checks the stage commitment.
   The [uncompressed root check](construction/decider.md#decider-checks)
   reconstructs the stage using the `Bootstrap` index to determine the sign.

### Final message {#iop-final}

$\mathcal{P}$ forms the two batched polynomials
$$p = \beta^{114} f + \sum_{j < 114} \beta^{113 - j} \psi_j,\qquad
p_q = \beta_q^{100} f_q + \sum_{j < 100} \beta_q^{99 - j} \psi_{q,j}.$$
It sends $c=\revdot{A}{B}$, $v=p(u)$, $c_q=\revdot{A_q}{B_q}$,
$v_q=p_q(u_q)$ and the bridge-hash coordinates $(h_x,h_y)$.
The [uncompressed proof](construction/proof.md#accumulator) carries $p,p_q$
and their walk commitments $P,P_q$. It derives the four scalars from its
polynomials when constructing its public instances. The transcript ends at
$\text{pre\_beta}$.

### Verifier checks {#iop-verifier}

During Fuse the prover constructs traces of the
[circuits that enforce these checks](construction/internal_circuits.md).
The native `hashes_1` and `hashes_2` circuits replay the eight bridge
commitments. `hashes_1` checks the sponge state saved in `OuterError`
after `BridgeInnerError`. `hashes_2` resumes there to squeeze $\mu$.
The nine squeezes must match the challenges in the native
instance in order. Each raw $\F_p$ value
$w,y,z,\mu,\mu',x,\alpha,u,\text{pre\_beta}$ must be below $2^{254}$.
The first eight are used directly on the native side. The nested side uses
their lifts, and both sides lift $\text{pre\_beta}$.

Check $\omega_{\text{id}}^{|D|}=1$ for the native registry domain $D$.
Check that $(h_x,h_y)$ are the coordinates of $R_q[\texttt{BridgeHash}]$
and that the stage holds the same $[o_1]$ as `BridgePreamble`.

1. Reject if $x = 0$, $z = 0$, or $u = \rho_i$ for some $i < 172$. On the
   nested side, reject if $x_q = 0$, $z_q = 0$, or $u_q = \rho_{q,i}$ for
   some $i < 150$.
2. Compute the [native](construction/claims.md#native-targets) and
   [nested](construction/claims.md#nested-claims) claim targets. The target
   for the native step circuit is the Horner evaluation, in wire order,
   $$k_{\text{app}}(y)=\operatorname{Horner}_y
   [w,(\xi_s,\eta_s)_{s<6},h_x,h_y,\text{hdr}_L,\text{hdr}_R,\text{hdr}_O,1].$$
   Each header contributes its [field encoding](construction/setup.md#headers),
   including the padding and type suffix. The two input headers use the same
   wires as their children's $k_{\text{bridge}}^{(i)}(y)$ targets. Outside
   the base case, these targets tie the headers to the children's `hashes_1`
   traces committed before $w$. For each child, `hashes_1` checks the
   $k_{\rm uni}$ and $k_{\rm bridge}$ values in `OuterError`, and native
   `collapse` checks $k_{\rm cv}$. The native batch uses the same six openings.
   The registry point $\omega_{\text{id}}$ selects the step's wiring.
3. Check every collapsed value on both curves, including in the base case.
   For each native group $g<14$ require
   $$\text{col}_g = \sum_{j<7}\ell_j^{(7)}(\mu)\,\text{tgt}_{7g+j}
                  + V^{(7)}(\mu)\,\text{quo}_g(\mu).$$
   For each nested group $g<10$ require
   $$\text{col}_{q,g} = \sum_{j<8}\ell_j^{(8)}(\mu_q)\,\text{tgt}_{q,8g+j}
                      + V^{(8)}(\mu_q)\,\text{quo}_{q,g}(\mu_q).$$
4. Outside the [base case](construction/base_case.md#waived), the native
   `collapse` and nested `Collapse` circuits enforce, respectively,
   $$c=\sum_{g<14}\ell_g^{(14)}(\mu')\,\text{col}_g
      +V^{(14)}(\mu')\,\text{quo}'(\mu'),$$
   $$c_q=\sum_{g<10}\ell_g^{(10)}(\mu'_q)\,\text{col}_{q,g}
      +V^{(10)}(\mu'_q)\,\text{quo}'_q(\mu'_q).$$
   The base case applies when both children's output headers end in the
   `Dummy` suffix $2$. Only these two equalities are waived. Native `collapse`
   then requires the `Bootstrap` registry point, the unit output header, and
   $(\xi_4,\eta_4)=(\xi_5,\eta_5)=(w,1)$. Nested `Collapse` reads the
   same decision from the sign in `ChallengeStage`.
5. Reconstruct the folded openings. For claim $k$, evaluate the expression
   for $a_k$ using the component values claimed at $xz$ to obtain $\text{ax}_k$.
   For the other side of the claim use
   $$\text{bx}_k=\begin{cases}
     B^{(i)}(x) & \text{raw claim of child }i,\\
     \text{ax}_k+s_j(x,y)+t(x,z) & \text{circuit claim at }j,\\
     s_j(x,y) & \text{bonding claim at }j,\\
     0 & \text{padding}.
   \end{cases}$$
   Here $B^{(i)}(x)$ and $s_j(x,y)=m(\omega_j,x,y)$ are claimed openings.
   The batch uses $\sum_k\text{wt}_k\,\text{ax}_k$ for $A(xz)$ and
   $\sum_k\text{wt}_k\,\text{bx}_k$ for $B(x)$. Apply the same rule to
   the nested claims, registry openings and weights for $A_q(x_qz_q)$ and $B_q(x_q)$.
6. Check the two batched values using each opening's batch index from
   [Round 8](#iop-round-8). Native `compute_v` enforces
   $$v=\beta^{114}\sum_{i<172}\alpha^{171-i}
       \frac{\epsilon_{j(i)}-\vartheta_i}{u-\rho_i}
       +\sum_{j<114}\beta^{113-j}\epsilon_j.$$
   Nested `ComputeV` enforces
   $$v_q=\beta_q^{100}\sum_{i<150}\alpha_q^{149-i}
       \frac{\epsilon_{q,j_q(i)}-\vartheta_{q,i}}{u_q-\rho_{q,i}}
       +\sum_{j<100}\beta_q^{99-j}\epsilon_{q,j}.$$
7. Compute the commitments to the two batch polynomials in the same order.
   $$\begin{aligned}
   P   &= \beta^{114}[f] + \sum_{j<114}\beta^{113-j}[\psi_j],\\
   P_q &= \beta_q^{100}[f_q] + \sum_{j<100}\beta_q^{99-j}[\psi_{q,j}].
   \end{aligned}$$
   For $P$, the [nested walk](construction/walks.md#nested-walk) takes its
   inputs from `PointsStage`. The `Loading` relation matches every input to
   its earlier bridge stage. `Collapse` checks curve membership of the
   walk points and the endoscalar's bits and bit products. `ComputeV` checks
   that the endoscalar lifts to $\beta_q$. `Collapse` matches $x_q,y_q,u_q$
   to `ChallengeStage` and all 16 exported points of the
   [nested instance](construction/proof.md#nested-unified), including $P$,
   to their stage wires.

   For $P_q$, the [native walk](construction/walks.md#native-walk) reads the
   nested commitments directly from their points stages. `bind_endoscalar`
   checks their curve membership and the walk bits and bit products derived
   from $\text{pre\_beta}$. It matches $P_q,[A_q],[B_q]$ and
   $[m_q(W,x_q,y_q)]$ to the native instance.
   `bind_beta` checks each child's $14$ commitments in `PointsBinding`
   against that child's native instance.

### Output {#iop-output}

The verifier outputs $(([A],[B],c),(P,u,v),([m(W,x,y)],x,y))$ and its nested
counterpart, together with the challenges, $\text{hdr}_O$, $\omega_{\text{id}}$,
$[o_0]$ and $[o_1]$.

The uncompressed proof retains the accumulator polynomials on both curves,
$o_0,o_1$, and the verifier circuits' traces and stages in its
[frontier](construction/proof.md#frontier). A parent folds the frontier and
raw claims and opens the child's batched polynomial and registry restriction
on each curve. At the root, the [uncompressed decider](construction/decider.md)
checks the retained polynomials directly in tests or with `test-utils`.
Production uses [`verify_compressed`](recursion/compression.md).
