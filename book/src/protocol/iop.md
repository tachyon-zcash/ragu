# Fuse PIOP {#fuse-iop}

This chapter gives the [Fuse procedure](construction/fuse.md) in more detail
as a public-coin polynomial interactive oracle proof (PIOP) between a prover
$\mathcal{P}$ and a verifier $\mathcal{V}$. Each round gives the prover's
message, the bridge commitment that Ragu absorbs, and the verifier's
challenge. The counts use the [Standard layout](construction/index.md) for
uncompressed proofs. The [Construction](construction/index.md) section has the
exact orders and layouts that the rounds refer to, and its
[schedule](construction/protocol.md#rounds) has the rounds at a glance.

## Preliminaries {#iop-preliminaries}

The notation is that of the [curve cycle](construction/cycle.md#notation).

- $\F_p$ is the native field and $\F_q$ the nested field. A subscript $q$
  marks a nested object. If the canonical integer for $\chi \in \F_p$ is
  below $2^{254}$, its [endoscalar](construction/cycle.md#endoscalars)
  is its low $143$ bits.
  The nested side uses $\chi_q = \text{lift}_q(\text{endo}(\chi))$.
- $[\phi]$ is the
  [Pedersen vector commitment](construction/cycle.md#commitments) to the
  coefficients of a polynomial $\phi$ with at most $4n$ coefficients, where
  $n$ is the number of gates at the circuit's rank. It is a point of the
  other field's curve. For a circuit or stage $S$, $r[S]$ is its own
  polynomial and $R[S]=[r[S]]$. Unless a round specifies a value, the prover
  samples the three [free coefficients](construction/wiring.md#blind-gate) of
  each new polynomial $r[S]$ uniformly in its field. A stage that is given a
  value of $\v{a}_0$ has zeros at the blind gate.
- Read as a PIOP, a commitment stands for an oracle to its polynomial: the
  verifier may ask for the polynomial's value at a point, and a linear
  combination of commitments is an oracle to the same combination of the
  polynomials. No oracle is queried on its own. Every query is an opening
  $(\phi_h, \rho_h, \vartheta_h)$ of the batch of rounds 6 to 8, which reduces
  all of them to the one opening of the output accumulator. Some steps use a
  commitment as a curve point instead, with its affine coordinates in a stage
  or as an input of a walk. Those steps belong to the compiled protocol, and
  the text marks them as such.
- A [revdot claim](construction/claims.md#claims) $(a,b;\ \text{tgt})$ asserts
  $\revdot{a}{b}=\sum_{d=0}^{4n-1} a_d b_{4n-1-d}=\text{tgt}$. For a circuit
  with trace $r$ at registry index $j$, $a=r$ and
  $b(X)=r(zX)+s_j(X,y)+t(X,z)$. Here $s_j(X,y)=m(\omega_j,X,y)$ is the
  circuit's [wiring polynomial](construction/registry.md) and $t$ is the
  [gate correction polynomial](construction/arithmetization.md#combinedcheck).
  The trace of a circuit is the sum of its own polynomial and the polynomials
  of the stages that it loads. For a
  [bonding claim](construction/staging.md#bonding), $a$ is a Horner
  fold of polynomials at $z$, $b=s_j(X,y)$, and the target is zero.
- $\ell^{(M)}_j$ and $V^{(M)}$ are the Lagrange basis and vanishing polynomials
  on the nodes $0, \dots, M - 1$, as in the
  [fold](construction/claims.md#fold).
- An [accumulator](construction/proof.md#accumulator) on each side is
  $\bigl(([A], [B], c),\ (P, u, v),\ ([\widehat{m}_{xy}], x, y)\bigr)$, where
  $\widehat{m}_{xy}(W)$ is a
  [candidate](construction/batch.md#registry-candidates) for a restriction of
  the registry. It is valid when $\revdot{A}{B} = c$, $P = [p]$ with
  $p(u) = v$, and $\widehat{m}_{xy}(W) = m(W, x, y)$. The honest prover's
  candidate is the restriction, and the rounds write its messages without the
  hat.
- The index $i$ is a child, $h$ is an opening and $j$ a batched polynomial of
  the [batch](construction/batch.md#batch-structure), and $k$ is a claim's
  position in its [list](construction/claims.md#native-claims). In the fold's
  grid, $g$ is a group and $j$ a slot.

## Contract {#iop-contract}

A fuse does not decide whether its children are valid. It reduces what the
children owe, and the claim of the current step, to what the output proof
owes.

Each child comes with obligations on each curve: its raw claim
$(A^{(i)}, B^{(i)};\ c^{(i)})$, its batched opening of $p^{(i)}$ at $u^{(i)}$,
the identity of its registry candidate, and the claims of its
[frontier](construction/proof.md#frontier), which say that the circuits of the
child's own fuse are satisfied. The current step adds the claim of its circuit
and two bonding claims on the native side. The fuse folds all of the revdot
claims into one raw claim per curve and batches all of the openings into one
opening per curve.

The verifier's [checks](#iop-verifier) of that fold and batch are not run
during a fuse. In the compiled protocol they are constraints of this fuse's
own internal circuits, the prover produces the traces of those circuits, and
the statements that the circuits are satisfied are revdot claims in turn: the
frontier of the output proof. The output proof therefore owes the new
accumulator on each curve and the claims of the new frontier.

The reduction is conditional. Valid output accumulators and true claims of the
new frontier are meant to imply that the children's obligations hold and that
the step's circuit is satisfied by a trace that was fixed before $y$ and $z$.
Construction argues each test separately and bounds the probability that it
passes on a false input: for the
[fold](construction/claims.md#fold-identity), for the
[batch](construction/batch.md#batch-structure) and for the
[registry chain](construction/batch.md#registry-candidates). Nothing in a fuse
is a final acceptance. A parent takes the output proof as a child and reduces
its obligations again, and the [root](#iop-output) is where they are settled.

The [base case](construction/base_case.md) is the exception. A fuse whose two
input headers are `Dummy` headers waives the last equality of the fold on each
curve, so it establishes nothing about the claims that it folds. Its other
checks stay in force, the collapsed values of the first layer among them, and
`collapse` holds such a fuse to the `Bootstrap` step, the unit output header
and padding output slots.

The bounds are those of single tests. They assume that commitments are binding
and that a committed polynomial can be extracted, and they do not account for
the queries of a prover to the transcript's hash, which the retried final
squeeze adds to. A statement for a whole tree of fuses has to combine them
through an argument that these chapters do not give.
[Assumptions of the Argument](ladder/assumptions.md) lists what is assumed and
what is left open.

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
drawn uniformly from $\F_p$. In the compiled protocol, Ragu derives them from
one [Poseidon transcript](construction/cycle.md#transcript) tagged
`ragu-pcd-v1`. It absorbs the named bridge commitment, affine $x$ coordinate
then $y$, and squeezes the challenges in order. Replay rejects an identity
point. Each raw squeeze must be below $2^{254}$ to supply its nested lift.
Only the final squeeze is retried.

Three properties of an object are kept apart in what follows. An object is
**fixed** before a challenge when the prover's message that determines it
precedes the challenge. A bridge commitment is **absorbed** by the transcript,
and it is the only thing of its round that is: it fixes the round's other
objects by holding their commitments or values. An object is **retained** when
the output proof stores it. The [schedule](construction/protocol.md#rounds)
lists what each bridge fixes, and the
[proof page](construction/proof.md#stored-derived) what is retained.

Before the first round, $\mathcal{P}$ checks that both child proofs have the
[shape the profile expects](construction/proof.md#stored-derived). It samples
`bridge_alpha` uniformly from $\F_q$. This is the code's name for a scalar
whose square is the $\v{a}_0$ of one bridge stage, and it is unrelated to the
challenge $\alpha$. It also samples the
[fold randomizers](construction/claims.md#randomizer) $a_\star$, $b_\star$,
$a_{q,\star}$, $b_{q,\star}$ and the
[batch randomizers](construction/batch.md#batch-randomizer) $p_\star$,
$p_{q,\star}$, with every coefficient uniform, and sets
$c_\star = \revdot{a_\star}{b_\star}$ and
$c_{q,\star} = \revdot{a_{q,\star}}{b_{q,\star}}$.

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
   All six slot polynomials and the staged values are fixed before $w$. A
   private value read only from the step's witness can still depend on $w$.
   In the compiled protocol, `BridgePreamble` holds these three commitments
   and binds both children's nested instances and their commitments on both
   curves.
3. **Challenge.** Absorb $R_q[\texttt{BridgePreamble}]$ and squeeze $w$.

### Round 2. Run the step and restrict the registries {#iop-round-2}

1. $\mathcal{P}$ runs the [step circuit](construction/setup.md#step-circuit)
   with $\zeta = w$ and the children's output header data. The prover rejects
   unless the encoded input headers returned by the circuit satisfy
   $\text{hdr}_L = \text{hdr}^{(0)}_O$ and $\text{hdr}_R = \text{hdr}^{(1)}_O$.
   The prover obtains the circuit's own polynomial $r[\texttt{Application}]$,
   the encoded output header $\text{hdr}_O$,
   and one opening $(\xi_s, \eta_s)$ per slot $s$.
   The six slots, numbered $0$ to $5$, hold
   $o^{(0)}_0, o^{(0)}_1, o^{(1)}_0, o^{(1)}_1, o_0, o_1$.
   The step can open each slot once. Its adapter opens the rest at $w$ and
   enforces $\eta_s=1$ for each output slot it opens this way.
2. $\mathcal{P}$ sends $R[\texttt{Application}]$, $\omega_{\text{id}}$,
   $\text{hdr}_O$ and $(\xi_s, \eta_s)_{s < 6}$. For each child $i$ it also
   sends $[m(w, x^{(i)}, Y)]$ and $[m_q(w_q, x_q^{(i)}, Y)]$, the two
   registry restrictions in the free variable $Y$. It sends the commitments
   of the fold randomizers, $[a_\star]$, $[b_\star]$, $[a_{q,\star}]$ and
   $[b_{q,\star}]$.
   In the compiled protocol, the
   [`Preamble` stage](construction/stage_contents.md#native-preamble)
   records the step's domain point, output header, openings and bridge-hash
   commitment, plus each child's native instance, output header and domain
   point. The proof stores
   the step's integer index $\text{id}$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeSPrime}]$ and squeeze $y$, then $z$.

The [bridge hash](construction/stage_contents.md#bridge-hash) is the point
$R_q[\texttt{BridgeHash}]$ with coordinates $(h_x,h_y)$. Round 1 fixes the
stage's input $[o_1]$. The stage's free coefficients are still free when $w$
is drawn, although the honest prover uses zero. The native `Preamble` records
the resulting point, and `BridgeSPrime` binds that stage before $y$ and $z$.
`collapse` enforces equality between this copy and the point in the unified
instance that the parent binds to `BridgeHash`.

### Round 3. Commit the group quotients {#iop-round-3}

1. $\mathcal{P}$ forms the $95$
   [native claims](construction/claims.md#native-claims) at $(y,z)$ and pads
   the list to $98$ entries $(a_k,b_k;\ \text{tgt}_k)$.

   - $k=i$ holds child $i$'s raw claim $(A^{(i)},B^{(i)};\ c^{(i)})$.
   - $k=2$ holds the step's circuit claim at $\text{id}$, with trace
     $r[\texttt{Application}]+r[\texttt{ApplicationStage}]$ and target
     $k_{\text{app}}(y)$.
   - $k=3+2j+i$ holds child $i$'s circuit claim for internal circuit $j<37$.
     Its trace is the circuit's own polynomial plus the stages it loads.
   - $k=40+j$ holds the bonding claim at index $37\le j<55$, with target zero.
     For $j<53$, take each polynomial in the list for $j$ from the left child
     and then the right. Indices $53$ and $54$
     constrain $r[\texttt{ApplicationStage}]$ and $r[\texttt{Application}]$,
     respectively.
   - Each remaining entry, $95\le k<98$, holds $(0,0;\ 0)$.

   The $82$ [nested claims](construction/claims.md#nested-claims) at
   $(y_q,z_q)$ are padded to $88$ entries. The list has the
   raw claims at $k = i$, the circuit claim of child $i$'s nested internal
   circuit $j$ at $k = 2 + 2j + i$ for $j < 33$, the bonding claims at
   $k = 35 + j$ for $33 \le j < 47$, and six zero claims.
2. Each list is laid out over a [grid](construction/claims.md#randomizer) of
   $N$ groups of $M$ slots, with $(M,N)=(8,15)$ native and $(9,12)$ nested.
   Each group $g<N-1$ takes the next $M-1$ claims of the list in its slots
   $0,\dots,M-2$ and the randomizer claim $(a_\star,b_\star;\ c_\star)$ in its
   last slot. The last group holds the half-claim $(a_\star,0;\ 0)$ in slot
   $0$ and zero claims in its other slots. Write
   $(a_{g,j},b_{g,j};\ \text{tgt}_{g,j})$ for the claim in slot $j$ of group
   $g$.
3. For each group, the
   [first layer](construction/claims.md#fold-layer-1) of the fold gives a
   quotient $\text{quo}_g(T)=\sum_{k<M-1}\text{quo}_{g,k}T^k$ with
   $$V^{(M)}(T)\,\text{quo}_g(T)
     =\sum_{j,j'<M}\revdot{a_{g,j}}{b_{g,j'}}\,\ell_j^{(M)}(T)\,\ell_{j'}^{(M)}(T)
      -\sum_{j<M}\revdot{a_{g,j}}{b_{g,j}}\,\ell_j^{(M)}(T).$$
   Revdot acts on the coefficients in $X$. The second sum uses the actual
   products at the nodes and not the targets, so the difference vanishes at
   every node and the division is exact whatever the claims are. The nested
   quotients $\text{quo}_{q,g}(T)$ are formed in the same way.
4. $\mathcal{P}$ sends $(\text{quo}_{g,k})$ with $c_\star$,
   $(\text{quo}_{q,g,k})$ with $c_{q,\star}$, and $[m(w, X, y)]$.
5. **Challenge.** Absorb $R_q[\texttt{BridgeInnerError}]$ and squeeze $\mu$.

### Round 4. Fold each group and commit the outer quotients {#iop-round-4}

1. For each group $g$, $\mathcal{P}$ computes
   $a'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, a_{g,j}$,
   $b'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, b_{g,j}$ and
   $$\text{col}_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{g,j} + V^{(M)}(\mu) \, \text{quo}_g(\mu),$$
   using the claim targets for the collapsed value $\text{col}_g$.
   The [second layer](construction/claims.md#fold-layer-2) repeats the
   construction over the $N$ pairs $(a'_g,b'_g)$ in group order, with their
   actual products $\revdot{a'_g}{b'_g}$ at the nodes. Write its quotient as
   $\text{quo}'(T)=\sum_{k<N-1}\text{quo}'_kT^k$. On the nested side,
   $\mu_q$ gives the folded pairs, collapsed values $\text{col}_{q,g}$ and
   outer quotient $\text{quo}'_q$.
2. $\mathcal{P}$ sends $(\text{quo}'_k)$, $(\text{col}_g)$,
   $(\text{quo}'_{q,k})$ and $(\text{col}_{q,g})$. The step claim contributes
   $k_{\text{app}}(y)$, including the bridge-hash coordinates, to the first
   native group.
   In the compiled protocol, the
   [`OuterError` stage](construction/stage_contents.md#native-outer-error)
   also records three targets per child, $k_{\text{uni}}^{(i)}(y)$,
   $k_{\text{bridge}}^{(i)}(y)$ and $k_{\text{cv}}^{(i)}(y)$, and the sponge
   state saved after absorbing $R_q[\texttt{BridgeInnerError}]$ and before
   squeezing $\mu$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeOuterError}]$ and squeeze $\mu'$.

### Round 5. Commit the folded polynomials {#iop-round-5}

1. With the fold weights
   $\text{wt}_{g,j} = \ell^{(N)}_g(\mu') \, \ell^{(M)}_j(\mu)$,
   $\mathcal{P}$ computes $A = \sum_{g,j} \text{wt}_{g,j} \, a_{g,j}$ and
   $B = \sum_{g,j} \text{wt}_{g,j} \, b_{g,j}$, and $A_q$, $B_q$ with
   $\mu_q, \mu'_q$.
2. $\mathcal{P}$ sends $[A]$, $[B]$, $[A_q]$, $[B_q]$ and
   $[m_q(w_q, X, y_q)]$. In the compiled protocol, `PointsAb` holds that
   restriction's commitment, followed by $[A_q]$ and $[B_q]$. `BridgeAB` holds
   $[A]$, $[B]$ and $R[\texttt{PointsAb}]$, with
   $\v{a}_0=\texttt{bridge\_alpha}^2$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeAB}]$ and squeeze $x$.

### Round 6. Claim the opening values {#iop-round-6}

1. Use the [180 native openings](construction/batch.md#native-openings)
   $(\phi_h, \rho_h)_{h < 180}$ and the
   [157 nested openings](construction/batch.md#nested-openings)
   $(\phi_{q,h}, \rho_{q,h})_{h < 157}$ in table order. Each opening has a
   claimed value $\vartheta_h$ or $\vartheta_{q,h}$. The children's batched
   openings use $v^{(i)}$ and $v_q^{(i)}$ from their instances. The native
   slot openings use the recorded $\eta_s$.
2. In the [registry chain](construction/batch.md#registry-chain), each pair
   below shares one claimed value.

   - Each child's candidate for $m(W, x^{(i)}, y^{(i)})$ at $w$ and the fuse's
     $m(w, x^{(i)}, Y)$ at $y^{(i)}$.
   - For each child $i$, $m(w, x^{(i)}, Y)$ at $y$ and $m(w, X, y)$ at
     $x^{(i)}$.
   - $m(w, X, y)$ at $x$ and $m(W, x, y)$ at $w$.

   The nested registry uses the same pairs with the nested polynomials and
   points.
3. $\mathcal{P}$ sends $[m(W,x,y)]$ and the $165$ native and $149$ nested
   query values, counting each shared value once. From these component
   evaluations and the fold weights, $\mathcal{V}$ derives the claimed
   $A(xz),B(x)$ and $A_q(x_qz_q),B_q(x_q)$.
4. **Challenge.** Absorb $R_q[\texttt{BridgeQuery}]$ and squeeze $\alpha$.
   The bridge fixes the claimed values on both curves before $\alpha$.

### Round 7. Commit the batched quotients {#iop-round-7}

1. $\mathcal{P}$ forms each quotient using the polynomial's actual value at
   its opening point.
   $$\begin{aligned}
   f(X)&=\sum_{h<180}\alpha^{179-h}\frac{\phi_h(X)-\phi_h(\rho_h)}{X-\rho_h},\\
   f_q(X)&=\sum_{h<157}\alpha_q^{156-h}
     \frac{\phi_{q,h}(X)-\phi_{q,h}(\rho_{q,h})}{X-\rho_{q,h}}.
   \end{aligned}$$
   The verifier uses the claimed values $\vartheta_h,\vartheta_{q,h}$ to
   check $v,v_q$.
2. $\mathcal{P}$ sends $[f]$, $[f_q]$, $[m_q(W, x_q, y_q)]$ and the
   commitments of the batch randomizers, $[p_\star]$ and $[p_{q,\star}]$.
3. **Challenge.** Absorb $R_q[\texttt{BridgeF}]$ and squeeze $u$.
   `BridgeQuery` fixed the claimed values of the nested restriction before
   $\alpha$. `BridgeF` fixes its commitment after $\alpha$ and before $u$.
   This order is intended. The
   [batching argument](construction/batch.md#batch-structure) treats the
   committed polynomial as a candidate and tracks it through the output
   accumulator.

### Round 8. Evaluate the batched polynomials {#iop-round-8}

1. Let $\psi_j$ and $\psi_{q,j}$ denote the native and nested batched
   polynomials. Both lists start with child $0$, then child $1$. For each
   child, list that side's circuit and stage polynomials in
   [rx order](construction/setup.md#rx-order), then the child's $A$, $B$,
   registry restriction and $p$. Append the current fuse's polynomials in
   this order.

   - The [native list](construction/batch.md#native-p) continues with
     $m(w,x^{(0)},Y)$, $m(w,x^{(1)},Y)$,
     $r[\texttt{Application}]$, $r[\texttt{ApplicationStage}]$, $m(w,X,y)$,
     $A$, $B$, $m(W,x,y)$, $a_\star$, $b_\star$, $p_\star$, then the six slot
     polynomials in slot order.
   - The [nested list](construction/batch.md#nested-p) continues with
     $m_q(w_q,x_q^{(0)},Y)$,
     $m_q(w_q,x_q^{(1)},Y)$, $m_q(w_q,X,y_q)$, $A_q$, $B_q$,
     $m_q(W,x_q,y_q)$, $a_{q,\star}$, $b_{q,\star}$, $p_{q,\star}$.

   Write $j(h)$ and $j_q(h)$ for the indices of the batched polynomials that
   native and nested opening $h$ name. Multiple openings of one polynomial
   share its index. Equal polynomials in distinct slots or children keep
   separate indices. No opening names $p_\star$ or $p_{q,\star}$.
2. $\mathcal{P}$ sends $\epsilon_j = \psi_j(u)$ for $j < 121$ and
   $\epsilon_{q,j} = \psi_{q,j}(u_q)$ for $j < 107$. In the compiled protocol,
   `Eval` also holds the running sums after the first two, four and six lifts
   in the
   [challenge stage commitment](construction/stage_contents.md#challenge-stage).
3. **Challenge.** The last squeeze is $\text{pre\_beta}$. The compiled prover
   keeps the evaluations at $u$ and $u_q$ fixed. On each attempt it samples
   fresh free coefficients for `Eval` and `BridgeEval`, absorbs the new
   $R_q[\texttt{BridgeEval}]$ into a copy of the transcript state after $u$,
   and squeezes $\text{pre\_beta}$. It keeps the stages from the first
   squeeze below $2^{254}$. An out-of-range squeeze in an earlier round
   aborts the fuse.
4. Set $\beta = \text{lift}_p(\text{endo}(\text{pre\_beta}))$ and
   $\beta_q = \text{lift}_q(\text{endo}(\text{pre\_beta}))$. The compiled
   `ChallengeStage` holds the eight nested lifts through $u_q$, the base-case
   sign ($+1$ if both input headers have suffix $2$, $-1$ otherwise), and
   $\beta_q$. Each occupies an $\v{a}$ wire with its $\v{d}$ wire zero,
   and the stage's free coefficients are zero. The native `bind_challenges`
   circuits compute `nested_challenges_partial` from the eight challenges and
   the headers. A parent's `bind_beta` adds the $\beta_q$ term and checks the
   stage commitment, as the
   [figure](construction/stage_contents.md#challenge-stage) of that chain
   shows. The
   [uncompressed root check](construction/decider.md#decider-checks)
   reconstructs the stage using the `Bootstrap` index to determine the sign.

### Final message {#iop-final}

$\mathcal{P}$ forms the two batched polynomials
$$p = \beta^{121} f + \sum_{j < 121} \beta^{120 - j} \psi_j,\qquad
p_q = \beta_q^{107} f_q + \sum_{j < 107} \beta_q^{106 - j} \psi_{q,j}.$$
It sends $c=\revdot{A}{B}$, $v=p(u)$, $c_q=\revdot{A_q}{B_q}$,
$v_q=p_q(u_q)$ and the bridge-hash coordinates $(h_x,h_y)$.
The [uncompressed proof](construction/proof.md#accumulator) carries $p,p_q$
and their walk commitments $P,P_q$. It derives the four scalars from its
polynomials when constructing its public instances. The transcript ends at
$\text{pre\_beta}$.

Deriving $c$ and $v$ from the retained polynomials makes the output's raw
claim and batched opening hold for whatever polynomials the proof retains. It
does not make them the polynomials that the rounds fixed. That is what the
checks below are for: check 4 holds $c$ to the fold of the claims' targets,
checks 5 and 6 hold the claimed $A(xz)$, $B(x)$ and $v$ to the opened values,
and check 7 holds $P$ to the commitments of the rounds.

### Verifier checks {#iop-verifier}

During Fuse the prover constructs traces of the
[circuits that enforce these checks](construction/internal_circuits.md). No
party evaluates the checks at that time: the claims of those circuits join
the output's frontier, as the [contract](#iop-contract) describes.
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

1. Reject if $x = 0$, $z = 0$, or $u = \rho_h$ for some $h < 180$. On the
   nested side, reject if $x_q = 0$, $z_q = 0$, or $u_q = \rho_{q,h}$ for
   some $h < 157$.
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
   The targets are laid out over the grid of [round 3](#iop-round-3), with
   $c_\star$ or $c_{q,\star}$ as the target of each randomizer claim and zero
   as the target of the half-claim. For each native group $g<15$ require
   $$\text{col}_g = \sum_{j<8}\ell_j^{(8)}(\mu)\,\text{tgt}_{g,j}
                  + V^{(8)}(\mu)\,\text{quo}_g(\mu).$$
   For each nested group $g<12$ require
   $$\text{col}_{q,g} = \sum_{j<9}\ell_j^{(9)}(\mu_q)\,\text{tgt}_{q,g,j}
                      + V^{(9)}(\mu_q)\,\text{quo}_{q,g}(\mu_q).$$
4. Outside the [base case](construction/base_case.md#waived), the native
   `collapse` and nested `Collapse` circuits enforce, respectively,
   $$c=\sum_{g<15}\ell_g^{(15)}(\mu')\,\text{col}_g
      +V^{(15)}(\mu')\,\text{quo}'(\mu'),$$
   $$c_q=\sum_{g<12}\ell_g^{(12)}(\mu'_q)\,\text{col}_{q,g}
      +V^{(12)}(\mu'_q)\,\text{quo}'_q(\mu'_q).$$
   The base case applies when both children's output headers end in the
   `Dummy` suffix $2$. Only these two equalities are waived. Native `collapse`
   then requires the `Bootstrap` registry point, the unit output header, and
   $(\xi_4,\eta_4)=(\xi_5,\eta_5)=(w,1)$. Nested `Collapse` reads the
   same decision from the sign in `ChallengeStage`.
5. Reconstruct the folded openings. For claim $k$ of the list, evaluate the
   expression for $a_k$ using the component values claimed at $xz$ to obtain
   $\text{ax}_k$. For the other side of the claim use
   $$\text{bx}_k=\begin{cases}
     B^{(i)}(x) & \text{raw claim of child }i,\\
     \text{ax}_k+s_j(x,y)+t(x,z) & \text{circuit claim at }j,\\
     s_j(x,y) & \text{bonding claim at }j,\\
     0 & \text{padding}.
   \end{cases}$$
   Here $B^{(i)}(x)$ and $s_j(x,y)=m(\omega_j,x,y)$ are claimed openings.
   With $\text{wt}_k$ the weight of the slot that holds claim $k$,
   $\text{wt}_\star$ the sum of the weights of the randomizer claim's slots
   and $\text{wt}_{N-1,0}$ the weight of the half-claim's slot, the batch uses
   $$\sum_k\text{wt}_k\,\text{ax}_k
       +(\text{wt}_\star+\text{wt}_{N-1,0})\,a_\star(xz)
     \quad\text{for }A(xz),\qquad
     \sum_k\text{wt}_k\,\text{bx}_k+\text{wt}_\star\,b_\star(x)
     \quad\text{for }B(x).$$
   Apply the same rule to the nested claims, registry openings, randomizers
   and weights for $A_q(x_qz_q)$ and $B_q(x_q)$.
6. Check the two batched values using each opening's index from
   [Round 8](#iop-round-8). Native `compute_v` enforces
   $$v=\beta^{121}\sum_{h<180}\alpha^{179-h}
       \frac{\epsilon_{j(h)}-\vartheta_h}{u-\rho_h}
       +\sum_{j<121}\beta^{120-j}\epsilon_j.$$
   Nested `ComputeV` enforces
   $$v_q=\beta_q^{107}\sum_{h<157}\alpha_q^{156-h}
       \frac{\epsilon_{q,j_q(h)}-\vartheta_{q,h}}{u_q-\rho_{q,h}}
       +\sum_{j<107}\beta_q^{106-j}\epsilon_{q,j}.$$
7. Compute the commitments to the two batched polynomials in the same order.
   $$\begin{aligned}
   P   &= \beta^{121}[f] + \sum_{j<121}\beta^{120-j}[\psi_j],\\
   P_q &= \beta_q^{107}[f_q] + \sum_{j<107}\beta_q^{106-j}[\psi_{q,j}].
   \end{aligned}$$
   This check belongs to the compiled protocol, where a commitment is a curve
   point and each side's circuits do the other side's group arithmetic.
   For $P$, the [nested walk](construction/walks.md#nested-walk) takes its
   inputs from `PointsStage`. `Collapse` matches every input to its earlier
   bridge stage, and checks curve membership of the walk points and the
   endoscalar's bits and bit products. `ComputeV` checks that the endoscalar
   lifts to $\beta_q$. `Collapse` also matches $x_q,y_q,u_q$ to
   `ChallengeStage` and all 16 exported points of the
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

The verifier outputs
$(([A],[B],c),(P,u,v),([\widehat{m}_{xy}],x,y))$ and its nested
counterpart, together with the challenges, $\text{hdr}_O$, $\omega_{\text{id}}$,
$[o_0]$ and $[o_1]$.

The uncompressed proof retains the accumulator polynomials on both curves,
$o_0,o_1$, and the verifier circuits' traces and stages in its
[frontier](construction/proof.md#frontier). It does not retain
$r[\texttt{Application}]$, $r[\texttt{ApplicationStage}]$, the restrictions in
$Y$ and in $X$, $f$, $f_q$ or the randomizers. The
[figure](construction/index.md#accumulator-frontier) of one generation shows
where each of these goes.

A parent does not verify the proof. It folds the frontier and raw claims and
opens the child's batched polynomial and registry candidate on each curve,
which leaves obligations of the same kinds on the parent's output. They are
discharged once, at the root. The
[uncompressed decider](construction/decider.md) checks the retained
polynomials directly, and is available in tests or with `test-utils`.
Production compresses the root and uses
[`verify_compressed`](recursion/compression.md).
