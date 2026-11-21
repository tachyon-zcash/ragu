# Fuse IOP {#fuse-iop}

This page states the fuse as a public-coin polynomial IOP between a prover
$\mathcal{P}$ and a verifier $\mathcal{V}$. Ragu compiles it with Pedersen
commitments, a Poseidon transcript, and internal circuits that perform the
verifier's checks, as the [Construction](construction/index.md) section
describes.

The fuse is generic over a profile. Wallets run the Standard profile.
Aggregators, such as miners, run the Aggregator profile, behind the
`unstable-aggregator` feature. It proves at the aggregator rank, takes
seventeen endoscalings per walk step instead of four, and adds circuits,
stages, claims, openings and an internal step for
[decompression](recursion/decompression.md). This page gives the fuse of the
Standard profile, in which those additions are empty, on uncompressed proofs.

## Preliminaries {#iop-preliminaries}

The notation is that of the [curve cycle](construction/cycle.md#notation).

- $\F_p$ and $\F_q$ are the native and nested fields, and every polynomial has
  at most $4n$ coefficients. $[\phi]$ is an oracle to $\phi$, compiled as its
  [commitment](construction/cycle.md#commitments). A subscript $q$ marks a
  nested object. The nested counterpart of a native challenge $\chi$ is
  $\chi_q = \text{lift}_q(\text{endo}(\chi))$, the lift of its
  [endoscalar](construction/cycle.md#endoscalars).
- A claim $(a, b;\ \text{tgt})$ asserts $\revdot{a}{b} = \text{tgt}$, with the
  [revdot product](construction/arithmetization.md). Circuit, bonding and raw
  claims are defined in [Claims](construction/claims.md#claims). A circuit or
  bonding claim at registry index $j$ uses $s_j(X, y) = m(\omega_j, X, y)$,
  where $m$ is the [registry polynomial](construction/registry.md).
- $\ell^{(M)}_j$ and $V^{(M)}$ are the Lagrange basis and vanishing polynomials
  on the nodes $0, \dots, M - 1$, as in the [fold](construction/claims.md#fold-groups).
- An [accumulator](construction/proof.md#accumulator) on each side is
  $\bigl(([A], [B], c),\ (P, u, v),\ ([m(W, x, y)], x, y)\bigr)$. It is valid
  when $\revdot{A}{B} = c$, $P = [p]$ with $p(u) = v$, and the stored
  restriction is $m(W, x, y)$.
- $U^{(i)}$ is child $i$'s [native unified instance](construction/proof.md#native-unified).
  The targets $k^{(i)}_{\text{uni}}$, $k^{(i)}_{\text{bridge}}$ and $k^{(i)}_q$
  are defined with the [claim lists](construction/claims.md#native-targets),
  and $k_{\text{app}}$ with the [step circuit](construction/setup.md#step-circuit).

## Protocol {#iop-fuse}

The input is two children $(\pi^{(0)}, \delta^{(0)})$ and
$(\pi^{(1)}, \delta^{(1)})$, each a proof with its output header data, and a
step with its witness. $\mathcal{V}$ holds the children's public instances and
has oracle access to their polynomials. Challenges are drawn from $\F_p$, and
$\mathcal{V}$ rejects a challenge of $2^{254}$ or more. The compiled prover
draws $\text{pre\_beta}$ again until it is below $2^{254}$.

The steps are stated for $\F_p$. From step 5 on, each also runs over $\F_q$ with
the nested challenges, $(M, N) = (8, 10)$ and the nested lists. $\mathcal{P}$
sends $[m_q(w_q, x_q^{(i)}, Y)]$ in step 3, $[m_q(w_q, X, y_q)]$ in step 10 and
$[m_q(W, x_q, y_q)]$ in step 14.

**Fuse**$\bigl((\pi^{(0)}, \delta^{(0)}), (\pi^{(1)}, \delta^{(1)})\bigr)$:

1. $\mathcal{P}$ runs the step's first phase and sends $[o_0]$, $[o_1]$ and
   $[r[\texttt{ApplicationStage}]]$.
2. $\mathcal{V}$ sends a challenge $w$.
3. $\mathcal{P}$ runs the step circuit at $\zeta = w$ and sends
   $[r[\texttt{Application}]]$, $\text{id}$, $\text{hdr}_O$,
   $(\xi_s, \eta_s)_{s < 6}$, $(h_x, h_y)$ and $[m(w, x^{(i)}, Y)]$ for
   $i \in \{0, 1\}$. $\mathcal{V}$ rejects unless $\omega_{\text{id}} \in D$.
4. $\mathcal{V}$ sends challenges $y$ and $z \ne 0$.
5. $\mathcal{P}$ and $\mathcal{V}$ form the claim list
   $(a_k, b_k;\ \text{tgt}_k)_{k < MN}$ of [round 3](#iop-protocol), in $N$
   groups of $M$, with $(M, N) = (7, 14)$.
6. $\mathcal{P}$ sends $[m(w, X, y)]$ and, for each group $g$, the
   coefficients of the polynomial $\text{quo}_g(T)$ such that
   $$\sum_{j, j' < M} \revdot{a_{Mg+j}}{b_{Mg+j'}} \, \ell^{(M)}_j(T) \, \ell^{(M)}_{j'}(T) = \sum_{j < M} \revdot{a_{Mg+j}}{b_{Mg+j}} \, \ell^{(M)}_j(T) + V^{(M)}(T) \, \text{quo}_g(T).$$
7. $\mathcal{V}$ sends a challenge $\mu$.
8. $\mathcal{P}$ sends, for each group $g$, the value
   $$\text{col}_g := \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{Mg+j} + V^{(M)}(\mu) \, \text{quo}_g(\mu),$$
   which $\mathcal{V}$ checks. $\mathcal{P}$ computes
   $a'_g = \sum_j \ell^{(M)}_j(\mu) \, a_{Mg+j}$ and
   $b'_g = \sum_j \ell^{(M)}_j(\mu) \, b_{Mg+j}$, and sends the coefficients
   of $\text{quo}'(T)$ such that
   $$\sum_{g, g' < N} \revdot{a'_g}{b'_{g'}} \, \ell^{(N)}_g(T) \, \ell^{(N)}_{g'}(T) = \sum_{g < N} \revdot{a'_g}{b'_g} \, \ell^{(N)}_g(T) + V^{(N)}(T) \, \text{quo}'(T).$$
9. $\mathcal{V}$ sends a challenge $\mu'$.
10. $\mathcal{P}$ and $\mathcal{V}$ compute
    $c := \sum_{g < N} \ell^{(N)}_g(\mu') \, \text{col}_g + V^{(N)}(\mu') \, \text{quo}'(\mu')$
    and $\text{wt}_{Mg+j} := \ell^{(N)}_g(\mu') \, \ell^{(M)}_j(\mu)$.
    $\mathcal{P}$ sends $[A]$ and $[B]$, where
    $A = \sum_k \text{wt}_k \, a_k$ and $B = \sum_k \text{wt}_k \, b_k$.
11. $\mathcal{V}$ sends a challenge $x \ne 0$.
12. $\mathcal{P}$ sends $[m(W, x, y)]$ and the claimed values
    $\vartheta_i = \phi_i(\rho_i)$ of the openings $(\phi_i, \rho_i)_{i < Q}$
    of [round 6](#iop-protocol), except those that $\mathcal{V}$ already holds
    or computes.
13. $\mathcal{V}$ sends a challenge $\alpha$.
14. $\mathcal{P}$ sends $[f]$, where
    $$f(X) = \sum_{i < Q} \alpha^{Q-1-i} \, \frac{\phi_i(X) - \phi_i(\rho_i)}{X - \rho_i}.$$
15. $\mathcal{V}$ sends a challenge $u$ that is not an opening point.
16. $\mathcal{P}$ sends $\epsilon_j = \psi_j(u)$ for each batched polynomial
    $\psi_j$, $j < J$: the distinct polynomials of the openings.
17. $\mathcal{V}$ sends a challenge $\text{pre\_beta}$, and both parties set
    $\beta := \text{lift}_p(\text{endo}(\text{pre\_beta}))$.
18. If both children's output headers end in the suffix $2$, $\mathcal{V}$
    checks that $\omega_{\text{id}}$ is the point of `Bootstrap`, that
    $\text{hdr}_O$ is the unit header, and that
    $(\xi_4, \eta_4) = (\xi_5, \eta_5) = (w, 1)$. In that case $c$ is the
    prover's value instead of the one computed in step 10.

At the end of the protocol,

- $\mathcal{V}$ outputs the accumulator
  $$\Bigl(([A], [B], c),\ \bigl(P, u, v\bigr),\ ([m(W, x, y)], x, y)\Bigr), \qquad P := \beta^{J} [f] + \sum_{j < J} \beta^{J-1-j} [\psi_j], \qquad v := \beta^{J} \sum_{i < Q} \alpha^{Q-1-i} \, \frac{\epsilon[\phi_i] - \vartheta_i}{u - \rho_i} + \sum_{j < J} \beta^{J-1-j} \epsilon_j,$$
  its nested counterpart, the challenges, $\text{hdr}_O$, $\omega_{\text{id}}$,
  $[o_0]$, $[o_1]$, and the step's instance
  $\bigl(\text{id}, w, (\xi_s, \eta_s)_{s<6}, (h_x, h_y), \text{hdr}^{(0)}_O, \text{hdr}^{(1)}_O, \text{hdr}_O\bigr)$;
- $\mathcal{P}$ outputs $A$, $B$,
  $p := \beta^{J} f + \sum_{j < J} \beta^{J-1-j} \psi_j$, $m(W, x, y)$, their
  nested counterparts, $o_0$ and $o_1$.

## Protocol in Detail {#iop-protocol}

The rounds below give the full claim and opening lists and the verifier's
checks.

**Common input.** For $i \in \{0, 1\}$: $U^{(i)}$, child $i$'s
[nested unified instance](construction/proof.md#nested-unified), its output
header $\text{hdr}^{(i)}_O$ and index point $\omega^{(i)}_{\text{id}}$, and
oracles to its polynomials. The values $c^{(i)}$, $v^{(i)}$, $u^{(i)}$,
$x^{(i)}$ and $y^{(i)}$ are entries of $U^{(i)}$.

**Prover input.** The children's polynomials, and a registered step with its
witness. $\mathcal{P}$ aborts if a child is not
[well formed](construction/proof.md#stored-derived), if the step circuit
encodes input headers other than the children's output headers, or if the step
prepared a polynomial other than the padding for an output slot that it does
not open.

The step's six online slots, numbered $0$ to $5$, hold
$o^{(0)}_0, o^{(0)}_1, o^{(1)}_0, o^{(1)}_1, o_0, o_1$.

**Round 1.**

1. $\mathcal{P}$ runs the step's first phase, obtaining its registry index
   $\text{id}$, its online polynomials $o_0, o_1$, and its staged values, and
   forms the [application stage](construction/setup.md#application-stage)
   polynomial $r[\texttt{ApplicationStage}]$ of the staged values with a
   uniformly random $\v{a}_0$.
2. $\mathcal{P}$ sends $[o_0]$, $[o_1]$, $[r[\texttt{ApplicationStage}]]$.
3. $\mathcal{V}$ sends $w \sample \F_p$.

**Round 2.**

1. $\mathcal{P}$ runs the [step circuit](construction/setup.md#step-circuit)
   with $\zeta = w$ and input headers $\text{hdr}_L = \text{hdr}^{(0)}_O$ and
   $\text{hdr}_R = \text{hdr}^{(1)}_O$. This gives the circuit's own polynomial
   $r[\texttt{Application}]$, with a uniformly random $\v{a}_0$, the output
   header $\text{hdr}_O$, and one opening $(\xi_s, \eta_s)$ per slot $s$. An
   unopened slot is opened at $\zeta$; for an output slot, $\eta_s$ is
   constrained to one.
2. $\mathcal{P}$ sends $[r[\texttt{Application}]]$, $\text{id}$,
   $\text{hdr}_O$, $(\xi_s, \eta_s)_{s < 6}$, the
   [bridge hash](construction/stage_contents.md#bridge-hash) $(h_x, h_y)$ of
   $[o_1]$, and $[m(w, x^{(i)}, Y)]$ and $[m_q(w_q, x_q^{(i)}, Y)]$ for
   $i \in \{0, 1\}$. In the compiled fuse the transcript does not absorb
   $(h_x, h_y)$, so the pair is not fixed before $y$ and $z$.
3. $\mathcal{V}$ sends $y, z \sample \F_p$.

**Round 3.**

1. $\mathcal{P}$ forms the native [claim list](construction/claims.md#native-claims)
   $(a_k, b_k;\ \text{tgt}_k)_{k < 98}$:
   - for $k = i \in \{0, 1\}$, the raw claim $(A^{(i)}, B^{(i)};\ c^{(i)})$;
   - for $k = 2$, the circuit claim of
     $r[\texttt{Application}] + r[\texttt{ApplicationStage}]$ at index
     $\text{id}$ with instance polynomial $k_{\text{app}}$;
   - for $k = 3 + 2j + i$ with $j < 35$, the circuit claim of child $i$'s
     internal circuit $j$, whose trace is its own polynomial plus the stages
     that it loads;
   - for $k = 38 + j$ with $35 \le j < 53$, the bonding claim at index $j$:
     for $j < 51$, over the polynomials of both children that bonding
     polynomial $j$ constrains, child $0$'s before child $1$'s for each; for
     $j = 51$, over $r[\texttt{ApplicationStage}]$; for $j = 52$, over
     $r[\texttt{Application}]$;
   - for $91 \le k < 98$, the claim $(0, 0;\ 0)$.

   The [nested list](construction/claims.md#nested-claims)
   $(a_{q,k}, b_{q,k};\ \text{tgt}_{q,k})_{k < 80}$, at $(y_q, z_q)$, has the
   raw claims at $k = i$, the circuit claim of child $i$'s nested internal
   circuit $j$ at $k = 2 + 2j + i$ for $j < 31$, the bonding claims at
   $k = 33 + j$ for $31 \le j < 46$, and one zero claim.
2. With $(M, N) = (7, 14)$ native and $(8, 10)$ nested, claim $Mg + j$ is in
   group $g$ at node $j$. For each group $g < N$, $\mathcal{P}$ computes
   $$\text{quo}_g(T) = \frac{\sum_{j, j' < M} \revdot{a_{Mg+j}}{b_{Mg+j'}} \, \ell^{(M)}_j(T) \, \ell^{(M)}_{j'}(T) - \sum_{j < M} \revdot{a_{Mg+j}}{b_{Mg+j}} \, \ell^{(M)}_j(T)}{V^{(M)}(T)} = \sum_{k < M - 1} \text{quo}_{g,k} \, T^k,$$
   and $\text{quo}_{q,g}$ over the nested list.
3. $\mathcal{P}$ sends $(\text{quo}_{g,k})$, $(\text{quo}_{q,g,k})$ and
   $[m(w, X, y)]$.
4. $\mathcal{V}$ sends $\mu \sample \F_p$.

**Round 4.**

1. For each group $g$, $\mathcal{P}$ computes
   $a'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, a_{Mg+j}$,
   $b'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, b_{Mg+j}$ and
   $$\text{col}_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{Mg+j} + V^{(M)}(\mu) \, \text{quo}_g(\mu),$$
   then
   $$\text{quo}'(T) = \frac{\sum_{g, g' < N} \revdot{a'_g}{b'_{g'}} \, \ell^{(N)}_g(T) \, \ell^{(N)}_{g'}(T) - \sum_{g < N} \revdot{a'_g}{b'_g} \, \ell^{(N)}_g(T)}{V^{(N)}(T)} = \sum_{k < N - 1} \text{quo}'_k \, T^k,$$
   and the nested $\text{col}_{q,g}$ and $\text{quo}'_q$ with $\mu_q$.
2. $\mathcal{P}$ sends $(\text{quo}'_k)$, $(\text{col}_g)$, $(\text{quo}'_{q,k})$
   and $(\text{col}_{q,g})$.
3. $\mathcal{V}$ sends $\mu' \sample \F_p$.

**Round 5.**

1. With $\text{wt}_{Mg+j} = \ell^{(N)}_g(\mu') \, \ell^{(M)}_j(\mu)$,
   $\mathcal{P}$ computes $A = \sum_k \text{wt}_k \, a_k$ and
   $B = \sum_k \text{wt}_k \, b_k$, and $A_q$, $B_q$ with $\mu_q, \mu'_q$.
2. $\mathcal{P}$ sends $[A]$, $[B]$, $[A_q]$, $[B_q]$ and
   $[m_q(w_q, X, y_q)]$.
3. $\mathcal{V}$ sends $x \sample \F_p$.

**Round 6.**

1. The native [openings](construction/batch.md#native-openings)
   $(\phi_i, \rho_i)_{i < 172}$ are, in order:
   1. $p^{(0)}, p^{(1)}$ at $u^{(0)}, u^{(1)}$;
   2. $m(W, x^{(0)}, y^{(0)}), m(W, x^{(1)}, y^{(1)})$ at $w$;
   3. $m(w, x^{(0)}, Y), m(w, x^{(1)}, Y)$ at $y^{(0)}, y^{(1)}$, then at $y$;
   4. $m(w, X, y)$ at $x^{(0)}, x^{(1)}$, then at $x$;
   5. $m(W, x, y)$ at $w$, then at $\omega_{\text{id}}$;
   6. $A^{(0)}$ at $xz$, $B^{(0)}$ at $x$, $A^{(1)}$ at $xz$, $B^{(1)}$ at
      $x$, $A$ at $xz$, $B$ at $x$;
   7. $r[\texttt{Application}]$ and $r[\texttt{ApplicationStage}]$ at $xz$;
   8. each $r^{(0)}[\cdot]$, then each $r^{(1)}[\cdot]$, in
      [rx order](construction/setup.md#rx-order), at $xz$;
   9. $m(W, x, y)$ at $\omega_0, \dots, \omega_{52}$;
   10. the polynomial of slot $s$ at $\xi_s$, for $s < 6$.

   The [nested openings](construction/batch.md#nested-openings)
   $(\phi_{q,i}, \rho_{q,i})_{i < 150}$ are items 1 to 6, 8 and 9 over the
   nested objects, without the opening at $\omega_{\text{id}}$, and with
   $\omega_{q,0}, \dots, \omega_{q,45}$ in item 9.
2. Each opening $i$ has a claimed value $\vartheta_i$. $\mathcal{V}$ sets
   $\vartheta_0 = v^{(0)}$, $\vartheta_1 = v^{(1)}$ and
   $\vartheta_{166 + s} = \eta_s$, and computes the values of $A$ at $xz$ and
   $B$ at $x$ in its step 5. Openings $4, 5, 8, 9, 11$ take the values of
   openings $2, 3, 6, 7, 10$, on both sides. $\mathcal{P}$ sends
   $\vartheta_i = \phi_i(\rho_i)$ for the remaining $157$ native and $141$
   nested openings, and $[m(W, x, y)]$.
3. $\mathcal{V}$ sends $\alpha \sample \F_p$.

**Round 7.**

1. $\mathcal{P}$ computes
   $$f(X) = \sum_{i < 172} \alpha^{171 - i} \, \frac{\phi_i(X) - \phi_i(\rho_i)}{X - \rho_i}, \qquad f_q(X) = \sum_{i < 150} \alpha_q^{149 - i} \, \frac{\phi_{q,i}(X) - \phi_{q,i}(\rho_{q,i})}{X - \rho_{q,i}}.$$
2. $\mathcal{P}$ sends $[f]$, $[f_q]$ and $[m_q(W, x_q, y_q)]$.
3. $\mathcal{V}$ sends $u \sample \F_p$.

**Round 8.**

1. The native [batched polynomials](construction/batch.md#native-p)
   $\psi_0, \dots, \psi_{113}$ are the distinct polynomials of the openings,
   in the order: for $i = 0, 1$, each $r^{(i)}[\cdot]$ in rx order, then
   $A^{(i)}, B^{(i)}, m(W, x^{(i)}, y^{(i)}), p^{(i)}$; then
   $m(w, x^{(0)}, Y), m(w, x^{(1)}, Y), r[\texttt{Application}],
   r[\texttt{ApplicationStage}], m(w, X, y), A, B, m(W, x, y)$ and the six
   slot polynomials. The [nested ones](construction/batch.md#nested-p)
   $\psi_{q,0}, \dots, \psi_{q,99}$ are, for $i = 0, 1$, each
   $r_q^{(i)}[\cdot]$ in rx order, then
   $A^{(i)}_q, B^{(i)}_q, m_q(W, x_q^{(i)}, y_q^{(i)}), p^{(i)}_q$; then
   $m_q(w_q, x_q^{(0)}, Y), m_q(w_q, x_q^{(1)}, Y), m_q(w_q, X, y_q), A_q,
   B_q, m_q(W, x_q, y_q)$.
2. $\mathcal{P}$ sends $\epsilon_j = \psi_j(u)$ for $j < 114$ and
   $\epsilon_{q,j} = \psi_{q,j}(u_q)$ for $j < 100$.
3. $\mathcal{V}$ sends $\text{pre\_beta} \sample \F_p$. Let
   $\beta = \text{lift}_p(\text{endo}(\text{pre\_beta}))$ and
   $\beta_q = \text{lift}_q(\text{endo}(\text{pre\_beta}))$.

**Verifier.** $\mathcal{V}$ does the following on each side, with
$(M, N, Q, J) = (7, 14, 172, 114)$ native and $(8, 10, 150, 100)$ nested.

1. Reject if a challenge is $2^{254}$ or more, $x = 0$, $z = 0$,
   $u = \rho_i$ for some $i$, or $\omega_{\text{id}}^{\lvert D \rvert} \ne 1$,
   where $D$ is the native registry domain.
2. Compute the target $\text{tgt}_k$ of every claim, with $k_{\text{app}}$
   over $\zeta = w$ and the round 2 messages.
3. For each group $g < N$, check
   $\text{col}_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{Mg+j} + V^{(M)}(\mu) \sum_{k < M-1} \text{quo}_{g,k} \, \mu^k$.
4. If $\text{hdr}^{(0)}_O$ and $\text{hdr}^{(1)}_O$ both end in the suffix $2$,
   check that $\omega_{\text{id}}$ is the point of `Bootstrap`, that
   $\text{hdr}_O$ encodes the unit header, and that
   $(\xi_4, \eta_4) = (\xi_5, \eta_5) = (w, 1)$, and take $c$ from
   $\mathcal{P}$. Otherwise set
   $$c = \sum_{g < N} \ell^{(N)}_g(\mu') \, \text{col}_g + V^{(N)}(\mu') \sum_{k < N-1} \text{quo}'_k \, \mu'^k.$$
5. For each claim $k$, let $\text{ax}_k$ be $a_k$ with each polynomial replaced
   by its claimed value at $xz$. Let $\text{bx}_k$ be the claimed value of
   $B^{(i)}$ at $x$ for a raw claim, $\text{ax}_k + s_j(x, y) + t(x, z)$ for a
   circuit claim at $j$, $s_j(x, y)$ for a bonding claim at $j$, and $0$ for
   padding, where $s_j(x, y)$ is the claimed value of $m(W, x, y)$ at
   $\omega_j$. The claimed value of $A$ at $xz$ is
   $\sum_k \text{wt}_k \, \text{ax}_k$, and that of $B$ at $x$ is
   $\sum_k \text{wt}_k \, \text{bx}_k$.
6. Set
   $$v = \beta^{J} \sum_{i < Q} \alpha^{Q-1-i} \, \frac{\epsilon[\phi_i] - \vartheta_i}{u - \rho_i} + \sum_{j < J} \beta^{J-1-j} \, \epsilon_j,$$
   where $\epsilon[\phi_i]$ is the $\epsilon_j$ of the polynomial $\phi_i$.

**Output.** $\mathcal{V}$ outputs the accumulators

$$\Bigl(([A], [B], c),\ \bigl(P, u, v\bigr),\ ([m(W, x, y)], x, y)\Bigr), \qquad P = \beta^{114} [f] + \sum_{j < 114} \beta^{113 - j} [\psi_j],$$

and their nested counterparts, with $P_q = \beta_q^{100} [f_q] + \sum_{j < 100} \beta_q^{99 - j} [\psi_{q,j}]$,
together with the challenges, $\text{hdr}_O$, $\omega_{\text{id}}$, $[o_0]$
and $[o_1]$. These form the public instance of the new proof. $\mathcal{P}$
outputs $p = \beta^{114} f + \sum_{j < 114} \beta^{113 - j} \psi_j$, its nested
counterpart, and the polynomials of the new accumulators.
