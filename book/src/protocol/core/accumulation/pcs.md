# Split-accumulation for Batched Evaluation

## PCS Aggregation

In the [last step](../nark.md#nark) of our NARK, the verifier needs to verify
many polynomial evaluations on different polynomials. Naively running an instance
of [PCS evaluation](../../prelim/bulletproofs.md) protocol for each claim is
expensive. Instead, we use batching techniques to aggregate all evaluation claims
into a single claim that can be verified once. This is sometimes called
_multi-opening_ or _batched opening_ in the literature. Here is how Ragu
aggregates evaluation claims of multiple points on multiple polynomials:

**Input claims**: For each $i$, we have the claim that $p_i(x_i) = y_i$ where

- public instance: $\inst:=(\bar{C}_i\in\G, x_i, y_i\in\F)_i$, the "(commitment,
  evaluation point, evaluation)" tuple held by both the prover and the verifier
- secret witness: $\wit:=(p_i(X)\in\F[X], \gamma_i\in\F)$, the underlying
  polynomial and the blinding factor used for commitment, held by the prover

**Output claim**: A single aggregated claim $p(u)=v$ where

- public instance: $\inst:=(\bar{P}, u, v)\in\G\times\F^2$, held by both
- secret witness: $\wit:=(p(X), \gamma)$, aggregated polynomial and blinding
  factors held by the prover

**Summary**: The key idea is to batch using quotient polynomials. For each
claim $p_i(x_i) = y_i$, the quotient $q_i(X) = \frac{p_i(X) - y_i}{X - x_i}$
exists (with no remainder) if and only if the claim is valid. The protocol
proceeds in three phases:
- _alpha batching_: linearly combines these quotients as 
  $f(X) = \sum_i \alpha^i \cdot q_i(X)$
- _evaluation at u_: the prover evaluates each $p_i$ at a fresh challenge point $u$
- _beta batching_: combines the quotient with the original polynomials as
  $p(X) = f(X) + \sum_i \beta^i \cdot p_i(X)$. The verifier derives the expected
  evaluation from the quotient relation and the $p_i(u)$ values.

The full protocol proceeds as follows:

1. Verifier sends challenge $\alpha \sample \F$
2. Prover computes quotient polynomials $q_i(X) = \frac{p_i(X) - y_i}{X - x_i}$
for each claim. The prover linearly combines them as
$f(X)=\sum_i \alpha^i \cdot q_i(X)$, samples a blinding factor
$\gamma_f\sample\F$, computes the commitment $\bar{F}\leftarrow\com(f(X);\gamma_f)$,
and sends $\bar{F}$ to the verifier
3. Verifier sends challenge $u\sample\F$, which will be the evaluation point for
the aggregated polynomial
4. Prover computes $p_i(u)$ for each $i$ and sends these to the verifier. When
multiple claims share the same underlying polynomial, only one evaluation per
polynomial is needed since $p_i(u)$ depends only on the polynomial, not the
original evaluation point $x_i$.
5. Verifier sends challenge $\beta\sample\F$
6. Prover computes the aggregated polynomial
$p(X) = f(X) + \sum_i \beta^i \cdot p_i(X)$ and the aggregated blinding factor
$\gamma = \gamma_f + \sum_i \beta^i \cdot \gamma_i$
7. Verifier derives the aggregated commitment
$\bar{P} = \bar{F} + \sum_i \beta^i \cdot \bar{C}_i$ and the aggregated evaluation
$v=\sum_i \alpha^i\cdot\frac{p_i(u)-y_i}{u-x_i} + \sum_i\beta^i\cdot p_i(u)$,
then outputs $(\bar{P}, u, v)$

The soundness of our aggregation relies on the simple fact that: the quotients
polynomial $q_i(X)=\frac{p_i(X)-y_i}{X-x_i}$ exist (with no remainder) if and
only if the claims $p_i(x_i) = y_i$ are valid. The random linear combination
would preserve this with overwhelming probability, causing the final verification
to fail if any one of the claims is false. The quotient relation is enforced
at step 7 when the verifier derives the $q_i(u)$ from the prover-provided
$p_i(u)$ values through the quotient equation.

## Simplified Split-accumulation

The split-accumulation scheme for batched polynomial evaluation wraps the PCS
aggregation technique to conform with the [2-arity PCD
syntax](./index.md#2-arity-pcd), with [adaptation](#ragu-adaptation) to eliminate
non-native arithmetic from the verifier circuits.

We first present a simplified single-curve version allowing non-native arithmetic
to convey the core idea, then explain Ragu's adaptation when implementing over
[a cycle of curves](./index.md#ivc-on-a-cycle-of-curves).

Consider folding PCS evaluation claims from a NARK instance $\pi.\inst$ into an
accumulator $\acc_i$:

$$
\begin{cases}
\pi.\inst = \Bigg(\begin{array}{l}
  (\bar{A}, 0, 1),(\bar{A}, x, a(x)), (\bar{A}, xz, a(xz)),\\
  (\bar{B}, x, b(x)),\\
  (S, x, s(x,y)),\\
  (K, 0, 1), (K, y, c) \in\G\times\F^2
\end{array}\Bigg)\\
\pi.\wit = (\v{a},\v{b},\v{s},\v{k}\in\F^{4n})\\
\end{cases}

\begin{cases}
\acc.\inst=(\bar{P}\in\G, u,v\in\F) \\
\acc.\wit=(\v{p}\in\F^{4n},\gamma\in\F)
\end{cases}
$$

The accumulation prover:
1. Parses all evaluation claims from both the accumulator and NARK proof as
  $\big[(\bar{C}_i, x_i, y_i)\big]_i$, along with the underlying polynomials
  and blinding factors $\big[(p_i(X), \gamma_i)\big]_i$
2. Runs the [PCS aggregation](#pcs-aggregation) protocol on all claims
3. Outputs $\acc_{i+1}.\inst:=(\bar{P}',u',v')$ as the batched claim,
  $\acc_{i+1}.\wit:=(\v{p}',\gamma')$ as the batched polynomial and blinding
  factor, and $\pf_{i+1}:=(\bar{F}\in\G, [p_i(u)]_i)$ containing all prover
  messages from the aggregation transcript

## Ragu Adaptation

To avoid non-native arithmetic in the accumulation verifier's logic, as [noted
previously](./index.md#admonition-split-up-of-the-folding-work-title), Ragu makes
two adaptations that enables splitting of folding work across a curve cycle.

An accumulation verifier folds some new claims into an accumulator that
incorporates all previous claims to get an updated accumulator. Usually, the
folding logic comprises random linear combinations of the input claims and the
old accumulator. For example, the $\mathsf{Acc.V}$ for the foregoing
[PCS evaluation](#simplified-split-accumulation) needs to linearly combine both
the commitments _and_ their claimed evaluations: 

$$
\begin{align*}
\bar{P}\in\G &=\bar{F} + \sum_i \beta^i\cdot \bar{C}_i\\
v \in\F &= \sum_i \alpha^i\cdot\frac{p_i(u)-y_i}{u-x_i} + \sum_i\beta^i\cdot p_i(u)
\end{align*}
$$

where $\bar{P}$ is the folded commitment in the updated PCS commitment, $v$ is
the updated evaluation of the folded underlying polynomial (at a new evaluation
point $u$). While the verifier can enforce $v$ computation natively in the
circuit, directly enforcing $\bar{P}$'s derivation would require expensive
non-native scalar multiplication.

Naturally, Ragu splits the folding work between the 2-cycle curves such that
each side only executes native arithmetic. Concretely, the primary merge circuit
$CS_{merge}^{(1)}$ over $\F_p$:

- Folds claims from $\pi_{i,L/R}^{(1)}.\inst, \acc_{i,L/R}^{(1)}.\inst$
  to enforce the correct value $\acc_{i+1}^{(1)}.v\in\F_p$
- Folds claims from $\pi_{i,L/R}^{(2)}.\inst, \acc_{i,L/R}^{(2)}.\inst$
  to enforce the correct commitment
  $\acc_{i+1}^{(2)}.\bar{P}\in\G^{(2)}\subseteq\F_p^2$

Effectively, the overall accumulation logic (for both $\acc_i^{(1)}$ and
$\acc_i^{(2)}$) is _split between the two merge circuits_.
Evaluations (or general field operations) are folded in their field-native
circuit while commitments (or general group operations) are folded in the
other merge circuit where group arithmetic is native.
This cross-circuit splitting begets two challenges:

1. **Input Consistency**: two merge circuits must access the same instances
  $\inst_{i,L/R},\acc_{i,L/R}$ containing both group elements and field elements
  from two curves (these contains elements in all of $\F_p,\F_q,\G_p,\G_q$).
2. **Challenge Consistency**: verifier challenges $\alpha,\beta$ used in the
  random linear combination must be consistent across circuits.

Ragu leverages [nested staged commitments](#nested-staged-commitments) to encode
the same input instances in two different ways. The consistency of the two
encoding is enforced during recursion at the next step.
Ragu further [shares the verifier challenges](#transcript-bridging) in two merge
circuits (of the same step) through endoscalars, ensuring the same random
combiners (e.g. $\alpha,\beta$) are used in two circuits.

### Nested Staged Commitments

To rephrase the challenge more generally: how to guarantee that the same input

$$
\inst=\bigg(\begin{align*}
a_1,b_1,\ldots\in\F_p&,\quad a_2,b_2,\ldots\in\F_q\\
A_1,B_1,\ldots\in\G_p&,\quad A_2,B_2,\ldots\in\G_q
\end{align*}\bigg)
$$

are supplied to two circuits over different fields ($\F_p,\F_q$) without
incurring non-native arithmetic?

Naively, we can hash all elements in $\inst$ on both circuits, mark the digest
as a public input, and enforce their equivalence. However, computing comparable
digests over two fields inevitably requires either non-native arithmetic or
bit decomposition on all values -- both prohibitively expensive.

Instead, Ragu proposes two encodings of the same input $\inst$ such that the
encoded values contains either purely $\F_p$ elements or $\F_q$ elements.
Then, by marking these encoded values as the witness for a dedicated
[stage](../../extensions/staging.md), Ragu can leverage the
[staging well-formedness checks]()
to enforce the same underlying input during the _recursion at the next step_.

**Encoding in the primary circuit** (over $\F_p$):
- Commits all $(a_1,b_1,\ldots\in\F_p, A_2,B_2,\ldots\in\G_q)$ using vector
  Pedersen commitment, resulting in $C\in\G_p$
- [Nested-commits](../../prelim/nested_commitment.md) all
  $(C,A_1,B_1,\ldots\in\G_p, a_2,b_2,\ldots\in\F_q)$, resulting in a nested
  commitment $\mathring{C}_1\in\F_p^2$
- Overall, the primary circuit witness the tuple
  $$
  \wit_1=(\mathring{C}_1\in\F_p^2, a_1,b_1,\ldots\in\F_p, A_2,B_2,\ldots\in\F_p^2)
  $$

**Encoding in the secondary circuit** (over $\F_q$):
- Commits all $(a_2,b_2,\ldots\in\F_q, A_1,B_1,\ldots\in\G_p)$ using vector
  Pedersen commitment, resulting in $C\in\G_q$
- Nested-commits all $(C,A_2,B_2,\ldots\in\G_q, a_1,b_1,\ldots\in\F_p)$, 
  resulting in a nested commitment $\mathring{C}_2\in\F_q^2$
- Overall, the secondary circuit witness the tuple
  $$
  \wit_2=(\mathring{C}_2\in\F_q^2, a_2,b_2,\ldots\in\F_q, A_1,B_1,\ldots\in\F_q^2)
  $$

Now, $\mathring{C}_1$ and $\mathring{C}_2$ are two binding encodings of the same
underlying input $\inst$, and are native to $\F_p$ and $\F_q$ respectively.
The nested commitments circumvent the cost of naive hashing.
However, simply witnessing the nested commitments doesn't guarantee the same
preimage $\inst$ because $\mathring{C}_1$ and $\mathring{C}_2$ are derived
outside of circuits and provided by the prover as a non-deterministic advice.
It's possible that malicious provers lie about the values of nested commitments.

Ragu relies on the [staging design](../../extensions/staging.md) for input
consistency. 
Informally, staging allows provers to incrementally commits to the witness in
stages rather than all at once; _stage checks_ ensure these partial witnesses at
different stages are non-overlapping and _staged commitment checks_ ensure the
commitments of all partial witnesses add up to that of the overall witness.

Due to symmetry, we only discuss from the primary circuit's perspective.
Ragu captures the input encoding in a dedicated stage, named _preamble stage_,
as the first stage of our multi-stage circuit $CS_{merge}^{(1)}$.
During the preamble stage, $\mathring{C}_1$ is added an advice wire, and other
values in the tuple $\wit_1$ is witnessed as public input wires.
Thus, $\mathring{C}_1$ is now a **nested staged commitment**, and its preimage
$(C,A_1,B_1,\ldots, a_2,b_2,\ldots)\in\F_q^\ast$ is a partial witness of
$CS_{merge}^{(2)}$ in the next recursion step. 
$CS_{merge}^{(2)}$ circuit embeds all necessary stage checks and staged
commitment checks on all nested staged commitments declared in
$CS_{merge}^{(1)}$'s advice wires in the last recursion step.

Then, any arithmetic on $\wit_1$ (e.g. the $\bar{P}\in\G_q$ folding and
$v\in\F_p$ folding) becomes natively constrained in $CS_{merge}^{(1)}$.
If the cheating prover lies about $\mathring{C}_1$ in step $i$, it will cause
either the stage checks or the staged commitment check at $CS_{merge}^{(2)}$ in
step $i+1$ to fail. That means the output accumulator at the end of step $i+1$
cannot have satisfying witness with overwhelming probability.
Therefore, accumulation decider or the outer PCD verifier will always reject the
$\acc_{i+1}$ -- preventing inconsistent instance input $\inst$ across the two
merge circuits in the last recursion step.

### Transcript Bridging

Ragu depends on [endoscalars](../../extensions/endoscalar.md) for the problem of
challenge consistency. After applying Poseidon hash function to the [verifier
transcript](../../prelim/transcript.md) to get the next random oracle output
$s\in\F_p$, we set the next verifier challenge as its extracted endoscalar
$\endo{s}:=\mathsf{extract(s)}\in\{0,1\}^\lambda\subset \F_p$. This supports both
native scalar arithmetic $\endo{s}\cdot c\in\F_p$ in the primary circuit and also
native scalar multiplication (a.k.a. _endoscaling_) $\endo{s}\cdot P\in\G^{(1)}$
in the secondary circuit.

Naively, we would maintain two sets of endoscalars -- one for verifier challenges
from the primary circuit, and the other from the secondary circuit.
Notice that the two merge circuits accept exactly the same input[^same-input].
Ragu **uses challenges squeezed from $\F_p$ transcript on the primary half for
both merge circuits**.
This optimization, named _transcript bridging_, is only sound in tandem with the
[input consistency](#nested-staged-commitments) guarantee.

[^same-input]: In the [IVC-over-2-cycle diagram](../index.md#ivc-on-a-cycle-of-curves),
it appears that the primary merge circuit accepts $(\inst_i, \acc_i)$ while the
secondary merge circuit accepts $(\inst_i, \acc'_{i+1})$. But that notation is
only for visual clarity. Since the perfect complementary splitting of the folding
work, two merge circuits will update different values in the $\acc_i$. There is
no internal dependency between merge circuits within the same step -- they both
parse $(\inst_i, \acc_i)$ as the same, general input expression:
$\inst\in\F_p^\ast\times \G_p^\ast\times \F_q^\ast\times \G_q^\ast$.
