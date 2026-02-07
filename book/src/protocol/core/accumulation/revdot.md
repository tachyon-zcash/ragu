# Revdot Product

Step 5 of our [NARK](../nark.md#nark-1) involves a special case of inner product
argument of the following form:

$$
\Rel_{rdp}=\bigg\{\begin{align*}
\inst&=(\bar{A},\bar{B}\in\G, c\in\F),\\
\wit&=(\v{a},\v{b}\in\F^{4n},\gamma_a,\gamma_b\in\F)\end{align*}:

\begin{align*}
&\phantom{-} \bar{A}=\com(\v{a};\gamma_a) \\
&\land \bar{B}=\com(\v{b};\gamma_b)\\
&\land \revdot{\v{a}}{\v{b}}=c
\end{align*}
\bigg\}
$$

where the prover is trying to convince the verifier that the revdot product
of two secret vectors $\v{a}, \v{b}$ is value $c$ given only their hiding
commitments $\bar{A}, \bar{B}$.
We call them **revdot product relations**.

Revdot products show up in different contexts in Ragu protocol:

- individual circuits'
  [consolidated constraint](../arithmetization.md#consolidated-constraints)
  enforcement against its public inputs 
- [staging polynomials](../../extensions/staging.md)' well-formness check 
  via enforcing its revdot product with its _stage mask_ polynomial
- Folded accumulator $\acc.\v{a}, \acc.\v{b}$ from the previous PCD step

## Intuition

Since revdot product is a special case of inner product relations, and the
concrete commitment scheme we use, Pedersen Vector commitment, is _linearly
homomorphic_, we can borrow the aggregation technique from Bulletproofs:
aggregating multiple claims into one via **random linear combination**.

Specifically, given:

$$
\begin{align*}
\wit &:= &\v{a}_0,\ldots,\v{a}_{n-1}, 
&\phantom{-} \v{b}_0,\ldots,\v{b}_{n-1},
&\phantom{-} \set{\gamma_{a,i}, \gamma_{b,i}}\\

\inst &:= &\bar{A}_0,\ldots,\bar{A}_{n-1}, 
&\phantom{-} \bar{B}_0,\ldots,\bar{B}_{n-1},
&\phantom{-} c_0,\ldots,c_{n-1}
\end{align*}
$$

The verifier can provide two random challenges $\mu,\nu\in\F$, with the goal
of aggregating $n$ revdot claims into one:

$$
\begin{align*}
\wit &:= \v{a}^\ast = \sum_i \mu^{-i}\cdot \v{a}_i,
&\phantom{-} \v{b}^\ast = \sum_i (\mu\nu)^i \cdot \v{b}_i,
&\phantom{-} \sum_i \mu^{-i}\gamma_{a,i}, \sum_i (\mu\nu)^i \gamma_{b,i}\\

\inst &:= \bar{A}^\ast = \sum_i \mu^{-i}\cdot \bar{A}_i,
&\phantom{-} \bar{B}^\ast = \sum_i (\mu\nu)^i\cdot \bar{B}_i,
&\phantom{-} c^\ast = \sum_{i,j} \mu^{j-i} \nu^j e_{i,j}
\end{align*}
$$

where $e_{i,j}=\revdot{\v{a}_i}{\v{b}_j}$ and particularly $e_{i,i} = c_i$.
Notice the verifier can only compute $\bar{A}^\ast, \bar{B}^\ast$ unassisted.
To compute $c^\ast$, he needs _cross terms_ $\set{e_{i,j}}_{i\neq j}$ in addition
to the $\set{c_i}$ terms he already has. For soundness, we require **the prover
to send (thus commit to) these cross terms before the verifier samples $\mu,\nu$**.

```admonish tip title="Off-diagonal Error Terms"
We can also view the expanded expression of $c^\ast$ as the summation of all
cells in a $n\times n$ matrix where the $(i,j)$-th cell holds the value

$$
\revdot{\mu^{-i}\cdot \v{a}_i}{(\mu\nu)^j \cdot \v{b}_j} = \mu^{j-i} \nu^j \cdot e_{i,j}
$$

for $\forall i,j \in[n]$.
In this matrix view, all the diagonal entries are $\nu^i\cdot c_i$, computable
by the verifier unassisted. Meanwhile, all off-diagonal entries (i.e. $i\neq j$)
contains **error terms** that made up the remaining summands.
We use _cross terms_ and _error terms_ interchangeably.
```

## Revdot Product Reduction

The accumulator instance and witness defined in the split-accumulation scheme
are identical to that of the revdot product relation $\Rel_{rdp}$.
We fold new revdot claims from various sources into $\acc_i$ to derive $\acc_{i+1}$.
This procedure is effectively aggregating all new revdot claims, including the
folded claim in $\acc_i$, into a single claim captured by the updated accumulator.

The split-accumulation proceeds as follows:

1. Prover and verifier parse $\acc_i$ and new revdot claims from proofs
   $\set{\pi_i}$ to be accumulated into the instance-witness pair
   [as above](#intuition).
   The verifier holds $\set{\bar{A}_i,\bar{B}_i, c_i}_{i\in[n]}$.
2. Prover sends all $n^2-n$ (off-diagonal) error terms $\set{e_{i,j}}_{i\neq j}$.
3. Verifier samples $\mu,\nu \sample\F$
4. Prover updates the folded witness:
   $$
   \acc_{i+1}.\wit = (
       \underbrace{\sum_i \mu^{-i}\cdot \v{a}_i}_{\v{a}^\ast},\,
       \underbrace{\sum_i (\mu\nu)^i \cdot \v{b}_i}_{\v{b}^\ast},\,
       \underbrace{\sum_i \mu^{-i}\gamma_{a,i}}_{\gamma_a^\ast},\,
       \underbrace{\sum_i (\mu\nu)^i \gamma_{b,i}}_{\gamma_b^\ast}
   )
   $$

   Verifier updates the folded instance:
   $$
   \acc_{i+1}.\inst = (
       \underbrace{\sum_i \mu^{-i}\cdot \bar{A}_i}_{\bar{A}^\ast},\,
       \underbrace{\sum_i (\mu\nu)^i \cdot \bar{B}_i}_{\bar{B}^\ast},\,
       \underbrace{\sum_{i,j} \mu^{j-i} \nu^j e_{i,j}}_{c^\ast}
   )
   $$
   
The verifier's work is dominated by $2\cdot \mathsf{MSM}(n)$ to compute
$\bar{A}^\ast, \bar{B}^\ast$; and $O(n^2)$ amount of field multiplications to
compute $c^\ast$. 
We introduce the next two techniques to reduce the verifier cost of enforcing
them in circuit naively. We use both techniques in conjunction, but present them
separately for clarity.

## Reducing Commitment Aggregation to Batched Evaluation

Enforcing the computation of $\bar{A}^\ast$ and $\bar{B}^\ast$ requires linear
combination of commitments in circuit. Naive implementation involves non-native
arithmetic to constrain scalar multiplications. Instead, Ragu transforms the
commitment aggregation statement into a PCS multi-opening claim, then piggybacks
on the existing [batched evaluation](./pcs.md) for accumulation.

Aggregation of homomorphic commitments $\bar{A}_i$ corresponds to aggregation of
their underlying polynomials $a_i(X)$. We can _spot check_ the constituent
polynomials and the aggregated polynomial at an arbitrary point $\beta\in\F$.
If their evaluations follow the expected linear combination relation, _and_ the
PCS evaluation claims are valid, then $\bar{A}^\ast$ is correct
with overwhelming probability.

$$
\begin{align*}
\bar{A}^\ast \in\G = \sum_i \mu^{-i}\cdot \bar{A}_i 
&\equiv a^\ast(X) = \sum_i \mu^{-i}\cdot a_i(X) \\
&\implies 
    \begin{cases}
        \set{(\bar{A}_i, \beta, a_i(\beta))}_i \quad\text{are valid PCS evals}\\
        (\bar{A}^\ast, \beta, a^\ast(\beta)) \quad\text{is a valid PCS eval}\\
        a^\ast(\beta) = \sum_i \mu^{-i}\cdot a_i(\beta)
    \end{cases}
    \quad\text{for } \beta\sample\F
\end{align*}
$$

After the reduction, the linear combination of evaluations can be natively
enforced and the $(n+1)$ PCS claims are shoveled into a grand batched evaluation
accumulation together with other PCS claims in the Ragu protocol.

This reduction benefits from lower amortized cost. In the [step 7 of PCS
aggregation](./pcs.md#pcs-aggregation), there is only _one scalar multiplication
per queried polynomial_ regardless of the number of queried points on it.
If some $a_i(X)$ is already queried elsewhere in the protocol, then our
reduction leads to fewer scalar multiplications in total.
Furthermore, all group operations are
[deferred](../../prelim/nested_commitment.md#deferred-operations) to avoid
non-native arithmetic.

## Multi-layer Revdot Reduction

Another challenge comes from the $O(n^2)$ field operations to derive $c^\ast$.
When folding many revdot claims (e.g., $n=133$ in Ragu's fuse operation), the
single-reduction approach above requires $n^2 = 17689$ field multiplications,
exceeding the targeted circuit size limit.
Ragu prefers smaller circuits (even if requiring more circuits per step) because
smaller circuits lead to smaller witness commitments, which lead to smaller IPA
proofs, ultimately yielding faster verifier times.

To address this, we employ a **two-layer reduction** scheme parameterized by
$(M, N)$ that folds up to $M \cdot N$ claims using roughly $NM^2 + N^2 - N + 3$
constraints instead of $(M \cdot N)^2$.

### Structure

The two-layer scheme works as follows:

- _Partition_: Group the $M \cdot N$ input claims into $N$ groups of $M$ claims each.
- _Layer 1_: Using challenges $\mu, \nu \sample \F$, fold each group of $M$
   claims into a single claim, producing $N$ intermediate claims.
- _Layer 2_: Using fresh challenges $\mu', \nu' \sample \F$, fold the $N$
   intermediate claims into one final claim.

This hierarchical approach reduces the quadratic blowup by processing claims in
smaller batches first, then combining the results.

### 2 Layer Reduction

Given initial revdot claims indexed as $\set{(\bar{A}_i, \bar{B}_i, c_i)}_{i \in [M\cdot N]}$,
the accumulation proceeds:

1. Prover and verifier partition claims into $N$ groups of $M$ claims each.
2. Layer 1:
   - Prover sends all error terms $\set{e^{(g)}_{i,j}}_{g\in[N], i\neq j, i,j\in[M]}$
     (i.e., $N$ groups of $M(M-1)$ error terms each)
   - Verifier samples $\mu, \nu \sample \F$
   - Both compute $N$ intermediate claims. For each group $g \in [N]$:
     $$
     \bar{A}^{(g)} = \sum_{i=0}^{M-1} \mu^{-i} \bar{A}_{gM+i},\quad
     \bar{B}^{(g)} = \sum_{i=0}^{M-1} (\mu\nu)^i \bar{B}_{gM+i},\quad
     c^{(g)} = \sum_{i,j\in[M]} \mu^{j-i} \nu^j e^{(g)}_{i,j}
     $$
3. Layer 2:
   - Prover sends error terms $\set{e_{g,h}}_{g\neq h, g,h\in[N]}$
     (i.e., $N(N-1)$ cross-terms between intermediate claims)
   - Verifier samples fresh $\mu', \nu' \sample \F$
   - Both compute final folded claim:
     $$
     \bar{A}^\ast = \sum_{g=0}^{N-1} (\mu')^{-g} \bar{A}^{(g)},\quad
     \bar{B}^\ast = \sum_{g=0}^{N-1} (\mu'\nu')^g \bar{B}^{(g)},\quad
     c^\ast = \sum_{g,h\in[N]} (\mu')^{h-g} (\nu')^h e_{g,h}
     $$

The key insight is that fresh challenges $\mu', \nu'$ in layer 2 are independent
from $\mu, \nu$ in layer 1, maintaining soundness across both layers.

### Complexity Analysis

For folding $M \cdot N$ claims via two layers with parameters $(M, N)$:

- Layer 1: Precompute $\mu\nu$ and $\mu^{-1}$ ($2$ constraints), then fold
  $N$ groups of $M$ claims using nested Horner evaluation ($N(M^2 - 1)$ constraints),
  totaling $NM^2 - N + 2$ constraints
- Layer 2: Precompute $\mu'\nu'$ and $(\mu')^{-1}$ ($2$ constraints), then fold
  $N$ intermediate claims using nested Horner evaluation ($N^2 - 1$ constraints),
  totaling $N^2 + 1$ constraints
- Total: $(NM^2 - N + 2) + (N^2 + 1) = NM^2 + N^2 - N + 3$ constraints

Compare this to a single-layer reduction of the same $M \cdot N$ claims:

- $(M \cdot N)^2 + 1$ constraints

For Ragu's parameters $M=7, N=19$ (supporting up to $133$ claims):

- Two-layer: $19 \cdot 49 + 361 - 19 + 3 = 1276$ constraints
- Single-layer: $133^2 + 1 = 17690$ constraints
- Savings: $\sim 93\%$ reduction
