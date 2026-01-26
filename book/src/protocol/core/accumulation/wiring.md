# Split-accumulation for Wiring Consistency

## The Problem

In our [Polynomial IOP](../nark.md#polynomial-iop), the wiring polynomial
$s(X,Y)$ encodes how the wires of multiplication gates connect to each other.
This polynomial is fixed and publicly known before proving begins. During
[verification](../nark.md#the-verification-checks), the verifier needs to
evaluate $s(x,y)$ at random challenge points—but computing this directly
requires $O(n)$ work, where $n$ is the circuit size.

We could avoid this cost by having the prover commit to the full bivariate
polynomial $s(X,Y)$ and open it at any point $(x,y)$ the verifier requests.
However, this approach would require a bivariate polynomial commitment scheme
(PCS), adding significant complexity. Ragu's design philosophy is to rely only
on simple univariate PCS.

## Our Solution

Instead, in [step 3 of our NARK](../nark.md#nark), the prover commits to a
univariate restriction $s(X,y)$ after the verifier provides the challenge
$y\in\F$. The prover sends a commitment $S\in\G$ to this univariate polynomial.
But now we have a new problem: how does the verifier know that $S$ actually
commits to the correct $s(X,y)$ from the fixed wiring polynomial, and not some
arbitrary polynomial $s'(X,y)$ that the prover made up?

This is where _wiring consistency_ comes in. We need a protocol that lets the
prover convince the verifier that their commitment is consistent with the known
wiring structure, without the verifier doing $O(n)$ work.

The [Halo paper](https://eprint.iacr.org/2019/1021) introduced a clever
solution for [single fixed circuits](#single-circuit-consistency). Ragu extends
this to handle a [bundle of multiple circuits](#registry-consistency)—allowing
us to verify that $s_i(X,Y)$ belongs to a fixed set of circuits $\set{s_j(X,Y)}$.
This extension is crucial for proof-carrying data (PCD), where different steps
might use different circuits from a pre-registered
[_registry_](../../extensions/registry.md).

## Single-circuit Consistency

We start with a simpler protocol for a single fixed $s(X,Y)$. Consider folding
two accumulators into one:
- $\acc_0.\inst=(S_0\in\G, y_0\in\F)$ with witness $\acc_0.\wit=s(X,y_0)\in\F[X]$
- $\acc_1.\inst=(S_1\in\G, y_1\in\F)$ with witness $\acc_1.\wit=s(X,y_1)\in\F[X]$

The protocol folds these into a single new accumulator as follows:

1. Prover sends both existing accumulators commitments $S_0, S_1$
2. Verifier samples $x\sample\F$
3. Prover sends the commitment to the restriction $S'\leftarrow \com(s(x,Y))$
4. Verifier samples $y_{new}\sample\F$
5. Prover sends the new accumulator $S_{new}:= \com(s(X, y_{new}))$
6. Prover and Verifier engage in a [batched PCS evaluation](./pcs.md) protocol
   for claims: $(S_0, x, v_0), (S', y_0, v_0), (S_1, x, v_1), (S', y_1, v_1),
   (S_{new}, x, v_2), (S', y_{new}, v_2)$

The partial evaluation $s(x,Y)$ restricted at $x$ bridges the two old
accumulators to the new one. The completeness property holds because:
$$
\begin{cases}
S_0(x)=s(x, y_0)=S'(y_0)\\
S_1(x)=s(x, y_1)=S'(y_1)\\
S_{new}(x)=s(x, y_{new})=S'(y_{new})
\end{cases}
$$

## Registry Consistency

Recall the definition of [registry polynomials](../../extensions/registry.md#construction):

$$
m(W, X, Y) = \sum_{i=0}^{2^k-1} \ell_i(W) \cdot s_i(X, Y)
$$

where $\ell_i(W)$ is the Lagrange basis polynomials and $2^k$ is the domain size
(namely total number of registered circuits in the registry).
The $i$-th circuit is $s_i(X,Y)=m(\omega^i, X, Y)$ where $\omega$ is a $2^k$-th
primitive root of unity that generates the entire Lagrange domain[^simplify].

[^simplify]: To disentangle orthogonal ideas and simplify presentation, we ignore
the domain element remapping used to support
[rolling domain extension](../../extensions/regitry.md#flexible-registry-sizes-via-domain-extension),
and use the naive $i\mapsto\omega^i$ mapping here.

Extending the consistency check for bivariate $s(X,Y)$ to multivariate $m(W,X,Y)$.
Consider folding two accumulators (e.g., from two child proofs in a binary PCD tree):

$$
\begin{align*}
\acc_0.\inst&=(S_0\in\G, x_0, y_0\in\F) \text{ with witness } m(W, x_0, y_0)\in\F[W]\\
\acc_1.\inst&=(S_1\in\G, x_1, y_1\in\F) \text{ with witness } m(W, x_1, y_1)\in\F[W]
\end{align*}
$$

The split-accumulation for registry consistency proceeds as follows:

1. Prover commits to both existing accumulators $S_0, S_1$
2. Verifier samples $w\sample\F$
3. Prover sends commitments $S'_0, S'_1$:
   - $S'_0 \leftarrow \com(m(w, x_0, Y))$
   - $S'_1 \leftarrow \com(m(w, x_1, Y))$
4. Verifier samples $y\sample\F$
5. Prover sends the commitment to the merged restriction:
   $S''\leftarrow \com(m(w, X, y))$
6. Verifier samples $x\sample\F$
7. Prover sends the new accumulator:
   $S_{new}:=\com(m(W, x, y))$
8. Prover and Verifier engage in a [batched PCS evaluation](./pcs.md) protocol
   for claims:
   $$
   \begin{align*}
   &(S_0, w, v_0), (S'_0, y_0, v_0),\\
   &(S_1, w, v_1), (S'_1, y_1, v_1),\\
   &(S'_0, y, v_2), (S'', x_0, v_2),\\
   &(S'_1, y, v_3), (S'', x_1, v_3),\\
   &(S'', x, v_4), (S_{new}, w, v_4)
   \end{align*}
   $$

The partial evaluations $m(w, x_i, Y)$ restricted at challenge $w$ bridge the
two old accumulators to the merged restriction $m(w, X, y)$, which then bridges
to the new accumulator. The completeness property holds because:
$$
\begin{cases}
S_0(w) = m(w, x_0, y_0) = S'_0(y_0)\\
S_1(w) = m(w, x_1, y_1) = S'_1(y_1)\\
S'_0(y) = m(w, x_0, y) = S''(x_0)\\
S'_1(y) = m(w, x_1, y) = S''(x_1)\\
S''(x) = m(w, x, y) = S_{new}(w)
\end{cases}
$$

