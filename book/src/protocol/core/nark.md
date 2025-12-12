# Non-interactive Argument of Knowledge

## Intuition

The previous constraint system reduces to a single consolidated revdot product
check. In this section, we establish a transformation from revdot products to
polynomial multiplication, where the revdot result appears as a coefficient in
the product polynomial. We then apply polynomial decomposition and reversal to
convert this "coefficient query" into standard "evaluation queries" that
polynomial oracles can handle. This enables us to build a Polynomial IOP, which
we later compile with a PCS to obtain a NARK.

## Revdot Products to Polynomial Predicates

Let's start with where we ended up in our arithmetization. The satisfiability
of our [Bootle16 constraint system](./arithmetization.md) culminates in a
single [consolidated constraint](./arithmetization.md#consolidated-constraints):

$$\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} - \v{t} + \v{s}} = \dot{\v{k}}{\v{y^{4n}}}$$

where:
- the witness vector $\v{r}=(\v{c}\|\rv{b}\|\v{a}\|\v{0})\in\F^{4n}$
- the circuit wiring vector
$\v{s}=(\v{0^n}\| \sum_{j=0}^{4n-1}y^j\cdot\rv{u}_j \| \sum_j y^j\cdot\v{v}_j \| \sum_j y^j\cdot \rv{w}_j)$
- the `mul` constraint vector
$\v{t} = (\v{0^{3n}}\|\, (\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n})\cdot \rv{1})$
- the public input vector $\v{k}\in\F^{4n}$

Now we need to express this in terms of polynomials. The connection comes from
a fundamental property of polynomial multiplication: the coefficients of a
product polynomial are discrete convolutions. For polynomials $p, q\in\F[X]$
with coefficient vectors $\v{p}, \v{q}\in\F^{4n}$:

$$
p(X)\cdot q(X) =c(X)= \sum_{k=0}^{8n-2}c_k\cdot X^k
\quad\text{where }c_k=\sum_{i+j=k}\v{p}_i\cdot \v{q}_j
\text{ and } c_{4n-1}=\revdot{\v{p}}{\v{q}}
$$

This is exactly what we need! If we multiply $\hat{r}(X)\cdot r(zX)$, the
coefficient of its $X^{4n-1}$ term equals
$\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}}}$—the left side of our constraint.

But there's a problem. Our witness polynomials have degree less than $4n$, so
their product $c(X)$ has degree up to $8n-2$. We could commit to this
product directly, but that's expensive—committing to degree-$8n$ polynomials
costs roughly twice as much as degree-$4n$ polynomials. And we only care about
one coefficient (the $c_{4n-1}$ term), so paying double for the whole thing
seems wasteful.

### The Decomposition Trick

Instead of committing to the full product, we decompose it into two smaller pieces:

$$c(X) = c_{lo}(X) + X^{4n}\cdot c_{hi}(X)$$

where $\v{c}_{lo}=\v{c}_{[:4n]}\in\F^{4n}$ and $\v{c}_{hi}=\v{c}_{[4n:]}\in\F^{4n-1}$.
Both pieces now have degree less than $4n$, which is exactly what we want.

But we still need to extract that $c_{4n-1}$ coefficient—it's buried as the
last coefficient of $c_{lo}$. This is where the reversal trick comes in. Define:

$$c_1(X)=\hat{c}_{lo}(X), \quad c_2(X)=c_{hi}(X)$$

By reversing the coefficient vector of $c_{lo}$, we get
$\v{c}_1=\rv{c}_{lo}=(c_{4n-1},\ldots,c_0)$. Notice what happened: **the
coefficient we care about, $c_{4n-1}$, is now the constant term of $c_1(X)$**.
And we can check the constant term by evaluating at zero.
The prover commits to $c_1(X)$ and $c_2(X)$, and the verifier can:
1. Check the decomposition is correct by querying at a random point $x$
2. Extract the coefficient value by querying $c_1(0)$

That's the transformation: we've turned a coefficient check into evaluation
queries that our PCS can handle efficiently.

## Polynomial IOP

Now that we understand how to turn our coefficient check into polynomial
evaluations, let's build out the complete Polynomial IOP protocol.

We'll start by taking all those coefficient vectors from our arithmetization
and interpreting them as polynomials.

- **witness polynomial**:
  $r(X)=\sum_{i=0}^{n-1} (c_iX^i+b_iX^{2n-1-i}+a_iX^{2n+i})$
  - dilated witness polynomial: $r(XZ)$ corresponding to $\v{r}\circ\v{z^{4n}}$
  fixated at $z\in\F$
- **wiring/circuit polynomial**:
    $$
    s(X,Y)=\sum_{j=0}^{4n-1} Y^j\cdot\left(\sum_{i=0}^{n-1} (
        \v{u}_j^{(i)}\cdot X^{2n-1-i} +
        \v{v}_j^{(i)}\cdot X^{2n+i} +
        \v{w}_j^{(i)}\cdot X^{4n-1-i}
    )\right)
    $$
- **gate polynomial**:
  $t(X, Z)=\sum_{i=0}^{n-1} (Z^{2n-1-i}+Z^{2n+i})\cdot X^{4n-1-i}$
- **public input polynomial**: $k(Y) = \sum_{j=0}^{4n-1} \v{k}_j\cdot Y^j$

We'll use the notation $\mathcal{O}^p$ for a polynomial oracle provided by the
prover. Think of an oracle as a black box that the verifier can query—they can
ask "what does $p$ evaluate to at point $z$?" and get back both the answer and
a proof it's correct. When we compile this with a PCS later, these oracles
become polynomial commitments with evaluation proofs.

```mermaid
sequenceDiagram
    participant P as Prover
    participant V as Verifier

    %% instance-independent circuit struct
    P<<->>V:  s(X, Y), t(X, Z)
    Note over P,V: online phase

    P<<->>V: k(Y)
    Note over P: prepare witness
    P->>V: Oracle r(X)
    V->>P: z, y in F
    Note over P: compute product polynomial and decompose
    P->>V: Oracle c1(X), Oracle c2(X)
    Note over V: query oracles and verify predicates
```

Here's how the protocol flows:

1. **Setup**: The circuit polynomials $s(X, Y)$ and $t(X, Z)$ are shared
   between prover and verifier. These encode the structure of the circuit and
   don't change per proof.

2. **Public input**: The public input polynomial $k(Y)$ is shared.

3. **Witness commitment**: The prover commits to the witness polynomial $r(X)$.

4. **Random challenges**: The verifier sends random challenges $z, y\in\F$.
   These are used to partially evaluate $s(X,y), t(X,z)$ such that the
   consolidated revdot product corresponds to a predicate about _univariate
   polynomials only_.

5. **Product and decomposition**: The prover computes the product polynomial
   $\hat{r}(X) \cdot r(zX)$, decomposes it into $c_1(X)$ and $c_2(X)$ using the
   trick we described earlier, and commits to both.

6. **Verification**: The verifier runs the checks we'll describe below.

### The Verification Checks

The verifier samples a random point $x\sample\F$ and queries the oracles at
specific points. Let's walk through what gets checked and why:

The verifier queries:
- $\mathcal{O}^r$ at $0, x, xz$
- $\mathcal{O}^{c_1}$ at $0, x^{-1}$
- $\mathcal{O}^{c_2}$ at $x$

Then computes locally:
- $s(x,y), t(x,z), k(y), k(0)$

And verifies three equations:
$$
\begin{cases}
  r(x) \cdot (r(xz) + s(x,y)- t(x,z))\iseq x^{4n-1}c_1(x^{-1}) + x^{4n} c_2(x)
      &\text{correct decomposition}\\
  c_1(0)\iseq k(y) &\text{consolidated CS check}\\
  r(0)\iseq k(0)\iseq 1 &\text{public "one"}
\end{cases}
$$

The first equation checks that $c_1(X)$ and $c_2(X)$ are actually the
decomposition of the product polynomial. The second equation is the main
constraint check—remember, $c_1(0)$ extracts the coefficient we care about. The
third equation enforces that the first element of the witness is the public
constant `ONE`, which is a convention in our constraint system.

### Performance Characteristics

This PIOP works, but it's not as efficient as we'd like. Here are the main
bottlenecks:

**Prover overhead**: Computing the product polynomial $\hat{r}(X) \cdot r(zX)$
and then decomposing it into $c_1(X)$ and $c_2(X)$ is expensive. We need at
least 3 FFTs over a domain of size $8n-2$[^prod-cost]. This is the most
expensive step for the prover.

**Verifier computation**: The verifier needs to evaluate $s(x,y)$ locally,
which is a linear-cost operation $O(|\Cir|)=O(n)$.

**Multiple PCS queries**: The verifier makes multiple polynomial oracle queries
(to $r$, $c_1$, and $c_2$), and each requires a PCS evaluation proof. When
using [Bulletproofs-based PCS](../prelim/bulletproofs.md), verification is
linear time per query, so these costs add up.

These inefficiencies are addressed in the next sections through various
optimizations, but the core protocol structure remains the same.

[^prod-cost]: FFT two multiplicands, each of polynomial of degree $4n-1$, over
an evaluation domain of size $\geq 8n-1$, then IFFT back to get the coefficient
of the product polynomial before decomposing.

## NARK

To get from our Polynomial IOP to a practical proof system, we need two more
pieces: a Polynomial Commitment Scheme (PCS) to instantiate the oracles, and
the Fiat-Shamir transformation to make everything non-interactive. The result
is a Non-interactive Argument of Knowledge (NARK).

For clarity, we'll present the interactive version of the NARK used in `ragu`.
The non-interactive version follows directly by replacing verifier challenges
with hash-derived values.
