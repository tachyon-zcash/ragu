# Registry Polynomial

As [previously discussed](../core/arithmetization.md), individual circuits can be represented entirely by a polynomial $s(X, Y)$ that represents all of its linear constraints. In order to make many different circuits available within the protocol simultaneously, it will be useful to define a registry polynomial $m(W, X, Y)$ in that third formal indeterminate $W$ that interpolates such that

$$
m(\omega^i, X, Y) = s_i(X, Y)
$$

for some root of unity $\omega \in \mathbb{F}$ of sufficiently large $2^k$ order to index all circuits. Evaluating the registry at any domain point $W = \omega^i$ recovers exactly the $i$-th circuit's bivariate polynomial.

## Construction

The registry is a collection of circuits over a particular field, and the registry has a *domain*, where each circuit is mapped to a successive power of $\omega$ in the domain.

### Consistency Checks

A fundamental property of multivariate polynomials is that two degree-bounded polynomials are equal if and only if they agree at all points in their domain. Our protocol exploits this to verify polynomial equality probabilistically through random challenge points.

Given two representations of a polynomial $p(W, X, Y)$, we verify consistency by evaluating at random challenge points. By the Schwartz-Zippel lemma, if two distinct polynomials of degree $d$ are evaluated at a random point, they agree with probability at most $d/|\mathbb{F}|$.

The protocol uses *partial evaluations* to reduce the dimensionality of the polynomial equality checks. We fix variables at specific challenge points and create lower-dimensional restrictions, where in each evaluation at most one variable remains free:

| Evaluation | Type | Description |
|------------|------|-------------|
| $p(W, x, y)$ | $\mathbb{F}[W]$ | Univariate in $W$ for fixed $x$ and $y$ |
| $p(w, X, y)$ | $\mathbb{F}[X]$ | Univariate in $X$ for fixed $w$ and $y$ |
| $p(w, x, Y)$ | $\mathbb{F}[Y]$ | Univariate in $Y$ for fixed $w$ and $x$ |
| $p(w, x, y)$ | $\mathbb{F}$ | Point evaluation |

This mirrors the technique used in the [sumcheck](https://people.cs.georgetown.edu/jthaler/sumcheck.pdf) protocol: within a protocol, we alternate between (univariate) restrictions of a polynomial using random challenges to prove equality, probabilistically reducing a claim about many different evaluations of a polynomial to a single polynomial evaluation.

### Applicability to the Registry

If independent parties claim to hold evaluations of the same registry polynomial $m(W, X, Y)$ at different points $(w_i, x_i, y_i)$ and $(w_z, x_z, y_z)$, we can verify they share the same underlying polynomial by:

1. Sampling random challenges $w^*, x^*, y^*$,
2. Evaluating the claimed polynomials at restrictions like $m(w^*, X, Y)$, $m(W, x^*, Y)$, etc,
3. Checking that the restricted polynomials agree at further challenge points

This ensures that claimed evaluations at different points are derived from the same underlying registry $m(W, X, Y)$.

For instance, the registry $m(W, x, y)$ is the polynomial free in $W$ that interpolates all circuit points. At each point $\omega$ in the domain, the registry polynomial equals the $i$-th circuit's evaluation:

$$
m(\omega^i, x, y) = s_i(x, y)
$$

These consistency checks may require evaluating the registry polynomial free in $X$:

$$
m(\omega^i, X, y) \;\equiv\; s_i(X, y)
$$

More generally, the protocol needs to evaluate the registry at *arbitrary* challenge points $w \in \mathbb{F}$ (not necessarily a root of unity $\omega$). We use Lagrange coefficients for polynomial interpolation. Suppose the registry is defined on the points ${\omega^0, \omega^1, ..., \omega^{n-1}}$ with

$$
f_i(X,y) \;=\; m(\omega^i, X, y) \;=\; s_i(X,y)
$$

Then for any $w \in \mathbb{F}$

$$
m(w, X, y) \;=\; \sum_{i=0}^{n-1} \ell_i(w)\, f_i(X,y)
$$

where the Lagrange basis coefficients are

$$
\ell_i(w) \;=\; \prod_{\substack{0\le j< n\\ j\ne i}} \frac{w-\omega^j}{\omega^i-\omega^j}.
$$

This gives you a polynomial that *(i)* passes through all circuit evaluations at their respective $\omega^i$ points, and *(ii)* evaluates to the correct interpolated value at the random challenge point $W = w$.

## Flexible Registry Sizes via Domain Extension

The registry requires a domain size $2^k$ for some non-negative integer k and assigns circuits to successive powers $\omega^j$, where $\omega$ is a $2^k$ primitive root of unity in the field. The domain size determines the degree of the interpolation polynomial.

A naive approach to registry construction would assign the $j$-th circuit directly to $\omega^j$ where $\omega$ is chosen based on the domain size $2^k$ needed to fit all circuits. However, this creates a fundamental problem: **the domain size must be known in advance**. If we allocate a $2^k$ domain and later register a $(2^k+1)$-th circuit into the registry, we would outgrow the registry and most previously-assigned values in the domain would be incorrect.

This limitation is cleverly resolved through *rolling domain extensions*: the domain is "rolling" in the sense that the registry accepts circuits incrementally without knowing the final domain size $k$. When $k$ is fixed at registry finalization, we use a bit-reversal technique that maps each circuit to its correct position in the finalized domain.


### Bit-Reversal

The way this construction works is $\omega$ values are *precomputed* in the maximal field domain $2^S$; the actual working domain $2^k$ is determined later and depends on the number of circuits that end up being registered in the registry. The precomputation remains valid regardless of $k$.

To assign a domain point to the $j$-th circuit, we don't use $\omega^j$ directly. Instead, we fix a maximal upper bound $k = S$ and set

$$
i := \text{bitreverse}(j, S)
$$

where we reverse the bits of $j$ to compute the power $i$, and assign circuit $j$ to domain point $\omega_S^i$. This bit-reversal ensures we effectively exhaust the smaller domains first.

During registry finalization when $k = \lceil \log_2 C \rceil$ is determined, the value $\omega_S^i$ (where $i = \text{bitreverse}(j, S)$) assigned to circuit $j$ is re-expressed in the smaller $2^k$ domain as $\omega_k^{i \gg (S-k)}$ (by right-shifting the exponent).

Notice that these represent the same field element in different domains, since $\omega_k = \omega_S^{2^{S-k}}$. We've effectively compressed the $2^S$-slot domain to the $2^k$-slot domain.

Consequently, circuit synthesis can compute $\omega_S^i$ at compile-time without knowing how many other circuits will be registered in the registry. This has the property that the domain element assigned to circuit $j$ depends only on the circuit index $j$ and the fixed maximal bound $S$, not on the total number of
circuits $C$. This enables incremental circuit registration during compilation, where each circuit independently computes its domain point, and the registry is finalized only after all circuits are known.
