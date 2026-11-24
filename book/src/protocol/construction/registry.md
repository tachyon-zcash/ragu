# Registry {#registry}

A fuse makes claims about many wiring polynomials over one field: one for each
circuit, and one for each [bonding polynomial](staging.md#bonding). A
**registry** collects them into a single polynomial $m(W, X, Y)$ that takes the
value $s_j(X, Y)$ at a point $\omega_j$ assigned to the index $j$. The value
$s_j(x, y)$ of any registered polynomial is then an opening of one committed
polynomial, $m(W, x, y)$, at $\omega_j$.

In practice, $m$ is never represented in full. A fuse computes restrictions of
it to one free variable, such as $m(W, x, y)$ for challenges $x$ and $y$, and
[opens them against one another](batch.md#registry-chain).

## Domain {#registry-domain}

A registry holds $L$ wiring polynomials over one field, indexed from zero. Its
**domain** $D$ is the set of roots of unity whose order is the smallest power of
two that is at least $L$. The index $j$ is assigned the domain point

$$
\omega_j = \Omega^{\text{bitrev}(j)},
$$

where $\Omega$ is the field's chosen root of unity of order $2^{32}$, the
largest power-of-two order in either Pasta field, and $\text{bitrev}$ reverses
$j$ as a string of $32$ bits. Bit reversal gives each index the point of
smallest order that no earlier index has taken, so the point of an index does
not depend on the size of the domain.

A fuse commits a restriction such as $m(W, x, y)$ as it commits any other
polynomial, with $4n$ coefficients, and the degree of $m$ in $W$ is less than
the size of $D$. The domain must therefore fit in the coefficients of one
polynomial:

$$
L \le 4n, \qquad |D| \le 4n.
$$

Since $4n$ is a power of two, the first bound gives the second.
[`RegistryBuilder::finalize`](ragu_circuits::registry::RegistryBuilder::finalize)
rejects a registry with more than $4n$ entries.

## Registry Polynomial {#registry-polynomial}

Let $\ell^D_j(W)$ be the Lagrange basis polynomial of $D$ that is one at
$\omega_j$ and zero at every other point of $D$. The **registry polynomial**
$m(W, X, Y)$ has degree less than the size of $D$ in $W$, and is determined by
its values on $D$:

$$
m(\omega_j, X, Y) = s_j(X, Y) \quad (j < L), \qquad
m(\omega, X, Y) = \textcolor{#7e22ce}{\kappa} \cdot (XY)^{4n-1}
\quad \text{at every other } \omega \in D.
$$

Every $s_j$ carries the [registry constraint](wiring.md#system-gate)
$\textcolor{#7e22ce}{\kappa} \cdot (XY)^{4n-1}$, so the polynomial at a point
with nothing registered is a wiring polynomial with that constraint and no
other. The basis polynomials of $D$ sum to one, which makes the constraint a
term of $m$ with no factor of $W$:

$$
m(W, X, Y) = \sum_{j=0}^{L-1} \ell^D_j(W)
  \left( s_j(X, Y) - \textcolor{#7e22ce}{\kappa} \cdot (XY)^{4n-1} \right)
  + \textcolor{#7e22ce}{\kappa} \cdot (XY)^{4n-1}.
$$

## Kinds of Registered Polynomial {#registry-kinds}

Every point of the domain therefore holds a wiring polynomial, and each is of
one of two kinds. The wiring polynomial of a circuit has $s(X, 0) = 1$. A
bonding polynomial has $s(X, 0) = 0$: the registered [masks](staging.md#masks)
are of this kind, and so is the polynomial at a point with nothing registered.

This is why an index only has to name a point of the domain. A claim about a
circuit has $\v{k}_0 = 1$, which no bonding polynomial can satisfy, so a claim
taken at an arbitrary point of the domain is confined to the registered circuits
without any check of what was registered there.

Indices are assigned by category: internal circuits first, then bonding
polynomials, then internal steps, then application steps. The index of an
internal circuit or of a bonding polynomial therefore does not depend on how
many steps an application registers.

## Tag {#tag}

The **tag** $\color{#7e22ce}{\kappa}$ of a registry is a BLAKE2b hash,
personalized `ragu_registry___`, of the field modulus, $n$, $L$, and the
monomials of every registered polynomial in index order, reduced into the field.
Each polynomial is hashed without the registry constraint, since that constraint
contains the tag. The registry derives the tag when it is finalized, and the
[`SYSTEM` gate](wiring.md#system-gate) section gives its purpose.

The transcript does not absorb the tag. It enters the protocol as a coefficient
of every wiring polynomial.
