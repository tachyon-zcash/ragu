# Endoscalars

Introduced in the [Halo protocol](https://eprint.iacr.org/2019/1021), an
_endoscalar_ $\endo{s}\in\{0,1\}^\lambda$ (where $\lambda = 134$)
is a small binary string used to perform scalar multiplication on curves with
an efficient endomorphism (such as both Pasta curves).
The endoscalar space is smaller than both $\F_p$ and $\F_q$, allowing it to
serve as a _cross-circuit scalar_ that can be efficiently mapped to both
target fields. In `ragu`, the endoscalar value type is `Uendo`, wrapped by
the `Endoscalar` circuit gadget; its width is the `ENDOSCALAR_BITS`
constant.

Endoscalars must support the following operations:

- $\mathsf{extract}(s\in\F)\rightarrow \endo{s}$: deterministically extract a
$\lambda$-bit value from an _in-range_ field element $s\in\F$ where
$\log |\F|>\lambda$. An element is in range when its canonical representative
fits in the field's capacity ($2^{254}$ for the Pasta fields), and the
extracted value is the lower $\lambda$ bits of that representative.
Extraction fails for the remaining elements; a prover that derives $s$ from
a transcript re-randomizes and re-derives the challenge in that case
(probability $\approx 2^{-129}$)
- $\mathsf{lift}(\endo{s})\rightarrow s\in\F$: deterministically lift an
endoscalar back to a target field; note that this target field can differ
from the source field from which $\endo{s}$ is extracted, as long as the target
field size is $>2^\lambda$
- $\endo{s}\cdot G\in\G \rightarrow H\in\G$: perform scalar multiplication
on group elements, we call this operation _endoscaling_

The expected properties include:

- uniform extraction: if the original field element is sampled from a uniform
distribution over the in-range subset of $\F$ where $|\F|\gg 2^\lambda$, then
the extracted $\endo{s}$ is uniform over $\{0,1\}^\lambda$
- endoscaling consistency: $\endo{s}\cdot G = \mathsf{lift}(\endo{s})\cdot G$
for any $\endo{s}$
- circuit efficiency: all three operations above should be efficient to
  constrain

## Radix-3 Endoscaling

Halo's endoscaling reads the endoscalar two bits at a time: each pair selects
one of $\pm G, \pm \phi(G)$, where $\phi(x, y) = (\zeta x, y)$ is the
endomorphism, and the accumulator is doubled before the selected point is
added. Writing $\lambda$ for the scalar $\phi$ acts by, the endomorphism gives
six cheap multiples of $G$, the units $\pm 1, \pm \lambda, \pm \lambda^2$ of
$\mathbb{Z}[\lambda]$, but a doubling walk cannot use all six: adding
$\pm \lambda^2$ to the radix-2 alphabet makes two bit strings map to the same
scalar, as $2 \cdot 1 + \lambda = 2 \cdot (-\lambda^2) + (-\lambda)$.

`ragu` instead walks the endoscalar in radix 3. After two initial bits
$(s_0, e_0)$, every three bits $(s, e_1, e_2)$ select one of the eight digits

$$
\mathcal{D} = \{\pm 1, \pm \lambda, \pm \lambda^2, \pm (1 - \lambda)\},
\qquad
d = (-1)^s \cdot \{1, \lambda, \lambda^2, 1 - \lambda\}[e_1, e_2],
$$

and the walk is $A_0 = [2] (-1)^{s_0} \phi^{e_0}(G)$, $A_{i+1} = [3] A_i +
[d_i] G$ over $n = 44$ digits. The eight digits are exactly the nonzero
residues of $\mathbb{Z}[\lambda]$ modulo $3$, so an expansion decodes uniquely
digit by digit and the map from bit strings to scalars is injective. Any two
distinct encodings differ by an element of norm below $33 \cdot 9^{n}$, far
below the Pasta group orders, so they remain distinct in the scalar field.
The effective scalar, which $\mathsf{lift}$ computes, is

$$
k = 2 \cdot 3^{n} (-1)^{s_0} \lambda^{e_0} + \sum_{i=0}^{n-1} 3^{n - 1 - i} d_i.
$$

In circuit, a round costs ten multiplication gates for three bits: seven for
$[3] A + D = ((A + D) + A) + A$, whose intermediate $y$-coordinates cancel out
of the slope equations, and three for the eight-way selection of $D$. The
selection is cheap because the base point is first moved to the isomorphic
curve on which it has coordinates $(r, r)$, by $(x, y) \mapsto (c^2 x, c^3 y)$
with $c = x / y$; there every digit multiple of the base point has coordinates
affine in $r$. With the three gates of that normalization, four for the
initial doubling and three to move the result back, an endoscaling costs
$10 n + 10$ gates: $450$ at the 134 bits used, where the radix-2 walk would
cost $476$, and $430$ against $455$ at 128 bits.

Consider a random verifier challenge $\alpha\in\F_p$ produced in a circuit over
$\F_p$ where we want to compute $\alpha\cdot G\in\G_1$.
Any group operations inside an $\F_p$-circuit require expensive non-native
arithmetic, so we prefer deferring this to an $\F_q$-circuit where group
elements are natively represented and arithmetic over coordinates $\in\F_q$
is also native.
We can move $\alpha$ across circuits via an endoscalar:
first, run $\mathsf{extract}$ in the $\F_p$-circuit to obtain the endoscalar
as a public output; then use the same endoscalar as the public input of the
$\F_q$-circuit and constrain $\endo{s}\cdot G$ completely natively.

## Convergence Problem

In a curve cycle, endoscaling is a scalar multiplication where the scalar is
from the foreign field. Our
[CycleFold](https://eprint.iacr.org/2023/1192)-inspired design exhibits a kind
of reflexive cost: when we add circuits to handle endoscaling operations on one
curve, each new circuit creates commitments that require endoscaling on the
other curve. We'd like to determine how many total circuits the process
converges to, given that each circuit can only handle $k$ endoscaling
operations ($k = 4$ without overflowing the recursion threshold of $2^{11}$
constraints). The convergence can be modeled as a **geometric series**.

Let $M$ denote the base endoscalings needed on Pallas, $N$ the base endoscaling
needed on Vesta, and $k$ the endoscaling capacity per circuit. For simplicity,
we assume $M = N$ as the initial conditions. In the first round, we have
$\frac{M}{k}$ circuits on Pallas and $\frac{N}{k}$ circuits on Vesta. In the
next round, each circuit from the previous round introduces one additional
endoscaling operation on the opposite curve. Consequently, Pallas requires an
additional $\frac{\frac{M}{k}}{k}$ and Vesta $\frac{\frac{N}{k}}{k}$ circuits.
This continues recursively across rounds.

### Blowup Factor

We can model this generalized sequence as:

**Pallas circuits added per round:** $\frac{M}{k}, \frac{M}{k^2}, \frac{M}{k^3},
\ldots$

**Vesta circuits added per round:** $\frac{N}{k}, \frac{N}{k^2}, \frac{N}{k^3},
\ldots$

Each term represents the additional circuits needed in that round. The total
is the sum of two coupled geometric series, each with ratio $\frac{1}{k^2}$.
If we expand this geometric series out for $k = 4$:

**(Pallas circuits)**

$$
M_{total} = \frac{M}{4} \cdot \left(1 + \frac{1}{16} + \frac{1}{256} + \ldots
\right) + \frac{N}{16} \cdot \left(1 + \frac{1}{16} + \frac{1}{256} + \ldots
\right) = \frac{M}{4} \cdot \frac{16}{15} + \frac{N}{16} \cdot \frac{16}{15}
= \frac{4M+N}{15}
$$

This derivation becomes clearer if we delineate, for the Pallas curve
specifically, where the work comes from:

1. **M Terms** (Pallas's own work bouncing back via Vesta):
   - Round 1: $\frac{M}{k}$, Round 3: $\frac{M}{k^3}$, Round 5: $\frac{M}{k^5}$
     $\ldots$

2. **N Terms** (Vesta's work forwarded to Pallas):
   - Round 2: $\frac{N}{k^2}$, Round 4: $\frac{N}{k^4}$, Round 6:
     $\frac{N}{k^6}$ $\ldots$

which, when cumulatively combined, equates to $M_{total}$. We can do the same
thing, but in reverse for Vesta, to get the same $N_{total}$.

**(Vesta circuits)**

$$
N_{total} = \frac{N}{4} \cdot \left(1 + \frac{1}{16} + \frac{1}{256} + \ldots
\right) + \frac{M}{16} \cdot \left(1 + \frac{1}{16} + \frac{1}{256} + \ldots
\right) = \frac{N}{4} \cdot \frac{16}{15} + \frac{M}{16} \cdot \frac{16}{15}
= \frac{4N+M}{15}
$$

In the symmetric case, where $M = N$, both formulas yield $\frac{5M}{15} =
\frac{M}{3}$. The base circuits required for each curve
are $\frac{M}{4}$. To get the total number of circuits needed for each side,
then we take the intermediate term
$\frac{M}{4} \cdot \frac{16}{15} + \frac{N}{16} \cdot \frac{16}{15}$ and factor
out the common terms and combine the fractions:

- Factor out $M \cdot \frac{16}{15}$:
  $M \cdot \frac{16}{15} \cdot (\frac{1}{4} + \frac{1}{16})$
- Combine denominators: $\frac{1}{4} + \frac{1}{16} = \frac{5}{16}$.

This means $M \cdot \frac{16}{15} \cdot \frac{5}{16} = \frac{M}{3}$ represents
the *total* number of circuits required. $\frac{M}{3}$ is the simplified
version of $\frac{4M+N}{15}$ when $M = N$. Therefore, the blowup factor for
$k = 4$ is: $\frac{M}{3} / \frac{M}{4} = \mathbf{1.33x}$. The same math works
for $k = 8$, since the base circuits would be $\frac{M}{8}$, so the total
circuits required would be $\frac{M}{7}$ and the blowup factor is
$\frac{M}{8} / \frac{M}{7} = \mathbf{1.14x}$.

In summary, endoscalars provide a bridge for moving scalar values between
circuits in a curve cycle, with three core operations (extract, lift, and
endoscale) that enable challenge consistency across the cycle. The convergence
analysis shows that the reflexive cost of endoscaling circuits is modest:
approximately 1.33x overhead for $k=4$ and 1.14x for $k=8$.
