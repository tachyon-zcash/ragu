# Endoscalars

Introduced in the [Halo protocol](https://eprint.iacr.org/2019/1021), an
_endoscalar_ $\endo{s}\in\{0,1\}^\lambda$ (where $\lambda$ is 128 or 136 bits)
is a small binary string used to perform scalar multiplication on curves with
an efficient endomorphism (such as both Pasta curves).
The endoscalar space is smaller than both $\F_p$ and $\F_q$, allowing it to
serve as a _cross-circuit scalar_ that can be efficiently mapped to both
target fields. In `ragu`, we support both `u128` (default) and 136-bit
`Uendo` as the endoscalar type, unified under the `Endoscalar` type.
Endoscalars must support the following operations:

- $\mathsf{extract}(s\in\F)\rightarrow \endo{s}$: deterministically extract a
$\lambda$-bit value from a field element $s\in\F$ where $\log |\F|>\lambda$
- $\mathsf{lift}(\endo{s})\rightarrow s\in\F$: deterministically lift an
endoscalar back to a target field; note that this target field can differ
from the source field from which $\endo{s}$ is extracted, as long as the target
field size is $>2^\lambda$
- $\endo{s}\cdot G\in\G \rightarrow H\in\G$: perform scalar multiplication
on group elements, we call this operation _endoscaling_

The expected properties include:

- pseudorandom extraction: informally, if the original field element is sampled
from a uniform distribution over $\F$ where $|\F|\gg 2^\lambda$, then
the extracted $\endo{s}$ is pseudorandom over $\{0,1\}^\lambda$
- endoscaling consistency: $\endo{s}\cdot G = \mathsf{lift}(\endo{s})\cdot G$
for any $\endo{s}$
- circuit efficiency: all three operations above should be efficient to
  constrain

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
