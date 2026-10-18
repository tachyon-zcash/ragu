# Endoscalars

Introduced in the [Halo protocol](https://eprint.iacr.org/2019/1021), an
_endoscalar_ $\endo{s}\in\{0,1\}^\ell$ (where $\ell = 143$)
is a small binary string used to perform scalar multiplication on curves with
an efficient endomorphism (such as both Pasta curves).
The endoscalar space is smaller than both $\F_p$ and $\F_q$, allowing it to
serve as a _cross-circuit scalar_ that can be efficiently mapped to both
target fields. In `ragu`, the endoscalar value type is `Uendo`, wrapped by
the `Endoscalar` circuit gadget; its width is the `ENDOSCALAR_BITS`
constant.

Endoscalars are for public transcript challenges. They must not encode
blinding factors or other scalars whose secrecy is required. Splitting the
radix expansion gives a sumset and a meet-in-the-middle search for a secret
$k$ from $[k]G$ in roughly $2^{\ell/2}$ work. For public challenges, the
relevant soundness event is instead that a fresh challenge hits the roots
of a previously fixed nonzero polynomial.

Endoscalars must support the following operations:

- $\mathsf{extract}(s\in\F)\rightarrow \endo{s}$: deterministically extract a
$\ell$-bit value from an _in-range_ field element $s\in\F$ where
$\log |\F|>\ell$. An element is in range when its canonical representative
fits in the field's capacity ($2^{254}$ for the Pasta fields), and the
extracted value is the lower $\ell$ bits of that representative.
Extraction fails for the remaining elements; a prover that derives $s$ from
a transcript re-randomizes and re-derives the challenge in that case
(probability $\approx 2^{-129}$)
- $\mathsf{lift}(\endo{s})\rightarrow s\in\F$: deterministically lift an
endoscalar back to a target field; note that this target field can differ
from the source field from which $\endo{s}$ is extracted, provided the target
field has the required cube root and satisfies the characteristic bound below
- $\endo{s}\cdot G\in\G \rightarrow H\in\G$: perform scalar multiplication
on group elements, we call this operation _endoscaling_

The expected properties include:

- uniform extraction: if the original field element is sampled from a uniform
distribution over the in-range subset of $\F$ where $|\F|\gg 2^\ell$, then
the extracted $\endo{s}$ is uniform over $\{0,1\}^\ell$
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
[d_i] G$ over $n = 47$ digits. The eight digits are exactly the nonzero
residues of $\mathbb{Z}[\lambda]$ modulo $3$, so an expansion decodes uniquely
digit by digit and the map from bit strings to scalars is injective. Any two
distinct encodings differ by an element whose norm is at most
$3 (5 \cdot 3^{n} - 1)^2 < 75 \cdot 9^{n}$, the sufficient bound used by
Lean's `endoscaleCharacteristicBound`. At $n = 47$ this is about $2^{155.2}$,
far below the Pasta group orders, so they remain distinct in the scalar field.
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
$10 n + 10$ gates: $430$ against $455$ for the radix-2 walk at 128 bits.

The input must be a valid nonidentity point. Normalization divides by $y$,
denormalization divides by $c^2$ and $c^3$, and the initial tangent uses
$r \ne 0$. Thus $x$, $y$, $c$, and $r$ must all be nonzero, and the base
field must have characteristic greater than three. Pasta's prime-order
groups have no nontrivial 2- or 3-torsion: on these curves $y = 0$ would give
2-torsion and $x = 0$ would give 3-torsion. The Lean parameter lemmas also
check the nonzero-coordinate facts directly in both base fields. The Rust
point contract and the circuits that re-establish it supply curve membership.

The roots in the two fields must agree with the group action:
$\phi(G) = [\lambda]G$, with $\lambda$ equal to the scalar field's `ZETA`.
Being a nontrivial cube root alone does not choose between $\lambda$ and
$\lambda^2$. `Point.Endomorphism` proves the deployed pairing on both Pasta
curves, and the Rust consistency test checks it independently using scalar
multiplication. `WalkScalar` then relates the affine walk to the verified
lift in the opposite field.

### Hoisted digit products

The selector's three gates are two products of $r$ with bit-linear forms
and one product of bits, $(u + v - 1) h$. Every endoscaling step of a fuse
scales by the same $\beta$, so the bit-only part of the selection can be
computed once rather than once per endoscaling: the walk stages carry, for
every digit, the products $e_1 e_2$ and $e_1 e_2 s$ beside the bits, and the
circuit that owns the stage's contracts (`bind_endoscalar` natively, the
nested `export`) enforces them once, two gates per digit, next to the bits'
booleanity. With those wires in hand both coordinates of the digit point are
$r$ times a linear form plus a linear form, so a step selects in two gates
per digit, $9 n + 10$ per endoscaling, and the lift in the nested
`compute_v` costs one gate per digit. That is what lets $\ell = 143$ fit
the same steps that held $128$ bits of the radix-2 walk: $433$ gates per
endoscaling in a step against $455$ before, with the ten binder challenges
widened to the same $143$ bits on the plain three-gate selector.

The hoisted lift still multiplies each unsigned digit by its sign. Its
$e_1 e_2$ and $e_1 e_2 s$ wires do not supply $s e_1$ or $s e_2$, so the
lift costs $n + 1 = 48$ gates including initialization. The nested
`EndoscalarStage` grows from 64 to 119 gates, and the nested `compute_v`
circuit grows from 1661 to 1700 gates. Hoisting saves work in the walk;
it does not make the lift linear in the stage wires.

Nested `export` grows from 1384 to 1548 gates: 94 product constraints,
15 additional fresh Boolean gates, and 55 additional stage gates. The
native `bind_endoscalar` instead compares the staged bits to the canonical
extraction of `pre_beta` and pins the products. On the nested side,
`export` pins Booleanity and products, while `compute_v` equates their
lift with the challenge stage's $\beta$. Lift injectivity is what makes
that equality determine the bits. Stage sharing, the parent challenge
commitment binding, and the root check must preserve these same wires.

`bind_beta` performs two plain endoscalings, one per child. Widening those
from 128 to 143 bits would change its 2029 gates to 2079. It now ends at the
preamble and omits the unused 186-gate `outer_error` stage, yielding 1893
gates. Its claim contains `BindBeta`, `PointsBinding`, and `Preamble`; the
new `PreambleFinalStaged` mask bonds `BindBeta`, which is removed from the
`OuterErrorFinalStaged` bonding claim. Registration includes the new mask.
The internal registry therefore has 53 native and 45 nested entries,
including masks, rather than the previous total of 97. The 25 native and
28 nested walk steps are unchanged.

The constraint census uses production rank `R<13>`, a 103-element header,
and 6000 placeholder application circuits. In that fixture the largest
`bind_challenges` variant uses 2046 of 2048 gates, leaving two gates of
headroom. The census tests pin that count; extending the binder requires
rechecking its capacity.

The exceptional-case invariant is explicit in the integer model: every
accumulator has Eisenstein norm at least four, while every digit has norm
one or three. Hence $A-D$, $A+D$, $2A+D$, and $3A+D$ are nonzero integer
indices: an equality would force $k^2 N(A) = N(D)$ for $k \in \{1,2,3\}$.
The positive norms of these combinations are at most
$3 (5 \cdot 3^{47})^2$, below either Pasta group order. The unchecked
additions are justified by the
[affine-walk proof](../../fv/circuits/contracts.md): `WalkGroup` identifies
each affine accumulator with its Eisenstein action in the complete curve
group, and the positive norm bounds rule out every exceptional addition.
`WalkPasta` derives success for both Pasta curves from their certified prime
group orders. The concrete gadget contracts therefore require curve
membership, Boolean selector bits, and (when hoisted) the product-wire
relations, without a separate walk-success premise.

`LiftInjectivity` equates `Lift.liftNative` with the integer encoding and
proves uniqueness of Boolean inputs for the plain and hoisted circuit
outputs. Its bounds are instantiated for both Pasta fields. `WalkScalar`
adds the concrete `ep_scalar_soundness` and `eq_scalar_soundness` endpoints
to both walk gadgets, proving $\endo{s}\cdot G = [\mathsf{lift}(\endo{s})]G$.
These are gadget contracts: they do not formalize the internal circuits'
sharing of staged wires, the binding of `pre_beta` and $\beta$, or the
recursive protocol's soundness reduction. The
[open endoscalar stage-binding contract](../../fv/circuits/contracts.md#endoscalar-stage-binding)
names the owners, consumers, parent and terminal checks, and the proof
obligations for that broader formalization.

### Challenge accounting

All ten nested challenges, in stage order, are 143-bit lifts:
$w_n, y_n, z_n, \mu_n, \nu_n, \mu'_n, \nu'_n, x_n, \alpha_n, u_n$.
The two fields also use the same 143-bit endoscalar for their $\beta$ folds.
Injectivity gives a sample space of size $2^{143}$ in each field; it does
not by itself prove the protocol's soundness reduction.

The following conservative local degree ledger uses $D=8192$, nested
registry domain size $K=64$, revdot group size $M=7$, number of groups
$N=12$, and $T=147$ nested PCS queries. Its entries bound the number of
roots charged to a challenge, conditional on the relevant discrepancy
being a nonzero polynomial fixed before that challenge is sampled.

| Challenge | Comparisons charged | Degree contribution |
| --- | --- | ---: |
| $w_n$ | Two child registry restrictions | $2(K-1)=126$ |
| $y_n$ | Constraint check and two registry restrictions | $3(D-1)=24573$ |
| $z_n$ | Gate check | $D-1=8191$ |
| $\mu_n$ | Inner revdot folds, clearing negative powers | $2N(M-1)=144$ |
| $\nu_n$ | Inner revdot folds | $N(M-1)=72$ |
| $\mu'_n$ | Outer revdot fold, clearing negative powers | $2(N-1)=22$ |
| $\nu'_n$ | Outer revdot fold | $N-1=11$ |
| $x_n$ | Two folded-polynomial checks and registry restriction | $3(D-1)=24573$ |
| $\alpha_n$ | Batching the $T$ opening claims | $T-1=146$ |
| $u_n$ | Quotient identity, clearing at most $T$ denominators | $D+T-1=8338$ |
| $\beta$ | Both point folds, with 99 and 113 terms | $98+112=210$ |

Counting the comparisons separately, rather than relying on the gist's
six-check shorthand, gives $66406/2^{143} \approx 2^{-126.98}$ for this
local ledger. In particular, the lower-degree challenges must not be
omitted, even though they do not change the rounded estimate of about
127 bits. The $u_n$ entry conservatively clears the quotient denominators;
it does not treat the rational identity as a degree-$D-1$ polynomial.

This is a conditional per-step accounting, not an end-to-end security
theorem. A full reduction must justify the choice of a first invalid
relation, the transcript timing, commitment and stage binding, and
propagation through recursion; account for the other protocol components;
and include an adversary's repeated Fiat–Shamir trials. These obligations
are outside the gadget formalization. The parameter counts must also be
recomputed if the registry, rank, or revdot grouping changes.

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
