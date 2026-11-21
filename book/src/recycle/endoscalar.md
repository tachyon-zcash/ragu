# Endoscalars

**This page is retained from an earlier version of the book and has not
been revised.** [Construction](../protocol/construction/index.md) describes
the current protocol.

## Hoisted digit products

The plain selector spends three gates per digit. Hoisting the bit products
$e_1 e_2$ and $e_1 e_2 s$ lets each selected coordinate be written as $r$
times a linear form in the bits and products, plus a linear form. Each
hoisted selector then needs two gates.

Every endoscaling step of a fuse scales by the same $\beta$. The walk stages
therefore carry these two products beside each digit's bits, sharing them
across walks. The hoisted gadget derives them in two gates per digit, and
the stage's contract owner (`bind_endoscalar` natively, `collapse` on the
nested side) re-establishes their relation to the Boolean bits.

A hoisted walk costs $9 n + 10 = 433$ gates, fitting $143$ bits into the
same steps that held $128$ bits at $455$ gates with radix 2. The eight
binder challenges also use $143$ bits, with the plain three-gate selector.

The hoisted lift still multiplies each unsigned digit by its sign. Its
$e_1 e_2$ and $e_1 e_2 s$ wires do not supply $s e_1$ or $s e_2$, so the
lift costs $n + 1 = 48$ gates including initialization. The nested
`EndoscalarStage` grows from 64 to 119 gates, and the nested `compute_v`
circuit grows from 1358 to 1397 gates. Hoisting saves work in the walk;
it does not make the lift linear in the stage wires.

Nested `collapse` grows from 1329 to 1493 gates: 94 product gates,
15 additional fresh Boolean gates, and 55 additional stage gates. The
native `bind_endoscalar` instead hoists the canonical extraction of
`pre_beta` and compares the staged bits and products to it. On the nested
side, `collapse` re-emits the stage gadget's contract, Booleanity and
products, while `compute_v` equates their lift with the challenge stage's
$\beta$. Lift injectivity is what makes
that equality determine the bits. Stage sharing, the parent challenge
commitment binding, and the root check must preserve these same wires.

`bind_beta` performs two plain endoscalings, one per child, and costs 1897
gates at 143 bits. It now ends at the preamble under its own final mask
instead of chaining through the `outer_error` stage, whose wires it never
read. Its claim contains `BindBeta`, `PointsBinding`, and `Preamble`; the
new `PreambleFinalStaged` mask bonds `BindBeta`, which is removed from the
`OuterErrorFinalStaged` bonding claim. Registration includes the new mask.
The internal registry therefore has 53 native and 46 nested entries,
including masks, with 25 native and 29 nested walk steps once the online
polynomials of the input and output proofs, the application stage and the
bridge-hash stage join the batch.

The constraint census uses wallet rank `R<13>`, a 201-element header,
and 6000 placeholder application circuits. In that fixture the largest
`bind_challenges` variant uses all 2048 gates; the binders load the
preamble, query and eval stages, and the preamble carries the step's own
output header and online openings beside the children's bridge hashes. The
header grew from 96 elements when each step began to fold its own
application claim: the preamble then stopped carrying the grandchildren's
headers. The census tests pin that count; extending the binder requires
rechecking its capacity.

The exceptional-case invariant is explicit in the integer model: every
accumulator has Eisenstein norm at least four, while every digit has norm
one or three. Hence $A-D$, $A+D$, $2A+D$, and $3A+D$ are nonzero integer
indices: an equality would force $k^2 N(A) = N(D)$ for $k \in \{1,2,3\}$.
The positive norms of these combinations are at most
$3 (5 \cdot 3^{47})^2$, below either Pasta group order. The unchecked
additions are justified by the
affine-walk proof: `WalkGroup` identifies
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
open endoscalar stage-binding contract
names the owners, consumers, parent and terminal checks, and the proof
obligations for that broader formalization.

## Challenge accounting

All eight nested challenges, in stage order, are 143-bit lifts:
$w_n, y_n, z_n, \mu_n, \mu'_n, x_n, \alpha_n, u_n$.
The two fields also use the same 143-bit endoscalar for their $\beta$ folds.
Injectivity gives a sample space of size $2^{143}$ in each field; it does
not by itself prove the protocol's soundness reduction.

The following conservative local degree ledger is derived from the
implementation's constants, which the `print_ledger_parameters` test in
`crates/ragu_pcd/src/recursion/tests.rs` prints: $D=8192$, nested registry
domain size $K=64$, revdot group size and group count $M=7$, $N=14$ on the
native side and $M=8$, $N=10$ on the nested side, $T=150$ nested PCS
queries (the 18 static openings, each child's 43 rx polynomials at
$x_n z_n$, and the registry restriction at each of the 46 nested internal
circuits' $\omega^j$), and point folds of 101 native and 115 nested terms.
One challenge set drives both fields' revdot folds, so each fold challenge
is charged for both sides. The entries bound the number of roots charged to
a challenge, conditional on the relevant discrepancy being a nonzero
polynomial fixed before that challenge is sampled.

For an $m$-claim revdot fold, $A$, $B$, and $K$ interpolate the claims at
$m$ nodes, whose monic vanishing polynomial is $Z$. The residual
$\operatorname{revdot}(A,B)-K-ZQ$ has degree at
most $2(m-1)$ and is nonzero at any false claim's node. The quotient $Q$
has $m-1$ coefficients and must be committed before the folding challenge.

| Challenge | Comparisons charged | Degree contribution |
| --- | --- | ---: |
| $w_n$ | Two child registry restrictions | $2(K-1)=126$ |
| $y_n$ | Constraint check and two registry restrictions | $3(D-1)=24573$ |
| $z_n$ | Gate check | $D-1=8191$ |
| $\mu_n$ | Inner revdot quotient folds on both sides | $2N(M-1)$ each: $168+140=308$ |
| $\mu'_n$ | Outer revdot quotient folds on both sides | $2(N-1)$ each: $26+18=44$ |
| $x_n$ | Two folded-polynomial checks and registry restriction | $3(D-1)=24573$ |
| $\alpha_n$ | Batching the $T$ opening claims | $T-1=149$ |
| $u_n$ | Quotient identity, clearing at most $T$ denominators | $D+T-1=8341$ |
| $\beta$ | Both point folds, with 101 and 115 terms | $100+114=214$ |

Counting the comparisons separately, rather than relying on the gist's
six-check shorthand, gives $66519/2^{143} \approx 2^{-126.98}$ for this
local ledger. In particular, the lower-degree challenges must not be
omitted, even though they do not change the rounded estimate of about
127 bits. The $u_n$ entry conservatively clears the quotient denominators;
it does not treat the rational identity as a degree-$D-1$ polynomial.

The native $w$ also serves as the application challenge $\zeta$ (see the
[online polynomial oracle](../protocol/poly-oracle.md)): the step's online
slots are opened at it, and the step's circuit checks its polynomial
identities there. Those checks are native, over the full field rather than
the 143-bit lifts, so they do not enter this ledger; each identity of degree
below $D$ adds at most $D-1$ roots to the native $w$ against a sample space of
about $2^{254}$. Every value such a check reads is committed in the `preamble`
bridge that $w$ absorbs, which is what lets one squeeze serve both the
registry restrictions and the application's identities.

This is a conditional per-step accounting, not an end-to-end security
theorem. A full reduction must justify the choice of a first invalid
relation, the transcript timing, commitment and stage binding, and
propagation through recursion; account for the other protocol components;
and include an adversary's repeated Fiat–Shamir trials. These obligations
are outside the gadget formalization. The parameter counts must also be
recomputed if the registry, rank, or revdot grouping changes.

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
$\frac{M}{7} / \frac{M}{8} = \mathbf{1.14x}$.

In summary, endoscalars provide a bridge for moving scalar values between
circuits in a curve cycle, with three core operations (extract, lift, and
endoscale) that enable challenge consistency across the cycle. The convergence
analysis shows that the reflexive cost of endoscaling circuits is modest:
approximately 1.33x overhead for $k=4$ and 1.14x for $k=8$.
