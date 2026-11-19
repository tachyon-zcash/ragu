# Split-Accumulation Schemes

## IVC Syntax

Imagine proving a blockchain's entire history is valid without replaying every
transaction. Incremental verifiable computation (IVC) and its generalization
proof-carrying data (PCD) enable this: each new proof $\pi_{i+1}$ attests to
the entire computational history, not just the latest step.

The challenge is recursion. Building these proofs requires proving that the
previous proof was valid. If verification is expensive, then proving you
verified becomes prohibitively expensive: a bootstrapping problem that makes
efficient recursion nearly impossible with traditional proof systems.

Accumulation schemes solve this by deferring expensive checks. Instead of fully
verifying each proof during recursion, we partially verify it and accumulate
the remaining work for later batch verification. The per-step overhead becomes
sublinear while the final decider amortizes the accumulated checks across all
steps, performing the deferred linear-time work only once.

Consider the IVC syntax formalized in
[[BCMS20]](https://eprint.iacr.org/2020/499) below[^split-accum-links]:

[^split-accum-links]: The diagram for accumulation schemes is heavily based on
talks by [Benedikt Bünz](https://youtu.be/CY84j0_E7KA) and
[Pratyush Mishra](https://youtu.be/7MtzoVM6e6w). The diagram presents the IVC
chain from the _prover's perspective_ who applies the step function once, runs
the accumulation prover to folds both the public instances and witnesses, then
with finally produce a NARK proof of honest stepping and folding.


<P align="center">
  <img src="../../../assets/ivc_syntax.svg" alt="ivc_syntax" />
</p>

Picture a step function being a blockchain VM. At each step $i$,
given current state $z_i$ (public instance), new transactions $w_i$
(auxiliary witness/advice), and proof $\pi_i$ attesting that $z_i$
was honestly derived from genesis, the IVC prover computes
$z_{i+1}$ and produces $\pi_{i+1}$.
This construction has two key properties:

1. **Single proof for entire history**: $\pi_{i+1}$ attests to the entire
   computational history, so the IVC verifier only needs to verify this single
   proof to be convinced of $z_{i+1}$'s validity without enumerating through
   all preceding steps and proofs.

2. **Incremental computation**: Verifying each step as we go avoids constructing
   a giant monolithic proof for the entire computation at once, enabling
   long-running computations.

The simplest IVC construction uses recursive SNARKs. After applying step
function $F$, the SNARK prover proves the relation $\Rel(\inst := (z_{i+1}),
\wit := (z_i, \pi_i))$ such that (1) $F(z_i) = z_{i+1}$; (2)
$\mathsf{SNARK.V}(vk, z_i, \pi_i) = 1$. The prover encodes the SNARK verifier
as part of the circuit, proving both correct state transition and validity of
the previous proof.

One bottleneck of full recursion is that SNARK verifier logic can be expensive.
For example, our Bulletproof verifier is linear, leading to an IVC prover
circuit that's prohibitively expensive to recurse. [Halo]
introduced a technique, later formalized by
[[BCMS20]](https://eprint.iacr.org/2020/499) as _accumulation schemes_, that
replaces full-blown SNARK verification with a sublinear accumulator verifier
who only _partially verifies_ $\pi_i$ and accumulates statements about the
remaining expensive operations into an _accumulator_ $\acc_i$ which will be
batch-checked by a _decider_ down the IVC/PCD tree. Now, the IVC verifier, on
top of verifying the IVC proof $\pi_{i+1}$, will further invoke
$\mathsf{Acc.Decide}(\acc_{i+1})$ subroutine which could contain linear-time
operations, but this is fine since the cost is amortized across all prior steps
and the per-step recursion overhead is massively reduced to sublinear.

Ragu implements **split accumulation**, a variant formalized in
[[BCLMS20]](https://eprint.iacr.org/2020/1618), in which the verifier
$\mathsf{Acc.V}$ checks correct accumulation of _only public
instances_, allowing a potentially non-succinct witness size (usually
linear), thus requiring only a NARK rather than a SNARK. Intuitively,
the accumulation prover
partially verifies a new NARK proof $\pi_i$, then folds the remaining unverified
statements with the previously accumulated statement $\acc_i$ into a new
$\acc_{i+1}$ through random linear combination. To enable verification of
correct accumulation by $\mathsf{Acc.V}$, the accumulation prover also includes
all necessary cross terms in $\pf_{i+1}$. Note that accumulation proof
$\pf_{i+1}$ is an internal value consumed by the NARK prover as a subroutine of
the outer IVC prover, not an output of the IVC prover.

The IVC proof becomes $(\acc_i, \pi_i)$, and the relation becomes
$\Rel(\inst := (z_{i+1}, \acc_{i+1}), \wit := (z_i, \pi_i, \acc_i, \pf_{i+1}))$
such that (1) $F(z_i) = z_{i+1}$; (2) $\mathsf{Acc.V}(\acc_i.\inst,
\pi_i.\inst, \pf_{i+1}, \acc_{i+1}.\inst) = 1$. The first ensures the step
function is computed correctly, the second ensures accumulators are updated
correctly.

```admonish note title="Split-accumulation = Folding"
Later, in [Nova [KS21]](https://eprint.iacr.org/2021/370), a conceptually cleaner
_folding scheme_ is introduced to describe the technique of maximally delaying
NARK verification work and only "fold" the committed public instances of a
running-instance (i.e. accumulator) and the NARK for the last step (i.e.
$\pi_i$). For all practical purposes, these two formalizations are equivalent.
In fact, Ragu also does "pure instance folding" and we subsequently use
"accumulation" and "folding" interchangeably.
```

## IVC on a Cycle of Curves

Accumulation requires folding commitments through random linear combinations (a
group operation). As explained [earlier](../../prelim/nested_commitment.md),
constraining non-native group operations is prohibitively expensive. The
solution: implement IVC over a 2-cycle of elliptic curves, where each curve's
group operations are native to the other curve's scalar field.

This creates a ping-pong pattern. We alternate between two circuits ($CS^{(1)}$
over field $\F_p$ and $CS^{(2)}$ over field $\F_q$) where commitments in one
circuit's group $\G^{(1)}$ are accumulated in the other circuit, and vice versa.
The application state and accumulator become tuples:
$z_i = (z_i^{(1)}, z_i^{(2)})$ and
$\acc_i = (\acc_i^{(1)}, \acc_i^{(2)})$. Furthermore, there is the
NARK instance from the last step
$\inst_i=(\inst_i^{(1)},\inst_i^{(2)})$.

<p align="center">
  <img src="../../../assets/ivc_on_cycle.svg" alt="ivc_on_cycle_of_curves" />
</p>

**Base Case**: $i=0$, $z_0$ set to the application init state,
accumulators are set to a trivial value $\acc_0:=\acc_\bot$, the previous step
instance $\inst_0:=\inst_\bot$ is set to a trivially satisfying instance
(similarly for its respective witness maintained by the prover).

Each future IVC step now consists of two halves working in tandem:

**Primary circuits** $CS^{(1)}$:
- **App Circuit**: Advances application state $z_i^{(1)} \to z_{i+1}^{(1)}$,
  producing new NARK public instance $\inst_{app,i+1}^{(1)}$
- **Fuse Circuit**: Folds (relevant part of) the previous step's instance into
  the accumulator
  - **base case**: if $i=0$, set
    $\acc'_{i+1}=\acc_0=\acc_\bot$ and skip the rest
  - folds scalars in the last step instances $\inst_{app,i}^{(1)}$ and
    $\inst_{fuse,i}^{(1)}$ into accumulator $\acc_i^{(1)}$ 
  - folds groups in the last step instances $\inst_{app,i}^{(2)}$ and
    $\inst_{fuse,i}^{(2)}$ into accumulator $\acc_i^{(2)}$
  - enforces
    [deferred operations](../../prelim/nested_commitment.md#deferred-operations)
    captured in $\inst_i^{(2)}$ from $CS^{(2)}$ of the last step (whose group
    operations are native here)
  - produces a NARK instance $\inst_{i+1}^{(1)}$ to be folded in _the next step_

**Secondary circuits** $CS^{(2)}$:
- **App Circuit**: Advances application state $z_i^{(2)} \to z_{i+1}^{(2)}$,
  producing new NARK public instance $\inst_{app,i+1}^{(2)}$
- **Fuse Circuit**: Folds (relevant part of) the current step's instance into
  the accumulator
  - **base case**: if $i=0$, set $\acc_{i+1}=\acc'_{i+1}$ without any folding
    and skip the rest
  - folds scalars in the last step instances $\inst_{app,i}^{(2)}$
    and $\inst_{fuse,i}^{(2)}$ into accumulator $\acc_i^{(2)}$
    (further update it)
  - folds groups in the last step instances $\inst_{app,i}^{(1)}$ and
    $\inst_{fuse,i}^{(1)}$ into accumulator $\acc_i^{(1)}$ (further update it)
  - enforces deferred operations captured in $\inst_{i}^{(1)}$ from $CS^{(1)}$
    of _the last step_
  - produces a NARK instance $\inst_{i+1}^{(2)}$ to be folded in _the next step_

Both circuits run accumulation verifiers $\mathsf{Acc.V}$ for the [3
subprotocols inside the NARK](../nark.md#nark) to verifiably update their
respective accumulators. The result is efficient recursion: each circuit only
performs native arithmetic, while the non-native work is deferred to its
counterpart on the cycle.[^ivc-curve-diagram]

[^ivc-curve-diagram]: The IVC on a curve cycle diagram is inspired by the
[[NBS23] paper](https://eprint.iacr.org/2023/969) and [Wilson Nguyen's
talk](https://youtu.be/l-F5ykQQ4qw). The diagram presents the IVC computation
chain from the _verifier's perspective_ and omits auxiliary advice and witness
parts of the NARK instance and accumulator managed by the prover.

<a id="split-up-folding-work"></a>

```admonish info title="Split-up of the folding work"

- The NARK instance for the application circuit in step $i$ is **folded in
  step $i$ itself**: its trace depends on none of the step's challenges, so it
  is committed via [nested commitment](../../prelim/nested_commitment.md)
  before the folding challenges are drawn, and the fuse circuit accumulates it
  in the same step.
- The NARK instances for the fuse circuits in step $i$ are **only folded in
  step $i+1$**: their traces contain step $i$'s own challenges, so they cannot
  be committed before them.
- The accumulator for one curve contains both group and field elements. E.g.,
  $\acc^{(1)}=(S,\bar{A},\bar{B},c,\bar{P},u,v)$ where
  $S,\bar{A},\bar{B},P\in\G^{(1)}$ and $c,u,v\in\F^{(1)}\equiv\F_p$.
  To avoid all non-native arithmetic, scalars are folded natively while
  commitments are folded on the other circuit. E.g. $c,v\in\F_p$ are folded in
  $CS_{fuse}^{(1)}$ (of the next step), and $\bar{A},\bar{B},\bar{P}$ are
  folded in $CS_{fuse}^{(2)}$ (of the next step); vice versa for $\acc^{(2)}$.
```

## 2-arity PCD

IVC proves linear chains of computation. But what if your computation is a tree?
Consider a distributed system where multiple branches of computation fuse: each
node needs to verify that both its children's states are valid before producing
its own output.

This is where proof-carrying data (PCD) generalizes IVC. Instead of a single
parent, each step takes inputs from two branches: data and proofs from both left
and right. The step function fuses them: $F_i(z_{i,L}, z_{i,R}) = z_{i+1}$,
and the accumulation verifiers fold both parent accumulators $\set{\acc_{i,L},
\acc_{i,R}}$ into a single $\acc_{i+1}$. This natural extension gives us
**2-arity PCD**, supporting trees of computational traces:

<p align="center">
  <img src="../../../assets/pcd_syntax.svg" alt="pcd_syntax" />
</p>

Two implementation details carry over from IVC on cycles:

1. **Cycling curves**: Each side's data and accumulator contains a
   pair (one per field) due to the ping-pong pattern
   [explained earlier](#ivc-on-a-cycle-of-curves).

2. **Init state tracking**: Unlike IVC's single $z_0$, PCD must track all
   initial states from the tree's leaves. We maintain a Merkle root of init
   states $z_0^{(1)} \in \F_p$ (and similarly $z_0^{(2)} \in \F_q$), updated
   efficiently in-circuit when branches fuse. This ensures the final proof
   attests to a valid tree rooted at a specific set of initial states.

Zooming into the first half of a PCD step (the second half mirrors this
symmetrically):

<p align="center">
  <img src="../../../assets/pcd_details.svg" alt="pcd_details" />
</p>

The primary circuit now:
- Runs the binary step function:
  $F_i(z_{i,L}^{(1)}, z_{i,R}^{(1)}) = z_{i+1}^{(1)}$
- Folds both left and right parent accumulators $\acc_{i,L}, \acc_{i,R}$ and
  $\F_p$-native parts of both prior step NARK instances
  $\inst_{i,L},\inst_{i,R}$ into $\acc'_{i+1}$
- Updates the init state root with left and right roots
- Produces instance $\inst_{i+1}^{(1)}$ for the secondary circuit

The secondary circuit performs the symmetric operations for the
$(2)$ components.

This establishes the general syntax for all split-accumulation schemes in Ragu:

- **Accumulation Prover**:
  $\mathsf{Acc.P}(\set{\pi_i}, \set{\acc_i}, \aux_i) \to (\acc_{i+1}, \pf_{i+1})$
- **Accumulation Verifier**:
  $\mathsf{Acc.V}(\set{\pi_i.\inst}, \set{\acc_i.\inst}, \acc_{i+1}.\inst, \pf_{i+1}) \to \{0,1\}$

where $\set{\acc_i}$ denotes the set of parent accumulators being
folded; and $\set{\pi_i}$ denotes the relevant set of NARK instances
from the previous steps.
