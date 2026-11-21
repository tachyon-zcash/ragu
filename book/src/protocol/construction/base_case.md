# Base Case {#base-case}

Every fuse folds the claims of two children, so the recursion needs proofs to
start from. The implementation synthesizes a **dummy proof** whose claims do not
hold, and fuses two of them once. The circuits of that fuse waive one equality
on each side. The result is the **bootstrap proof**, which verifies and is used
as both children of every leaf.

## Predicate {#predicate}

A fuse is a **base case** when the output headers of both children, as its
`preamble` stage holds them, are `Dummy` headers, whose suffix is $2$. The
native [predicate](internal_circuits.md) $\text{base}$ is read by `collapse` and
`bind_challenges[3]`, and the nested predicate $\text{base}_q$ by `Collapse`.

The prover sets $\sigma = +1$ when both headers end in $2$ and $\sigma = -1$
otherwise. No nested circuit constrains $\sigma$. The native
`bind_challenges[3]` places $\pm \Gamma_8$, the generator of the sign's
position, in `nested_challenges_partial` according to $\text{base}$, and the
[binding chain](stage_contents.md#challenge-stage) of the challenge stage
carries that sign to the polynomial that the nested claims are about.

## Waived Equalities {#waived}

The base case waives two equalities, one on each side: $c = c^\ast$ in the
native [`collapse`](internal_circuits.md#native-collapse), and $c_q = c_q^\ast$
in the nested [`Collapse`](internal_circuits.md#nested-collapse).

Everything else stays enforced: the transcript, the targets, the first-layer
fold relations for every group, both batch formulas, both walks, every binding
and every mask. A base-case fuse therefore proves nothing about the claims of
its native fold: its children's, and that of its own step circuit, which is
[one of them](claims.md#native-claims). When those claims are false, the two
equalities above are the only fold relations that
[can fail](claims.md#fold-identity).

## Dummy Proof {#dummy-proof}

The dummy proof is deterministic. Let $\mathbf{1}$ denote the polynomial with
$\v{a}_0 = \v{b}_0 = \v{c}_0 = \v{d}_0 = 1$ and all other wires zero, over
either field, and let $1_q = \text{lift}_q(\text{endo}(1))$, the nested
counterpart of a challenge equal to one.

| Object | Value |
|---|---|
| challenges $w, \dots, u$, $\text{pre\_beta}$ | all $1$ |
| `circuit_id` | $0$ |
| `bridge_alpha` | $1$ |
| $A$, $B$, $A_q$, $B_q$ | $\mathbf{1}$ |
| $m(W, x, y)$ | $m(W, 1, 1)$, the true restriction |
| $m_q(W, x_q, y_q)$ | $m_q(W, 1_q, 1_q)$, the true restriction |
| $o_0$, $o_1$ | the padding polynomial |
| the polynomials of the ten native internal circuits other than the endoscaling steps, and the stages `Preamble`, `InnerError`, `OuterError`, `Query` | $\mathbf{1}$ |
| `Eval` stage | a true stage with $\v{a}_0 = 1$: evaluations zero, and the partial sums of the challenge stage commitment |
| the five native points input stages, `PointsWalk` and the $27$ native `EndoscalingStep` polynomials | a true native walk over placeholder points |
| $p_q$, $P_q$ | the Horner combination of the polynomials behind those placeholders, and the walk's output |
| `ChallengeStage` | $\v{a}_0 = 0$, every lift $1_q$, $\sigma = +1$, $\beta_q = 1_q$ |
| nested `Collapse`, `ComputeV` | $\mathbf{1}$ |
| `BridgeHash` | the stage of $O_1$ with $\v{a}_0 = 0$ |
| the other eight bridge stages | true stages with $\v{a}_0 = 1$ over the commitments above, with every quotient coefficient, target, collapsed value, claimed value and evaluation zero |
| `EndoscalarStage`, `PointsStage` and the $31$ nested `EndoscalingStep` polynomials | a true nested walk over placeholder points |
| $p$, $P$ | the Horner combination of the polynomials behind those placeholders, and the walk's output |

The placeholder points of each walk are commitments of polynomials that the
dummy holds: $[\mathbf{1}]$ in every position, with two exceptions. The three
positions of `registry_xy`, the children's and the proof's own, hold the
commitment of the dummy's own restriction. In the nested walk, the six online
slots hold the padding commitments $O_0$ and $O_1$. The dummy has no step
circuit and no randomizers, and the positions of a step circuit's trace and of
a fuse's randomizers hold $[\mathbf{1}]$ like the rest.

The dummy's circuit claims are false,[^node] but a parent's openings of the
dummy hold: $p$ and $p_q$ are the polynomials behind $P$ and $P_q$, and the two
restrictions are those of the registries.

[^node]: The dummy's native fold challenges equal one, which is an interpolation
    node of the fold. This does not matter, because the dummy's claims are never
    relied on.

The dummy would not pass the [decider](decider.md) and is never given to it.

## Bootstrap {#bootstrap}

Finalizing an application runs

$$\pi_{\text{boot}} = \text{fuse}(\texttt{Bootstrap}, (\pi_{\text{dummy}}, \texttt{Dummy}), (\pi_{\text{dummy}}, \texttt{Dummy}))$$

once, with a fixed random seed. `Bootstrap` is an internal step at native
registry index $56$. Its input headers are both `Dummy`, its output header is
the unit header, and it has no witness and opens no online slot, so each of its
output slots is opened at $\zeta$ and constrained to equal one.

The [fuse procedure](fuse.md#procedure) has no branch for the base case. Both
headers encode to $(0, \dots, 0, 2)$, so the prover sets $\sigma = +1$, both
predicates hold in circuit, and the two waived equalities are not enforced.

The decider accepts the bootstrap proof, which certifies nothing.

A leaf of the proof tree is made by [`seed`](ragu_pcd::Application::seed), which
fuses two copies of the bootstrap proof through a step whose two input headers
are the unit header. That fuse is ordinary: the unit header has suffix $1$, the
predicates are false, and the bootstrap proof's claims are enforced.

An application may be given a stored bootstrap proof instead of building one.
The only checks on that proof are that it is well formed and that it carries
`Bootstrap`'s `circuit_id`. An invalid one cannot make anything verify. Every
`seed` enforces its claims, and those claims [hold](#confinement) a proof with
`Bootstrap`'s index to the unit header and padding output slots.

## Confinement {#confinement}

A fuse outside the base case has every claim of its fold enforced, the claim of
its own step circuit included. That claim keeps a registered step away from the
base case, by the following mechanisms.

1. Registration rejects, at compile time, an application step with a `Dummy`
   input header, and likewise every internal step other than `Bootstrap`.
2. Only the unit header may use a suffix below $3$, application suffixes are
   offset by $3$, and the `Dummy` type is private to the crate.
3. For a step whose headers are encoded as gadgets, the suffix of each input
   header is a constant of the step circuit.
4. The one internal step whose input suffix is a witness wire constrains that
   wire to differ from $2$ and from $0$.
5. The predicate and $k_{\text{app}}(y)$ read the same header wires of the
   `preamble` stage, so the headers that the predicate saw are the input headers
   in the step circuit's public output.

These do not confine the base case by themselves. The header wires are the
prover's witness, and the step circuit's claim is folded into $c$, the value
that the base case leaves free. A prover could give any fuse two `Dummy`
headers, take the base case, and export an output header and an index of its
choosing.

`collapse` therefore [pins](internal_circuits.md#native-collapse) a fuse that
takes the base case: its index is that of `Bootstrap`, its output header is the
unit header, and each of its output slots is opened at $\zeta = w$ to the value
one. The claim of `collapse` is not among those that the fuse folds. A parent
or the decider enforces it, so the pin holds whatever $c$ the fuse states.

The pin on the slots repeats, where it is enforced, what the step circuit of
`Bootstrap` requires of its output slots. $O_0$ and $O_1$ are absorbed before
$w$, and `compute_v`, whose claim is enforced like that of `collapse`, proves
the two openings over the same wires. Each output polynomial thus takes the
value one at a point drawn after it was committed, and is the padding
polynomial except with probability at most its degree over $|\F_p|$.

A proof that took the base case is therefore a bootstrap proof with the unit
header and padding slots, and certifies nothing. In the other direction, a
proof with `Bootstrap`'s index that did not take the base case had the claim of
its step circuit enforced, and that circuit fixes both input suffixes to
`Dummy`. The index alone thus tells whether a proof took the base case, and the
[decider](decider.md) reads the sign $\sigma$ from it.

Two more mechanisms keep the two sides and the two kinds of circuit apart.

6. The nested verdict is the sign that the native binding circuits derive from
   the same header wires, not a choice of the nested prover.
7. Native internal circuits end their public output in suffix $0$, which no
   header carries, so their claims cannot take the place of a step's.
