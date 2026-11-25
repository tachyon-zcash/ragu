# Rung 14: Bindings of Claims to the Statement

**Problem.** A merge that is correct on its own terms proves nothing if its
inputs are about the wrong things. Splitting the work across circuits, stages,
two curves and two generations has created several places where a prover could
substitute one object for another. Each needs its own binding.

**Refinement.**

*Targets come from public values.* For each child, the parent's
[`preamble`](../construction/stage_contents.md#native-preamble) stage holds the
child's unified instance, its output header and its circuit identifier. The
parent's circuits compute the target $k(y)$ of every child claim from those
values.

The step circuit's claim is the fuse's own ([rung 3](rung_03.md)), and its
target is computed from the fuse's own values: its $\zeta$, which is $w$; the
points and values of the six openings that its step made
([rung 0](rung_00.md)); the
[bridge hash](../construction/stage_contents.md#bridge-hash); its two input
headers, which are the children's output headers in the `preamble` stage; and
its output header. The fuse exposes that output header, with its circuit
identifier, in the instance of one of its internal circuits. Its parent holds a
copy of both, the header as an input of the parent's own step, and computes the
target of that internal circuit's claim from the copy. Each header is thus
checked twice, by the fuse that produced it and by the fuse that consumes it.
This is how consecutive nodes of the tree are linked.

The six openings in the step circuit's target are the wires that the fuse's
`compute_v` circuit folds into the batch. The step's circuit therefore saw the
points and values that the fuse's opening batch proves.

*Internal circuits and step circuits cannot be exchanged.* Every native internal
circuit's instance ends in a zero where a step circuit's instance has its output
header's suffix. Suffixes of real headers are nonzero, so no instance satisfies
both forms. The nested registry holds internal circuits only and needs no such
marker.

*Recursion has exactly one base case.* Some fuse must proceed without valid
children. If a node could declare itself such a fuse, it could discard an
invalid history. One internal step, the
[bootstrap](../construction/base_case.md#bootstrap), has inputs of a reserved
`Dummy` header type and outputs the unit header `()`. The final comparison of
the fold is waived only when both children's headers carry the `Dummy` suffix.
An application step's circuit fixes its input suffixes as constants, none of
which is `Dummy`. The one internal step that witnesses a suffix,
rerandomization, constrains it away from `Dummy` and from zero. These are
properties of a step circuit's claim, though, and a fuse folds that claim
itself: where the comparison is waived, nothing shows that the step circuit was
satisfied, or which step it was. The `collapse` circuit therefore requires a
fuse that takes the base case to carry the bootstrap's circuit identifier and
the unit output header, and to open each of the two polynomials that its step
prepared ([rung 0](rung_00.md)) at $w$ to the value one. Those polynomials are
committed before $w$, so each is the constant one, which is what the bootstrap
prepares, except with probability at most its degree over $|\F_p|$. The claim of
`collapse` is folded one generation later, where the comparison is enforced. The
bootstrap proof
therefore attests to nothing beyond the unit header, which
[rung 0](rung_00.md) made valid by definition, and anyone can make one. A leaf
of the application's tree is an ordinary fuse, with every child claim enforced,
whose two children are the bootstrap proof; this is `seed`. On the nested side,
the base-case sign sits in the challenge stage and is bound to the headers by
the same native circuits that bind the challenges.

*A walk's inputs are bound individually.* The endpoint of a walk does not
determine its inputs. For a walk $\sum_{i=0}^{J} \beta^{J-i} C_i$ over points
$C_0, \ldots, C_J$, replacing $C_j$ by $C_j + \Delta$ and $C_0$ by
$C_0 - \beta^{-j} \Delta$ leaves the result unchanged. So every point entering a
walk is committed in a stage that the transcript absorbs before $u$ is drawn,
and the circuits compare the walked points with their sources.

For the walk that produces $P$, the nested `Collapse` circuit holds each walked
point equal to its copy in the bridge stages. It also enforces that the walked
points lie on the curve and that the walk's bits are bits, and the nested
`ComputeV` circuit ties those bits to $\beta_q$. For the walk that produces
$P_q$, the walked points sit in native stages whose commitments the bridges
carry, so there is no second copy to compare. The native `bind_endoscalar`
circuit enforces curve membership, ties the walk's bits to `pre_beta` and
exports the endpoint.

A parent's `bind_beta` circuit then holds the points that carry a child's own
commitments forward to what the child's circuits exported: its bridge
commitments, its challenge stage and the commitments of its nested accumulator.
The child's other commitments on the nested side are those of fresh traces. They
need only be fixed before the parent's $w$, and the claims the parent folds are
what constrain them.

*The circuits themselves are fixed by the setup.* The transcript never absorbs a
description of the registry. It cannot do so directly, because the registry
contains the hashing circuits, whose behavior would depend on the digest of
their own description. Ragu instead adds a term $\kappa \cdot (XY)^{4n-1}$ to
the registry polynomial, and so to the wiring polynomial at every point of its
domain. Each registry has its own
[**registry tag**](../construction/registry.md#tag) $\kappa$: a hash of the
registry's wiring polynomials, taken before the term is added, which the
registry derives when it is finalized. A change to a wiring polynomial changes
$\kappa$, unless the hash collides, and with it this coefficient of every wiring
polynomial. The tag's purpose is to keep whoever chooses the circuits from
adapting them to challenges that were already derived. As a constraint the term
reads $\kappa \, \v{c}_0 = 0$, in the position that [rung 1](rung_01.md)
reserved. Every satisfying trace already has $\v{c}_0 = 0$, and a stage
polynomial holds nothing on that wire, so the tag changes the polynomials and
rejects nothing that an honest prover commits. The hash relies on circuit code
that emits the same constraints every time it is synthesized, which nothing
enforces.

**Why it holds.** Two of these bindings are not deterministic: the tag, which is
a hash and is covered with the other [assumptions](assumptions.md), and the
opening at $w$ that holds a base-case fuse to the bootstrap's two polynomials.
The others are deterministic. Each is a constraint in a step circuit, whose
claim its own fuse folds, a constraint in an internal circuit, whose claim is
folded one generation later, a check the decider performs, or a rule that the
application's setup applies when it registers steps. A binding missing from this
list would be a flaw in the protocol, not an event of small probability.

**Still owed.** The root has no parent. Its own circuits have been checked by
nobody, and its accumulator is still three unpaid claims per side.
