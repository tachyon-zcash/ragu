# Rung 3: An Accumulator of Carried Claims

**Problem.** PCD requires the proof at a node to vouch for the node's whole
subtree. The classical construction makes each node's circuit verify the proofs
of its two children. Here that fails on cost: verifying a child means performing
the three jobs of [rung 2](rung_02.md), each linear in $4n$, inside a circuit of
size $n$. The circuit that verifies would be larger than the circuit it
verifies.

**Refinement.** A node does not perform the three jobs. It carries one pending
claim of each kind, called its
[**accumulator**](../construction/proof.md#accumulator):

$$
\bigl([A], [B], c\bigr), \qquad \bigl([m(W, x, y)], x, y\bigr), \qquad \bigl([p], u, v\bigr),
$$

together with the witness polynomials $A$, $B$, $m(W, x, y)$ and $p$. The middle
claim is the wiring claim, made precise in [rung 8](rung_08.md).

A **fuse** takes two children and runs one step. Each child brings its
accumulator and the fresh, unchecked claims for the internal circuits that its
own fuse ran. The fuse adds the claim for the step circuit that it has just
run, and merges all of these into one new accumulator. The node's circuits
verify only that the merge was carried out correctly on the short instances.
The long witnesses travel with the proof and never enter a circuit, which is
the "split" in split accumulation. A
[**decider**](../construction/decider.md) at the root performs the three jobs
once, on the final accumulator.

A proof therefore carries an accumulator and a
[**frontier**](../construction/proof.md#frontier): the traces of the internal
circuits its own fuse ran, which nothing has checked yet.

**Why it holds.** Each merge must have two properties. If every input claim is
true, the honest prover produces a true output claim. If any input claim is
false, then except with small probability over the merge's challenges the output
claim is false. Given the second property, a true accumulator at the root
implies by induction that every claim ever merged into it was true, and so that
every circuit whose claim was merged was satisfied. The claims not yet merged
are those of the root's frontier, which the decider checks itself.

The circuits that verify a merge, a fuse's **internal circuits**, are circuits
like any other. Their satisfaction is a new set of revdot claims. Their traces
contain the challenges of the merge that they verify, so they cannot be
committed before those challenges, and their claims join the *next* merge. The
step circuit is different. Its trace depends on none of the challenges that
test its claim, so it is committed before them, and its claim joins the merge
of its own fuse. The checks of the internal circuits consequently run one
generation behind:

| Product of a Fuse | Checked By |
| --- | --- |
| The merge of the children's claims and the step circuit's claim into the fuse's accumulator | The fuse's own internal circuits |
| The traces of the fuse's internal circuits | The parent's fuse, or the decider if the fuse is the root |

**Still owed.** A sound merge for each kind of claim (rungs [4](rung_04.md) to
[10](rung_10.md)); a merge verifier small enough to run inside the circuits
(rungs [11](rung_11.md) to [13](rung_13.md)); a guarantee that the merged claims
are about the right statement ([rung 14](rung_14.md)); and the root (rungs
[15](rung_15.md) and [16](rung_16.md)).
