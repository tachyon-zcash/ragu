# Rung 15: The Decider at the Root

**Problem.** Deferral has to end. Someone must perform the three jobs of
[rung 2](rung_02.md) on the final accumulator, and must do for the root what a
parent would have done.

**Refinement.** The [decider](../construction/decider.md#decider-checks)
receives the root's full proof, polynomials included, and the header it is asked
to accept. It trusts nothing in the proof that it can recompute:

- It recomputes the commitment of every polynomial the proof carries, including
  $P$ and $P_q$, and compares it with the commitment the proof states. The
  comparisons on each curve are batched under a random scalar of the decider's
  own.
- It replays the transcript over the bridge commitments and compares the
  challenges, rejecting any that is out of range for its lift.
- It draws $\tau_y$ and $\tau_z$ from its own randomness, after it holds the
  proof and the header, and checks every revdot claim of the root's internal
  circuits and masks, on both sides. The targets $k(\tau_y)$ are computed from
  the given header and the proof's public values. The root's step circuit has no
  claim here: the root folded it, and the given header enters through the
  internal circuit that exposes the root's output header
  ([rung 14](rung_14.md)).
- It pays the revdot and opening claims by computing $c = \revdot{A}{B}$ and
  $v = p(u)$ from the polynomials. These values enter the targets of the root's
  internal circuits, which is how the folds verified in those circuits are held
  to the true values.
- It pays the wiring claim by evaluating the registry itself and comparing with
  the stored restriction at a fresh point $\tau_w$.
- It checks the registry values that the root claimed in its `query` stage, and
  the evaluations of its own $A$, $B$ and registry restrictions that it claimed
  in its `eval` stage, against the registry and the polynomials. The proof does
  not carry the intermediate restrictions $m(w, x^{(i)}, Y)$ and $m(w, X, y)$.
  It carries their claimed evaluations, and the decider computes from the
  registry what those must be.
- It compares the commitments to $A_q$, $B_q$ and the nested restriction that
  the root's native stages hold for the walk with the commitments of the nested
  polynomials it read. In recursion this comparison is split between the fuse's
  own `bind_endoscalar` circuit and the parent's `bind_beta` circuit.
- It recomputes the parts of the root's stages that are functions of other proof
  data, such as the challenge stage that a parent would have bound.

**Why it holds.** The decider establishes that the root's circuits are satisfied
and that the root's accumulator is true. The root's circuits establish that the
accumulator was merged correctly from the children's claims and the claim of
the root's step circuit. By the property
required in [rung 3](rung_03.md), those claims are true except with the
accumulated probability of the merge's challenges landing on a root, and the
argument repeats down the tree.

The decider's work is linear in $4n$ and in the size of the registry. It does
not depend on the size of the tree.

**Still owed.** The proof the decider reads holds about a hundred polynomials of
$4n$ coefficients each. It is suitable for fusing further and too large to send
to a third party.

In the code this is `verify_uncompressed`, which is available as a test oracle.
Production verification goes through the next rung.
