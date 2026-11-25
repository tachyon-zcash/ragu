# Rung 16: Compression of the Decider's Checks

**Problem.** Produce a short proof that the decider would accept. The decider
read polynomials and drew its own challenges. A short proof can rely on neither:
the polynomials are too long to send, and its challenges must come from a hash.

**Refinement.** A [compressed proof](../recursion/compression.md) holds an
**instance** and, for each curve, the prover's messages in three reductions. The
instance is what the decider used other than polynomials and the fuse's
challenges, which the verifier rederives: the root's circuit identifier, every
commitment, and the scalars the decider computed or read
from polynomials, such as $c$, $v$ and each child's $x$ and $y$. The verifier
works outside any circuit and is free to do group arithmetic.

1. *Replay.* The verifier recomputes the fuse's challenges from the bridge
   commitments, under the tag `ragu-pcd-v1`, and rejects if any of them is out
   of range for its lift. It recomputes the two stage commitments that the
   decider derived from other proof data and compares them with the instance.
2. *Bind the statement.* A second transcript, under the tag `ragu-ipa-v1`,
   absorbs the complete instance and then the output header that the verifier
   was asked to accept. Every challenge of the compression is squeezed after
   that, beginning with $\tau_w$, $\tau_y$ and $\tau_z$ for each curve.
3. *Revdot claims to openings.* The decider's revdot claims are joined by claims
   that pin individual wires of the committed stages to the values the instance
   and the registry say they hold. All of them are folded to three claims per
   curve. Those are reduced to openings: the prover commits to the two halves of
   the combined product polynomial $\sum_i \rho^i a_i(X) b_i(X)$, the lower one
   reversed, so that its constant term is the product's middle coefficient,
   which is the claimed revdot value. The verifier checks the product at a
   random point and opens that half at zero.
4. *Openings to one opening.* All openings on a curve, including the registry
   restriction at $\tau_w$ and the accumulator's $p(u) = v$, are batched as in
   rungs [9](rung_09.md) and [10](rung_10.md).
5. *The opening.* One inner product argument per curve proves the batched
   opening.

The fold in item 3 is not the quotient fold of [rung 5](rung_05.md). It is the
one-round merge that [rung 4](rung_04.md) set aside, applied in two layers as in
[rung 6](rung_06.md), with two challenges per layer and every cross term of
every group. A circuit could not afford those cross terms. Here the prover
commits to them as the coefficients of one polynomial per layer, their weighted
sum becomes one more revdot claim against a public polynomial of weights, and
the verifier never reads them.

The verifier's group arithmetic is dominated by one multiscalar multiplication
of size $4n$ on each curve. Like the decider, it also evaluates the registry
polynomials at the points the claims refer to. In the standard profile a
compressed proof is terminal: it can be verified, and no step accepts it as a
child. An application of the unaudited aggregator profile can continue from
one. Its
[decompression](../recursion/decompression.md) checks this verifier's equations
in circuits, with a compressed proof of a standard application as the witness,
and produces a proof that a fuse accepts as a child.

**Why it holds.** Item 2 restores the order of commitment and challenge for the
statement itself. The decider drew $\tau_y$ after it was handed the header. Here
$\tau_y$ is a hash output, and anything the hash did not absorb can be chosen
after $\tau_y$ is known. Suppose the output header were left out. The target of
the root's claim that exposes its output header is a Horner sum in $\tau_y$
over the header's elements, so a prover holding an accepting proof could add
$\delta$ to one data element and $-\tau_y \delta$ to the next. The two changes
cancel in $k(\tau_y)$, every check passes unchanged, and the verifier accepts
the same proof for a header it was not made for. The prover does not get to
pick that header freely, but the statement is no longer fixed before the
challenge that tests it. Absorbing the instance and the header first makes
every target a function of data fixed before its challenge.

The reductions are earlier arguments in a new setting. The fold is
[rung 4](rung_04.md)'s: with the cross terms committed before the challenges, a
false claim leaves a nonzero polynomial in those challenges. The product check
is a polynomial identity tested at a random point, as in [rung 7](rung_07.md).
The batch is rungs [9](rung_09.md) and [10](rung_10.md), and the verifier
rejects when its $u$ lands on an evaluation point. The inner product argument is
where the opening job of [rung 2](rung_02.md) is finally done.

Every challenge of the compression is a lift, as the nested challenges of a
fuse are: the low 143 bits of a transcript output, lifted into the scalar field
of the curve that the challenge is used on. On either curve it ranges over
$2^{143}$ values, and the verifier rejects a proof if a transcript output is
$2^{254}$ or more. The verifier of this rung has no need of lifts. They are
there for decompression, whose circuits multiply curve points by these
challenges as the walks of [rung 11](rung_11.md) do. The fuse's own challenges,
which the verifier replays, keep the supports of that rung.

**Still owed.** Nothing. This is the acceptance procedure: `compress` and
`verify_compressed`.
