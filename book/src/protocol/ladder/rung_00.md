# Rung 0: A Verifier of the Whole History

**Problem.** Before making verification cheaper, we need a definition of what is
being verified.

An application registers a set of [**steps**](../construction/setup.md#steps).
Step $i$ is a relation

$$
R_i(\text{hdr}_L, \text{hdr}_R, \text{hdr}_O;\, \mathsf{wit})
$$

over two input [**headers**](../construction/setup.md#headers), an output header
and a private witness. A header is a short encoding of the application's state
at one point of the computation, ending in a suffix that identifies the header's
type. One header is distinguished: the unit header `()`, which carries no data.

Validity is defined inductively. The unit header is *valid* by definition, with
no step behind it. If $\text{hdr}_L$ and $\text{hdr}_R$ are valid and
$R_i(\text{hdr}_L, \text{hdr}_R, \text{hdr}_O;\, \mathsf{wit})$ holds for some
registered step $i$ and some witness, then $\text{hdr}_O$ is valid. No other
header is. A valid header other than `()` is therefore the root output of a
finite binary tree of step applications in which each input is either a child's
output or `()`. A step whose two inputs are both `()` starts a new branch.

The base rule matters later. [Rung 14](rung_14.md) builds a proof for `()` that
anyone can produce, and a verifier that accepts it has accepted a valid header.

**Refinement.** None yet. The reference verifier receives the whole tree,
including every witness, and re-executes the step at every node.

**Why it holds.** By inspection: the verifier accepts a header exactly when it
has seen a valid tree for it.

**Still owed.** Nothing is deferred, and that is the difficulty. The proof is
the entire history, verification repeats all of the computation, and every
witness is exposed. The remaining rungs keep the same notion of validity. The
goal is that a verifier who accepts a header can conclude that a valid tree
exists for it, except with small probability and under stated assumptions, while
doing work that does not depend on the size of the tree.

In the code, steps and headers are the `Step` and `Header` traits. One node of
the tree is one call to `fuse`.

A `Step` can do more than the relation above describes. Every proof carries two
polynomials prepared by the step of the fuse that produced it. A step's circuit
may open these polynomials of the two child proofs and of its own proof, six in
all, each at a point the circuit chooses. It also receives a challenge $\zeta$
that is drawn after the six commitments are fixed. The points and the opened
values reach the circuit as public inputs. The six openings join the batch of
[rung 9](rung_09.md), and [rung 14](rung_14.md) holds the circuit's inputs to
the values that batch proves. A step can also stage values of its own: the fuse
commits them, in an
[application stage](../construction/setup.md#application-stage), before $\zeta$
is drawn, and the circuit reads them as wires.
