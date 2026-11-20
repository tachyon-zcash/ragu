# Rung 11: A Second Curve and a Second Accumulator

**Problem.** Circuits over $\F_p$ commit to their polynomials on a curve whose
scalar field is $\F_p$. That curve's points have coordinates in a different
field, $\F_q$. Computing $P$ is arithmetic on those coordinates, and an $\F_p$
circuit can only emulate $\F_q$ arithmetic at great cost.

**Refinement.** Use the [Pasta cycle](../construction/cycle.md#fields), in which
each curve's coordinate field is the other's scalar field, and give each field's
circuits the group arithmetic that is native to them.

| Side | Field of the Polynomials | Commitment Curve | Field of the Coordinates |
| --- | --- | --- | --- |
| Native | $\F_p$ | $\E_q$, which is Vesta | $\F_q$ |
| Nested | $\F_q$ | $\E_p$, which is Pallas | $\F_p$ |

Computing $P$ by Horner's rule over points of $\E_q$ is a
[**walk**](../construction/walks.md#nested-walk), and it runs in $\F_q$
circuits, the nested **endoscaling steps**. Those circuits have traces of their
own, committed on $\E_p$, and their satisfaction is a new set of revdot claims
over $\F_q$. So the nested side needs everything from rungs [4](rung_04.md) to
[10](rung_10.md) again: its own fold, its own registry of internal circuits, its
own batch of openings and its own accumulator. That accumulator's commitment
$P_q$ is a walk over points of $\E_p$, which the native $\F_p$ circuits perform.
A subscript $q$ marks the nested counterpart of a native object.

The result is symmetric. Each side's circuits verify the scalar half of their
own field's accumulation and the group half of the other field's.

Three smaller problems come with the second curve.

*One challenge, two fields.* The walk for $P$ multiplies points of $\E_q$ by
$\beta$, an element of $\F_p$, yet it runs in $\F_q$ circuits, which cannot hold
$\beta$ as a field element. What both fields can hold is a string of bits. Ragu
takes the low 143 bits of a transcript output as an
[**endoscalar**](../construction/cycle.md#endoscalars). A walk consumes the bits
directly, using the curve's endomorphism, at a fraction of the cost of a general
scalar multiplication. Each field maps the bits to its own element by a fixed
injective **lift**, and that element is the scalar the walk multiplies by. One
bit string therefore gives two challenges. The native $\beta$ is its lift into
$\F_p$, used by the walk for $P$ and, as a field element, by the native
`compute_v` circuit. The nested $\beta_q$ is its lift into $\F_q$, used the same
way for $P_q$. Each ranges over only $2^{143}$ values.

The other eight nested challenges are obtained the same way: each is the lift of
the low 143 bits of the corresponding native challenge. The native side uses
those eight at full width.

| Challenge | Native Side | Nested Side |
| --- | --- | --- |
| $w, y, z, \mu, \mu', x, \alpha, u$ | the transcript output: nearly all of $\F_p$ | a lift: $2^{143}$ values |
| $\beta$ | a lift: $2^{143}$ values | a lift: $2^{143}$ values |

A test of degree $d$ therefore has error at most $d / 2^{143}$ on the nested
side, and also on the native side when its challenge is $\beta$, as in
[rung 10](rung_10.md).

*Hashing foreign points.* [Rung 13](rung_13.md) has $\F_p$ circuits hash native
commitments, whose coordinates are in $\F_q$. The fix is a **nested
commitment**: place the coordinates on the wires of an $\F_q$ polynomial and
commit to that on $\E_p$. The resulting point has $\F_p$ coordinates and binds
the original commitments. The code calls the $\F_q$ polynomials that do this
[*bridge stages*](../construction/stage_contents.md#nested-stages).

*Two views of one object.* The $\F_q$ circuits walk points that the $\F_p$ side
knows only through nested commitments. [Rung 14](rung_14.md) covers how the two
views are held equal.

**Why it holds.** The nested accumulator is rungs [4](rung_04.md) to
[10](rung_10.md) over a different field, and each walk is a deterministic
computation checked by circuits. The arguments of those rungs carry over, with
one change of order that needs an argument of its own.

On the nested side the prover commits to its restriction of the registry
together with $f_q$, after $\alpha_q$ is drawn. [Rung 9](rung_09.md) drew
$\alpha$ after every claim was fixed. Here the claimed values are fixed before
$\alpha_q$ and this one polynomial is not, so its committer can choose it to
cancel the error of another claim at a shared evaluation point. There are two
cases. If the committed polynomial is the registry's restriction
$m_q(W, x_q, y_q)$, then $x_q$ and $y_q$ determined it before $\alpha_q$, and
the argument of rung 9 applies unchanged. If it is any other polynomial, the
fuse's new wiring claim is false, and the property required in
[rung 3](rung_03.md) asks for nothing more than a false output.
[Rung 8](rung_08.md) already left that claim for the next fuse to test.

**Still owed.** The merge verifier is now a substantial program: transcript
hashing on the native side, and on each side two fold layers, a batch of 150 or
more openings and a walk over more than a hundred points. It does not fit in one
circuit of $n$ gates, and its parts need to read the same data.
