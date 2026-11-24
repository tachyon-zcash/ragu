# Rung 12: A Verifier Split Across Circuits by Stages

**Problem.** Two needs pull against the single-trace circuit of
[rung 1](rung_01.md).

- The verifier must be divided among many small circuits. Keeping $n$ small is a
  design goal, because the decider's cost grows with $4n$. Those circuits
  operate on shared data, such as the children's public values, and passing that
  data through public inputs would cost constraints in every circuit that reads
  it.
- Challenges must depend on the prover's messages. Hashing hundreds of field
  elements inside a circuit is too expensive.

**Refinement.** Split a trace into
[**stages**](../construction/staging.md#stages):

$$
r(X) = r_{\text{own}}(X) + r_{\text{stage}_1}(X) + r_{\text{stage}_2}(X) + \cdots
$$

The first summand is the circuit's **own polynomial**, the part of its trace
that no stage holds. Among the stages of one circuit, each stage polynomial
occupies its own range of gates, and each is committed separately. A circuit
claim uses the sum, and by homomorphism the sum's commitment is the sum of the
parts' commitments. This meets both needs. Two circuits whose claims include the
same stage polynomial read the same wires. And a stage's commitment is a binding
digest of its contents, so the transcript can absorb one point in place of
hundreds of field elements.

Staging adds an obligation. If a stage polynomial could be nonzero outside its
range, it would overlap the other summands, and the wires a circuit reads would
no longer be the wires that were committed. Each stage polynomial is therefore
checked against a [**mask**](../construction/staging.md#masks), a wiring
polynomial $s_{\text{mask}}$ with

$$
\revdot{r_{\text{stage}}}{s_{\text{mask}}(X, y)} = 0,
$$

whose constraints say that every wire outside the stage's range is zero. The own
polynomial is checked against a mask that forces it to zero on every stage's
range.

Gate $0$ is exempt from every mask. Each committed polynomial may carry an
arbitrary value on that gate's $\v{a}$ wire, so the summands do overlap there.
The overlap is harmless: circuits take nothing from gate $0$ except the constant
`ONE`, and the circuit claim on the sum fixes that wire.

The $\v{a}$ and $\v{d}$ wires of the last gate are exempt from every mask as
well. That gate is the [blind gate](../construction/wiring.md#blind-gate),
which no circuit uses, and each committed polynomial may carry arbitrary values
on those two wires. The summands overlap there too, and nothing reads the sum.

The mask checks enter the fold as the
[**bonding claims**](../construction/staging.md#bonding) of
[rung 7](rung_07.md). They differ from circuit claims in ways that make them
cheap. A bonding claim has no dilated copy of the trace and no gate correction,
so it is linear in the trace, and its target is zero. Several polynomials owed
the same mask can share one claim: for two of them,
$\revdot{z \, r_0 + r_1}{s_{\text{mask}}(X, y)} = 0$ checks both. A fuse uses
this to cover both children with one claim per mask.

**Why it holds.** A mask claim is a set of linear constraints batched by $y$, so
the argument of [rung 1](rung_01.md) applies, and the combination by $z$ fails
to expose a violation only if $z$ is a root of a low-degree polynomial.

A mask must not be able to stand in for a circuit. A proof names its step's
circuit, and that choice ranges over the whole registry domain, masks included.
The separation comes from the constant term in $Y$. A circuit's wiring
polynomial has $s(X, 0) = 1$, from the `ONE` constraint, and a circuit claim has
$\v{k}_0 = 1$. A mask omits that constraint, so $s(X, 0) = 0$. Put a mask into a
circuit claim, and the claim's residual in $(y, z)$ has constant term
$\v{c}_0 \v{d}_0 - 1$, while its coefficient of $z^{4n-1}$ is $\v{c}_0 \v{d}_0$.
No trace makes both vanish. The residual is a nonzero polynomial, and the claim
fails except with the probability of [rung 1](rung_01.md). Domain points where
nothing was registered carry no wiring except the tag term of
[rung 14](rung_14.md), which also vanishes at $Y = 0$, so they fail a circuit
claim the same way. This is what makes it safe for a proof to name any point of
the domain as its step's circuit.

The reverse substitution is not excluded, and does not need to be. A bonding
claim is homogeneous, so nonzero polynomials can satisfy it against a circuit's
wiring polynomial. The polynomial a bonding claim uses is fixed by the protocol,
though, and never chosen by the prover.

A mask constrains where a stage's values sit, not what they are. Conditions on
staged values, such as range checks and curve membership, are emitted by at most
one of the circuits that load a stage, and the others read its wires as given.
Stages with no such circuit hold values that need no conditions of their own, or
values pinned by equality to ones that a circuit checks or computes.

**Still owed.** The verifier now fits. Its challenges still come from nowhere.
