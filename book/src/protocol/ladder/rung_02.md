# Rung 2: Commitments and Three Expensive Jobs

**Problem.** A claim that is going to be carried forward and merged must be
short. A claim about $r$ cannot contain $r$.

**Refinement.** The prover sends the
[commitment](../construction/cycle.md#commitments) $[r]$ before $y$ and $z$ are
drawn. The check of [rung 1](rung_01.md) becomes a statement about committed
polynomials: for $a = r$ and $b = r(zX) + s(X, y) + t(X, z)$, the value
$\revdot{a}{b}$ equals $k(y)$.

A verifier who holds only commitments faces three jobs, each of which costs time
proportional to $4n$ if done directly. Every later rung refers to them.

| Job | Short Instance | Long Witness | Relation |
| --- | --- | --- | --- |
| Revdot | $[a], [b], c$ | $a, b$ | $\revdot{a}{b} = c$ |
| Wiring | a commitment and the point at which the wiring was restricted | the restricted wiring polynomial | the commitment opens to the registered circuit's wiring, not to a polynomial of the prover's choosing |
| Opening | $[p], u, v$ | $p$ | $p(u) = v$ |

The opening job arises whenever the verifier needs a fact about a committed
polynomial, and it is the job that an inner product argument eventually
discharges at linear verifier cost.

**Why it holds.** Committing does not prove anything. It fixes the objects that
later challenges test. Consider a test that a polynomial $E$ is zero by
evaluating it at a random $\rho$. If the prover may choose $E$ after seeing
$\rho$, the nonzero polynomial $E(X) = X - \rho$ passes with certainty. With
$[E]$ sent first and the commitment binding, a nonzero $E$ passes with
probability at most $\deg(E) / |S|$.

**Still owed.** At this rung the prover still hands over the witness polynomials
and the verifier performs all three jobs for every node. Nothing is cheaper yet.
What has changed is that the per-node check is now a fixed number of claims of
three fixed shapes about homomorphic commitments, which is what allows claims to
be combined.
