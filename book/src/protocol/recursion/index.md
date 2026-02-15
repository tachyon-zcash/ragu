# Protocol Mechanics

The preceding chapters describe the ingredients of Ragu's recursive proof
system in isolation: a [NARK](../core/nark.md) that reduces circuit
satisfiability to revdot claims, an
[accumulation scheme](../core/accumulation/index.md) that defers expensive
checks across recursion steps, and a
[staging mechanism](../extensions/staging.md) that bridges computation across
the curve cycle. This chapter focuses on the recursion verification circuits
and how they connect to the shared public inputs.

## Internal Circuits

The recursive verifier is split into five internal circuits that collectively
check that the previous fuse step was performed correctly:

| Circuit | Role |
|---------|------|
| `hashes_1` | Re-derives $w, y, z$ from the transcript (first half) |
| `hashes_2` | Re-derives $\mu, \nu, \mu', \nu', x, \alpha, u, \text{pre\_beta}$ from the saved transcript state (second half) |
| `partial_collapse` | Verifies layer-1 folding with $(\mu, \nu)$ |
| `full_collapse` | Verifies layer-2 folding with $(\mu', \nu')$, handles base case |
| `compute_v` | Derives effective $\beta$ from $\text{pre\_beta}$ via endoscalar extraction, checks $v = f(u) + \beta \cdot \text{eval}$ |

### Unified output

Four of the five internal circuits (`hashes_2`, `partial_collapse`,
`full_collapse`, `compute_v`) share a common set of 29 public-input wires
defined by the `Output` structure. The fifth circuit (`hashes_1`) extends
this structure with the left and right child proof output headers, since it
additionally binds the proof to specific header data. The shared wires
include:

- Nested curve commitments from each proof component (preamble, $s'$, error
  $M$, error $N$, $AB$, query, $f$, eval)
- Fiat-Shamir challenges ($w, y, z, \mu, \nu, \mu', \nu', x, \alpha, u,
  \text{pre\_beta}$)
- Final claim values ($c$ and $v$)

Sharing the output structure avoids redundant $k(Y)$ evaluations across
circuits and simplifies the [registry](../extensions/registry.md) wiring.
Each circuit is assigned an `InternalCircuitIndex` (13 indices total: 5
stages, 3 final-staged masks, and 5 circuits) that determines its position in
the registry domain.

## Fiat-Shamir transcript split

The fuse pipeline derives all challenges from a single Poseidon sponge. The
prover absorbs each new commitment into the sponge before squeezing the next
challenge, ensuring the entire proof is bound to a single consistent
transcript.

For recursive verification, the verifier must re-derive these challenges
inside a circuit. Poseidon hashing inside a circuit is expensive, so Ragu
splits the transcript verification across two internal circuits:

- **hashes_1** derives $w$, $y$, and $z$ by absorbing the preamble, $s'$, and
  error $M$ commitments. It then saves the sponge state for handoff.
- **hashes_2** resumes from the saved sponge state and derives the remaining
  challenges: $\mu, \nu, \mu', \nu', x, \alpha, u, \text{pre\_beta}$.

The saved transcript state bridges the two circuits. During fuse, the state is
captured after the error $M$ commitment is absorbed, serialized into field
elements, and passed as witness data to the error $N$ computation.

## Stage dependencies

Not every circuit uses every stage's witness data. The stage dependency chains
are:

- `hashes_1`: preamble → error $N$ → *circuit*
- `hashes_2`: preamble → error $N$ → *circuit*
- `partial_collapse`: preamble → error $N$ → error $M$ → *circuit*
- `full_collapse`: preamble → error $N$ → *circuit*
- `compute_v`: preamble → query → eval → *circuit*

Each chain determines which stage masks the circuit uses and which "final
staged" mask applies (see [Staging](../extensions/staging.md)).

## Related topics

- [NARK](../core/nark.md) — how circuit satisfiability reduces to revdot claims
- [Accumulation](../core/accumulation/revdot.md) — how claims are folded
  across recursion steps
- [Staging](../extensions/staging.md) — how deferred checks are tracked
  across the curve cycle
