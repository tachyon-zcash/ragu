# Recursion {#recursion}

For proof-carrying data to work, each recursive step must verify the
previous proof inside a circuit. Ragu splits this verification across
specialized circuits to manage the cost of in-circuit hashing and
polynomial evaluation. This chapter describes those circuits and how
they connect to the shared public inputs.

The preceding chapters describe the ingredients in isolation: a
[NARK](../core/nark.md) that reduces circuit satisfiability to revdot
claims, an
[accumulation scheme](../core/accumulation/index.md) that defers
expensive checks across recursion steps, and a
[staging mechanism](../extensions/staging.md) that bridges computation
across the curve cycle.

## Internal Circuits {#internal-circuits}

The recursive verifier is split into five internal circuits that
collectively check that the previous fuse step was performed
correctly:

| Circuit | Role |
|---------|------|
| `hashes_1` | Re-derives $w, y, z$ from the transcript (first half) |
| `hashes_2` | Re-derives $\mu, \nu, \mu', \nu', x, \alpha, u, \text{pre\_beta}$ from the saved transcript state (second half) |
| `partial_collapse` | Verifies layer-1 folding with $(\mu, \nu)$ |
| `full_collapse` | Verifies layer-2 folding with $(\mu', \nu')$, handles base case |
| `compute_v` | Derives effective $\beta$ from $\text{pre\_beta}$ via endoscalar extraction, checks $v = f(u) + \beta \cdot \text{eval}$ |

### Unified output {#unified-output}

Four of these (`hashes_2`, `partial_collapse`, `full_collapse`,
`compute_v`) share a common set of public-input wires defined by the
`Output` structure. The fifth circuit (`hashes_1`) extends this
structure with the left and right child proof output headers, since it
additionally binds the proof to specific header data. The shared wires
include:

- Nested curve commitments from each proof component (preamble, $s'$,
  error $M$, error $N$, $AB$, query, $f$, eval)
- Fiat-Shamir challenges ($w, y, z, \mu, \nu, \mu', \nu', x, \alpha,
  u, \text{pre\_beta}$)
- Final claim values ($c$ and $v$)

Sharing the output structure avoids redundant evaluations of the public
input polynomial $k(Y)$ across circuits and simplifies the
[registry](../extensions/registry.md) wiring. Each circuit is assigned
an `InternalCircuitIndex` that determines its position in the registry
domain.

## Fiat-Shamir transcript split {#transcript-split}

The fuse pipeline derives all challenges from a single Poseidon sponge.
The prover absorbs each new commitment into the sponge before squeezing
the next challenge, ensuring the entire proof is bound to a single
consistent transcript.

For recursive verification, the verifier must re-derive these challenges
inside a circuit. Poseidon hashing inside a circuit is expensive, so
Ragu splits the transcript verification across two internal circuits:

- **hashes_1** derives $w$, $y$, and $z$ by absorbing the preamble,
  $s'$, and error $M$ commitments. It then saves the sponge state for
  handoff.
- **hashes_2** resumes from the saved sponge state and derives the
  remaining challenges:
  $\mu, \nu, \mu', \nu', x, \alpha, u, \text{pre\_beta}$.

The saved transcript state bridges the two circuits. During fuse, the
state is captured after the error $M$ commitment is absorbed, serialized
into field elements, and passed as witness data to the error $N$
computation.

## Stage dependencies {#stage-dependencies}

Not every circuit uses every stage's witness data. The stage dependency
chains are:

- `hashes_1`: preamble → error $N$ → *circuit*
- `hashes_2`: preamble → error $N$ → *circuit*
- `partial_collapse`: preamble → error $N$ → error $M$ → *circuit*
- `full_collapse`: preamble → error $N$ → *circuit*
- `compute_v`: preamble → query → eval → *circuit*

Each chain determines which stage masks the circuit uses and which
"final staged" mask applies
(see [Staging](../extensions/staging.md)).

## Related topics {#related-topics}

- [NARK](../core/nark.md) — how circuit satisfiability reduces to
  revdot claims
- [Accumulation](../core/accumulation/index.md) — how claims are folded
  across recursion steps
- [Staging](../extensions/staging.md) — how deferred checks are tracked
  across the curve cycle
