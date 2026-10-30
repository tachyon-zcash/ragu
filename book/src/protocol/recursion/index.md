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

The native recursive verifier divides its checks among these internal
circuits:

| Circuit | Role |
|---------|------|
| `hashes_1` | Re-derives $w, y, z$ from the transcript (first half) |
| `hashes_2` | Re-derives $\mu, \mu', x, \alpha, u, \text{pre\_beta}$ from the saved transcript state (second half) |
| `collapse` | Checks the children's application $k(y)$ values and both quotient-fold layers under $\mu$ and $\mu'$, with the final claim check waived at bootstrap |
| `compute_v` | Derives effective $\beta$ from $\text{pre\_beta}$ via endoscalar extraction and checks the batched evaluation $v$ |
| `bind_challenges` | Binds the lifted nested challenges and base-case flag, two challenges per circuit |
| `bind_beta` | Binds the walked child commitments and completes their challenge bindings |
| `bind_endoscalar` | Binds the nested accumulation's endoscalar and exported commitments |
| `endoscaling_step` | Checks one step of commitment accumulation |

The two folding layers remain separate mathematical reductions: first fold
groups of claims, then fold the group results. Their checks fit in one
`collapse` circuit. The nested `collapse` circuit likewise checks both
layers and binds its unified instance's exported values to their stages.

### Unified output {#unified-output}

The `hashes_2`, `collapse`, `compute_v`, `bind_challenges`, `bind_beta`
and `bind_endoscalar` circuits share a common set of public-input wires
defined by the `Output` structure. The `hashes_1` circuit extends this
structure with the left and right child proof output headers, since it
additionally binds the proof to specific header data. The shared wires
include:

- Nested curve commitments from each proof component (preamble, $s'$,
  `inner_error`, `outer_error`, $AB$, query, $f$, eval)
- Fiat-Shamir challenges ($w, y, z, \mu, \mu', x, \alpha,
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
  $s'$, and inner-error bridge commitments. It then saves the sponge
  state for handoff.
- **hashes_2** resumes from the saved sponge state and derives the
  remaining challenges:
  $\mu, \mu', x, \alpha, u, \text{pre\_beta}$.

The saved transcript state bridges the two circuits. During fuse, the
state is captured after the inner-error bridge commitment is absorbed,
serialized into field elements, and carried in the `outer_error` stage's
witness data.

## Stage dependencies {#stage-dependencies}

Not every circuit uses every stage's witness data. The stage dependency
chains include:

- `hashes_1`: preamble -> `outer_error` -> *circuit*
- `hashes_2`: preamble -> `outer_error` -> *circuit*
- `collapse`: preamble -> `outer_error` -> `inner_error` ->
  *circuit*
- `compute_v`: preamble -> query -> eval -> *circuit*

For a profile with a native extension binding circuit, `collapse` also
loads the points binding stage before the preamble.

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
