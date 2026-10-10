# Public Inputs

Three kinds of data flow through a recursive step, and which is which decides
what a verifier is trusting. Public inputs are the values it checks. Stage
outputs pass between stages and never reach it. Staging circuit outputs are the
public inputs the internal circuits expose, and their shape is what stops an
internal proof from standing in for an application one.

## Public Inputs

A circuit's public inputs are encoded as a polynomial $k(Y)$, introduced in the
[NARK](../core/nark.md) chapter. The verifier evaluates $k(y)$ at a random point
$y$ and checks it against the revdot claim.

Recursion instantiates $k(Y)$ three times: once for the values the internal
circuits share, once for those same values bound to the child headers, and once
for the application's own step circuit.

### `unified_ky`

The [unified output](index.md#unified-output) shared by the internal circuits,
followed by a zero element:

$$k_\text{unified}(Y) = \text{Horner}(\texttt{unified\_output} \,\|\, 0 \,\|\, 1, \; Y)$$

The trailing $1$ comes from the Horner wrapper, which appends it once every wire
has been absorbed. The zero before it is the suffix that separates internal
circuits from application circuits, described under
[substitution](#substitution).

Four of the five internal circuits — `hashes_2`, `inner_collapse`,
`outer_collapse`, and `compute_v` — use this value directly. The stage and
final-staged masks take zero for their $k(y)$ values, since staging masks
enforce those constraints instead.

### `unified_bridge_ky`

The same wires, extended with both child headers:

$$k_\text{bridge}(Y) = \text{Horner}(\texttt{unified\_output} \,\|\, \texttt{left\_header} \,\|\, \texttt{right\_header} \,\|\, 0 \,\|\, 1, \; Y)$$

Binding the headers is what stops a proof from claiming one pair of headers
while proving a different pair. `hashes_1` uses this rather than
$k_\text{unified}(y)$, because it is the circuit that binds child headers.

### `application_ky`

The two application circuits share one public input polynomial. It contains
the ordered bundle's circuit IDs (as registry domain points), followed by the
three headers, with no unified output and no zero suffix:

$$k_\text{app}(Y) = \text{Horner}(\texttt{circuit\_ids} \,\|\, \texttt{left\_header} \,\|\, \texttt{right\_header} \,\|\, \texttt{output\_header} \,\|\, 1, \; Y)$$

Each step's adapter fixes both IDs as circuit constants at registration.
The terminal verifiers derive them from the proof's actual selectors, and the
recursive `outer_collapse` circuit derives them from the committed child
preamble. A prover cannot replace `(A, B)` with `(A, A)` or swap its
steps: the public inputs would disagree with the registered circuits.
A standalone step registers the repeated bundle `(A, A)`; the prover traces
it once and places the same polynomial in both slots, so each slot's claim is
the same valid claim.

Split steps share data through the proof's *shared stage*, a third
application polynomial committed once per proof. Each application circuit
loads it at its first gates, `ceil(n / 2)` of them for an application whose
shared stage holds `n` elements, where `n` is derived from the largest
registered `Step::Shared` gadget. Both steps in a bundle must use the
same gadget type. The adapter constrains each actual returned gadget wire
to its corresponding reserved stage wire; the prover derives the stage's
values from those gadgets. Smaller bundles pad unused capacity with zeros.
Each slot's claim is checked on the sum
of the slot's own polynomial and the stage's, so both steps' returned
connections agree. Two bonding claims, folded
like the internal stages' masks, keep the lanes apart: the stage's mask pins
the stage polynomial to its block, and the application final mask pins every
slot's own polynomial to zero inside it. Without them a step could carry
a private copy of a shared value in its own lane.

Verification derives the shared-stage lane selector from the proof's bound
circuit IDs: equal IDs identify a standalone step and disable the lane
claims, while distinct IDs identify a split bundle and keep them active.
Standalone steps, including bootstrap and rerandomization, reserve no shared
block and retain their full circuit capacity.

### Horner Evaluation

Each $k(y)$ is computed by streaming Horner evaluation. Given wires $w_0,
\ldots, w_{n-1}$ and the trailing constant:

$$k(y) = (\cdots((w_0 \cdot y + w_1) \cdot y + w_2) \cdots + w_{n-1}) \cdot y + 1$$

Wires are absorbed one at a time, with a multiplication by $y$ between each.
Streaming lets the shared prefix be computed once: $k_\text{unified}$ and
$k_\text{bridge}$ diverge only after the unified output is absorbed, so the work
up to that point is shared.

## Stage Outputs

Stage outputs are prover-internal values consumed by later stages or internal
circuits. A verifier never sees them. The framework separately encodes their
wire values into a partial trace polynomial and commits to that trace.

The saved transcript state is the stage output worth knowing about. Once the
inner-error bridge commitment has been absorbed into the sponge, the sponge
state is serialized into field elements and carried by the `outer_error` stage.
That is what lets `hashes_1` and `hashes_2` split the Fiat-Shamir re-derivation
between them, as the [transcript split](index.md#transcript-split) describes.

## Staging Circuit Outputs

Staging circuit outputs are the internal circuits' public inputs: the values the
recursive verifier actually checks, carried through the $k(Y)$ mechanism above.

The shared `Output` structure holds 29 wires: eight nested-curve commitments at
two wires each, and thirteen field elements covering the Fiat-Shamir challenges
and the final values $c$ and $v$. `hashes_1` emits a wider structure that adds
the two child headers.

Each circuit constrains the wires it is responsible for and reads the rest from
witness data, so every wire is constrained exactly once and no circuit repeats
another's work.

The verifier then checks:

1. The raw $c$ value from the $AB$ component, directly — this is the folded
   revdot scalar rather than a $k(y)$ evaluation.
2. $k_\text{app}(y)$ against the application circuit's claim.
3. $k_\text{bridge}(y)$ against the bridge claim.
4. $k_\text{unified}(y)$ against the claims of the four internal circuits that
   share it.
5. Stage and final-staged mask claims against zero.

## Substitution {#substitution}

Internal circuits and application circuits sit at different registry positions,
so an attacker might try to supply one where the other is expected.

The zero suffix is what prevents it. Internal circuit outputs serialize suffix
zero, which forces the linear term of $k(Y)$ to zero. An application circuit
instead serializes its output header suffix. That suffix is always nonzero: one
is reserved for the trivial header, and application-defined suffixes begin at
two.

No valid application $k(Y)$ can equal a valid internal $k(Y)$, and substitution
in either direction fails the verifier's check.
