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

Recursion instantiates $k(Y)$ four times: once for the values the internal
circuits share, once for those same values bound to the child headers, once for
those same values bound to the step's online openings, and once for the
application's own step circuit.

### `unified_ky`

The [unified output](index.md#unified-output) shared by the internal circuits,
followed by a zero element:

$$k_\text{unified}(Y) = \text{Horner}(\texttt{unified\_output} \,\|\, 0 \,\|\, 1, \; Y)$$

The trailing $1$ comes from the Horner wrapper, which appends it once every wire
has been absorbed. The zero before it is the suffix that separates internal
circuits from application circuits, described under
[substitution](#substitution).

The `hashes_2`, `collapse`, `bind_challenges`, `bind_beta` and
`bind_endoscalar` circuits use this value directly. The stage and
final-staged masks take zero for their $k(y)$ values, since staging masks
enforce those constraints instead.

### `unified_bridge_ky`

The same wires, extended with both child headers:

$$k_\text{bridge}(Y) = \text{Horner}(\texttt{unified\_output} \,\|\, \texttt{left\_header} \,\|\, \texttt{right\_header} \,\|\, 0 \,\|\, 1, \; Y)$$

Binding the headers is what stops a proof from claiming one pair of headers
while proving a different pair. `hashes_1` uses this rather than
$k_\text{unified}(y)$, because it is the circuit that binds child headers.

### `compute_v_bridge_ky`

The same wires, extended with the step's online openings: the point and the
claimed value of each of its six online slots, as the `query` stage holds them.

$$k_\text{compute\_v}(Y) = \text{Horner}(\texttt{unified\_output} \,\|\, x_0 \,\|\, y_0 \,\|\, \cdots \,\|\, x_5 \,\|\, y_5 \,\|\, 0 \,\|\, 1, \; Y)$$

`compute_v` folds those openings into the batch it verifies, so exporting them
is what lets the parent hold the step's application instance to the openings
the step actually proved. `compute_v` uses this rather than
$k_\text{unified}(y)$ for the same reason `hashes_1` uses $k_\text{bridge}(y)$.

### `application_ky`

The step circuit's own public inputs, with no unified output and no zero
suffix: the step's challenge $\zeta$, its six online openings and its three
headers.

$$k_\text{app}(Y) = \text{Horner}(\zeta \,\|\, x_0 \,\|\, y_0 \,\|\, \cdots \,\|\, x_5 \,\|\, y_5 \,\|\, \texttt{left\_header} \,\|\, \texttt{right\_header} \,\|\, \texttt{output\_header} \,\|\, 1, \; Y)$$

The parent computes it from the wires it already holds: $\zeta$ is the
child's $w$ in the unified output, and the openings are the ones the
`compute_v` bridge carries. The step circuit's instance is therefore held to
the openings the step proved, with nothing exported for the purpose. The
online prefix has a fixed size, so the headers keep their positions and the
output header's suffix stays the linear term.

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

The shared `Output` structure holds 37 wires: twelve nested-curve commitments
at two wires each, and thirteen field elements covering the Fiat-Shamir
challenges and the final values $c$ and $v$. `hashes_1` emits a wider structure
that adds the two child headers, and `compute_v` one that adds the step's
online openings.

Each circuit constrains the wires it is responsible for and reads the rest from
witness data, so every wire is constrained exactly once and no circuit repeats
another's work.

The verifier then checks:

1. The raw $c$ value from the $AB$ component, directly — this is the folded
   revdot scalar rather than a $k(y)$ evaluation.
2. $k_\text{app}(y)$ against the application circuit's claim.
3. $k_\text{bridge}(y)$ against the bridge claim.
4. $k_\text{compute\_v}(y)$ against the `compute_v` claim.
5. $k_\text{unified}(y)$ against the claims of the internal circuits that
   share it.
6. Stage and final-staged mask claims against zero.

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

A profile's extension circuits are internal circuits too, registered through a
slot that appends the same zero to their outputs, so the barrier holds in every
profile. The zero is needed even for an extension circuit with no output of its
own: without it, the circuit's first constraint would occupy the linear row, and
a trace meeting that constraint at the suffix's value instead of zero would pass
as an application instance.
