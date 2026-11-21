# Setup {#setup}

An application determines two registries, a header size and a set of steps
before it makes any proof.

## Parameters {#parameters}

| Parameter | Content |
|---|---|
| generators | $4n$ points of $\E_q$ and $4n$ points of $\E_p$ |
| Poseidon | the permutation over $\F_p$ used by the [transcript](cycle.md#transcript) |
| $n$ | gates per circuit, from the rank |
| $H$ | `HEADER_SIZE`, the length of an encoded header |
| $K$ | the number of registered application steps |
| `stage_size` | the largest number of staged values any registered step declares |
| native [registry](registry.md), tag $\kappa$ | $57 + K$ wiring polynomials over $\F_p$ |
| nested registry, tag $\kappa_q$ | $48$ wiring polynomials over $\F_q$ |
| bootstrap proof | built at finalization; see [the base case](base_case.md) |

## Headers {#headers}

A [header](../../concepts/pcd.md#headers) type has a **suffix**, a data type and
an encoding of its data as a gadget. The encoded header is a vector of $H$ field
elements,

$$\text{hdr}(\delta) = (h_0, h_1, \dots, 0, \dots, 0, \text{suffix}),$$

where $h_0, h_1, \dots$ are the elements that the gadget writes, at most $H - 1$
of them. The suffix is the last element. The scheme binds a proof to this
vector and not to the data $\delta$, so the application must make the encoding
[injective](../../guide/writing_circuits.md#injective-encodings): two values
of the data with one encoding share every proof.

| Suffix | Header |
|---|---|
| 0 | none; the trailing zero of every native internal circuit's public output |
| 1 | the unit header `()`, which carries no data |
| 2 | `Dummy`, the input header of `Bootstrap` and of no other step |
| 3 and above | application headers |

Every proof stores two **online polynomials** $o_0, o_1 \in \F_p[X]$ for its
output header, with commitments $O_0, O_1$. A header type names the kind of
polynomial in each of the two slots, or marks a slot as padding. The padding
polynomial is the constant one.

A step has six online slots, numbered $0$ to $5$ in the fixed order

$$o^{(0)}_0, \quad o^{(0)}_1, \quad o^{(1)}_0, \quad o^{(1)}_1, \quad o_0, \quad o_1.$$

The first four are its input slots, which hold the online polynomials of its two
children, and the last two are its output slots.

## Steps {#steps}

A [`Step`](ragu_pcd::step::Step) declares a left, a right and an output header
type, a number of staged values, and two phases. Its challenge is $\zeta = w$,
the first challenge of the fuse.

The first phase runs before $w$ and determines:

- the registry index of the step's circuit, stored as `circuit_id`;
- $\text{hdr}_L$ and $\text{hdr}_R$, the encodings of the children's header
  data;
- the step's own online polynomials $o_0, o_1$, each nonzero with at most $4n$
  coefficients;
- the staged values $\nu_0, \nu_1, \dots$, exactly as many as the step declares.

Of these, the fuse commits the online polynomials and the staged values before
$w$ is drawn. The registry index and the two headers are committed later, with
the native [`preamble`](stage_contents.md#native-preamble) stage.

The second phase runs after $w$. It synthesizes the step circuit with
$\zeta = w$ and yields the output header's data and the six online openings. We
write $\text{hdr}_O$ for the encoding of the output header's data.

### Application Stage {#application-stage}

The staged values are committed in their own [stage](staging.md#stages), with
$(g, m) = (1, \lceil \texttt{stage\_size} / 2 \rceil)$. The stage has this one
size in every step circuit of the application, and a step that stages fewer
values leaves the rest of the stage unused.

$$r[\texttt{ApplicationStage}] = \textcolor{#dc2626}{\v{a}_0} \, X^{2n-1} + \sum_{k \text{ even}} \nu_k \, X^{2n-2-k/2} + \sum_{k \text{ odd}} \nu_k \, X^{4n-2-(k-1)/2} + \textcolor{#dc2626}{\v{a}_{n-1}} \, X^{n} + \textcolor{#dc2626}{\v{d}_{n-1}} \, X^{3n}$$

The three [free coefficients](wiring.md#blind-gate) are uniformly random. The
stage mask at [native index](#native-registry) $53$ confines this polynomial to
the gates of the stage, and the final mask at index $54$ forces the step
circuit's own polynomial to zero on those gates.

### Step Circuit {#step-circuit}

The step circuit reserves the application stage, allocates each staged value and
equates it with its stage wire, runs the step, and then closes the online
openings.

A step may open each of the six slots at most once, at any wire. Opening slot
$s$ at $\xi_s$ allocates a wire $\eta_s$ for the claimed value. The circuit does
not check that $\eta_s$ is the slot polynomial's value at $\xi_s$; the
[batched opening](batch.md) does. After the step runs:

1. each output slot that the step left unopened is opened at $\zeta$, and its
   value is constrained to equal one;
2. each input slot that the step left unopened is opened at $\zeta$ with no
   constraint on its value.

Every slot therefore has exactly one opening $(\xi_s, \eta_s)$ per step.

The circuit also allocates two wires $(h_x, h_y)$ for the
[bridge hash](stage_contents.md#bridge-hash). They are the coordinates of the commitment
of the stage that holds $O_1$, and a step that hashes its own second online
commitment reads them.

The public output is $\zeta$, the six openings, the two wires of the bridge hash
and the three headers, which is $1 + 12 + 2 + 3H = 15 + 3H$ elements, so

$$k_{\text{app}}(Y) = \text{Horner}_Y[\zeta, \xi_0, \eta_0, \dots, \xi_5, \eta_5, h_x, h_y, \text{hdr}_L, \text{hdr}_R, \text{hdr}_O, 1].$$

The coefficient of $Y^1$ is the suffix of the output header. For a step whose
headers are encoded as gadgets, each suffix is a circuit constant.

We write $r[\texttt{Application}]$ for the step circuit's own polynomial. The
claim about a step uses the trace
$r[\texttt{Application}] + r[\texttt{ApplicationStage}]$, at the registry index
`circuit_id`, and the fuse that runs the step
[folds that claim itself](claims.md#native-claims). The trace depends on no
challenge after $w$, so both polynomials are committed before $y$ is drawn.
They exist only during the fuse: a proof does not store them, and they are not
among the polynomials of the [orders](#rx-order) below.

## Registration and Finalization {#finalization}

Registering a step with
[`ApplicationBuilder::register`](ragu_pcd::ApplicationBuilder::register) checks
the following and defers the construction of the step's circuit.

1. Neither input header of the step has the `Dummy` suffix, which is reserved
   for the [base case](base_case.md#confinement).
2. The step's index is the next unused one.
3. No header of the step names the same online polynomial kind in both slots.
4. Each header suffix maps to one header type, and only the unit header uses a
   reserved suffix.
5. `stage_size` is raised to the step's staged value count. One plus the gates
   of that stage must be below $n - 1$, the one being the
   [`SYSTEM` gate](wiring.md#system-gate) and gate $n - 1$ the
   [blind gate](wiring.md#blind-gate).

Finalizing with
[`ApplicationBuilder::finalize_with`](ragu_pcd::ApplicationBuilder::finalize_with)
then runs in this order.

1. Construct every application step circuit with the final `stage_size`.
2. Register the native internal circuits and bonding polynomials. The `hashes_1`
   circuit takes the base-two logarithm of the native domain size as a
   parameter, which its [domain check](internal_circuits.md#hashes-1) uses.
3. Register the internal steps `Rerandomize` and `Bootstrap`.[^rerandomize]
4. Register the nested internal circuits and bonding polynomials.
5. Finalize both registries, which derives the [tags](registry.md#tag) $\kappa$
   and $\kappa_q$.
6. Unless a bootstrap proof was supplied, fuse two dummy proofs through
   `Bootstrap` with a fixed random seed and keep the result.

[^rerandomize]: `Rerandomize` is registered with the other steps, but
    rerandomization is out of scope for this section.

## Polynomial Orders {#rx-order}

Many lists in this section run over the [rx polynomials](cycle.md#notation) of
one side in the order of `RxIndex::ALL`.

| Position | Native `RxIndex` | Position | Nested `RxIndex` |
|---|---|---|---|
| 0 | `Hashes1` | 0 to 30 | `EndoscalingStep(0..=30)` |
| 1 | `Hashes2` | 31 | `Collapse` |
| 2 | `Collapse` | 32 | `ComputeV` |
| 3 | `ComputeV` | 33 | `EndoscalarStage` |
| 4 to 7 | `BindChallenges(0..=3)` | 34 | `PointsStage` |
| 8 | `BindBeta` | 35 | `BridgePreamble` |
| 9 | `BindEndoscalar` | 36 | `BridgeHash` |
| 10 to 36 | `EndoscalingStep(0..=26)` | 37 | `BridgeSPrime` |
| 37 | `Preamble` | 38 | `BridgeInnerError` |
| 38 | `InnerError` | 39 | `BridgeOuterError` |
| 39 | `OuterError` | 40 | `BridgeAB` |
| 40 | `Query` | 41 | `BridgeQuery` |
| 41 | `Eval` | 42 | `BridgeF` |
| 42 to 47 | `PointsBinding`, `PointsPreamble`, `PointsRegistryWx`, `PointsAb`, `PointsF`, `PointsWalk` | 43 | `BridgeEval` |
| | | 44 | `ChallengeStage` |

A native circuit or stage appears under three names. A circuit is named after
its module and a polynomial after its `RxIndex` variant. The registry entry of a
stage is the entry of its mask.

| Object | Name | Polynomial | Registry Entry |
|---|---|---|---|
| native circuit | `hashes_1`, `bind_challenges[k]` | `Hashes1`, `BindChallenges(k)` | `Hashes1Circuit` |
| native stage | `preamble`, `points::BindingStage` | `Preamble`, `PointsBinding` | `PreambleStage`, `PointsBindingStage` |

The nested circuits are written `EndoscalingStep(s)`, `Collapse`, `ComputeV` and
`Loading` on every page, and a nested stage has one name.

## Native Registry {#native-registry}

Each entry is a circuit or a [bonding polynomial](registry.md#registry-kinds),
and the steps are circuits. Each [mask](staging.md#masks) belongs to the
[stage](stage_contents.md) that it is named after.

| Index | Entry | Kind |
|---|---|---|
| 0 | `Hashes1Circuit` | circuit |
| 1 | `Hashes2Circuit` | circuit |
| 2 | `CollapseCircuit` | circuit |
| 3 | `ComputeVCircuit` | circuit |
| 4 to 7 | `BindChallengesCircuit(0..=3)` | circuit |
| 8 | `BindBetaCircuit` | circuit |
| 9 | `BindEndoscalarCircuit` | circuit |
| 10 to 36 | `EndoscalingStep(0..=26)` | circuit |
| 37 | `PreambleStage` | stage mask |
| 38 | `InnerErrorStage` | stage mask |
| 39 | `OuterErrorStage` | stage mask |
| 40 | `QueryStage` | stage mask |
| 41 | `EvalStage` | stage mask |
| 42 | `PointsBindingStage` | stage mask |
| 43 | `PointsPreambleStage` | stage mask |
| 44 | `PointsRegistryWxStage` | stage mask |
| 45 | `PointsAbStage` | stage mask |
| 46 | `PointsFStage` | stage mask |
| 47 | `PointsWalkStage` | stage mask |
| 48 | `InnerErrorFinalStaged` | final mask |
| 49 | `OuterErrorFinalStaged` | final mask |
| 50 | `EvalFinalStaged` | final mask |
| 51 | `PointsWalkFinalStaged` | final mask |
| 52 | `PreambleFinalStaged` | final mask |
| 53 | `ApplicationStage` | stage mask |
| 54 | `ApplicationFinalStaged` | final mask |
| 55 | `Rerandomize` | internal step |
| 56 | `Bootstrap` | internal step |
| $57 + i$ | application step $i$, for $i < K$ | application step |

The domain has $64$ points for $K \le 7$ and $128$ points for $8 \le K \le 71$.

## Nested Registry {#nested-registry}

| Index | Entry | Kind |
|---|---|---|
| 0 to 30 | `EndoscalingStep(0..=30)` | circuit |
| 31 | `Collapse` | circuit |
| 32 | `ComputeV` | circuit |
| 33 | `EndoscalarStage` | stage mask |
| 34 | `PointsStage` | stage mask |
| 35 | `PointsFinalStaged` | final mask |
| 36 | `BridgePreamble` | stage mask |
| 37 | `BridgeHash` | stage mask |
| 38 | `BridgeSPrime` | stage mask |
| 39 | `BridgeInnerError` | stage mask |
| 40 | `BridgeOuterError` | stage mask |
| 41 | `BridgeAB` | stage mask |
| 42 | `BridgeQuery` | stage mask |
| 43 | `BridgeF` | stage mask |
| 44 | `BridgeEval` | stage mask |
| 45 | `ChallengeStage` | stage mask |
| 46 | `ChallengeFinalStaged` | final mask |
| 47 | `Loading` | stripped circuit |

The nested registry is the same for every application, and its domain has $64$
points.

## Shape {#shape}

The size of each side depends on the size of the other. The nested
[walk](walks.md) folds a point for every native rx polynomial, and its
endoscaling steps are nested rx polynomials. The native walk folds a point for
every nested rx polynomial, and its endoscaling steps are native rx polynomials.
With four endoscalings per endoscaling step, the standard profile has these
counts.

| Quantity | Arithmetic | Value |
|---|---|---|
| native rx polynomials | $21 + 27$ | 48 |
| points of the nested walk | $1 + 2 (48 + 4) + 11 + 6$ | 122 |
| nested walk steps | $\lceil 121 / 4 \rceil$ | 31 |
| nested rx polynomials | $31 + 14$ | 45 |
| points of the native walk | $1 + 2 (45 + 4) + 9$ | 108 |
| native walk steps | $\lceil 107 / 4 \rceil$ | 27 |
| native claims, of $14 \cdot 7$ places | $2 + 1 + 2 \cdot 37 + 18$ | 95 |
| nested claims, of $11 \cdot 8$ places | $2 + 2 \cdot 33 + 15$ | 83 |
| native openings | $23 + 2 \cdot 48 + 55 + 6$ | 180 |
| nested openings | $20 + 2 \cdot 45 + 48$ | 158 |

In the two rx counts, $27$ and $31$ are the native and nested endoscaling steps,
and $21$ and $14$ are the other polynomials of the [orders](#rx-order) above.
The terms of the other sums are explained with the [walks](walks.md), the
[claim lists](claims.md) and the [opening lists](batch.md). The places for
claims are those that the [fold's grid](claims.md#randomizer) leaves beside the
fuse's own randomizer.
