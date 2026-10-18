# Composable gadget contracts

Ragu's Lean circuits already compose at two levels.

At the circuit level, a parent calls a packaged child such as
`Boolean.Alloc.circuit`. Clean's `CoeFun` instance routes that call through the
appropriate subcircuit constructor. The child operations are nested at the
current offset, its local wires are fresh, and its declared output expressions
are returned to the parent.

At the theorem level, the same packaged value carries `Assumptions`, `Spec`,
`soundness`, and `completeness`. `toSubcircuit` invokes those proofs. In a
parent soundness proof, the child contribution therefore has the form

```text
Child.Assumptions evaluated_input -> Child.Spec evaluated_input evaluated_output
```

and not the child's raw gate equations. The parent must establish the premise
and may then use the postcondition.

The complete call path is:

```text
Parent.main
  -> Child.circuit input
  -> CoeFun / subcircuitWithHintAssertion (or the matching pure/assertion form)
  -> Child.circuit.toSubcircuit
  -> Child.circuit.soundness and Child.circuit.completeness
  -> a nested Subcircuit carrying the child assumptions and specification
```

`circuit_proof_start [Child.circuit, Child.Assumptions, Child.Spec]` normalizes
that packaged boundary so the parent can use it. Mentioning `Child.circuit`
there exposes the record interface; it does not ask the parent to prove the
child's operation trace again.

## Contract surface

The composition checks cover every circuit builder under
`qa/fv/Ragu/Circuits`, including recursive and loop helpers rather than only
simple functions named `main`.

| Wrapper | Count |
| --- | ---: |
| `FormalCircuit` | 34 |
| `FormalAssertion` | 8 |
| `GeneralFormalCircuit` | 4 |
| `GeneralFormalCircuit.WithHint` | 15 |
| **Packaged contracts** | **61** |

Those contracts are distributed as follows:

- Boolean (6): `Alloc`, `And`, `ConditionalEnforceEqual`,
  `ConditionalSelect`, `Consistent`, and `Decompose`.
- Core and element (18): `Core.Mul` plus all 17 element contracts.
- Endoscalar, Horner, and nonzero bank (16): `Endoscalar.Alloc`,
  `HoistedAlloc`, `Extract`, `Initial`, `Lift.Digit`, `Lift`,
  `HoistedLift.Digit`, `HoistedLift`, `EnforceProducts.Digit`,
  `EnforceProducts`, `GroupScale.Step`, `GroupScale`, `HoistedGroupScale.Step`,
  `HoistedGroupScale`, `Horner.Ky`, and `NonzeroBank.Scope`.
- Point (12): allocation, consistency, conditional endomorphism/negation,
  addition, doubling, checked/unchecked double-and-add variants, the
  unchecked triple-and-add, and the normalization to and from the walk's
  `(r, r)` form.
- Poseidon (9): `Sbox`, both round kinds, `AnyRound`, `Permutation`, `Hash1`,
  `Blocks`, `Squeeze`, and `Ragged`.

There are 61 `soundness` and 61 `completeness` endpoints. Poseidon's internal
`Blocks.loop_soundness` and `Blocks.loop_completeness` bring the pinned theorem
total to 124. Every one is directly pinned in `Ragu.Meta.TrustBoundary`.

The builders contain 61 packaged `main` definitions and one additional
proof-carrying helper, `Poseidon.Sponge.Blocks.loop`. The composition check
pins those counts so adding or removing a builder requires an explicit review
and count update.

## Direct composition edges

The parent-to-child edges are:

- Boolean: `Alloc`, `And`, and `ConditionalEnforceEqual` use `Core.mul`;
  `ConditionalSelect` uses `Element.Mul`; `Consistent` and `Decompose` use
  `Boolean.Alloc`.
- Element: allocation, multiplication, division, inversion, and zero tests use
  `Core.mul` at the leaf. Composite contracts use `EnforceNonzero` plus
  `Divide`, `Invertible`, `InvertWith`, `IsZero`, or repeated `Mul` calls as
  appropriate.
- Endoscalar: `Alloc` and `HoistedAlloc` repeat `Boolean.Alloc`; `Extract`
  uses `Boolean.Decompose`; `Lift` opens with `Boolean.And` and repeats
  `Lift.Digit` (a `Boolean.And` and an `Element.Mul` per digit), `HoistedLift`
  likewise with `HoistedLift.Digit` (one `Element.Mul`); `EnforceProducts`
  repeats `EnforceProducts.Digit` (two `Boolean.And`); `Initial` composes
  `Element.Square` and `Element.Mul`; `GroupScale.Step` composes three
  `Element.Mul` selector gates with the unchecked triple-and-add,
  `HoistedGroupScale.Step` two; and both walks compose `Point.Normalize`,
  `Initial`, 47 `Step` calls, and `Point.Denormalize`.
- Horner and nonzero bank: `Horner.Ky` uses `Element.Fold`; the bank scope folds
  with `Element.Mul` and discharges with `Element.EnforceNonzero`.
- Point: the formulas compose `Element.Divide`, `Square`, `Mul`, and, in the
  checked variants, `EnforceNonzero`; conditional operations use
  `Boolean.ConditionalSelect`; `Consistent` uses `Point.Alloc`.
- Poseidon: `Sbox` uses three `Element.Mul` calls; rounds use `Sbox`;
  `AnyRound` dispatches to a round contract; `Permutation` recursively chains
  `AnyRound`; `Blocks.loop` chains `Permutation`; and the sponge entry points
  compose `Blocks` and/or `Permutation`.

No parent circuit builder or soundness proof calls a child's qualified `main`.
`Endoscalar.EnforceProducts.Digit.soundness` names `Boolean.And.output`, and
the lift and walk proofs name their `Digit.output` and `Step.output`: the
children's stable output/layout accessors, while deriving their meaning from
the children's `Spec`.

## Assumption discharge

Most child verifier assumptions are `True`. The nontrivial paths are:

| Child obligation | How callers discharge it |
| --- | --- |
| Boolean inputs are `IsBool` | Passed from the parent contract (`ConditionalSelect`, conditional point operations, `Lift`, and group-scale steps). |
| `Element.Divide`: `y != 0` or `x != 0` | `DivNonzero` obtains `y != 0` from `EnforceNonzero`; checked point gadgets obtain it from the bank discharge; unchecked point gadgets require the relevant non-degeneracy in their own assumptions. |
| Point inputs lie on the curve | Passed from the parent assumption or established by a prior point child spec. |
| Point doubling has no order-two input | Derived from `curveParams.noOrderTwoPoints`, giving the nonzero denominator. |
| An unchecked triple-and-add chain succeeds | `GroupScale.Step` and `HoistedGroupScale.Step` pass `stepNative != none` on; `Point.TripleAndAddIncompleteUnchecked` unpacks it into the chain's three distinct-x conditions. |
| Every group-scale step succeeds | `WalkGroup` proves the 47-step affine/group invariant; `WalkPasta` discharges `groupScaleNative != none` for both Pasta curves. Generic curve contracts still carry the premise. |
| Product wires are the products of their bits | `HoistedLift` and `HoistedGroupScale` receive it as an assumption; it is `EnforceProducts`'s postcondition. |
| A nontrivial cube root of unity | Passed from the parent (`Lift`, the walks, and their digit and step children), where the `(1, 1)` digit's affine value `2 + λ²` is `1 - λ` only modulo `λ² + λ + 1 = 0`. |
| Lift output uniquely determines Boolean bits | `LiftInjectivity` connects `Lift.liftNative` to `endoscaleN`, discharges both Pasta characteristic bounds, and strengthens the plain and hoisted circuit soundness endpoints. |
| The coordinate root and scalar root have matching orientation | `Point.Endomorphism` checks the scalar action on `(-1, 2)` by kernel reduction and extends it to all points using each curve's certified prime order. |

The caller-visible residual assumptions are:

- `Point.Consistent` receives `curveParams.nonzeroCoordinates` externally.
- Generic `Endoscalar.GroupScale` and `HoistedGroupScale` contracts receive
  `groupScaleNative != none`. Their concrete `ep_soundness`, `eq_soundness`,
  `ep_completeness`, and `eq_completeness` endpoints derive it and require
  only `PastaAssumptions`: an on-curve affine point, boolean bits, and, for
  the hoisted walk, the product-wire relation.
- `HoistedLift` and `HoistedGroupScale` receive the product-wire relation,
  which `EnforceProducts` establishes once per endoscalar stage at the
  circuit that pins the stage.

The non-degeneracy proof connects the integer bounds to the actual affine
walk. `CoordinateMap` proves that normalization preserves complete addition
and group order. `Point.Group` identifies the partial affine formulas with
the complete group law. `WalkGroup.accAfter_exists` proves that each
accumulator is `a · φ(P) + b · P` for its integer Eisenstein index. If an
exceptional combination vanished, its positive norm would annihilate the
base point. `EndoscalarGroup` excludes that because the norm is below the
prime group order. This argument uses `φ²(P) + φ(P) + P = 0` directly and
does not assume an endomorphism eigenvalue certificate.

The Pallas and Vesta instantiations reuse CompElliptic's existing group-order
certificates. Their exact native-certificate dependencies are declared in
`Ragu.Meta.TrustBoundary`; the bridge adds no new axioms or native certificates.
`WalkPasta.collisionBound_lt_p` and `collisionBound_lt_q` name the concrete
inequalities used by both walk-success proofs.

`LiftInjectivity.liftNative_eq_endoscaleN` connects the field-vector model to
the integer model, including initial bits, every digit, and fold order.
`decode_injective` proves the conversion loses no Boolean bits. The plain
and hoisted `ep_injective_soundness` and `eq_injective_soundness` endpoints
then prove output uniqueness about the same builders used by extraction.
Their numeric bounds and theorem dependencies use the standard theorem tier.

`WalkScalar` transports the accumulator's group action back through
denormalization and connects its index to the lift encoding.
`Point.Endomorphism.pallas_generator` and `vesta_generator` fix the deployed
root orientation using `decide +kernel`; neither introduces a native
certificate. The prime-order certificates extend the identity to every
point. The resulting plain and hoisted `ep_scalar_soundness` and
`eq_scalar_soundness` endpoints state multiplication by `Lift.liftNative`
in the opposite field, not just agreement with the affine evaluator.

Verifier and prover contracts remain distinct. For example,
`Element.Alloc.Spec` is intentionally `True` because an arbitrary fresh
allocation has no verifier-visible relationship to its private hint;
`ProverSpec` records the honest-witness relationship. Similar hint obligations
belong only to completeness.

## Open contract: endoscalar stage binding {#endoscalar-stage-binding}

**Status: open protocol proof obligation.** The arithmetic gadget theorems
above do not establish this contract. It belongs to the broader recursive
formalization; it is not an additional Lean axiom or an assumed theorem.

The target relation is that, for each logical proof step, there is one
143-bit Boolean encoding $s$ with the following properties:

1. $s$ is the canonical extraction of that step's transcript-derived,
   in-range `pre_beta`. The transcript includes the prescribed commitments
   in their prescribed order.
2. Each owner and consumer uses that same encoding. Across the 47 digits,
   the 94 hoisted product wires satisfy $p_i=e_{1,i}e_{2,i}$ and
   $q_i=p_i s_i$. This includes every walk step and the nested lift.
3. The two fields' beta values are their respective lifts of $s$. This
   requires equality of the Boolean encoding across fields; it does not
   equate elements of different fields. Nested `compute_v`'s beta wire is
   the value authenticated by the challenge-stage commitment.
4. The commitments opened, folded, exported to the unified instance, and
   checked by the next parent or terminal verifier refer to these same
   stages and walk results. The recursive argument covers both child
   positions and every recursion depth, with an explicit base-case relation
   for the bootstrap path and its sign convention.

An eventual soundness reduction must derive this relation from acceptance
for adversarial witnesses, or reduce its failure to explicitly defined and
bounded cryptographic failure events. Those events must follow from the
stated commitment, accumulation, and challenge assumptions; naming a stage
mismatch as a bad event supplies neither a reduction nor a probability bound.

The implementation responsibilities to connect are:

| Producer or contract owner | Value or relation established | Consumer or binding check |
| --- | --- | --- |
| Native `hashes_2` | Transcript-derived `pre_beta` in the unified instance | Native `compute_v`, native `bind_endoscalar`, and the parent's `bind_beta` |
| Native `bind_endoscalar` | Walk bits equal extracted bits, products are pinned, input points are on curve, and the walked result is exported | Native walk steps and the parent's checks of the walked commitments |
| Nested `export` | Endoscalar stage bits are Boolean and both products per digit are pinned | Nested walk steps and nested `compute_v` |
| Nested `compute_v` | The staged bits' lift equals the challenge stage's beta | Nested evaluation folding and the walk's scalar interpretation |
| Native `bind_challenges`, then the parent's `bind_beta` | The nested challenge-stage commitment matches the transcript-derived lifts, sign, and beta term | Nested stage openings and all consumers of those challenges |
| Stage commitments, native/nested claims, and bonding masks | Owner and consumer constraints refer to the same staged values and exported commitments | The recursive accumulation and terminal verification checks |

The parent step is essential: `pre_beta` is sampled after the native
`eval` commitment, so the proof's own challenge binders export a partial
commitment without its beta term. The parent's `bind_beta` completes that
term using the child's exported `pre_beta` and compares the result with the
child's walked challenge-stage commitment. At the terminal proof, the
verifier reconstructs the challenge-stage polynomial and compares its
coefficients, checks cached commitments against the retained polynomials,
and replays the transcript. A proof must cover this terminal path as well
as the inductive parent path.

Closing this contract requires all of the following:

1. Model the relevant internal circuits and their actual stage layouts,
   unified-instance slots, claim chains, and final masks. Connect those
   models to the deployed implementation under the stated refinement boundary.
2. Derive the equality of owner and consumer values from their shared
   commitments, openings, claims, and bonding. Supplying stage equality
   as a premise leaves this obligation open.
3. Prove the parent/child and terminal bindings, including transcript
   timing, in-range extraction, child positions, and base cases. State the
   binding assumptions and account for their failure events and repeated
   Fiat–Shamir trials in the broader reduction.
4. Compose the result with `EnforceProducts`, `LiftInjectivity`, and
   `WalkScalar`, and include the resulting endpoints in the trust census.

The recursive substitution tests currently exercise stage-bit, product,
and challenge substitutions through two generations, with honest controls.
PR CI replays the saved cases and a fresh case for the selected properties.
Separate owner-circuit regressions change every hoisted product at native
`bind_endoscalar` and nested `export`, at bootstrap and at an ordinary fuse.
They isolate each product equation and reject malformed stage values without
depending on the walk's constraints. These are finite checks. They do not
establish this contract, and passing them does not discharge any of the proof
obligations above.

## Robustness and enforcement

Three checks enforce this boundary:

1. `Ragu.Meta.Tests.ContractComposition` checks that a child postcondition
   cannot be consumed before its assumptions are supplied.
2. `scripts/check_fv_contract_composition.sh` strips Lean comments and rejects
   qualified `.main` references anywhere in the circuit modules. CI runs this
   before the Lean build.
3. `Ragu.Meta.ContractCompositionCheck` scans the elaborated environment for
   every definition whose final result is `Circuit`, pins all 62 builders, and
   rejects direct semantic references to a different circuit's `main` or to
   the raw `FormalCircuitBase.main` projection.

The lint is an accidental-drift guard, not a parser-level security boundary.
Lean type checking and Clean's subcircuit definitions are the semantic check.

## What this does not prove

Composable contracts prove the meaning of the Lean circuit hierarchy. They do
not by themselves show that a Rust implementation has the same trace, or that
an isolated gadget has the deployed composed circuit's system gates, allocator
context, routine placement, final layout, wiring, or verifier acceptance
behavior. Those are separate Rust-to-Lean binding and deployment-layer checks,
tracked in [#865](https://github.com/tachyon-zcash/ragu/issues/865).

Layout proofs such as `localLength_eq`, `output_eq`, and
`subcircuitsConsistent` are also expected to depend on child layout metadata.
That is circuit composition, not a leak of the child's semantic proof. The
modularity claim is specifically that a parent derives child meaning from the
child contract rather than re-proving the child's raw constraints.
