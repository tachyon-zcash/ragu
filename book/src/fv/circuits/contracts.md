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
| Every group-scale step succeeds | `GroupScale` and `HoistedGroupScale` thread `groupScaleNative != none` through the 47-step invariant. |
| Product wires are the products of their bits | `HoistedLift` and `HoistedGroupScale` receive it as an assumption; it is `EnforceProducts`'s postcondition. |
| A nontrivial cube root of unity | Passed from the parent (`Lift`, the walks, and their digit and step children), where the `(1, 1)` digit's affine value `2 + λ²` is `1 - λ` only modulo `λ² + λ + 1 = 0`. |

Two caller-visible residual assumptions remain deliberate:

- `Point.Consistent` receives `curveParams.nonzeroCoordinates` externally.
- `Endoscalar.GroupScale` and `HoistedGroupScale` receive
  `groupScaleNative != none`, representing the no-collision/non-degeneracy
  argument in (Bowe–Grigg–Hopwood,
  <a href="https://eprint.iacr.org/2019/1021">Recursive Proof Composition
  without a Trusted Setup</a>, Appendix C), adapted to the radix-3 walk.
  `Ragu.Lemmas.EndoscalarProof.groupScale_collision_combinations_ne_zero`
  proves its integer core: the accumulator's Eisenstein norm never drops
  below 4 while a digit point's is at most 3. The curve-side step relating
  the affine accumulator to the scalar multiple remains outside the gadget
  proof, which does not manufacture the premise.
- `HoistedLift` and `HoistedGroupScale` receive the product-wire relation,
  which `EnforceProducts` establishes once per endoscalar stage at the
  circuit that pins the stage.

Verifier and prover contracts remain distinct. For example,
`Element.Alloc.Spec` is intentionally `True` because an arbitrary fresh
allocation has no verifier-visible relationship to its private hint;
`ProverSpec` records the honest-witness relationship. Similar hint obligations
belong only to completeness.

## Robustness and enforcement

Three checks enforce this boundary:

1. `Ragu.Meta.Tests.ContractComposition` checks that a child postcondition
   cannot be consumed before its assumptions are supplied.
2. `scripts/check_fv_contract_composition.sh` strips Lean comments and rejects
   qualified `.main` references anywhere in the circuit modules. CI runs this
   before the Lean build.
3. `Ragu.Meta.ContractCompositionCheck` scans the elaborated environment for
   every definition whose final result is `Circuit`, pins all 50 builders, and
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
