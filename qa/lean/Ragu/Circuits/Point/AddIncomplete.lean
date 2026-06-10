import Clean.Circuit
import Clean.Utils.Primes
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.EnforceNonzero
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.AddIncomplete
variable {p : ℕ} [Fact p.Prime]

/-- The new shape: just two input points. The old `nonzero : F` field
that surfaced the running product is gone — discharge is in-circuit via
`NonzeroBank::scope` and emits an `enforce_nonzero` at the end of
`main`. -/
structure Inputs (F : Type) where
  P1 : Spec.Point F
  P2 : Spec.Point F
  /-- Prover hint: inverse of `P2.x - P1.x` (the bank's running product
  after `K = 1` fold), used by the trailing discharge. -/
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- Body of the new `Point::add_incomplete` wrapped in
`NonzeroBank::scope`:

  ```rust
  NonzeroBank::scope(dr, |dr, bank| p1.add_incomplete(dr, &p2, bank))
  ```

  - **Fold** (`bank.fold(P2.x - P1.x)`): one `Element::mul` of the
    running product `1` against the new factor.
  - **Divide / Square / Mul**: the standard affine-add formulas, where
    the divide's divisor is the *raw* `(P2.x - P1.x)` wire (not the
    running product). This is why the bank fold is a separate side
    effect rather than a transform.
  - **Discharge** at scope end: `enforce_nonzero` on the running
    product, which proves `P2.x - P1.x ≠ 0` (i.e. `P1.x ≠ P2.x`). -/
def main (input : Var Inputs (F p)) : Circuit (F p) (Var Spec.Point (F p)) := do
  let ⟨⟨x1, y1⟩, ⟨x2, y2⟩, inverse⟩ := input

  -- bank.fold(P2.x - P1.x): running product = 1 · (x2 - x1)
  let bank_prod ← Element.Mul.circuit ⟨1, x2 - x1⟩

  -- delta = (y2 - y1) / (x2 - x1)
  let delta ← Element.Divide.circuit ⟨y2 - y1, x2 - x1⟩

  -- x3 = delta² - x1 - x2
  let delta_sq ← Element.Square.circuit delta
  let x3 := delta_sq - x1 - x2

  -- y3 = delta · (x1 - x3) - y1
  let y_term ← Element.Mul.circuit ⟨delta, x1 - x3⟩
  let y3 := y_term - y1

  -- scope-end discharge: bank_prod ≠ 0
  let _ ← Element.EnforceNonzero.circuit { input := bank_prod, inverse }

  return ⟨x3, y3⟩

/-- Verifier-side assumptions: both inputs on curve. The discharge at
scope end *forces* `P1.x ≠ P2.x`, so we don't need to assume it. -/
def Assumptions (curveParams : Spec.CurveParams p)
    (input : Value Inputs (F p)) (_data : ProverData (F p)) :=
  input.P1.isOnCurve curveParams ∧
  input.P2.isOnCurve curveParams

/-- Prover-side: needs `P1.x ≠ P2.x` (otherwise the discharge can't be
satisfied), expressed via the inverse hint. -/
def ProverAssumptions (curveParams : Spec.CurveParams p)
    (input : ProverValue Inputs (F p)) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) :=
  let p1x : F p := input.P1.x
  let p2x : F p := input.P2.x
  let inverse : F p := input.inverse
  input.P1.isOnCurve curveParams ∧
  input.P2.isOnCurve curveParams ∧
  (p2x - p1x) * inverse = 1

/-- Verifier-side spec: when constraints hold, the output is the affine
sum (which exists since the discharge proves `P1.x ≠ P2.x`) and lies on
the curve. -/
def Spec (curveParams : Spec.CurveParams p)
    (input : Value Inputs (F p)) (output : Value Spec.Point (F p))
    (_data : ProverData (F p)) :=
  input.P1.add_incomplete input.P2 = some output ∧
  output.isOnCurve curveParams

instance elaborated :
    ElaboratedCircuit (F p) Inputs Spec.Point where
  main
  -- bank_prod (3) + divide (3) + square (3) + mul_for_y (3) + discharge (3) = 15 wires
  localLength _ := 15

theorem soundness (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint.Soundness (F p) elaborated
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.EnforceNonzero.circuit, Element.EnforceNonzero.Spec]
  obtain ⟨h_P1_eq, h_P2_eq, _⟩ := h_input
  obtain ⟨h_curve1, h_curve2⟩ := h_assumptions
  obtain ⟨h_bank, h_div, h_sq, h_y_term, _, h_nz⟩ := h_holds
  rw [← h_P1_eq] at h_curve1
  rw [← h_P2_eq] at h_curve2
  rw [← h_P1_eq, ← h_P2_eq]
  set x1 := Expression.eval env input_var.1.x
  set y1 := Expression.eval env input_var.1.y
  set x2 := Expression.eval env input_var.2.x
  set y2 := Expression.eval env input_var.2.y
  rw [h_bank] at h_nz
  have h_x_ne : x1 ≠ x2 := by
    intro h; apply h_nz; simp [h]
  have h_delta : env.get (i₀ + 3) = (y2 + -y1) / (x2 + -x1) := h_div (Or.inl h_nz)
  have h_add_eq :
      Spec.Point.add_incomplete { x := x1, y := y1 } { x := x2, y := y2 } =
        some { x := env.get (i₀ + 3 + 3 + 2) + -x1 + -x2,
               y := env.get (i₀ + 3 + 3 + 3 + 2) + -y1 } := by
    simp only [Spec.Point.add_incomplete, if_neg h_x_ne, Option.some.injEq,
      Spec.Point.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [h_sq, h_delta]; ring
    · rw [h_y_term, h_sq, h_delta]; ring
  refine ⟨h_add_eq, ?_⟩
  simpa [h_add_eq] using
    Lemmas.add_incomplete_preserves_membership
      ⟨x1, y1⟩ ⟨x2, y2⟩ curveParams h_x_ne h_curve1 h_curve2

theorem completeness (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint.Completeness (F p) elaborated
      (ProverAssumptions curveParams) (fun _ _ _ => True) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Element.Divide.circuit, Element.Divide.ProverAssumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions,
    Element.EnforceNonzero.circuit, Element.EnforceNonzero.ProverAssumptions]
  obtain ⟨h_P1_eq, h_P2_eq, _⟩ := h_input
  obtain ⟨_, _, h_inv⟩ := h_assumptions
  have h_P1x : input_P1.x = Expression.eval env.toEnvironment input_var.1.x := by
    rw [← h_P1_eq]
  have h_P2x : input_P2.x = Expression.eval env.toEnvironment input_var.2.x := by
    rw [← h_P2_eq]
  rw [h_P1x, h_P2x, sub_eq_add_neg] at h_inv
  refine ⟨?_, ?_⟩
  · intro h
    rw [h, zero_mul] at h_inv
    exact zero_ne_one h_inv
  · obtain ⟨h_bank, _⟩ := h_env
    rw [h_bank]
    exact h_inv

def circuit (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint (F p) Inputs Spec.Point where
  elaborated
  Assumptions := Assumptions curveParams
  Spec := Spec curveParams
  ProverAssumptions := ProverAssumptions curveParams
  soundness := soundness curveParams
  completeness := completeness curveParams

end Ragu.Circuits.Point.AddIncomplete
