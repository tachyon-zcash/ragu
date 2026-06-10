import Clean.Circuit
import Clean.Utils.Primes
import Ragu.Circuits.Element.AllocSquare
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.Double
variable {p : ℕ} [Fact p.Prime] [NeZero (2 : F p)]

def main (input : Var Spec.Point (F p)) : Circuit (F p) (Var Spec.Point (F p)) := do
  let ⟨x, y⟩ := input

  -- delta = 3x^2 / 2y
  let double_y := y + y
  let x2 ← Element.Square.circuit x
  let x2_scaled := (3 : F p) * x2
  let delta ← Element.Divide.circuit { x := x2_scaled, y := double_y }

  -- x3 = delta^2 - 2x
  let double_x := x + x
  let delta2 ← Element.Square.circuit delta
  let x3 := delta2 - double_x

  -- y3 = delta * (x - x3) - y
  let x_sub_x3 := x - x3
  let delta_x_sub_3 ← Element.Mul.circuit ⟨delta, x_sub_x3⟩
  let y3 := delta_x_sub_3 - y

  return ⟨x3, y3⟩

def Assumptions (curveParams : Spec.CurveParams p)
    (input : Spec.Point (F p)) :=
  input.isOnCurve curveParams ∧
  curveParams.noOrderTwoPoints

def Spec (curveParams : Spec.CurveParams p) (input : Spec.Point (F p)) (output : Spec.Point (F p)) :=
  input.double = some output ∧
  output.isOnCurve curveParams

instance elaborated :
    ElaboratedCircuit (F p) Spec.Point Spec.Point where
  main
  localLength _ := 12

theorem soundness (curveParams : Spec.CurveParams p) :
    Soundness (F p) elaborated (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec]
  obtain ⟨h_curve, h_no_order2⟩ := h_assumptions
  have hy_ne : input_y ≠ 0 := h_no_order2 ⟨input_x, input_y⟩ h_curve
  have h_2y_eq : input_y + input_y = 2 * input_y := (two_mul _).symm
  have h_2y_ne : input_y + input_y ≠ 0 := h_2y_eq ▸ mul_ne_zero (NeZero.ne 2) hy_ne
  obtain ⟨h_x2, h_div, h_delta_sq, h_y_term⟩ := h_holds
  have h_delta : env.get (i₀ + 3) = 3 * input_x ^ 2 / (input_y + input_y) := by
    rw [h_div (Or.inl h_2y_ne), h_x2]
  have h_double_eq :
      (Spec.Point.mk input_x input_y).double =
        some ⟨env.get (i₀ + 3 + 3 + 2) + -(input_x + input_x),
              env.get (i₀ + 3 + 3 + 3 + 2) + -input_y⟩ := by
    simp only [Spec.Point.double, hy_ne, if_false, Option.some.injEq,
      Spec.Point.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [h_delta_sq, h_delta, h_2y_eq]; ring
    · rw [h_y_term, h_delta_sq, h_delta, h_2y_eq]; ring
  refine ⟨h_double_eq, ?_⟩
  simpa [h_double_eq] using
    Lemmas.double_preserves_membership ⟨input_x, input_y⟩ curveParams h_curve h_no_order2

theorem completeness (curveParams : Spec.CurveParams p) :
    Completeness (F p) elaborated (Assumptions curveParams) := by
  circuit_proof_start [Element.Square.circuit, Element.Square.Assumptions,
    Element.Divide.circuit, Element.Divide.ProverAssumptions,
    Element.Mul.circuit, Element.Mul.Assumptions]
  obtain ⟨h_curve, h_no_order2⟩ := h_assumptions
  have hy_ne : input_y ≠ 0 := h_no_order2 ⟨input_x, input_y⟩ h_curve
  rw [(two_mul input_y).symm]
  exact mul_ne_zero (NeZero.ne 2) hy_ne

def circuit (curveParams : Spec.CurveParams p) : FormalCircuit (F p) Spec.Point Spec.Point where
  elaborated
  Assumptions := Assumptions curveParams
  Spec := Spec curveParams
  soundness := soundness curveParams
  completeness := completeness curveParams

end Ragu.Circuits.Point.Double
