import Clean.Circuit
import Clean.Utils.Primes
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.Denormalize
variable {p : ℕ} [Fact p.Prime]

/-- The walk's result on the normalized curve, with the normalization's
`c` and `c²`. -/
structure Input (F : Type) where
  pt : Spec.Point F
  c : F
  c2 : F
deriving ProvableStruct

/-- The three gates that move the walk's result back from the normalized
curve, in the Rust order: `Mul ⟨c², c⟩` for `c³`, then `Divide ⟨X, c²⟩` and
`Divide ⟨Y, c³⟩`. The divisors are nonzero because `c` is, which the
caller establishes. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var Spec.Point (F p)) := do
  let ⟨⟨X, Y⟩, c, c2⟩ := input
  let c3 ← Element.Mul.circuit ⟨c2, c⟩
  let x ← Element.Divide.circuit ⟨X, c2⟩
  let y ← Element.Divide.circuit ⟨Y, c3⟩
  return ⟨x, y⟩

/-- `c ≠ 0` and `c² = c ^ 2`, both from the normalization. -/
def Assumptions (input : Input (F p)) :=
  input.c ≠ 0 ∧ input.c2 = input.c ^ 2

def Spec (input : Input (F p)) (output : Spec.Point (F p)) :=
  output.x = input.pt.x / input.c ^ 2 ∧
  output.y = input.pt.y / input.c ^ 3

instance elaborated : ElaboratedCircuit (F p) Input Spec.Point main where
  -- Mul (3) + Divide (3) + Divide (3)
  localLength _ := 9
  output _ offset :=
    ⟨varFromOffset field (offset + 3), varFromOffset field (offset + 3 + 3)⟩
  output_eq := by
    intro input offset
    rcases input with ⟨⟨X, Y⟩, c, c2⟩
    simp [main, circuit_norm, Element.Divide.circuit, Element.Mul.circuit]

theorem soundness :
    Soundness (F p) (Input := Input) (Output := Spec.Point) main Assumptions Spec := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec]
  obtain ⟨h_c, h_c2⟩ := h_assumptions
  obtain ⟨h_c3, h_x, h_y⟩ := h_holds
  have h_c2_ne : input_c2 ≠ 0 := by
    rw [h_c2]; exact pow_ne_zero 2 h_c
  have h_c3_ne : env.get (i₀ + 2) ≠ 0 := by
    rw [h_c3]; exact mul_ne_zero h_c2_ne h_c
  refine ⟨?_, ?_⟩
  · rw [h_x (Or.inl h_c2_ne), h_c2]
  · rw [h_y (Or.inl h_c3_ne), h_c3, h_c2]; ring

theorem completeness :
    Completeness (F p) (Input := Input) (Output := Spec.Point) main Assumptions := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.ProverAssumptions,
    Element.Mul.circuit, Element.Mul.Assumptions]
  obtain ⟨h_c, h_c2⟩ := h_assumptions
  obtain ⟨h_c3, _⟩ := h_env
  have h_c2_ne : input_c2 ≠ 0 := by
    rw [h_c2]; exact pow_ne_zero 2 h_c
  refine ⟨h_c2_ne, ?_⟩
  rw [h_c3]
  exact mul_ne_zero h_c2_ne h_c

def circuit : FormalCircuit (F p) Input Spec.Point :=
  { main := main, elaborated := elaborated, Assumptions, Spec, soundness, completeness }

end Ragu.Circuits.Point.Denormalize
