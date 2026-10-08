import Clean.Circuit
import Clean.Utils.Primes
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.Normalize
variable {p : ℕ} [Fact p.Prime]

/-- The normalization data `Endoscalar::group_scale` computes before its
walk: `c = x / y`, `c² ` and `r = c² x`, so that the base point moves to
`(r, r)` on the isomorphic curve `y² = x³ + c⁶ b` under
`(x, y) ↦ (c² x, c³ y)`. -/
structure Output (F : Type) where
  c : F
  c2 : F
  r : F
deriving ProvableStruct

/-- The three gates of the normalization, in the order the Rust walk emits
them: `Divide ⟨x, y⟩`, `Square c`, `Mul ⟨c², x⟩`. The division's bank
discharge is the caller's (the point's coordinates are nonzero by curve
membership), so only the divide gate appears. -/
def main (input : Var Spec.Point (F p)) : Circuit (F p) (Var Output (F p)) := do
  let ⟨x, y⟩ := input
  let c ← Element.Divide.circuit ⟨x, y⟩
  let c2 ← Element.Square.circuit c
  let r ← Element.Mul.circuit ⟨c2, x⟩
  return ⟨c, c2, r⟩

/-- `y ≠ 0`: on the curves Ragu uses every affine point has nonzero
coordinates, which the walk's caller establishes. -/
def Assumptions (input : Spec.Point (F p)) :=
  input.y ≠ 0

def Spec (input : Spec.Point (F p)) (output : Output (F p)) :=
  output.c = input.x / input.y ∧
  output.c2 = output.c ^ 2 ∧
  output.r = output.c2 * input.x

instance elaborated : ElaboratedCircuit (F p) Spec.Point Output main where
  -- Divide (3) + Square (3) + Mul (3)
  localLength _ := 9
  output _ offset :=
    ⟨varFromOffset field offset,
     varFromOffset field (offset + 3 + 2),
     varFromOffset field (offset + 3 + 3 + 2)⟩
  output_eq := by
    intro input offset
    rcases input with ⟨x, y⟩
    simp [main, circuit_norm, Element.Divide.circuit, Element.Square.circuit,
      Element.Mul.circuit]

theorem soundness :
    Soundness (F p) (Input := Spec.Point) (Output := Output) main Assumptions Spec := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec]
  obtain ⟨h_div, h_sq, h_mul⟩ := h_holds
  exact ⟨h_div (Or.inl h_assumptions), h_sq, h_mul⟩

theorem completeness :
    Completeness (F p) (Input := Spec.Point) (Output := Output) main Assumptions := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.ProverAssumptions,
    Element.Square.circuit, Element.Square.Assumptions,
    Element.Mul.circuit, Element.Mul.Assumptions]
  exact h_assumptions

def circuit : FormalCircuit (F p) Spec.Point Output :=
  { main := main, elaborated := elaborated, Assumptions, Spec, soundness, completeness }

end Ragu.Circuits.Point.Normalize
