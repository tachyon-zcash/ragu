import Clean.Circuit
import Ragu.Core
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.EnforceNonzero

namespace Ragu.Circuits.Element.DivNonzero
variable {p : ℕ} [Fact p.Prime]

/-- `Input` carries the numerator `x`, the divisor `y`, and a prover hint
with `1 / y` used by the in-circuit `enforce_nonzero(y)` discharge. -/
structure Input (F : Type) where
  x : F
  y : F
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- `Element::div_nonzero(&y)` is `y.enforce_nonzero(...)` followed by
`x.divide(&y_nonzero)`. The Lean reimpl composes the two sub-gadgets the
same way Rust does, rather than inlining their `Core.mul` rows:

  1. `EnforceNonzero.circuit ⟨y, inverse⟩` discharges `y ≠ 0` and returns
     the `Nonzero` wire (constrained `= y`).
  2. `Divide.circuit ⟨x, y_nonzero⟩` links its denominator against that
     wire — mirroring `Rust::divide`'s use of `y_nonzero.wire()`. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var field (F p)) := do
  let ⟨x, y, inverse⟩ := input
  let y_nonzero ← Element.EnforceNonzero.circuit ⟨y, inverse⟩
  Element.Divide.circuit ⟨x, y_nonzero⟩

/-- Verifier side: the circuit *itself* discharges `y ≠ 0` via the
`Invertible::alloc` half, so no precondition is required for soundness.
The spec pins `out = x / y`. -/
def Spec (input : Value Input (F p))
    (out : field (F p)) (_data : ProverData (F p)) :=
  out = input.x / input.y

/-- Prover-side assumptions: `y ≠ 0` so the supplied inverse hint is
coherent. -/
def ProverAssumptions (input : ProverValue Input (F p))
    (_data : ProverData (F p)) (_hint : ProverHint (F p)) :=
  let yValue : F p := input.y
  let inverse : F p := input.inverse
  yValue * inverse = 1

instance elaborated : ElaboratedCircuit (F p) Input field where
  main
  output _ offset := varFromOffset field (offset + 3)
  localLength _ := 6

theorem soundness :
    GeneralFormalCircuit.WithHint.Soundness (F p) elaborated (fun _ _ => True) Spec := by
  -- Compose: EnforceNonzero.Spec gives `y_nonzero = y ∧ y ≠ 0`; Divide.Spec
  -- gives `out = x / y_nonzero`; discharge Divide.Assumptions via `y ≠ 0`.
  circuit_proof_start [Element.EnforceNonzero.circuit, Element.EnforceNonzero.Spec,
    Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec]
  obtain ⟨⟨h_en, h_ne⟩, h_div⟩ := h_holds
  have h_ne' : env.get i₀ ≠ 0 := h_en ▸ h_ne
  rw [h_div (Or.inl h_ne'), h_en]

theorem completeness :
    GeneralFormalCircuit.WithHint.Completeness (F p) elaborated ProverAssumptions
      (fun _ _ _ => True) := by
  -- ProverAssumptions `y * inverse = 1` discharges EnforceNonzero's prover
  -- assumption; the returned wire `= y ≠ 0` discharges Divide's.
  circuit_proof_start [Element.EnforceNonzero.circuit, Element.EnforceNonzero.ProverAssumptions,
    Element.EnforceNonzero.Spec, Element.Divide.circuit, Element.Divide.ProverAssumptions]
  obtain ⟨h_en_spec, _⟩ := h_env
  obtain ⟨h_eq, h_ne⟩ := h_en_spec h_assumptions
  exact ⟨h_assumptions, h_eq ▸ h_ne⟩

def circuit : GeneralFormalCircuit.WithHint (F p) Input field where
  elaborated
  Spec
  ProverAssumptions
  soundness
  completeness

end Ragu.Circuits.Element.DivNonzero
