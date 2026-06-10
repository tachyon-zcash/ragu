import Clean.Circuit
import Ragu.Core
import Ragu.Circuits.Core.Mul

namespace Ragu.Circuits.Element.EnforceNonzero
variable {p : ℕ} [Fact p.Prime]

/-- `Input` carries the field element to be constrained nonzero, plus a
prover-side hint with its multiplicative inverse. -/
structure Input (F : Type) where
  input : F
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- `Element::enforce_nonzero(input)` allocates an `Invertible::alloc`
mul gate `(a, b, c)` with `a · b = c`, then enforces `c = 1` (so
`b = a⁻¹`) and `input = a` (linking the input to the discharged wire).
Witnessing the trace implies `input ≠ 0`. Mirroring Rust's
`enforce_nonzero(self) -> Nonzero(self)`, the circuit returns the
discharged wire `a` (constrained `= input`) so callers like
`Element::divide` can link against it. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var field (F p)) := do
  let ⟨input, inverse⟩ := input
  let ⟨a, _b, c⟩ ← Core.mul fun env =>
    ⟨env input, inverse env, 1⟩
  assertZero (c - 1)
  assertZero (input - a)
  return a

/-- Verifier-side spec: the returned wire equals the input (Rust's
`Nonzero(self)`), and the trace implies that input is nonzero. -/
def Spec (input : Value Input (F p))
    (out : field (F p)) (_data : ProverData (F p)) :=
  out = input.input ∧ input.input ≠ 0

/-- Prover-side assumption: the supplied inverse hint actually inverts
`input` (so the prover can satisfy `a · b = 1`). -/
def ProverAssumptions (input : ProverValue Input (F p))
    (_data : ProverData (F p)) (_hint : ProverHint (F p)) :=
  let inputValue : F p := input.input
  let inverse : F p := input.inverse
  inputValue * inverse = 1

instance elaborated : ElaboratedCircuit (F p) Input field where
  main
  output _ offset := varFromOffset field offset
  localLength _ := 3

theorem soundness :
    GeneralFormalCircuit.WithHint.Soundness (F p) elaborated (fun _ _ => True) Spec := by
  circuit_proof_start
  obtain ⟨h_mul, h_c, h_lin⟩ := h_holds
  -- h_mul : a * b = c, h_c : c - 1 = 0, h_lin : input - a = 0
  rw [add_neg_eq_zero] at h_c h_lin
  -- h_c : c = 1, h_lin : input = a (and a is the returned wire)
  refine ⟨h_lin.symm, ?_⟩
  intro h0
  rw [← h_lin, h_c] at h_mul
  -- h_mul : input.input * b = 1
  rw [h0, zero_mul] at h_mul
  exact zero_ne_one h_mul

theorem completeness :
    GeneralFormalCircuit.WithHint.Completeness (F p) elaborated ProverAssumptions
      (fun _ _ _ => True) := by
  circuit_proof_start
  grind

def circuit : GeneralFormalCircuit.WithHint (F p) Input field where
  elaborated
  Spec
  ProverAssumptions
  soundness
  completeness

end Ragu.Circuits.Element.EnforceNonzero
