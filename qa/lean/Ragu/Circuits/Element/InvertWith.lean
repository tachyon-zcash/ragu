import Clean.Circuit
import Ragu.Core
import Ragu.Circuits.Core.Mul

namespace Ragu.Circuits.Element.InvertWith
variable {p : ℕ} [Fact p.Prime]

structure Input (F : Type) where
  input : F
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- `invert_with` allocates a mul gate `(a, b, c)` with `a·b = c`, then
enforces `c = 1` (the `Invertible::alloc_with_advice` linking) and
`input = a` (the `enforce_invertible` linking), returning `b` as the
inverse wire. -/
def main (input : Var Input (F p))
    : Circuit (F p) (Expression (F p)) := do
  let ⟨input, inverse⟩ := input
  let ⟨a, b, c⟩ ← Core.mul fun env =>
    ⟨env input, inverse env, 1⟩
  assertZero (c - 1)
  assertZero (input - a)
  return b

def ProverAssumptions (input : ProverValue Input (F p))
    (_data : ProverData (F p)) (_hint : ProverHint (F p)) :=
  let inputValue : F p := input.input
  let inverse : F p := input.inverse
  inputValue * inverse = 1

def Spec (input : Value Input (F p))
    (out : F p) (_data : ProverData (F p)) :=
  input.input * out = 1

def ProverSpec (input : ProverValue Input (F p))
    (out : F p) (_hint : ProverHint (F p)) :=
  out = input.inverse

instance elaborated
    : ElaboratedCircuit (F p) Input field where
  main
  output _ offset := varFromOffset field (offset + 1)
  localLength _ := 3

theorem soundness :
    GeneralFormalCircuit.WithHint.Soundness (F p) elaborated (fun _ _ => True) Spec := by
  circuit_proof_start
  obtain ⟨h_mul, h_c, h_lin⟩ := h_holds
  -- h_mul : a * b = c, h_c : c - 1 = 0, h_lin : input - a = 0
  rw [add_neg_eq_zero] at h_c h_lin
  -- h_c : c = 1, h_lin : input = a
  rw [← h_lin, h_c] at h_mul
  exact h_mul

theorem completeness :
    GeneralFormalCircuit.WithHint.Completeness (F p) elaborated ProverAssumptions ProverSpec := by
  circuit_proof_start
  grind

def circuit : GeneralFormalCircuit.WithHint (F p) Input field :=
  { elaborated with Spec, ProverAssumptions, ProverSpec, soundness, completeness }

end Ragu.Circuits.Element.InvertWith
