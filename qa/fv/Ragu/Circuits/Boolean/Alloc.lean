import Clean.Circuit
import Clean.Gadgets.Boolean
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Core.Mul

namespace Ragu.Circuits.Boolean.Alloc
variable {p : ℕ} [Fact p.Prime]

/-- `Boolean::alloc` constrains a wire to hold `0` or `1`.

Delegates the 3-wire `a * b = c` gate to `Core.mul`, feeding it
the row `(v, 1 - v, 0)` derived from the boolean hint, then asserts
`c = 0` (collapsing the gate to `a * b = 0`) and `1 - a - b = 0`
(binding `b = 1 - a`). Together: `a * (1 - a) = 0`, so `a ∈ {0, 1}`. -/
def main (hint : ProverEnvironment (F p) → Bool)
    : Circuit (F p) (Var field (F p)) := do
  let ⟨a, b, c⟩ ← Core.mul fun env =>
    let v : F p := if hint env then 1 else 0
    ⟨v, 1 - v, 0⟩
  assertZero c
  assertZero (1 - a - b)
  return a

def Assumptions (_input : Unit) (_data : ProverData (F p)) := True

def ProverAssumptions (_input : Bool) (_data : ProverData (F p)) (_hint : ProverHint (F p)) := True

/-- The verifier learns the output wire is boolean-valued. -/
def Spec (_input : Unit) (out : F p) (_data : ProverData (F p)) :=
  IsBool out

/-- The honest prover's output wire holds exactly the hint bit. Callers use
this to chain witness values through composed completeness proofs. -/
def ProverSpec (input : Bool) (out : F p) (_hint : ProverHint (F p)) :=
  out = if input then 1 else 0

/-- The output expression exported to parent layout proofs: the gate's first
wire, the boolean `main` returns. Keeping this separate from `main` lets
callers name the wire without unfolding the gate. -/
@[circuit_norm]
def output (offset : ℕ) : Expression (F p) :=
  varFromOffset field offset

instance elaborated
    : ElaboratedCircuit (F p) (UnconstrainedNative Bool) field main where
  localLength _ := 3
  output _ offset := output offset
  output_eq _ offset := by
    simp [main, output, circuit_norm, Core.mul]

theorem soundness
    : GeneralFormalCircuit.WithHint.Soundness (F p) (Input := (UnconstrainedNative Bool)) (Output := field) main Assumptions Spec := by
  circuit_proof_start
  obtain ⟨h_mul, h_c, h_lin⟩ := h_holds
  -- h_mul : a * b = c, h_c : c = 0, h_lin : 1 - a - b = 0
  rw [h_c] at h_mul
  rcases mul_eq_zero.mp h_mul with ha | hb
  · exact Or.inl ha
  · exact Or.inr (by linear_combination -h_lin - hb)

theorem completeness
    : GeneralFormalCircuit.WithHint.Completeness (F p) (Input := (UnconstrainedNative Bool)) (Output := field) main
        ProverAssumptions ProverSpec := by
  circuit_proof_start
  obtain ⟨_, hx, hy, hz⟩ := h_env
  -- hx : a = v, hy : b = 1 - v, hz : c = v * (1 - v), where v ∈ {0, 1}.
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · rw [hz]; by_cases h : input <;> simp [h]
  · rw [hx, hy]; ring
  · exact hx

def circuit : GeneralFormalCircuit.WithHint (F p) (UnconstrainedNative Bool) field :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    ProverAssumptions := ProverAssumptions,
    ProverSpec := ProverSpec,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Boolean.Alloc
