import Clean.Circuit
import Ragu.Core
import Ragu.Circuits.Core.Mul

namespace Ragu.Circuits.Element.Divide
variable {p : ℕ} [Fact p.Prime]

/-- Bare divide sub-circuit: the building block underlying
`Element::divide(&Nonzero)`. Takes a numerator `x` and a divisor `y` that
the caller has already proven nonzero by some external means
(`NonzeroBank::scope` discharge in production; `EnforceNonzero` directly
in `Element/DivNonzero`). The sub-circuit emits only the divide gate
itself — it does *not* discharge `y ≠ 0` on its own. -/
structure Input (F : Type) where
  x : F
  y : F
deriving ProvableStruct

/-- `quotient · denominator = numerator`, with the linking constraints
`numerator = x` and `denominator = y`. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var field (F p)) := do
  let { x, y } := input
  let ⟨quotient, denominator, numerator⟩ ← Core.mul fun eval =>
    ⟨(eval x) / (eval y), (eval y), (eval x)⟩
  assertZero (x - numerator)
  assertZero (y - denominator)
  return quotient

/-- Honest prover needs `y ≠ 0` to provide a coherent quotient. -/
def ProverAssumptions (input : Input (F p))
    (_data : ProverData (F p)) (_hint : ProverHint (F p)) :=
  input.y ≠ 0

/-- Verifier side: the circuit enforces `quotient · y = x`. When
`y ≠ 0`, this pins `quotient = x / y`. When `y = 0 ∧ x ≠ 0` no witness
exists; when `y = 0 ∧ x = 0` the quotient is unconstrained but the
premise is false. Callers are responsible for `(x, y) ≠ (0, 0)`. -/
def Assumptions (input : Input (F p)) (_data : ProverData (F p)) :=
  input.y ≠ 0 ∨ input.x ≠ 0

def Spec (input : Input (F p))
    (out : field (F p)) (_data : ProverData (F p)) :=
  out = input.x / input.y

instance elaborated : ElaboratedCircuit (F p) Input field where
  main
  output _ offset := varFromOffset field offset
  localLength _ := 3

theorem soundness : GeneralFormalCircuit.Soundness (F p) elaborated Assumptions Spec := by
  circuit_proof_start
  obtain ⟨c1, c2, c3⟩ := h_holds
  rw [add_neg_eq_zero] at c2 c3
  rw [← c2, ← c3] at c1
  have hy : input_y ≠ 0 := by
    rcases h_assumptions with hy | hx
    · exact hy
    · intro hy0
      rw [hy0, mul_zero] at c1
      exact hx c1.symm
  exact (eq_div_iff hy).mpr c1

theorem completeness
    : GeneralFormalCircuit.Completeness (F p) elaborated ProverAssumptions
        (fun _ _ _ => True) := by
  circuit_proof_start
  grind

def circuit : GeneralFormalCircuit (F p) Input field :=
  { elaborated with
    Assumptions := Assumptions,
    Spec := Spec,
    ProverAssumptions := ProverAssumptions,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Element.Divide
