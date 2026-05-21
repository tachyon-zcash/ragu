import Clean.Circuit
import Clean.Circuit.Loops
import Ragu.Circuits.Element.Mul

namespace Ragu.Circuits.Element.EnforceRootOfUnity
variable {p : ℕ} [Fact p.Prime]

/-- `Element::enforce_root_of_unity(k)` enforces `self ^ (2^k) = 1` by
squaring `k` times. This Lean reimpl is polymorphic on `k : ℕ`, mirroring
the Rust gadget's full generality (parameter `k : u32` in
`crates/ragu_primitives/src/element.rs::enforce_root_of_unity`).

Modeled as a `FormalAssertion`: the gadget is constraint-only (no
output), `Spec` acts as both assumption for completeness and conclusion
for soundness.

The `k+1` branch uses `Circuit.foldl (.finRange (k+1))` so that
`ConstantOutput` (the body's output is a fresh wire, independent of
`acc`) is auto-discharged and `foldl.output_eq` / `foldl.soundness` /
`foldl.completeness` fire under `circuit_norm`. The `k = 0` branch is
handled explicitly because `Inhabited (Fin 0)` doesn't exist. -/
def main : (k : ℕ) → Expression (F p) → Circuit (F p) (Var unit (F p))
  | 0, input => assertZero (input - 1)
  | k + 1, input => do
    let final ← Circuit.foldl (.finRange (k + 1)) input fun x _ => Mul.circuit ⟨x, x⟩
    assertZero (final - 1)

def Assumptions (_ : F p) := True

/-- The verifier learns `input ^ (2^k) = 1`. -/
def Spec (k : ℕ) (input : F p) :=
  input ^ (2 ^ k) = 1

instance elaborated (k : ℕ) : ElaboratedCircuit (F p) field unit where
  main := main k
  localLength _ := 3 * k
  localLength_eq := by
    rcases k with _ | k
    · simp [main, circuit_norm]
    · simp +arith [main, circuit_norm, Mul.circuit]
  subcircuitsConsistent := by
    rcases k with _ | k
    · simp [main, circuit_norm]
    · simp +arith [main, circuit_norm, Mul.circuit]

/-- Each wire in the squaring chain holds `x_val^(2^(i+1))`. Parameterized so
both soundness and completeness can apply it without the `field (F p) = F p`
typeclass-synthesis snag at the `have`-site. -/
private lemma wire_value_eq_pow (k : ℕ) (env : Environment (F p))
    (x_val : F p) (i₀ : ℕ)
    (h0 : env.get (i₀ + 2) = x_val * x_val)
    (hk : ∀ i, i + 1 < k + 1 →
          env.get (i₀ + (i + 1) * 3 + 2) =
            env.get (i₀ + i * 3 + 2) * env.get (i₀ + i * 3 + 2)) :
    ∀ i, i ≤ k → env.get (i₀ + i * 3 + 2) = x_val ^ (2 ^ (i + 1)) := by
  intro i hi
  induction i with
  | zero =>
    simp only [zero_mul, Nat.add_zero, zero_add, pow_one]
    rw [pow_two]
    exact h0
  | succ i ih =>
    have ih' := ih (by omega)
    have hstep := hk i (by omega)
    rw [hstep, ih', ← pow_add]
    congr 1
    rw [Nat.pow_succ]
    ring

theorem soundness (k : ℕ) :
    FormalAssertion.Soundness (F p) (elaborated k) Assumptions (Spec k) := by
  rcases k with _ | k
  · -- k=0: main = assertZero (input - 1); spec collapses to input = 1.
    circuit_proof_start
    rw [add_neg_eq_zero] at h_holds
    simp [pow_zero, h_holds]
  · -- k+1: chain of squarings; apply wire_value_eq_pow at i = k.
    circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]
    obtain ⟨⟨h0, hk⟩, h_final⟩ := h_holds
    have wire_k := wire_value_eq_pow k env input i₀ h0 hk k (le_refl k)
    simp only [Nat.add_sub_cancel] at h_final
    rw [add_neg_eq_zero, wire_k] at h_final
    exact h_final

theorem completeness (k : ℕ) :
    FormalAssertion.Completeness (F p) (elaborated k) Assumptions (Spec k) := by
  rcases k with _ | k
  · -- k=0: spec is input^1=1; goal is input - 1 = 0.
    circuit_proof_start
    rw [pow_zero, pow_one] at h_spec
    rw [h_spec]
    ring
  · -- k+1: canonical witnesses give the squaring chain; conclude the final wire = 1.
    circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]
    obtain ⟨h0, hk⟩ := h_env
    have wire_k :=
      wire_value_eq_pow k env.toEnvironment input i₀ h0 hk k (le_refl k)
    simp only [Nat.add_sub_cancel]
    rw [add_neg_eq_zero, wire_k]
    exact h_spec

def circuit (k : ℕ) : FormalAssertion (F p) field :=
  { elaborated k with
    Assumptions
    Spec := Spec k
    soundness := soundness k
    completeness := completeness k }

end Ragu.Circuits.Element.EnforceRootOfUnity
