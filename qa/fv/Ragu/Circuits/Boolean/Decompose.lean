import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Utils.Bits
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Boolean.Alloc

namespace Ragu.Circuits.Boolean.Decompose
open Utils.Bits
variable {p : ℕ} [Fact p.Prime]

/-- The recomposition `b₀ + 2·b₁ + 4·b₂ + ⋯ + 2ⁿ⁻¹·bₙ₋₁`, shaped exactly as
the extraction driver's linear-expression accumulator builds it for
`decompose`'s `lc.add(bit).gain(Two)` loop
(`qa/fv/extraction/src/linexp.rs`): the coefficient-one first term is
the bare wire, every later term is `const 2ⁱ * bᵢ` with the constant on the
left, and the sum is left-nested. An empty accumulator is the constant `0`.

`Utils.Bits.fieldFromBitsExpr` has the same value but a different tree (a
leading `0`, constants on the right: `0 + b₀ * 2⁰ + b₁ * 2¹ + ⋯`), and the
fingerprint compares trees, not values, so `main` uses this definition;
`eval_recomposeExpr` relates it to `fieldFromBits`. -/
def recomposeExpr : {n : ℕ} → Vector (Expression (F p)) n → Expression (F p)
  | 0, _ => 0
  | m + 1, bits =>
    Fin.foldl m
      (fun acc (i : Fin m) =>
        acc + Expression.const (2 ^ (i.val + 1)) * bits[i.val + 1]'(by have := i.isLt; omega))
      bits[0]

/-- `boolean.rs::decompose`: the canonical `n`-bit little-endian decomposition
of a field element — `multipack`'s inverse. In Rust, `decompose` uses `CAPACITY`
and `decompose_n` takes a const `N`. One `Boolean::alloc` per bit, with
honest witness `bit i = elem.to_le_bits()[i]`, then a single linear constraint
binding the weighted sum of the bits to the element. Mirrored here as
`Circuit.mapFinRange` over `Alloc.circuit` (the hint reads bit `i` of the
input's canonical representative) and one `assertZero` on `recomposeExpr`.

`n` bits with `2ⁿ < p` represent exactly `[0, 2ⁿ)`, with no wrapped alias, so
the decomposition is canonical; an element at or above `2ⁿ` has no
decomposition and the constraints are unsatisfiable.

The `0` arm matches `decompose_n::<_, 0>`, constraining `0 - input = 0`.

Sub-gadget: `decompose` is `pub(crate)` and reaches the constraint system only
through the `Extract` routine's `execute`, so it has no extraction instance of
its own. It is fingerprinted through `Endoscalar.Extract`, whose instance
drives the real `EndoscalarChallenge::from_element`. -/
def main : (n : ℕ) → Var field (F p) → Circuit (F p) (Var (fields n) (F p))
  | 0, input => do
    assertZero (recomposeExpr (#v[] : Vector (Expression (F p)) 0) - input)
    pure #v[]
  | n + 1, input => do
    let bits ← Circuit.mapFinRange (n + 1) fun (i : Fin (n + 1)) =>
      Alloc.circuit fun env => (env input).val.testBit i.val
    assertZero (recomposeExpr bits - input)
    pure bits

/-- Honest-prover precondition: the element is in range. An out-of-range
element has no `n`-bit decomposition. -/
def ProverAssumptions (n : ℕ) (input : F p) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) :=
  input.val < 2 ^ n

/-- Verifier-side contract — the same as Clean's `Gadgets.ToBits`: any
satisfying assignment places the element below `2ⁿ` and makes the output its
`n`-bit little-endian decomposition. There is no verifier-side precondition:
the range restriction is enforced by the circuit, not assumed. -/
def Spec (n : ℕ) (input : F p) (bits : Vector (F p) n) (_data : ProverData (F p)) :=
  input.val < 2 ^ n ∧ bits = fieldToBits n input

instance elaborated (n : ℕ) : ElaboratedCircuit (F p) field (fields n) (main n) where
  localLength _ := n * 3
  localLength_eq _ _ := by
    rcases n with _ | n
    · simp [main, circuit_norm]
    · simp [main, circuit_norm, Alloc.circuit]
  subcircuitsConsistent _ _ := by
    rcases n with _ | n
    · simp [main, circuit_norm]
    · simp [main, circuit_norm, Alloc.circuit]
  channelsLawful := by
    rcases n with _ | n
    · simp [main, circuit_norm]
    · simp [main, circuit_norm, Alloc.circuit]

/-! ## Bridging `recomposeExpr` to `Utils.Bits`

`eval_recomposeExpr` turns the mirror-shaped expression into Clean's
value-level `fieldFromBits`, so the canonicity facts of `Utils.Bits`
(`fieldToBits_fieldFromBits`, `fieldFromBits_lt`, `fieldFromBits_fieldToBits`)
do the number theory. The two `decomposition_*` lemmas state soundness and
completeness of the bit/sum constraints for an arbitrary family of bit
expressions `e`, which keeps the `Alloc` output terms abstract in the main
proofs. -/

private theorem eval_zero (env : Environment (F p)) :
    Expression.eval env (0 : Expression (F p)) = 0 := rfl

private theorem eval_recomposeExpr_succ (env : Environment (F p)) (m : ℕ) :
    ∀ bits : Vector (Expression (F p)) (m + 1),
      Expression.eval env (recomposeExpr bits) =
        fieldFromBits (bits.map (Expression.eval env)) := by
  induction m with
  | zero =>
    intro bits
    rw [fieldFromBits_succ 0]
    simp [recomposeExpr, fieldFromBits, fromBits]
  | succ m ih =>
    intro bits
    have h_pop := ih bits.pop
    simp only [recomposeExpr] at h_pop ⊢
    simp only [Vector.getElem_pop'] at h_pop
    rw [Fin.foldl_succ_last, fieldFromBits_succ (m + 1), ← Vector.map_pop]
    simp only [Expression.eval, Fin.val_castSucc, Fin.val_last]
    rw [h_pop]
    simp [Vector.getElem_map, mul_comm]

/-- Evaluating the recomposition expression gives `fieldFromBits` of the
evaluated bits. -/
theorem eval_recomposeExpr (env : Environment (F p)) {n : ℕ}
    (bits : Vector (Expression (F p)) n) :
    Expression.eval env (recomposeExpr bits) =
      fieldFromBits (bits.map (Expression.eval env)) := by
  cases n with
  | zero => simp [recomposeExpr, fieldFromBits, fromBits, eval_zero]
  | succ m => exact eval_recomposeExpr_succ env m bits

/-- Soundness of the decomposition constraints, for an arbitrary family of
bit expressions `e`: boolean bits whose recomposition equals `x` force
`x < 2ⁿ` and make the bits the decomposition of `x`. -/
private theorem decomposition_sound (env : Environment (F p)) {n : ℕ} (h_cap : 2 ^ n < p)
    (e : Fin n → Expression (F p)) (x : F p)
    (h_bool : ∀ i, IsBool (Expression.eval env (e i)))
    (h_sum : fieldFromBits (Vector.map (Expression.eval env) (Vector.mapFinRange n e)) - x = 0) :
    x.val < 2 ^ n ∧
      Vector.map (Expression.eval env) (Vector.mapFinRange n e) = fieldToBits n x := by
  generalize h_bits : Vector.map (Expression.eval env) (Vector.mapFinRange n e) = bits at h_sum ⊢
  have h_bits_bool : ∀ (i : ℕ) (hi : i < n), bits[i] = 0 ∨ bits[i] = 1 := by
    intro i hi
    rw [← h_bits]
    simp only [Vector.getElem_map, Vector.getElem_mapFinRange]
    exact h_bool ⟨i, hi⟩
  have hx : x = fieldFromBits bits := by linear_combination -h_sum
  subst hx
  exact ⟨fieldFromBits_lt bits h_bits_bool,
    (fieldToBits_fieldFromBits h_cap bits h_bits_bool).symm⟩

/-- Completeness of the decomposition constraints: if every bit expression
holds the corresponding bit of an in-range `x`, the recomposition equals `x`. -/
private theorem decomposition_complete (env : Environment (F p)) {n : ℕ}
    (e : Fin n → Expression (F p)) (x : F p) (hx : x.val < 2 ^ n)
    (h_bits : ∀ i : Fin n, Expression.eval env (e i) = if x.val.testBit i.val then 1 else 0) :
    Expression.eval env (recomposeExpr (Vector.mapFinRange n e)) - x = 0 := by
  rw [eval_recomposeExpr]
  have h_vec : Vector.map (Expression.eval env) (Vector.mapFinRange n e) = fieldToBits n x := by
    ext i hi
    simp only [Vector.getElem_map, Vector.getElem_mapFinRange, fieldToBits, toBits,
      Vector.getElem_mapRange, h_bits ⟨i, hi⟩]
    simp
  rw [h_vec, fieldFromBits_fieldToBits hx]
  ring

theorem soundness (n : ℕ) (h_cap : 2 ^ n < p) :
    GeneralFormalCircuit.Soundness (F p) (Input := field) (Output := (fields n)) (main n) (fun _ _ => True) (Spec n) := by
  rcases n with _ | n
  · circuit_proof_start
    rw [eval_recomposeExpr] at h_holds
    simp [fieldFromBits, fromBits] at h_holds
    subst h_holds
    exact ⟨by simp, (Array.eq_empty_of_size_eq_zero (Vector.size_toArray _)).symm⟩
  · circuit_proof_start [Alloc.circuit, Alloc.Assumptions, Alloc.Spec]
    obtain ⟨h_bool, h_sum⟩ := h_holds
    rw [eval_recomposeExpr] at h_sum
    exact decomposition_sound env h_cap _ input h_bool h_sum

theorem completeness (n : ℕ) :
    GeneralFormalCircuit.Completeness (F p) (Input := field) (Output := (fields n)) (main n) (ProverAssumptions n)
      (fun _ _ _ => True) := by
  rcases n with _ | n
  · circuit_proof_start
    have h0 : input = 0 := by
      rw [← ZMod.val_eq_zero]
      simpa [Nat.lt_one_iff] using h_assumptions
    rw [eval_recomposeExpr]
    simp [fieldFromBits, fromBits, h0]
  · circuit_proof_start [Alloc.circuit, Alloc.Assumptions, Alloc.Spec,
      Alloc.ProverAssumptions, Alloc.ProverSpec]
    exact decomposition_complete env.toEnvironment _ input h_assumptions (fun i => (h_env i).2)

def circuit (n : ℕ) (h_cap : 2 ^ n < p) : GeneralFormalCircuit (F p) field (fields n) :=
  { main := main n,
    elaborated := elaborated n,
    requirementsChannelsLawful := by
      rcases n with _ | n
      · simp [main, circuit_norm]
      · simp [main, circuit_norm, Alloc.circuit]
    Spec := Spec n
    ProverAssumptions := ProverAssumptions n
    soundness := soundness n h_cap
    completeness := completeness n }

end Ragu.Circuits.Boolean.Decompose
