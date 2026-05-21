import Clean.Circuit
import Clean.Circuit.Loops
import Ragu.Circuits.Element.Mul

namespace Ragu.Circuits.Element.Fold
variable {p : ℕ} [Fact p.Prime]

/-- `Element::fold` is a variadic Horner reduction in Rust: given
elements `[x₀, x₁, …, x_{n-1}]` and a scale factor `s`, returns
`((…((x₀·s + x₁)·s + x₂)…)·s + x_{n-1})`, with the empty-input case
returning zero. This Lean reimpl is polymorphic on `n : ℕ`, mirroring
the Rust gadget's full generality.

The `n+3` branch uses `Circuit.foldl (.finRange (n+1))` per
mitschabaude's PR #710 review. The body `fun acc i => Mul.circuit
⟨acc + xs[i+1], s⟩` returns the fresh `Mul` wire (an offset-relative
`var`), which is `ConstantOutput` — independent of both `acc` and the
iteration index. The first Horner step (`xs[0] * s`) is done *outside*
the loop as an explicit `Mul.circuit ⟨xs[0], s⟩`, threading the
resulting wire into the foldl as `init`. The final `+ xs[n+2]` adds
the last element after the loop (Horner's trailing addition has no
multiplication). The `0`, `1`, `2` branches handle the cases where the
loop would be empty (`Fin 0` is not `Inhabited`) or absent. -/
structure Input (n : ℕ) (F : Type) where
  xs : Vector F n
  s : F
deriving ProvableStruct

def main : (n : ℕ) → Var (Input n) (F p) → Circuit (F p) (Expression (F p))
  | 0, _ => pure 0
  | 1, input => pure input.xs[0]
  | 2, input => do
    let scaled ← Mul.circuit ⟨input.xs[0], input.s⟩
    pure (scaled + input.xs[1])
  | n+3, input => do
    let scaled_0 ← Mul.circuit ⟨input.xs[0], input.s⟩
    let scaled_last ← Circuit.foldl (.finRange (n+1)) scaled_0 fun acc i =>
      Mul.circuit ⟨acc + input.xs[i.val + 1], input.s⟩
    pure (scaled_last + input.xs[n+2])

def Assumptions {n : ℕ} (_input : Input n (F p)) := True

/-- For `n = 0` the output is `0` (matching `Element::zero`).
For `n ≥ 1` the output is the Horner reduction of `xs` with scale `s`. -/
def Spec {n : ℕ} (input : Input n (F p)) (output : F p) :=
  output = match n, input.xs with
    | 0, _ => 0
    | m+1, xs => Fin.foldl m
        (fun acc (i : Fin m) => acc * input.s + xs[i.val + 1]) xs[0]

instance elaborated (n : ℕ) : ElaboratedCircuit (F p) (Input n) field where
  main := main n
  localLength _ := 3 * (n - 1)
  localLength_eq input offset := by
    rcases n with _ | _ | _ | n
    · simp [main, circuit_norm]
    · simp [main, circuit_norm]
    · simp +arith [main, circuit_norm, Mul.circuit]
    · simp +arith [main, circuit_norm, Mul.circuit]
  subcircuitsConsistent input offset := by
    rcases n with _ | _ | _ | n
    · simp [main, circuit_norm]
    · simp [main, circuit_norm]
    · simp +arith [main, circuit_norm, Mul.circuit]
    · simp +arith [main, circuit_norm, Mul.circuit]

-- For n+3 elements, each foldl Mul wire `wire(k) = env.get (i₀+3+k*3+2)`
-- holds `horner(k+1) * s`, where `horner` is the value-level Horner partial.
-- Sidesteps the `field (F p) = F p` HPow snag the same way as
-- `EnforceRootOfUnity.wire_value_eq_pow`: parameterize by `xs_val : Vector
-- (F p) _` and `s_val : F p`.
omit [Fact p.Prime] in
private theorem wire_value_eq_horner (n : ℕ) (env : Environment (F p))
    (xs_val : Vector (F p) (n+3)) (s_val : F p) (i₀ : ℕ)
    (h0 : env.get (i₀ + 2) = xs_val[0] * s_val)
    (h_iter0 : env.get (i₀ + 3 + 2) =
      (env.get (i₀ + 2) + xs_val[1]) * s_val)
    (h_iterk : ∀ (i : ℕ) (_ : i + 1 < n + 1),
        env.get (i₀ + 3 + (i + 1) * 3 + 2) =
          (env.get (i₀ + 3 + i * 3 + 2) + xs_val[i + 2]) * s_val) :
    ∀ (k : ℕ) (_ : k ≤ n),
      env.get (i₀ + 3 + k * 3 + 2) =
        (Fin.foldl (k + 1) (fun acc (i : Fin (k + 1)) =>
          acc * s_val + xs_val[i.val + 1]'(by omega))
          xs_val[0]) * s_val := by
  intro k hk
  induction k with
  | zero =>
    simp only [zero_mul, add_zero]
    rw [h_iter0, h0, Fin.foldl_succ_last, Fin.foldl_zero]
    simp
  | succ k ih =>
    have ih' := ih (by omega)
    have hstep := h_iterk k (by omega)
    rw [hstep, ih']
    -- Peel only the RHS Fin.foldl (k+1+1).
    conv_rhs => rw [Fin.foldl_succ_last]
    simp [Fin.val_last, Fin.val_castSucc]

theorem soundness (n : ℕ) :
    Soundness (F p) (elaborated n) Assumptions Spec := by
  rcases n with _ | _ | _ | n
  · -- 0 elements
    circuit_proof_start
  · -- 1 element: goal is eval input_var.xs[0] = Fin.foldl 0 ... = input.xs[0].
    circuit_proof_start
    simp only [Fin.foldl_zero]
    have := congrArg (fun v => v.xs[0]) h_input
    simpa [Vector.getElem_map] using this
  · -- 2 elements
    circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]
    -- h_holds : env.get (i₀ + 2) = eval xs[0] * eval s
    -- Goal: env.get (i₀ + 2) + eval xs[1] = Fin.foldl 1 val_body input.xs[0]
    have h_s : Expression.eval env input_var.s = input.s := congrArg Input.s h_input
    have h_xs0 : Expression.eval env input_var.xs[0] = input.xs[0] := by
      have heq : Vector.map (Expression.eval env) input_var.xs = input.xs :=
        congrArg Input.xs h_input
      have := congrArg (fun v => v[0]) heq
      simpa [Vector.getElem_map] using this
    have h_xs1 : Expression.eval env input_var.xs[1] = input.xs[1] := by
      have heq : Vector.map (Expression.eval env) input_var.xs = input.xs :=
        congrArg Input.xs h_input
      have := congrArg (fun v => v[1]) heq
      simpa [Vector.getElem_map] using this
    rw [h_xs0, h_s] at h_holds
    -- Fin.foldl 1 val_body xs[0] = val_body xs[0] ⟨0,_⟩ = xs[0]*s + xs[1]
    rw [Fin.foldl_succ_last, Fin.foldl_zero, h_holds, h_xs1]
  · -- n+3 elements
    circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]
    obtain ⟨h0, h_iter0, h_iterk⟩ := h_holds
    have h_s : Expression.eval env input_var.s = input.s := congrArg Input.s h_input
    have heq : Vector.map (Expression.eval env) input_var.xs = input.xs :=
      congrArg Input.xs h_input
    have h_xs : ∀ (i : ℕ) (hi : i < n + 3),
        Expression.eval env (input_var.xs[i]'hi) = input.xs[i]'hi := by
      intro i hi
      have := congrArg (fun v => v[i]'hi) heq
      simpa [Vector.getElem_map] using this
    -- Promote h0 to value-level form.
    rw [h_xs 0 (by omega), h_s] at h0
    -- Build h_iter0' in value form via convert.
    have h_iter0' : env.get (i₀ + 3 + 2) =
        (env.get (i₀ + 2) + input.xs[1]) * input.s := by
      have e1 := h_xs 1 (by omega)
      have heq0 : (input_var.xs[0 + 1] : Expression (F p)) = input_var.xs[1] := by
        congr 1
      rw [heq0, e1, h_s] at h_iter0
      exact h_iter0
    -- Build h_iterk' in value form.
    have h_iterk' : ∀ (i : ℕ) (_ : i + 1 < n + 1),
        env.get (i₀ + 3 + (i + 1) * 3 + 2) =
          (env.get (i₀ + 3 + i * 3 + 2) + input.xs[i + 2]'(by omega)) * input.s := by
      intro i hi
      have e2 := h_xs (i + 2) (by omega)
      have heqi : (input_var.xs[i + 1 + 1] : Expression (F p)) = input_var.xs[i + 2] := by
        congr 1
      have := h_iterk i hi
      rw [heqi, e2, h_s] at this
      exact this
    -- Apply wire_value_eq_horner at k = n.
    have wire_n := wire_value_eq_horner n env input.xs input.s i₀ h0 h_iter0' h_iterk' n (le_refl n)
    -- Goal: env.get (i₀ + 3 + (n + 1 - 1)*3 + 2) + eval xs[n+2] = Fin.foldl (n+2) val_body input.xs[0]
    rw [show n + 1 - 1 = n from by omega, h_xs (n + 2) (by omega), wire_n]
    -- Goal: Fin.foldl (n+1) ... * s + xs[n+2] = Fin.foldl (n+2) ...
    conv_rhs => rw [Fin.foldl_succ_last]
    simp [Fin.val_last, Fin.val_castSucc]

theorem completeness (n : ℕ) :
    Completeness (F p) (elaborated n) Assumptions := by
  rcases n with _ | _ | _ | n
  · circuit_proof_start
  · circuit_proof_start
  · circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]
  · circuit_proof_start [Mul.circuit, Mul.Assumptions, Mul.Spec]

def circuit (n : ℕ) : FormalCircuit (F p) (Input n) field :=
  { elaborated n with
    Assumptions
    Spec
    soundness := soundness n
    completeness := completeness n }

end Ragu.Circuits.Element.Fold
