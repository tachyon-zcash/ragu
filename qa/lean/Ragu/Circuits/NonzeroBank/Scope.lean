import Clean.Circuit
import Clean.Circuit.Loops
import Ragu.Core
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.EnforceNonzero

namespace Ragu.Circuits.NonzeroBank.Scope
variable {p : ℕ} [Fact p.Prime]

/-- `Input` carries the `K` factors folded into the bank and a prover
hint with the inverse of their product, used by the discharge at scope
end. -/
structure Input (K : ℕ) (F : Type) where
  factors : Vector F K
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- `NonzeroBank::scope` over `K` factors, polymorphic on `K : ℕ` (the
Rust extractor `NonzeroBankScopeInstance<const K>` is likewise generic;
the autogen + formal instance pin one concrete `K` at a time). Mirrors
the Rust body:

```rust
NonzeroBank::scope(dr, |dr, bank| {
    for factor in factors { bank.fold(dr, factor)?; }
    Ok(())
})
```

Each `bank.fold` multiplies the new factor into the running product (one
`Element::mul`, starting from `1`); at scope end the bank discharges
`product ≠ 0` via `Element::enforce_nonzero`. By multiplicative
integrality (`F` is a field), `product ≠ 0` implies each factor is
nonzero — the reusable lemma this circuit anchors.

The `K + 1` branch uses `Circuit.foldl (.finRange (K+1))` with `init = 1`:
the body `Mul.circuit ⟨acc, factors[i]⟩` returns the fresh `Mul` product
wire, which is `ConstantOutput` (independent of both `acc` and the
index), so `foldl.output_eq` / `.soundness` / `.completeness` fire under
`circuit_norm`. `K = 0` is split out because `Fin 0` is not `Inhabited`;
there the running product is the constant `1`, discharged directly. -/
def main : (K : ℕ) → Var (Input K) (F p) → Circuit (F p) Unit
  | 0, input => do
      let _ ← Element.EnforceNonzero.circuit { input := 1, inverse := input.inverse }
      pure ()
  | K + 1, input => do
      let prod ← Circuit.foldl (.finRange (K + 1)) (1 : Expression (F p)) fun acc i =>
        Element.Mul.circuit ⟨acc, input.factors[i]⟩
      let _ ← Element.EnforceNonzero.circuit { input := prod, inverse := input.inverse }
      pure ()

/-- Verifier side: the discharge witnesses that the running product is
nonzero, which (since `F p` is a field) implies every factor is
nonzero. -/
def Spec (K : ℕ) (input : Value (Input K) (F p))
    (_out : Unit) (_data : ProverData (F p)) :=
  let factors : Vector (F p) K := input.factors
  ∀ i : Fin K, factors[i] ≠ 0

/-- Prover side: the running product `∏ factors` must be invertible, so
the supplied inverse hint is coherent (equivalently, every factor is
nonzero). -/
def ProverAssumptions (K : ℕ) (input : ProverValue (Input K) (F p))
    (_data : ProverData (F p)) (_hint : ProverHint (F p)) :=
  let factors : Vector (F p) K := input.factors
  let inverse : F p := input.inverse
  (∏ i : Fin K, factors[i]) * inverse = 1

instance elaborated (K : ℕ) : ElaboratedCircuit (F p) (Input K) unit where
  main := main K
  output _ _ := ()
  -- K Mul gates (3 wires each) + 1 EnforceNonzero (3 wires) = 3·(K+1).
  localLength _ := 3 * (K + 1)
  localLength_eq := by
    rcases K with _ | K
    · simp [main, circuit_norm, Element.EnforceNonzero.circuit]
    · simp +arith [main, circuit_norm, Element.Mul.circuit, Element.EnforceNonzero.circuit]
  subcircuitsConsistent := by
    rcases K with _ | K
    · simp [main, circuit_norm, Element.EnforceNonzero.circuit]
    · simp +arith [main, circuit_norm, Element.Mul.circuit, Element.EnforceNonzero.circuit]

-- The running-product wire after `k` folds equals the product of the
-- first `k+1` factors. Parameterized over an explicit `env` and value-level
-- `factors_val` to sidestep the `field (F p) = F p` HPow/typeclass snag at
-- the `have`-site (cf. `EnforceRootOfUnity.wire_value_eq_pow`,
-- `Fold.wire_value_eq_horner`). `omit` doesn't bind through a `/-- -/`
-- docstring, so this comment is line-style.
omit [Fact p.Prime] in
private theorem wire_value_eq_prod (K : ℕ) (env : Environment (F p))
    (factors_val : Vector (F p) (K + 1)) (i₀ : ℕ)
    (h0 : env.get (i₀ + 2) = factors_val[0])
    (hk : ∀ (i : ℕ) (_ : i + 1 < K + 1),
        env.get (i₀ + (i + 1) * 3 + 2) =
          env.get (i₀ + i * 3 + 2) * factors_val[i + 1]) :
    ∀ (k : ℕ) (_ : k ≤ K),
      env.get (i₀ + k * 3 + 2) = ∏ j : Fin (k + 1), factors_val[j.val]'(by omega) := by
  intro k hle
  induction k with
  | zero =>
    simp only [zero_mul, add_zero]
    rw [h0, Fin.prod_univ_one]
    rfl
  | succ k ih =>
    have ih' := ih (by omega)
    have hstep := hk k (by omega)
    rw [hstep, ih']
    conv_rhs => rw [Fin.prod_univ_castSucc]
    simp [Fin.val_last, Fin.val_castSucc]

theorem soundness (K : ℕ) :
    GeneralFormalCircuit.WithHint.Soundness (F p) (elaborated K) (fun _ _ => True) (Spec K) := by
  rcases K with _ | K
  · -- K = 0: Spec is `∀ i : Fin 0, …`, vacuously true.
    circuit_proof_start [Element.EnforceNonzero.circuit, Element.EnforceNonzero.Spec]
    intro i
    exact i.elim0
  · -- K + 1
    circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
      Element.EnforceNonzero.circuit, Element.EnforceNonzero.Spec]
    obtain ⟨⟨h0, hk⟩, _, h_disc⟩ := h_holds
    -- Work with the evaluated factor vector; reconcile with `input.factors` at the end.
    set fv : Vector (F p) (K + 1) := Vector.map (Expression.eval env) input_var.factors with hfv
    have heq : fv = input.factors := h_input.1
    have h0' : env.get (i₀ + 2) = fv[0] := by
      rw [hfv]; simpa [Vector.getElem_map] using h0
    have hk' : ∀ (i : ℕ) (hi : i + 1 < K + 1),
        env.get (i₀ + (i + 1) * 3 + 2) = env.get (i₀ + i * 3 + 2) * fv[i + 1] := by
      intro i hi
      rw [hfv]; simpa [Vector.getElem_map] using hk i hi
    -- The discharge wire is the running product over all K+1 factors.
    have wire_K := wire_value_eq_prod K env fv i₀ h0' hk' K (le_refl K)
    rw [show K + 1 - 1 = K from by omega, wire_K] at h_disc
    -- h_disc : (∏ j : Fin (K+1), fv[j.val]) ≠ 0, where `fv` is a genuine Vector.
    rw [Finset.prod_ne_zero_iff (f := fun j : Fin (K + 1) => fv[(j : ℕ)])] at h_disc
    intro i
    rw [← heq]
    exact h_disc i (Finset.mem_univ i)

theorem completeness (K : ℕ) :
    GeneralFormalCircuit.WithHint.Completeness (F p) (elaborated K) (ProverAssumptions K)
      (fun _ _ _ => True) := by
  rcases K with _ | K
  · -- K = 0
    circuit_proof_start [Element.EnforceNonzero.circuit, Element.EnforceNonzero.ProverAssumptions]
    simpa using h_assumptions
  · -- K + 1
    circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
      Element.EnforceNonzero.circuit, Element.EnforceNonzero.ProverAssumptions]
    obtain ⟨⟨h0, hk⟩, _⟩ := h_env
    set fv : Vector (F p) (K + 1) :=
      Vector.map (Expression.eval env.toEnvironment) input_var.factors with hfv
    have heq : fv = input.factors := h_input.1
    have h0' : env.get (i₀ + 2) = fv[0] := by
      rw [hfv]; simpa [Vector.getElem_map] using h0
    have hk' : ∀ (i : ℕ) (hi : i + 1 < K + 1),
        env.get (i₀ + (i + 1) * 3 + 2) = env.get (i₀ + i * 3 + 2) * fv[i + 1] := by
      intro i hi
      rw [hfv]; simpa [Vector.getElem_map] using hk i hi
    have wire_K :=
      wire_value_eq_prod K env.toEnvironment fv i₀ h0' hk' K (le_refl K)
    rw [show K + 1 - 1 = K from by omega, wire_K, heq]
    exact h_assumptions

def circuit (K : ℕ) : GeneralFormalCircuit.WithHint (F p) (Input K) unit where
  elaborated := elaborated K
  Spec := Spec K
  ProverAssumptions := ProverAssumptions K
  soundness := soundness K
  completeness := completeness K

end Ragu.Circuits.NonzeroBank.Scope
