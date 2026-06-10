import Clean.Circuit
import Clean.Utils.Primes
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.EnforceNonzero
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.DoubleAndAddIncomplete
variable {p : ℕ} [Fact p.Prime]

/-- Two input points, plus a prover-side inverse hint for the bank's
final product (`(x_q - x_p) · (x_p - x_r)`) that the trailing
`enforce_nonzero` discharges. -/
structure Inputs (F : Type) where
  P1 : Spec.Point F  -- the point to be doubled (Rust's `self`)
  P2 : Spec.Point F  -- the point to be added once (Rust's `other`)
  inverse : UnconstrainedDep field F
deriving CircuitType

/-- `Point::double_and_add_incomplete(other)` wrapped in
`NonzeroBank::scope`. Computes `2·P1 + P2` via the zcash trick:

  - λ₁ = (y₂ - y₁) / (x₂ - x₁) — slope through P1 and P2 (divide #1).
  - x_r = λ₁² - x₁ - x₂ — x-coord of P1 + P2.
  - λ₂ = 2y₁ / (x₁ - x_r) - λ₁ — slope through (P1 + P2) and P1
    (divide #2).
  - x_s = λ₂² - x_r - x₁; y_s = λ₂ (x₁ - x_s) - y₁.

  The bank folds in two factors `(x₂ - x₁)` and `(x₁ - x_r)`; the
  discharge at scope end proves their product is nonzero, which (since
  `F p` is a field) implies each is individually nonzero. -/
def main (input : Var Inputs (F p)) : Circuit (F p) (Var Spec.Point (F p)) := do
  let ⟨⟨x_p, y_p⟩, ⟨x_q, y_q⟩, inverse⟩ := input

  -- fold 1: running product = 1 · (x_q - x_p)
  let bank_prod_1 ← Element.Mul.circuit ⟨1, x_q - x_p⟩

  -- λ₁ = (y_q - y_p) / (x_q - x_p)
  let lambda_1 ← Element.Divide.circuit ⟨y_q - y_p, x_q - x_p⟩

  -- x_r = λ₁² - x_p - x_q
  let lambda_1_sq ← Element.Square.circuit lambda_1
  let x_r := lambda_1_sq - x_p - x_q

  -- fold 2: running product = bank_prod_1 · (x_p - x_r)
  let bank_prod_2 ← Element.Mul.circuit ⟨bank_prod_1, x_p - x_r⟩

  -- λ₂_half = 2 y_p / (x_p - x_r)
  let lambda_2_half ← Element.Divide.circuit ⟨y_p + y_p, x_p - x_r⟩
  let lambda_2 := lambda_2_half - lambda_1

  -- x_s = λ₂² - x_r - x_p
  let lambda_2_sq ← Element.Square.circuit lambda_2
  let x_s := lambda_2_sq - x_r - x_p

  -- y_s = λ₂ (x_p - x_s) - y_p
  let y_term ← Element.Mul.circuit ⟨lambda_2, x_p - x_s⟩
  let y_s := y_term - y_p

  -- scope-end discharge: bank_prod_2 ≠ 0
  let _ ← Element.EnforceNonzero.circuit { input := bank_prod_2, inverse }

  return ⟨x_s, y_s⟩

/-- Verifier-side assumptions: both inputs on curve. The discharge
forces both `x_q ≠ x_p` and `x_p ≠ x_r`. -/
def Assumptions (curveParams : Spec.CurveParams p)
    (input : Value Inputs (F p)) (_data : ProverData (F p)) :=
  input.P1.isOnCurve curveParams ∧
  input.P2.isOnCurve curveParams

/-- Prover-side: the bank's running product
`(x_q - x_p) · (x_p - x_r)` must be invertible. Equivalently, both
non-degeneracy conditions hold. -/
def ProverAssumptions (curveParams : Spec.CurveParams p)
    (input : ProverValue Inputs (F p)) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) :=
  let p1x : F p := input.P1.x
  let p2x : F p := input.P2.x
  let p1y : F p := input.P1.y
  let p2y : F p := input.P2.y
  let inverse : F p := input.inverse
  input.P1.isOnCurve curveParams ∧
  input.P2.isOnCurve curveParams ∧
  ∃ lambda_1 x_r,
    (p2x - p1x) * lambda_1 = p2y - p1y ∧
    x_r = lambda_1 ^ 2 - p1x - p2x ∧
    ((p2x - p1x) * (p1x - x_r)) * inverse = 1

/-- Spec: the output is `2·P1 + P2`, stated via two affine additions
(`P1 + P2 = r`, then `r + P1 = output`), both of which are forced by
the discharge to be well-defined. -/
def Spec (curveParams : Spec.CurveParams p)
    (input : Value Inputs (F p)) (output : Value Spec.Point (F p))
    (_data : ProverData (F p)) :=
  ∃ r, input.P1.add_incomplete input.P2 = some r ∧
    r.add_incomplete input.P1 = some output ∧
    output.isOnCurve curveParams

instance elaborated :
    ElaboratedCircuit (F p) Inputs Spec.Point where
  main
  -- fold1 (3) + divide1 (3) + square1 (3) + fold2 (3) + divide2 (3)
  -- + square2 (3) + mul_for_y (3) + discharge (3) = 24
  localLength _ := 24

theorem soundness (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint.Soundness (F p) elaborated
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.EnforceNonzero.circuit, Element.EnforceNonzero.Spec]
  obtain ⟨h_P1_eq, h_P2_eq, _⟩ := h_input
  obtain ⟨h_curve1, h_curve2⟩ := h_assumptions
  obtain ⟨h_bank1, h_div1, h_sq1, h_bank2, h_div2, h_sq2, h_yterm, _, h_nz⟩ := h_holds
  rw [← h_P1_eq] at h_curve1
  rw [← h_P2_eq] at h_curve2
  rw [← h_P1_eq, ← h_P2_eq]
  set x_p := Expression.eval env input_var.1.x
  set y_p := Expression.eval env input_var.1.y
  set x_q := Expression.eval env input_var.2.x
  set y_q := Expression.eval env input_var.2.y
  -- bank_prod_2 = (x_q - x_p) · (x_p - x_r), and discharge says it ≠ 0
  rw [h_bank1] at h_bank2
  rw [h_bank2] at h_nz
  have h_xqxp_ne : x_q + -x_p ≠ 0 := fun h => h_nz (by rw [h, zero_mul])
  have h_xpxr_ne : x_p + -(env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q) ≠ 0 :=
    fun h => h_nz (by rw [h, mul_zero])
  have h_lam1 : env.get (i₀ + 3) = (y_q + -y_p) / (x_q + -x_p) := h_div1 (Or.inl h_xqxp_ne)
  have h_lam2half :
      env.get (i₀ + 3 + 3 + 3 + 3) =
        (y_p + y_p) / (x_p + -(env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) :=
    h_div2 (Or.inl h_xpxr_ne)
  have h_x_ne : x_p ≠ x_q := fun h => h_xqxp_ne (by rw [h]; ring)
  have h_r_ne_xp : (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q) ≠ x_p :=
    fun h => h_xpxr_ne (by rw [h]; ring)
  have h_diff_ne : x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q) ≠ 0 := by
    rw [sub_eq_add_neg]; exact h_xpxr_ne
  have h_lam2_mul :
      env.get (i₀ + 3 + 3 + 3 + 3) * (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) = y_p + y_p := by
    rw [sub_eq_add_neg, h_lam2half, div_mul_cancel₀ _ h_xpxr_ne]
  have h_slope :
      (y_p - (env.get (i₀ + 3) *
            (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) - y_p)) /
          (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) =
        env.get (i₀ + 3 + 3 + 3 + 3) - env.get (i₀ + 3) := by
    rw [show y_p - (env.get (i₀ + 3) *
                (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) - y_p) =
            y_p + y_p - env.get (i₀ + 3) *
                (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) by ring]
    rw [← h_lam2_mul,
        show env.get (i₀ + 3 + 3 + 3 + 3) *
              (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) -
            env.get (i₀ + 3) * (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) =
          (env.get (i₀ + 3 + 3 + 3 + 3) - env.get (i₀ + 3)) *
            (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) by ring]
    exact mul_div_cancel_right₀ _ h_diff_ne
  -- The intermediate point r = P1 + P2.
  have h_add_eq1 :
      ({ x := x_p, y := y_p } : Spec.Point (F p)).add_incomplete { x := x_q, y := y_q } =
        some { x := env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q,
               y := env.get (i₀ + 3) *
                      (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) - y_p } := by
    simp only [Spec.Point.add_incomplete, if_neg h_x_ne, Option.some.injEq, Spec.Point.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [h_sq1, h_lam1]; ring
    · rw [h_sq1, h_lam1]; ring
  have h_add_eq2 :
      ({ x := env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q,
         y := env.get (i₀ + 3) *
                (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) - y_p } :
            Spec.Point (F p)).add_incomplete { x := x_p, y := y_p } =
        some { x := env.get (i₀ + 3 + 3 + 3 + 3 + 3 + 2) +
                      -(env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q) + -x_p,
               y := env.get (i₀ + 3 + 3 + 3 + 3 + 3 + 3 + 2) + -y_p } := by
    simp only [Spec.Point.add_incomplete, if_neg h_r_ne_xp, Option.some.injEq, Spec.Point.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [h_slope, h_sq2]; ring
    · rw [h_slope, h_yterm, h_sq2]
      linear_combination (-h_lam2_mul)
  refine ⟨_, h_add_eq1, h_add_eq2, ?_⟩
  have h_r_curve := by
    simpa [h_add_eq1] using Lemmas.add_incomplete_preserves_membership
      { x := x_p, y := y_p } { x := x_q, y := y_q } curveParams h_x_ne h_curve1 h_curve2
  simpa [h_add_eq2] using Lemmas.add_incomplete_preserves_membership
    { x := env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q,
      y := env.get (i₀ + 3) *
            (x_p - (env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q)) - y_p }
    { x := x_p, y := y_p } curveParams h_r_ne_xp h_r_curve h_curve1

theorem completeness (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint.Completeness (F p) elaborated
      (ProverAssumptions curveParams) (fun _ _ _ => True) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Element.Divide.circuit, Element.Divide.ProverAssumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.EnforceNonzero.circuit, Element.EnforceNonzero.ProverAssumptions]
  obtain ⟨h_P1_eq, h_P2_eq, _⟩ := h_input
  obtain ⟨_, _, lambda_1, x_r, h_lam, h_xr, h_invasm⟩ := h_assumptions
  obtain ⟨h_bank1_env, h_div1_env, h_sq1_env, h_bank2_env, _, _, _, _⟩ := h_env
  set x_p := Expression.eval env.toEnvironment input_var.1.x
  set y_p := Expression.eval env.toEnvironment input_var.1.y
  set x_q := Expression.eval env.toEnvironment input_var.2.x
  set y_q := Expression.eval env.toEnvironment input_var.2.y
  have h_P1x : input_P1.x = x_p := by rw [← h_P1_eq]
  have h_P1y : input_P1.y = y_p := by rw [← h_P1_eq]
  have h_P2x : input_P2.x = x_q := by rw [← h_P2_eq]
  have h_P2y : input_P2.y = y_q := by rw [← h_P2_eq]
  simp only [h_P1x, h_P1y, h_P2x, h_P2y] at h_lam h_xr h_invasm
  -- Discharge denominator nonzero for the first divide.
  have h_xqxp_ne : x_q + -x_p ≠ 0 := by
    intro h
    have h_sub : x_q - x_p = 0 := by rw [sub_eq_add_neg]; exact h
    rw [h_sub, zero_mul, zero_mul] at h_invasm
    exact zero_ne_one h_invasm
  -- Pin the circuit's λ₁ wire to the witnessed lambda_1.
  have h_circ_lam : env.get (i₀ + 3) = lambda_1 := by
    rw [h_div1_env h_xqxp_ne (Or.inl h_xqxp_ne), div_eq_iff h_xqxp_ne]
    linear_combination -h_lam
  -- env.get (i₀+8) + -x_p + -x_q = x_r.
  have h_xr_env : env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q = x_r := by
    rw [h_sq1_env, h_circ_lam, h_xr]; ring
  -- Discharge denominator nonzero for the second divide.
  have h_xpr_ne : x_p + -(env.get (i₀ + 3 + 3 + 2) + -x_p + -x_q) ≠ 0 := by
    rw [h_xr_env]
    intro h
    have h_pr : x_p - x_r = 0 := by rw [sub_eq_add_neg]; exact h
    rw [h_pr, mul_zero, zero_mul] at h_invasm
    exact zero_ne_one h_invasm
  refine ⟨h_xqxp_ne, h_xpr_ne, ?_⟩
  -- Discharge the EnforceNonzero gate.
  rw [h_bank2_env, h_bank1_env, h_xr_env]
  rw [show (x_q + -x_p) = x_q - x_p from (sub_eq_add_neg _ _).symm,
      show x_p + -x_r = x_p - x_r from (sub_eq_add_neg _ _).symm]
  exact h_invasm

def circuit (curveParams : Spec.CurveParams p) :
    GeneralFormalCircuit.WithHint (F p) Inputs Spec.Point where
  elaborated
  Assumptions := Assumptions curveParams
  Spec := Spec curveParams
  ProverAssumptions := ProverAssumptions curveParams
  soundness := soundness curveParams
  completeness := completeness curveParams

end Ragu.Circuits.Point.DoubleAndAddIncomplete
