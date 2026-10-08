import Clean.Circuit
import Clean.Utils.Primes
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Element.Divide
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked
variable {p : ℕ} [Fact p.Prime]

/-- The accumulator `A` to be tripled and the digit point `D` to be added,
as `Endoscalar::group_scale`'s walk does against an *unchecked*
`NonzeroBank`: the three bank folds emit no constraints. -/
structure Inputs (F : Type) where
  A : Spec.Point F
  D : Spec.Point F
deriving ProvableStruct

/-- `[3] A + D = ((A + D) + A) + A` in seven gates, mirroring the walk's
loop body in `crates/ragu_primitives/src/endoscalar.rs::walk`:

  - `t₁ = (y_D - y) / (x_D - x)`, then `x₁ = t₁² - x - x_D` (divide, square);
  - `(t₁ + t₂)(x₁ - x) = -2y` as `t₂ = -2y / (x₁ - x) - t₁`, then
    `x₂ = t₂² - x₁ - x` (divide, square);
  - `(t₂ + t₃)(x₂ - x) = -2y` likewise, then `x₃ = t₃² - x₂ - x` (divide,
    square) and `y₃ = t₃ (x - x₃) - y` (mul).

The intermediate `y`-coordinates cancel out of the slope equations, which is
what makes three additions cost seven gates rather than nine. `x₃` is
written with the intermediate `x`-coordinates cancelled,
`t₃² - t₂² + t₁² - x - x_D`, so that the accumulator enters the output once:
the walk feeds each output into the next step, and a nested form would make
the symbolic accumulator grow exponentially in the step count, which the
fingerprint's polynomial normalizer cannot absorb. Nothing in the
constraint system forces the three distinct-x conditions; they are caller
obligations (`Assumptions`), justified for the walk by the magnitude argument
in `Endoscalar::group_scale`. The curve itself never enters: the addition
formulas do not read its constant term, and membership is the caller's to
track, which lets the walk run this on the normalized curve whose constant
term is a witness value. -/
def main (input : Var Inputs (F p)) : Circuit (F p) (Var Spec.Point (F p)) := do
  let ⟨⟨x, y⟩, ⟨x_d, y_d⟩⟩ := input
  let neg_2y := Expression.const (-2) * y

  -- t₁ = (y_D - y) / (x_D - x); x₁ = t₁² - x - x_D
  let t1 ← Element.Divide.circuit ⟨y_d - y, x_d - x⟩
  let t1_sq ← Element.Square.circuit t1
  let x1 := t1_sq - x - x_d

  -- t₂ = -2y / (x₁ - x) - t₁; x₂ = t₂² - x₁ - x
  let q2 ← Element.Divide.circuit ⟨neg_2y, x1 - x⟩
  let t2 := q2 - t1
  let t2_sq ← Element.Square.circuit t2
  let x2 := t2_sq - x1 - x

  -- t₃ = -2y / (x₂ - x) - t₂; x₃ = t₃² - x₂ - x = t₃² - t₂² + t₁² - x - x_D
  let q3 ← Element.Divide.circuit ⟨neg_2y, x2 - x⟩
  let t3 := q3 - t2
  let t3_sq ← Element.Square.circuit t3
  let x3 := t3_sq - t2_sq + t1_sq - x - x_d

  -- y₃ = t₃ (x - x₃) - y
  let y_term ← Element.Mul.circuit ⟨t3, x - x3⟩
  let y3 := y_term - y

  return ⟨x3, y3⟩

/-- The native chain `((A + D) + A) + A`, `none` when an addition is
degenerate. -/
def tripleAddNative (A D : Spec.Point (F p)) : Option (Spec.Point (F p)) :=
  match A.add_incomplete D with
  | none => none
  | some r1 =>
    match r1.add_incomplete A with
    | none => none
    | some r2 => r2.add_incomplete A

/-- Caller obligation: the full non-degeneracy of the chain. The circuit does
*not* enforce any distinct-x condition. -/
def Assumptions (input : Inputs (F p)) :=
  tripleAddNative input.A input.D ≠ none

def Spec (input : Inputs (F p)) (output : Spec.Point (F p)) :=
  tripleAddNative input.A input.D = some output

/-- The output on the layout: the three Squares' product wires and the Mul's,
with the input coordinates. Explicit so parent proofs get a shallow
projection. -/
@[circuit_norm]
def output (input : Var Inputs (F p)) (offset : ℕ) : Var Spec.Point (F p) :=
  ⟨varFromOffset field (offset + 3 + 3 + 3 + 3 + 3 + 2) -
      varFromOffset field (offset + 3 + 3 + 3 + 2) +
      varFromOffset field (offset + 3 + 2) - input.A.x - input.D.x,
   varFromOffset field (offset + 3 + 3 + 3 + 3 + 3 + 3 + 2) - input.A.y⟩

instance elaborated : ElaboratedCircuit (F p) Inputs Spec.Point main where
  -- divide + square, three times, then the mul: 7 × 3 = 21
  localLength _ := 21
  output := output
  output_eq := by
    intro input offset
    rcases input with ⟨⟨x, y⟩, ⟨x_d, y_d⟩⟩
    simp [main, output, circuit_norm, Element.Divide.circuit, Element.Square.circuit,
      Element.Mul.circuit]

/-- Unpacks the chain's non-degeneracy into its three distinct-x conditions
and the intermediate points. -/
lemma chain_conditions (A D : Spec.Point (F p))
    (h : tripleAddNative A D ≠ none) :
    A.x ≠ D.x ∧
    ∃ r1, A.add_incomplete D = some r1 ∧ r1.x ≠ A.x ∧
    ∃ r2, r1.add_incomplete A = some r2 ∧ r2.x ≠ A.x := by
  have h1 : A.x ≠ D.x := by
    intro hx
    apply h
    simp only [tripleAddNative, Spec.Point.add_incomplete, if_pos hx]
  obtain ⟨r1, hr1⟩ : ∃ r1, A.add_incomplete D = some r1 := by
    rcases hr : A.add_incomplete D with _ | r1
    · exact absurd (by simp only [tripleAddNative, hr]) h
    · exact ⟨r1, rfl⟩
  have h2 : r1.x ≠ A.x := by
    intro hx
    apply h
    simp only [tripleAddNative]
    rw [hr1]
    simp only [Spec.Point.add_incomplete, if_pos hx]
  obtain ⟨r2, hr2⟩ : ∃ r2, r1.add_incomplete A = some r2 := by
    rcases hr : r1.add_incomplete A with _ | r2
    · exact absurd (by simp only [tripleAddNative]; rw [hr1]; simp only [hr]) h
    · exact ⟨r2, rfl⟩
  have h3 : r2.x ≠ A.x := by
    intro hx
    apply h
    simp only [tripleAddNative]
    rw [hr1]
    simp only
    rw [hr2]
    simp only [Spec.Point.add_incomplete, if_pos hx]
  exact ⟨h1, r1, hr1, h2, r2, hr2, h3⟩

/-- The chain preserves curve membership, for any curve: the addition
formulas are the group law on it. -/
lemma tripleAddNative_isOnCurve (curveParams : Spec.CurveParams p) (A D out : Spec.Point (F p))
    (hA : A.isOnCurve curveParams) (hD : D.isOnCurve curveParams)
    (h : tripleAddNative A D = some out) : out.isOnCurve curveParams := by
  obtain ⟨h1, r1, hr1, h2, r2, hr2, h3⟩ := chain_conditions A D (by rw [h]; exact Option.some_ne_none _)
  have hr1c := by
    simpa [hr1] using Lemmas.add_incomplete_preserves_membership A D curveParams h1 hA hD
  have hr2c := by
    simpa [hr2] using Lemmas.add_incomplete_preserves_membership r1 A curveParams h2 hr1c hA
  have h3' : r2.add_incomplete A = some out := by
    simp only [tripleAddNative] at h
    rw [hr1] at h
    simp only at h
    rw [hr2] at h
    exact h
  simpa [h3'] using Lemmas.add_incomplete_preserves_membership r2 A curveParams h3 hr2c hA

/-- The wire-form facts the gates establish, shared by soundness and
completeness: the three slope wires and the two distinct-x conditions of the
later additions, derived from the chain's non-degeneracy. The divide facts
are taken conditionally on their denominators being nonzero, which is how
both proof directions expose them. -/
private lemma wire_facts (env : Environment (F p)) (i₀ : ℕ)
    (x y x_d y_d : F p)
    (h_chain : tripleAddNative ⟨x, y⟩ ⟨x_d, y_d⟩ ≠ none)
    (h_div1 : x_d + -x ≠ 0 → env.get i₀ = (y_d + -y) / (x_d + -x))
    (h_sq1 : env.get (i₀ + 3 + 2) = env.get i₀ ^ 2)
    (h_div2 : env.get (i₀ + 3 + 2) + -x + -x_d + -x ≠ 0 →
      env.get (i₀ + 3 + 3) =
        (-(2 * y)) / (env.get (i₀ + 3 + 2) + -x + -x_d + -x))
    (h_sq2 : env.get (i₀ + 3 + 3 + 3 + 2) = (env.get (i₀ + 3 + 3) - env.get i₀) ^ 2) :
    x ≠ x_d ∧
    env.get i₀ = (y_d + -y) / (x_d + -x) ∧
    env.get (i₀ + 3 + 2) + -x + -x_d ≠ x ∧
    env.get (i₀ + 3 + 3) = (-(2 * y)) / (env.get (i₀ + 3 + 2) + -x + -x_d + -x) ∧
    env.get (i₀ + 3 + 3 + 3 + 2) + -(env.get (i₀ + 3 + 2) + -x + -x_d) + -x ≠ x := by
  obtain ⟨h_ne1, r1, hr1, h_ne2, r2, hr2, h_ne3⟩ :=
    chain_conditions ⟨x, y⟩ ⟨x_d, y_d⟩ h_chain
  simp only at h_ne1 h_ne2 h_ne3
  have h_d1 : x_d + -x ≠ 0 := by
    intro h; apply h_ne1; linear_combination -h
  have h_t1 := h_div1 h_d1
  have hr1' : r1 = ⟨env.get i₀ ^ 2 + -x + -x_d,
      env.get i₀ * (x - (env.get i₀ ^ 2 + -x + -x_d)) - y⟩ := by
    simp only [Spec.Point.add_incomplete, if_neg h_ne1, Option.some.injEq] at hr1
    rw [← hr1, h_t1]
    simp only [Spec.Point.mk.injEq]
    exact ⟨by ring, by ring⟩
  have h_ne2w : env.get (i₀ + 3 + 2) + -x + -x_d ≠ x := by
    rw [h_sq1]; intro h; apply h_ne2; rw [hr1']; exact h
  have h_d2 : env.get (i₀ + 3 + 2) + -x + -x_d + -x ≠ 0 := by
    intro h; apply h_ne2w; linear_combination h
  have h_q2 := h_div2 h_d2
  have h_r2x : r2.x = env.get (i₀ + 3 + 3 + 3 + 2) +
      -(env.get (i₀ + 3 + 2) + -x + -x_d) + -x := by
    have h_ne2r : r1.x ≠ x := by rw [hr1']; rw [h_sq1] at h_ne2w; exact h_ne2w
    simp only [Spec.Point.add_incomplete, if_neg h_ne2r, Option.some.injEq] at hr2
    rw [← hr2, hr1']
    simp only
    rw [h_sq2, h_q2, h_sq1]
    have hd : x - (env.get i₀ ^ 2 + -x + -x_d) ≠ 0 := by
      intro h; apply h_d2; rw [h_sq1]; linear_combination -h
    have hd' : env.get i₀ ^ 2 + -x + -x_d + -x ≠ 0 := by
      intro h; apply hd; linear_combination -h
    field_simp
    ring
  have h_ne3w : env.get (i₀ + 3 + 3 + 3 + 2) +
      -(env.get (i₀ + 3 + 2) + -x + -x_d) + -x ≠ x := by
    rw [← h_r2x]; exact h_ne3
  exact ⟨h_ne1, h_t1, h_ne2w, h_q2, h_ne3w⟩

theorem soundness :
    Soundness (F p) (Input := Inputs) (Output := Spec.Point) main Assumptions Spec := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec, output]
  simp only [sub_eq_add_neg] at h_holds ⊢
  obtain ⟨h_div1, h_sq1, h_div2, h_sq2, h_div3, h_sq3, h_yterm⟩ := h_holds
  obtain ⟨h_ne1, h_t1, h_ne2w, h_q2, h_ne3w⟩ := wire_facts env i₀
    input_A_x input_A_y input_D_x input_D_y h_assumptions
    (fun h => h_div1 (Or.inl h)) h_sq1 (fun h => h_div2 (Or.inl h))
    (by linear_combination (id h_sq2 : @Eq (F p) _ _))
  have h_d3 : env.get (i₀ + 3 + 3 + 3 + 2) +
      -(env.get (i₀ + 3 + 2) + -input_A_x + -input_D_x) + -input_A_x + -input_A_x ≠ 0 := by
    intro h; apply h_ne3w; linear_combination h
  have h_q3 := h_div3 (Or.inl h_d3)
  obtain ⟨r1', r2', h_add1, h_add2, h_add3⟩ :=
    Lemmas.triple_and_add_incomplete_eq_of_wires input_A_x input_A_y input_D_x input_D_y
      (env.get i₀) (env.get (i₀ + 3 + 2)) (env.get (i₀ + 3 + 3))
      (env.get (i₀ + 3 + 3 + 3 + 2)) (env.get (i₀ + 3 + 3 + 3 + 3))
      (env.get (i₀ + 3 + 3 + 3 + 3 + 3 + 2)) (env.get (i₀ + 3 + 3 + 3 + 3 + 3 + 3 + 2))
      h_ne1 h_t1 (by linear_combination (id h_sq1 : @Eq (F p) _ _)) h_ne2w h_q2
      (by linear_combination (id h_sq2 : @Eq (F p) _ _)) h_ne3w h_q3
      (by linear_combination (id h_sq3 : @Eq (F p) _ _))
      (by linear_combination (id h_yterm : @Eq (F p) _ _))
  simp only [tripleAddNative, h_add1, h_add2, h_add3]

theorem completeness :
    Completeness (F p) (Input := Inputs) (Output := Spec.Point) main Assumptions := by
  circuit_proof_start [Element.Divide.circuit, Element.Divide.ProverAssumptions,
    Element.Divide.Assumptions, Element.Divide.Spec,
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions]
  simp only [sub_eq_add_neg] at h_env ⊢
  obtain ⟨h_div1_env, h_sq1_env, h_div2_env, h_sq2_env, _⟩ := h_env
  obtain ⟨h_ne1, _, h_ne2w, _, h_ne3w⟩ := wire_facts env.toEnvironment i₀
    input_A_x input_A_y input_D_x input_D_y h_assumptions
    (fun h => h_div1_env h (Or.inl h)) h_sq1_env (fun h => h_div2_env h (Or.inl h))
    (by linear_combination (id h_sq2_env : @Eq (F p) _ _))
  have h_d1 : input_D_x + -input_A_x ≠ 0 := by
    intro h; apply h_ne1; linear_combination -h
  have h_d2 : env.get (i₀ + 3 + 2) + -input_A_x + -input_D_x + -input_A_x ≠ 0 := by
    intro h; apply h_ne2w; linear_combination h
  have h_d3 : env.get (i₀ + 3 + 3 + 3 + 2) +
      -(env.get (i₀ + 3 + 2) + -input_A_x + -input_D_x) + -input_A_x + -input_A_x ≠ 0 := by
    intro h; apply h_ne3w; linear_combination h
  exact ⟨h_d1, h_d2, h_d3⟩

def circuit : FormalCircuit (F p) Inputs Spec.Point :=
  { main := main, elaborated := elaborated, Assumptions, Spec, soundness, completeness }

end Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked
