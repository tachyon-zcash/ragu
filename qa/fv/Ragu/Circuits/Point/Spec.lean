import Clean.Circuit
import Mathlib.FieldTheory.Finite.Basic
import Mathlib.Tactic.LinearCombination
import Mathlib.Tactic.ReduceModChar
import Ragu.Core

namespace Ragu.Circuits.Point.Spec
open Core.Primes
variable {p : ℕ} [Fact p.Prime]

structure Point (F : Type) where
  x : F
  y : F
deriving ProvableStruct

/--
  Short Weierstrass curves with a = 0.

  `h_small_order` is a proof that the element ζ has order 3 in the base field
-/
structure CurveParams (base_p : ℕ) where
  b : F base_p
  ζ : F base_p
  h_small_order : ζ^3 = 1

def Point.isOnCurve (point : Point (F p)) (curveParams : CurveParams p) : Prop :=
  point.y^2 = point.x^3 + curveParams.b

def CurveParams.noOrderTwoPoints (curveParams : CurveParams p) : Prop :=
  (∀ point : Spec.Point (F p), (point.isOnCurve curveParams) → point.y ≠ 0)

/-- An on-curve affine point never has a zero `x` coordinate. -/
def CurveParams.noZeroXPoints (curveParams : CurveParams p) : Prop :=
  ∀ point : Spec.Point (F p), point.isOnCurve curveParams → point.x ≠ 0

/-- The coordinate assumptions carried by Rust's `Point` type. -/
def CurveParams.nonzeroCoordinates (curveParams : CurveParams p) : Prop :=
  curveParams.noZeroXPoints ∧ curveParams.noOrderTwoPoints

def Point.negate (point : Point (F p)) : Point (F p) :=
  {
    x := point.x,
    y := -point.y
  }

def Point.endo (point : Point (F p)) (curveParams : CurveParams p) : Point (F p) :=
  {
    x := curveParams.ζ * point.x,
    y := point.y
  }

/--
  Add two affine point

  Returns some point only if the result is affine as well, otherwise return none
-/
def Point.add_incomplete (point_1 : Point (F p)) (point_2 : Point (F p)) : Option (Point (F p)) :=
  -- a / 0 is defined to be 0 for fields, therefore to make the spec precise
  -- we return None if the x coordinates of the points are equal
  if point_1.x = point_2.x then none else
  let lambda := (point_2.y - point_1.y) / (point_2.x - point_1.x)
  let x3 := lambda^2 - point_1.x - point_2.x
  some {
    x := x3,
    y := lambda * (point_1.x - x3) - point_1.y
  }

def Point.double (point : Point (F p)) : Option (Point (F p)) :=
  -- a / 0 is defined to be 0 for fields, therefore to make the spec precise
  -- we return None if point.y is zero
  if point.y = 0 then none else
  let lambda := (3 * point.x^2) / (2 * point.y)
  let x2 := lambda^2 - 2*point.x
  some {
    x := x2,
    y := lambda * (point.x - x2) - point.y
  }

-- concrete pasta curves parameters
def EpAffineParams: Circuits.Point.Spec.CurveParams Core.Primes.p :=
{
  b := 5,
  ζ := 0x12ccca834acdba712caad5dc57aab1b01d1f8bd237ad31491dad5ebdfdfe4ab9,
  h_small_order := by decide
}

def EqAffineParams: Circuits.Point.Spec.CurveParams Core.Primes.q :=
{
  b := 5,
  ζ := 0x6819a58283e528e511db4d81cf70f5a0fed467d47c033af2aa9d2e050aa0e4f,
  h_small_order := by decide
}

/-! ### Nonzero coordinates for the concrete Pasta parameters

A point of order two is an affine point with `y = 0`, i.e. a root of
`x³ + b`. For both Pasta curves `b = 5` and `−5` is not a cube (checked by
Euler's cube criterion `(-5)^((p-1)/3) ≠ 1`), so no such point exists.
Likewise, `x = 0` would require `y² = 5`, while `5` is not a square in either
base field. -/

/-- Euler-style cube criterion: if `−b` fails the cube test
`(−b)^((q−1)/3) = 1` then `x³ + b` has no root, so the curve has no points
of order two. -/
theorem noOrderTwoPoints_of_neg_b_not_cube {q : ℕ} [Fact q.Prime]
    (cp : CurveParams q)
    (h3 : 3 * ((q - 1) / 3) = q - 1)
    (hb0 : cp.b ≠ 0)
    (hcube : (-cp.b) ^ ((q - 1) / 3) ≠ 1) :
    cp.noOrderTwoPoints := by
  intro pt h_curve hy0
  rw [Point.isOnCurve, hy0] at h_curve
  have h_x3 : pt.x ^ 3 = -cp.b := by linear_combination -h_curve
  have hx0 : pt.x ≠ 0 := by
    intro h
    rw [h] at h_x3
    exact hb0 (by linear_combination h_x3)
  apply hcube
  calc (-cp.b) ^ ((q - 1) / 3)
      = (pt.x ^ 3) ^ ((q - 1) / 3) := by rw [h_x3]
    _ = pt.x ^ (3 * ((q - 1) / 3)) := by rw [← pow_mul]
    _ = pt.x ^ (q - 1) := by rw [h3]
    _ = 1 := ZMod.pow_card_sub_one_eq_one hx0

/-- Euler-style square criterion: if `b` fails the square test
`b^((q−1)/2) = 1`, then an on-curve point cannot have `x = 0`. -/
theorem noZeroXPoints_of_b_not_square {q : ℕ} [Fact q.Prime]
    (cp : CurveParams q)
    (h2 : 2 * ((q - 1) / 2) = q - 1)
    (hb0 : cp.b ≠ 0)
    (hsquare : cp.b ^ ((q - 1) / 2) ≠ 1) :
    cp.noZeroXPoints := by
  intro pt h_curve hx0
  rw [Point.isOnCurve, hx0] at h_curve
  have h_y2 : pt.y ^ 2 = cp.b := by simpa using h_curve
  have hy0 : pt.y ≠ 0 := by
    intro hy0
    apply hb0
    rw [← h_y2, hy0]
    simp
  apply hsquare
  calc cp.b ^ ((q - 1) / 2)
      = (pt.y ^ 2) ^ ((q - 1) / 2) := by rw [h_y2]
    _ = pt.y ^ (2 * ((q - 1) / 2)) := by rw [← pow_mul]
    _ = pt.y ^ (q - 1) := by rw [h2]
    _ = 1 := ZMod.pow_card_sub_one_eq_one hy0

/-- The Pallas parameters have no points of order two: `−5` is not a cube
in `F_p`. Discharges the `noOrderTwoPoints` caller obligation of
`Point.Double` / `Endoscalar.GroupScale` at the concrete instantiation. -/
theorem epAffineParams_noOrderTwoPoints : EpAffineParams.noOrderTwoPoints := by
  apply noOrderTwoPoints_of_neg_b_not_cube
  · decide
  · decide
  · have hbase : (-5 :
        ZMod 28948022309329048855892746252171976963363056481941560715954676764349967630337) =
        28948022309329048855892746252171976963363056481941560715954676764349967630332 := by
      change ((-5 : ℤ) :
          ZMod 28948022309329048855892746252171976963363056481941560715954676764349967630337) =
        ((28948022309329048855892746252171976963363056481941560715954676764349967630332 : ℤ) :
          ZMod 28948022309329048855892746252171976963363056481941560715954676764349967630337)
      rw [ZMod.intCast_eq_intCast_iff']
      norm_num
    have hpow :
        (28948022309329048855892746252171976963363056481941560715954676764349967630332 :
          ZMod 28948022309329048855892746252171976963363056481941560715954676764349967630337) ^
          9649340769776349618630915417390658987787685493980520238651558921449989210112 ≠ 1 := by
      reduce_mod_char
      decide
    intro h
    apply hpow
    rw [← hbase]
    exact h

/-- The Vesta parameters have no points of order two: `−5` is not a cube
in `F_q`. -/
theorem eqAffineParams_noOrderTwoPoints : EqAffineParams.noOrderTwoPoints := by
  apply noOrderTwoPoints_of_neg_b_not_cube
  · decide
  · decide
  · have hbase : (-5 :
        ZMod 28948022309329048855892746252171976963363056481941647379679742748393362948097) =
        28948022309329048855892746252171976963363056481941647379679742748393362948092 := by
      change ((-5 : ℤ) :
          ZMod 28948022309329048855892746252171976963363056481941647379679742748393362948097) =
        ((28948022309329048855892746252171976963363056481941647379679742748393362948092 : ℤ) :
          ZMod 28948022309329048855892746252171976963363056481941647379679742748393362948097)
      rw [ZMod.intCast_eq_intCast_iff']
      norm_num
    have hpow :
        (28948022309329048855892746252171976963363056481941647379679742748393362948092 :
          ZMod 28948022309329048855892746252171976963363056481941647379679742748393362948097) ^
          9649340769776349618630915417390658987787685493980549126559914249464454316032 ≠ 1 := by
      reduce_mod_char
      decide
    intro h
    apply hpow
    rw [← hbase]
    exact h

/-- Pallas has no on-curve affine point with `x = 0`: `5` is not a square
in `F_p`. -/
theorem epAffineParams_noZeroXPoints : EpAffineParams.noZeroXPoints := by
  apply noZeroXPoints_of_b_not_square
  · decide
  · decide
  · have hpow : (5 :
        ZMod 28948022309329048855892746252171976963363056481941560715954676764349967630337) ^
        14474011154664524427946373126085988481681528240970780357977338382174983815168 ≠ 1 := by
      reduce_mod_char
      decide
    exact hpow

/-- Vesta has no on-curve affine point with `x = 0`: `5` is not a square
in `F_q`. -/
theorem eqAffineParams_noZeroXPoints : EqAffineParams.noZeroXPoints := by
  apply noZeroXPoints_of_b_not_square
  · decide
  · decide
  · have hpow : (5 :
        ZMod 28948022309329048855892746252171976963363056481941647379679742748393362948097) ^
        14474011154664524427946373126085988481681528240970823689839871374196681474048 ≠ 1 := by
      reduce_mod_char
      decide
    exact hpow

/-- Both coordinates of every affine Pallas point are nonzero. -/
theorem epAffineParams_nonzeroCoordinates : EpAffineParams.nonzeroCoordinates :=
  ⟨epAffineParams_noZeroXPoints, epAffineParams_noOrderTwoPoints⟩

/-- Both coordinates of every affine Vesta point are nonzero. -/
theorem eqAffineParams_nonzeroCoordinates : EqAffineParams.nonzeroCoordinates :=
  ⟨eqAffineParams_noZeroXPoints, eqAffineParams_noOrderTwoPoints⟩

end Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Point.Lemmas
variable {p : ℕ} [Fact p.Prime]
open Spec

lemma double_preserves_membership [NeZero (2 : F p)] (point : Point (F p)) (curveParams: CurveParams p)
    (h_membership: point.isOnCurve curveParams) (h_order : curveParams.noOrderTwoPoints) :
    match point.double with
    | none =>
      -- this is impossible: since we assume that the curve does not have points of order two,
      -- every affine point has an affine double
      False
    | some double => double.isOnCurve curveParams := by
  simp only [CurveParams.noOrderTwoPoints] at h_order
  specialize h_order point h_membership
  simp only [Point.double, if_neg h_order, Point.isOnCurve]
  simp only [Point.isOnCurve] at h_membership
  have h2 : (2 : F p) ≠ 0 := NeZero.ne 2
  have h2y : (2 : F p) * point.y ≠ 0 := mul_ne_zero h2 h_order
  field_simp [h_order, h2y, h2]
  have hb : curveParams.b = point.y ^ 2 - point.x ^ 3 := by rw [h_membership]; ring
  rw [hb]
  ring


lemma add_incomplete_preserves_membership (p1 p2 : Point (F p)) (cp : CurveParams p) (h : p1.x ≠ p2.x)
    (hm1 : p1.isOnCurve cp) (hm2 : p2.isOnCurve cp) :
    match p1.add_incomplete p2 with
    | none => False
    | some r => r.isOnCurve cp := by
  simp only [Point.add_incomplete, if_neg h, Point.isOnCurve]
  simp only [Point.isOnCurve] at hm1 hm2
  have hdiff : p2.x - p1.x ≠ 0 := sub_ne_zero.mpr (Ne.symm h)
  set lambda := (p2.y - p1.y) / (p2.x - p1.x) with hlambda
  have h_lam_mul : lambda * (p2.x - p1.x) = p2.y - p1.y := by
    simp only [hlambda]; field_simp [hdiff]
  have h_sum : lambda * (p2.y + p1.y) = p2.x ^ 2 + p1.x * p2.x + p1.x ^ 2 := by
    have key : (p2.y - p1.y) * (p2.y + p1.y) = (p2.x - p1.x) * (p2.x ^ 2 + p1.x * p2.x + p1.x ^ 2) := by
      have : p2.y ^ 2 - p1.y ^ 2 = p2.x ^ 3 - p1.x ^ 3 := by rw [hm1, hm2]; ring
      calc (p2.y - p1.y) * (p2.y + p1.y) = p2.y ^ 2 - p1.y ^ 2 := by ring
        _ = p2.x ^ 3 - p1.x ^ 3 := this
        _ = (p2.x - p1.x) * (p2.x ^ 2 + p1.x * p2.x + p1.x ^ 2) := by ring
    have hmul : (p2.x - p1.x) * (lambda * (p2.y + p1.y)) = (p2.x - p1.x) * (p2.x ^ 2 + p1.x * p2.x + p1.x ^ 2) := by
      calc (p2.x - p1.x) * (lambda * (p2.y + p1.y))
          = lambda * (p2.x - p1.x) * (p2.y + p1.y) := by ring
        _ = (p2.y - p1.y) * (p2.y + p1.y) := by rw [h_lam_mul]
        _ = (p2.x - p1.x) * (p2.x ^ 2 + p1.x * p2.x + p1.x ^ 2) := key
    exact mul_left_cancel₀ hdiff hmul
  have h_bracket : lambda ^ 2 * (p1.x - p2.x) + p1.x ^ 2 + p1.x * p2.x + p2.x ^ 2 - 2 * lambda * p1.y = 0 := by
    have eq3 : lambda * (p2.y - p1.y) = lambda ^ 2 * (p2.x - p1.x) := by
      calc lambda * (p2.y - p1.y)
          = lambda * (lambda * (p2.x - p1.x)) := by rw [h_lam_mul]
        _ = lambda ^ 2 * (p2.x - p1.x) := by ring
    have eq4 : 2 * lambda * p1.y = lambda * (p2.y + p1.y) - lambda * (p2.y - p1.y) := by ring
    rw [eq4, h_sum, eq3]; ring
  rw [← sub_eq_zero]
  have factored : (lambda * (p1.x - (lambda ^ 2 - p1.x - p2.x)) - p1.y) ^ 2 - ((lambda ^ 2 - p1.x - p2.x) ^ 3 + cp.b)
      = (2 * p1.x + p2.x - lambda ^ 2) * (lambda ^ 2 * (p1.x - p2.x) + p1.x ^ 2 + p1.x * p2.x + p2.x ^ 2 - 2 * lambda * p1.y)
        + (p1.y ^ 2 - p1.x ^ 3 - cp.b) := by ring
  rw [factored, h_bracket, mul_zero, zero_add]
  have : p1.y ^ 2 - p1.x ^ 3 - cp.b = p1.y ^ 2 - (p1.x ^ 3 + cp.b) := by ring
  rw [this, hm1, sub_self]

/-! ### Wire-level forms of the incomplete additions

The checked and unchecked `add_incomplete` / `double_and_add_incomplete`
reimpls emit the same affine-addition gates and differ only in the bank
bookkeeping around them, so their soundness proofs share the algebra that
turns the gate outputs into `Point.add_incomplete` equations. The statements
are in the `a + -b` normal form `circuit_proof_start` produces. -/

/-- One incomplete addition on the circuit's wires: given the chord slope
`delta`, its square `delta_sq`, and `y_term = delta · (x₁ - x₃)`, the wires
`(delta_sq - x₁ - x₂, y_term - y₁)` are the affine sum `P₁ + P₂`. -/
lemma add_incomplete_eq_of_wires (x1 y1 x2 y2 delta delta_sq y_term : F p)
    (h_ne : x1 ≠ x2)
    (h_delta : delta = (y2 + -y1) / (x2 + -x1))
    (h_sq : delta_sq = delta ^ 2)
    (h_y : y_term = delta * (x1 - (delta_sq + -x1 + -x2))) :
    Point.add_incomplete ⟨x1, y1⟩ ⟨x2, y2⟩ =
      some ⟨delta_sq + -x1 + -x2, y_term + -y1⟩ := by
  subst h_y h_sq h_delta
  simp only [Point.add_incomplete, if_neg h_ne, Option.some.injEq, Point.mk.injEq]
  exact ⟨by ring, by ring⟩

/-- The two chained incomplete additions of `double_and_add_incomplete` on the
circuit's wires: `r = P₁ + P₂` from the first slope `lambda_1`, then
`r + P₁` from the second slope `lambda_2_half - lambda_1`, where
`lambda_2_half = 2y₁ / (x₁ - x_r)`. -/
lemma double_and_add_incomplete_eq_of_wires (x_p y_p x_q y_q : F p)
    (lambda_1 lambda_1_sq lambda_2_half lambda_2_sq y_term : F p)
    (h_ne : x_p ≠ x_q)
    (h_lam1 : lambda_1 = (y_q + -y_p) / (x_q + -x_p))
    (h_sq1 : lambda_1_sq = lambda_1 ^ 2)
    (h_r_ne : lambda_1_sq + -x_p + -x_q ≠ x_p)
    (h_lam2 : lambda_2_half = (y_p + y_p) / (x_p + -(lambda_1_sq + -x_p + -x_q)))
    (h_sq2 : lambda_2_sq = (lambda_2_half - lambda_1) ^ 2)
    (h_y : y_term = (lambda_2_half - lambda_1) *
      (x_p - (lambda_2_sq + -(lambda_1_sq + -x_p + -x_q) + -x_p))) :
    Point.add_incomplete ⟨x_p, y_p⟩ ⟨x_q, y_q⟩ =
        some ⟨lambda_1_sq + -x_p + -x_q,
              lambda_1 * (x_p - (lambda_1_sq + -x_p + -x_q)) - y_p⟩ ∧
      Point.add_incomplete
          ⟨lambda_1_sq + -x_p + -x_q, lambda_1 * (x_p - (lambda_1_sq + -x_p + -x_q)) - y_p⟩
          ⟨x_p, y_p⟩ =
        some ⟨lambda_2_sq + -(lambda_1_sq + -x_p + -x_q) + -x_p, y_term + -y_p⟩ := by
  have h_diff_ne : x_p + -(lambda_1_sq + -x_p + -x_q) ≠ 0 := by
    intro h
    apply h_r_ne
    linear_combination -h
  have h_diff_ne' : x_p - (lambda_1_sq + -x_p + -x_q) ≠ 0 := by
    rw [sub_eq_add_neg]; exact h_diff_ne
  have h_lam2_mul :
      lambda_2_half * (x_p + -(lambda_1_sq + -x_p + -x_q)) = y_p + y_p := by
    rw [h_lam2]
    exact div_mul_cancel₀ _ h_diff_ne
  refine ⟨?_, ?_⟩
  · subst h_sq1 h_lam1
    simp only [Point.add_incomplete, if_neg h_ne, Option.some.injEq, Point.mk.injEq]
    exact ⟨by ring, by ring⟩
  · have h_slope :
        (y_p - (lambda_1 * (x_p - (lambda_1_sq + -x_p + -x_q)) - y_p)) /
            (x_p - (lambda_1_sq + -x_p + -x_q)) =
          lambda_2_half - lambda_1 := by
      rw [div_eq_iff h_diff_ne']
      linear_combination -h_lam2_mul
    simp only [Point.add_incomplete, if_neg h_r_ne, Option.some.injEq, Point.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [h_slope, h_sq2]; ring
    · rw [h_slope, h_y, h_sq2]
      linear_combination -h_lam2_mul


/-- The three chained incomplete additions of `triple_and_add_incomplete` on
the circuit's wires: `r₁ = A + D` from the slope `t₁`, `r₂ = r₁ + A` from
`q₂ - t₁` where `q₂ = -2y / (x₁ - x)`, and `r₂ + A` from `q₃ - (q₂ - t₁)`
where `q₃ = -2y / (x₂ - x)`. The intermediate `y`-coordinates cancel out of
the slope equations, so only the `x`-coordinates `x₁ = t₁² - x - x_D` and
`x₂ = t₂² - x₁ - x` are wires. The result's `x₃ = t₃² - x₂ - x` is written
with the intermediate `x`-coordinates cancelled, `t₃² - t₂² + t₁² - x - x_D`,
as the gadget computes it. -/
lemma triple_and_add_incomplete_eq_of_wires (x y x_d y_d t1 t1_sq q2 t2_sq q3 t3_sq y_term : F p)
    (h_ne1 : x ≠ x_d)
    (h_t1 : t1 = (y_d + -y) / (x_d + -x))
    (h_sq1 : t1_sq = t1 ^ 2)
    (h_ne2 : t1_sq + -x + -x_d ≠ x)
    (h_q2 : q2 = (-(2 * y)) / (t1_sq + -x + -x_d + -x))
    (h_sq2 : t2_sq = (q2 - t1) ^ 2)
    (h_ne3 : t2_sq + -(t1_sq + -x + -x_d) + -x ≠ x)
    (h_q3 : q3 = (-(2 * y)) / (t2_sq + -(t1_sq + -x + -x_d) + -x + -x))
    (h_sq3 : t3_sq = (q3 - (q2 - t1)) ^ 2)
    (h_y : y_term = (q3 - (q2 - t1)) * (x - (t3_sq + -t2_sq + t1_sq + -x + -x_d))) :
    ∃ r1 r2 : Point (F p),
      Point.add_incomplete ⟨x, y⟩ ⟨x_d, y_d⟩ = some r1 ∧
      r1.add_incomplete ⟨x, y⟩ = some r2 ∧
      r2.add_incomplete ⟨x, y⟩ = some ⟨t3_sq + -t2_sq + t1_sq + -x + -x_d, y_term + -y⟩ := by
  subst h_sq1 h_sq2 h_sq3 h_y
  have h_d1 : x_d - x ≠ 0 := by
    intro h; apply h_ne1; linear_combination -h
  have h_d2 : x - (t1 ^ 2 + -x + -x_d) ≠ 0 := by
    intro h; apply h_ne2; linear_combination -h
  have h_d3 : x - ((q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x) ≠ 0 := by
    intro h; apply h_ne3; linear_combination -h
  -- The slope equations in product form.
  have e1 : t1 * (x_d - x) = y_d - y := by
    rw [h_t1]
    have h1 : x_d + -x = x_d - x := by ring
    have h2 : y_d + -y = y_d - y := by ring
    rw [h1, h2]
    exact div_mul_cancel₀ _ h_d1
  have e2 : q2 * (x - (t1 ^ 2 + -x + -x_d)) = 2 * y := by
    rw [h_q2]
    have hd : t1 ^ 2 + -x + -x_d + -x ≠ 0 := by
      intro h; apply h_d2; linear_combination -h
    field_simp
    ring
  have e3 : q3 * (x - ((q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x)) = 2 * y := by
    rw [h_q3]
    have hd : (q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x + -x ≠ 0 := by
      intro h; apply h_d3; linear_combination -h
    field_simp
    ring
  -- The three slopes as the definition writes them.
  have hl1 : (y_d - y) / (x_d - x) = t1 := by
    rw [div_eq_iff h_d1]; exact e1.symm
  have hl2 : (y - (t1 * (x - (t1 ^ 2 + -x + -x_d)) - y)) / (x - (t1 ^ 2 + -x + -x_d)) =
      q2 - t1 := by
    rw [div_eq_iff h_d2]; linear_combination -e2
  have hl3 : (y - ((q2 - t1) * (x - ((q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x)) - y)) /
      (x - ((q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x)) = q3 - (q2 - t1) := by
    rw [div_eq_iff h_d3]; linear_combination -e3
  refine ⟨⟨t1 ^ 2 + -x + -x_d, t1 * (x - (t1 ^ 2 + -x + -x_d)) - y⟩,
    ⟨(q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x,
      (q2 - t1) * (x - ((q2 - t1) ^ 2 + -(t1 ^ 2 + -x + -x_d) + -x)) - y⟩, ?_, ?_, ?_⟩
  · simp only [Point.add_incomplete, if_neg h_ne1, Option.some.injEq, Point.mk.injEq]
    rw [hl1]
    exact ⟨by ring, by ring⟩
  · simp only [Point.add_incomplete, if_neg h_ne2, Option.some.injEq, Point.mk.injEq]
    rw [hl2]
    exact ⟨by ring, by linear_combination -e2⟩
  · simp only [Point.add_incomplete, if_neg h_ne3, Option.some.injEq, Point.mk.injEq]
    rw [hl3]
    exact ⟨by ring, by linear_combination -e3⟩

end Ragu.Circuits.Point.Lemmas
