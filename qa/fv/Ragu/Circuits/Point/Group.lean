import Ragu.Circuits.Point.Spec
import Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked
import Ragu.Lemmas.CoordinateMap
import Mathlib.Tactic.Module

/-!
# Affine operations in the complete curve group

The `Option` specifications use incomplete affine formulas. These lemmas
identify every successful operation with the complete group law and derive
success from group inequalities, rather than assuming it.
-/

namespace Ragu.Circuits.Point.Group

open Spec CompElliptic.CurveForms.ShortWeierstrass
open Ragu.Lemmas

variable {p : ℕ} [Fact p.Prime]
variable (E : SWCurve (F p)) (hA : E.A = 0) (cp : CurveParams p) (hB : E.B = cp.b)

/-- Embed an on-curve affine point in the complete group. -/
def embed (P : Point (F p)) (hP : P.isOnCurve cp) : SWPoint E :=
  ⟨P.x, P.y, Or.inl (by simpa only [OnCurve, hA, hB, zero_mul, _root_.add_zero] using hP)⟩

/-- Affine points cannot be the identity sentinel on a nonsingular curve. -/
theorem embed_ne_zero (P : Point (F p)) (hP : P.isOnCurve cp) :
    embed E hA cp hB P hP ≠ 0 := by
  intro h
  have hc : OnCurve E.A E.B (P.x, P.y) := by
    simpa only [OnCurve, hA, hB, zero_mul, _root_.add_zero] using hP
  have hp : (P.x, P.y) = (0, 0) := congrArg (fun Q => (Q.x, Q.y)) h
  rw [hp] at hc
  exact origin_not_on_curve E hc

/-- Affine negation is group negation under the embedding. -/
theorem embed_negate (P : Point (F p)) (hP : P.isOnCurve cp)
    (hneg : P.negate.isOnCurve cp) :
    embed E hA cp hB P.negate hneg = -embed E hA cp hB P hP :=
  SWPoint.ext_pair rfl

/-- The affine endomorphism `(x, y) ↦ (ζx, y)` is `CoordinateMap.endo`
under the embedding. -/
theorem embed_endo (P : Point (F p)) (hP : P.isOnCurve cp)
    (he : (P.endo cp).isOnCurve cp) :
    embed E hA cp hB (P.endo cp) he =
      CoordinateMap.endo E hA cp.ζ cp.h_small_order (embed E hA cp hB P hP) :=
  SWPoint.ext_pair rfl

/-- A successful incomplete addition is the complete group sum. -/
theorem embed_add (P Q R : Point (F p))
    (hP : P.isOnCurve cp) (hQ : Q.isOnCurve cp) (hR : R.isOnCurve cp)
    (hadd : P.add_incomplete Q = some R) :
    embed E hA cp hB R hR = embed E hA cp hB P hP + embed E hA cp hB Q hQ := by
  have hx : P.x ≠ Q.x := by
    intro h
    simp only [Point.add_incomplete, if_pos h] at hadd
    cases hadd
  have hp : (P.x, P.y) ≠ (0, 0) := by
    intro h
    exact embed_ne_zero E hA cp hB P hP (SWPoint.ext_pair h)
  have hq : (Q.x, Q.y) ≠ (0, 0) := by
    intro h
    exact embed_ne_zero E hA cp hB Q hQ (SWPoint.ext_pair h)
  simp only [Point.add_incomplete, if_neg hx, Option.some.injEq] at hadd
  subst R
  apply SWPoint.ext_pair
  change _ = add E.A (P.x, P.y) (Q.x, Q.y)
  simp only [add, hp, hq, hx, if_false]
  rfl

/-- Distinct, nonopposite group points admit an incomplete affine sum. -/
theorem add_exists (P Q : Point (F p)) (hP : P.isOnCurve cp) (hQ : Q.isOnCurve cp)
    (hne : embed E hA cp hB P hP ≠ embed E hA cp hB Q hQ)
    (hneg : embed E hA cp hB P hP ≠ -embed E hA cp hB Q hQ) :
    ∃ (R : Point (F p)) (hR : R.isOnCurve cp),
      P.add_incomplete Q = some R ∧
      embed E hA cp hB R hR = embed E hA cp hB P hP + embed E hA cp hB Q hQ := by
  have hx : P.x ≠ Q.x := by
    intro h
    rcases SWPoint.eq_pm_of_x_eq (embed_ne_zero E hA cp hB P hP)
      (embed_ne_zero E hA cp hB Q hQ) h with h | h
    · exact hne h
    · exact hneg h
  obtain ⟨R, hadd⟩ : ∃ R, P.add_incomplete Q = some R := by
    simp only [Point.add_incomplete, if_neg hx]
    exact ⟨_, rfl⟩
  have hR := Lemmas.add_incomplete_preserves_membership P Q cp hx hP hQ
  rw [hadd] at hR
  exact ⟨R, hR, hadd, embed_add E hA cp hB P Q R hP hQ hR hadd⟩

/-- Successful affine doubling agrees with doubling in the complete group. -/
theorem embed_double [NeZero (2 : F p)] (P D : Point (F p))
    (hP : P.isOnCurve cp) (hD : D.isOnCurve cp) (hd : P.double = some D) :
    embed E hA cp hB D hD = (2 : ℤ) • embed E hA cp hB P hP := by
  have hy : P.y ≠ 0 := by
    intro h
    simp only [Point.double, if_pos h] at hd
    cases hd
  have hp : (P.x, P.y) ≠ (0, 0) := by
    intro h
    exact embed_ne_zero E hA cp hB P hP (SWPoint.ext_pair h)
  have hy' : P.y + P.y ≠ 0 := by
    rw [← two_mul]
    exact mul_ne_zero (NeZero.ne 2) hy
  simp only [Point.double, if_neg hy, Option.some.injEq] at hd
  subst D
  rw [two_zsmul]
  apply SWPoint.ext_pair
  change _ = add E.A (P.x, P.y) (P.x, P.y)
  simp only [add, hp, if_false, if_true, hy', hA, _root_.add_zero, embed, Prod.mk.injEq]
  constructor <;> ring

/-- The four group inequalities exclude every exceptional affine addition
in `((A + D) + A) + A`. -/
theorem tripleAdd_exists (A D : Point (F p)) (hAc : A.isOnCurve cp) (hDc : D.isOnCurve cp)
    (hminus : embed E hA cp hB A hAc - embed E hA cp hB D hDc ≠ 0)
    (hplus : embed E hA cp hB A hAc + embed E hA cp hB D hDc ≠ 0)
    (h2 : (2 : ℤ) • embed E hA cp hB A hAc + embed E hA cp hB D hDc ≠ 0)
    (h3 : (3 : ℤ) • embed E hA cp hB A hAc + embed E hA cp hB D hDc ≠ 0) :
    ∃ (R : Point (F p)) (hR : R.isOnCurve cp),
      TripleAndAddIncompleteUnchecked.tripleAddNative A D = some R ∧
      embed E hA cp hB R hR = (3 : ℤ) • embed E hA cp hB A hAc + embed E hA cp hB D hDc := by
  let a := embed E hA cp hB A hAc
  let d := embed E hA cp hB D hDc
  obtain ⟨R1, hR1, hadd1, hg1⟩ := add_exists E hA cp hB A D hAc hDc
    (fun h => hminus (by rw [h, sub_self]))
    (fun h => hplus (by rw [h, neg_add_cancel]))
  have hne2 : embed E hA cp hB R1 hR1 ≠ a := by
    intro h
    apply embed_ne_zero E hA cp hB D hDc
    have heq : a + d = a + 0 := by simpa only [_root_.add_zero] using hg1.symm.trans h
    exact add_left_cancel heq
  have hneg2 : embed E hA cp hB R1 hR1 ≠ -a := by
    intro h
    apply h2
    calc (2 : ℤ) • a + d = (a + d) + a := by module
         _ = embed E hA cp hB R1 hR1 + a := by rw [hg1]
         _ = 0 := by rw [h, neg_add_cancel]
  obtain ⟨R2, hR2, hadd2, hg2⟩ := add_exists E hA cp hB R1 A hR1 hAc hne2 hneg2
  have hg2' : embed E hA cp hB R2 hR2 = (2 : ℤ) • a + d := by
    rw [hg2, hg1]
    dsimp [a, d]
    module
  have hne3 : embed E hA cp hB R2 hR2 ≠ a := by
    intro h
    apply hplus
    calc a + d = embed E hA cp hB R2 hR2 - a := by rw [hg2']; module
         _ = 0 := by rw [h, sub_self]
  have hneg3 : embed E hA cp hB R2 hR2 ≠ -a := by
    intro h
    apply h3
    calc (3 : ℤ) • a + d = embed E hA cp hB R2 hR2 + a := by rw [hg2']; module
         _ = 0 := by rw [h, neg_add_cancel]
  obtain ⟨R, hR, hadd3, hg3⟩ := add_exists E hA cp hB R2 A hR2 hAc hne3 hneg3
  refine ⟨R, hR, ?_, ?_⟩
  · simp only [TripleAndAddIncompleteUnchecked.tripleAddNative, hadd1, hadd2, hadd3]
  · rw [hg3, hg2']
    dsimp [a, d]
    module

end Ragu.Circuits.Point.Group
