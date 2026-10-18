import CompElliptic.CurveForms.ShortWeierstrass
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.LinearCombination

/-!
# Coordinate changes on the complete short-Weierstrass group

The endoscalar walk normalizes by `(x, y) ↦ (c²x, c³y)`. The same
coordinate change, with `c = ζ²`, gives the cube-root endomorphism.
These lemmas cover the complete addition law, including infinity and doubling.
-/

namespace Ragu.Foundation.Pasta.CoordinateMap

open CompElliptic.CurveForms.ShortWeierstrass

variable {K : Type*} [Field K]

/-- Scale a coordinate pair, preserving the identity sentinel. -/
def coords (c : K) (P : K × K) : K × K := (c ^ 2 * P.1, c ^ 3 * P.2)

@[simp] theorem coords_zero (c : K) : coords c (0, 0) = (0, 0) := by
  simp [coords]

theorem coords_injective {c : K} (hc : c ≠ 0) : Function.Injective (coords c) := by
  rintro ⟨x, y⟩ ⟨x', y'⟩ h
  have hx := congrArg Prod.fst h
  have hy := congrArg Prod.snd h
  exact Prod.ext (mul_left_cancel₀ (pow_ne_zero 2 hc) hx)
    (mul_left_cancel₀ (pow_ne_zero 3 hc) hy)

/-- Complete addition commutes with a nonzero coordinate change. -/
theorem coords_add [DecidableEq K] {c : K} (hc : c ≠ 0) (P Q : K × K) :
    coords c (add 0 P Q) = add 0 (coords c P) (coords c Q) := by
  have hzero (R : K × K) : coords c R = (0, 0) ↔ R = (0, 0) := by
    simpa only [coords_zero] using
      ((coords_injective hc).eq_iff : coords c R = coords c (0, 0) ↔ R = (0, 0))
  have hx : (coords c P).1 = (coords c Q).1 ↔ P.1 = Q.1 :=
    mul_right_inj' (pow_ne_zero 2 hc)
  have hy : (coords c P).2 + (coords c Q).2 = 0 ↔ P.2 + Q.2 = 0 := by
    change c ^ 3 * P.2 + c ^ 3 * Q.2 = 0 ↔ _
    rw [← mul_add, mul_eq_zero, or_iff_right (pow_ne_zero 3 hc)]
  simp only [add, hzero, hx, hy]
  split_ifs with hP hQ hPQ hY
  all_goals try rfl
  · exact coords_zero c
  · apply Prod.ext <;> simp only [coords, _root_.add_zero]
    all_goals field_simp
  · apply Prod.ext <;> simp only [coords]
    all_goals field_simp

/-- Transport a curve by the normalization's nonzero scale factor. -/
def curve (E : SWCurve K) (c : K) (hc : c ≠ 0) : SWCurve K where
  A := c ^ 4 * E.A
  B := c ^ 6 * E.B
  B_nonzero := mul_ne_zero (pow_ne_zero 6 hc) E.B_nonzero
  IsElliptic := by
    have h : sw_Δ (c ^ 4 * E.A) (c ^ 6 * E.B) = c ^ 12 * sw_Δ E.A E.B := by
      unfold sw_Δ
      ring
    rw [h]
    exact (isUnit_iff_ne_zero.mpr (pow_ne_zero 12 hc)).mul E.IsElliptic

/-- A coordinate change carries every representable point to the new curve. -/
def point (E : SWCurve K) (c : K) (hc : c ≠ 0) (P : SWPoint E) :
    SWPoint (curve E c hc) where
  x := c ^ 2 * P.x
  y := c ^ 3 * P.y
  onCurve := by
    rcases P.onCurve with h | h
    · left
      simp only [OnCurve, curve] at h ⊢
      linear_combination c ^ 6 * h
    · right
      simpa only [coords_zero] using congrArg (coords c) h

/-- The normalization is an additive map for the `a = 0` curves in the walk. -/
def hom [DecidableEq K] (E : SWCurve K) (hA : E.A = 0) (c : K) (hc : c ≠ 0) :
    SWPoint E →+ SWPoint (curve E c hc) where
  toFun := point E c hc
  map_zero' := SWPoint.ext_pair (coords_zero c)
  map_add' P Q := by
    apply SWPoint.ext_pair
    change coords c (add E.A (P.x, P.y) (Q.x, Q.y)) =
      add (c ^ 4 * E.A) (coords c (P.x, P.y)) (coords c (Q.x, Q.y))
    simpa only [hA, mul_zero] using coords_add hc (P.x, P.y) (Q.x, Q.y)

/-- Normalization preserves the complete group's cardinality. -/
theorem hom_bijective [DecidableEq K] (E : SWCurve K) (hA : E.A = 0)
    (c : K) (hc : c ≠ 0) : Function.Bijective (hom E hA c hc) := by
  constructor
  · intro P Q h
    apply SWPoint.ext_pair
    apply coords_injective hc
    exact congrArg (fun R => (R.x, R.y)) h
  · intro Q
    have hvalid : Valid E.A E.B (Q.x / c ^ 2, Q.y / c ^ 3) := by
      rcases Q.onCurve with h | h
      · left
        simp only [OnCurve, curve] at h ⊢
        field_simp
        linear_combination h
      · right
        have hx := congrArg Prod.fst h
        have hy := congrArg Prod.snd h
        change Q.x = 0 at hx
        change Q.y = 0 at hy
        simp [hx, hy]
    refine ⟨⟨Q.x / c ^ 2, Q.y / c ^ 3, hvalid⟩, SWPoint.ext_pair ?_⟩
    change (c ^ 2 * (Q.x / c ^ 2), c ^ 3 * (Q.y / c ^ 3)) = (Q.x, Q.y)
    apply Prod.ext <;> field_simp

theorem card_curve [DecidableEq K] (E : SWCurve K) (hA : E.A = 0)
    (c : K) (hc : c ≠ 0) : Nat.card (SWPoint (curve E c hc)) = Nat.card (SWPoint E) :=
  (Nat.card_congr (Equiv.ofBijective _ (hom_bijective E hA c hc))).symm

/-- The cube-root coordinate map is an endomorphism of the complete group. -/
def endo [DecidableEq K] (E : SWCurve K) (hA : E.A = 0)
    (ζ : K) (hζ : ζ ^ 3 = 1) : SWPoint E →+ SWPoint E where
  toFun P := ⟨ζ * P.x, P.y, by
    rcases P.onCurve with h | h
    · left
      simpa only [OnCurve, hA, zero_mul, _root_.add_zero, mul_pow, hζ, one_mul] using h
    · right
      have hx := congrArg Prod.fst h
      have hy := congrArg Prod.snd h
      change P.x = 0 at hx
      change P.y = 0 at hy
      simp [hx, hy]⟩
  map_zero' := SWPoint.ext_pair (by change (ζ * 0, 0) = (0, 0); simp)
  map_add' P Q := by
    have hz : ζ ≠ 0 := by intro h; simp [h] at hζ
    have h4 : (ζ ^ 2) ^ 2 = ζ := by
      calc (ζ ^ 2) ^ 2 = ζ ^ 3 * ζ := by ring
           _ = ζ := by rw [hζ, one_mul]
    have h6 : (ζ ^ 2) ^ 3 = 1 := by rw [← pow_mul, Nat.mul_comm, pow_mul, hζ, one_pow]
    apply SWPoint.ext_pair
    change (ζ * (add E.A (P.x, P.y) (Q.x, Q.y)).1,
      (add E.A (P.x, P.y) (Q.x, Q.y)).2) =
      add E.A (ζ * P.x, P.y) (ζ * Q.x, Q.y)
    simpa only [coords, hA, h4, h6, one_mul] using
      coords_add (pow_ne_zero 2 hz) (P.x, P.y) (Q.x, Q.y)

/-- The three endomorphism images are collinear on `y = P.y`; their sum is zero.
Only the base point's nonzero `x` coordinate is needed. -/
theorem endo_quadratic [DecidableEq K] (E : SWCurve K) (hA : E.A = 0)
    (ζ : K) (hζ : ζ ^ 3 = 1) (hne : ζ ≠ 1) (P : SWPoint E) (hx : P.x ≠ 0) :
    endo E hA ζ hζ (endo E hA ζ hζ P) + endo E hA ζ hζ P + P = 0 := by
  have hz : ζ ≠ 0 := by intro h; simp [h] at hζ
  have hpoly : ζ ^ 2 + ζ + 1 = 0 := by
    have h : (ζ - 1) * (ζ ^ 2 + ζ + 1) = 0 := by linear_combination hζ
    exact (mul_eq_zero.mp h).resolve_left (sub_ne_zero.mpr hne)
  have hp : (P.x, P.y) ≠ (0, 0) := fun h => hx (congrArg Prod.fst h)
  have he : (ζ * P.x, P.y) ≠ (0, 0) := fun h =>
    mul_ne_zero hz hx (congrArg Prod.fst h)
  have hxe : P.x ≠ ζ * P.x := by
    intro h
    apply hne
    exact mul_right_cancel₀ hx (by simpa using h.symm)
  have hsum : P + endo E hA ζ hζ P = -(endo E hA ζ hζ (endo E hA ζ hζ P)) := by
    apply SWPoint.ext_pair
    change add E.A (P.x, P.y) (ζ * P.x, P.y) = (ζ * (ζ * P.x), -P.y)
    simp only [add, hp, he, hxe, if_false, sub_self, zero_div, zero_pow (by decide : 2 ≠ 0),
      zero_sub, zero_mul, Prod.mk.injEq]
    exact ⟨by linear_combination -P.x * hpoly, trivial⟩
  rw [_root_.add_comm P] at hsum
  rw [_root_.add_assoc, hsum, add_neg_cancel]

end Ragu.Foundation.Pasta.CoordinateMap
