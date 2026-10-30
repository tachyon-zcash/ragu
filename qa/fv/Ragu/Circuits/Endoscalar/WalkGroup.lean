import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Point.Group
import Ragu.Lemmas.EndoscalarGroup

/-!
# The affine walk in the complete group

Each affine accumulator is the action of its integer Eisenstein index.
The integer norm bounds then exclude the exceptional cases of all three
incomplete additions in each radix-3 step.
-/

namespace Ragu.Circuits.Endoscalar.WalkGroup

open Point.Spec Walk Ragu.Lemmas.EndoscalarProof
open Ragu.Lemmas
open CompElliptic.CurveForms.ShortWeierstrass

variable {p : ℕ} [Fact p.Prime]

/-- The choices made by the native digit selector. Circuit contracts also
require booleanity; the partial native walk itself branches on equality to one. -/
def nativeDigit (s e1 e2 : F p) : Digit := ⟨decide (s = 1), decide (e1 = 1), decide (e2 = 1)⟩

variable (E : SWCurve (F p)) (hA : E.A = 0) (cp : CurveParams p) (hB : E.B = cp.b)

local notation "ι" => Point.Group.embed E hA cp hB
local notation "φ" => CoordinateMap.endo E hA cp.ζ cp.h_small_order

/-- Initialization succeeds and represents the initial Eisenstein index. -/
theorem initial_exists [NeZero (2 : F p)] (r s0 e0 : F p)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve cp) (hno2 : cp.noOrderTwoPoints) :
    ∃ (A : Point (F p)) (hAcurve : A.isOnCurve cp),
      Initial.initNative cp r s0 e0 = some A ∧
      ι A hAcurve = EndoscalarGroup.eval φ (ι ⟨r, r⟩ hbase)
        (initIndex (decide (s0 = 1)) (decide (e0 = 1))) := by
  have hr : r ≠ 0 := hno2 ⟨r, r⟩ hbase
  obtain ⟨D, hd⟩ : ∃ D, (⟨r, r⟩ : Point (F p)).double = some D := by
    simp only [Point.double, if_neg hr]
    exact ⟨_, rfl⟩
  have hD := Point.Lemmas.double_preserves_membership ⟨r, r⟩ cp hbase hno2
  rw [hd] at hD
  have hDe := endo_isOnCurve cp D hD
  have hg := Point.Group.embed_double E hA cp hB ⟨r, r⟩ D hbase hD hd
  let A := if s0 = 1 then (if e0 = 1 then D.endo cp else D).negate
    else (if e0 = 1 then D.endo cp else D)
  have hinit : Initial.initNative cp r s0 e0 = some A := by
    simp only [Initial.initNative, hd, A]
  have hAc := initNative_isOnCurve cp r s0 e0 A hbase hno2 hinit
  refine ⟨A, hAc, hinit, ?_⟩
  by_cases hs : s0 = 1 <;> by_cases he : e0 = 1
  all_goals
    simp only [A, hs, he, if_true, if_false, decide_true, decide_false,
      initIndex, Bool.false_eq_true, EndoscalarGroup.eval]
    simp only [Point.Group.embed_negate E hA cp hB D hD,
      Point.Group.embed_negate E hA cp hB (D.endo cp) hDe,
      Point.Group.embed_endo E hA cp hB D hD, hg, map_zsmul]
    module

/-- Every unsigned selector choice exists and has the stated group index. -/
theorem unsigned_digit_exists (r e1 e2 : F p) (hr : r ≠ 0) (hζ : cp.ζ ≠ 1)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve cp) :
    ∃ (D : Point (F p)) (hD : D.isOnCurve cp),
      digitPointUnsigned cp r e1 e2 = some D ∧
      ι D hD = EndoscalarGroup.eval φ (ι ⟨r, r⟩ hbase)
        (digitIndex ⟨false, decide (e1 = 1), decide (e2 = 1)⟩) := by
  let P : Point (F p) := ⟨r, r⟩
  have he := endo_isOnCurve cp P hbase
  have hee := endo_isOnCurve cp (P.endo cp) he
  have hen := negate_isOnCurve cp (P.endo cp) he
  have hxe : r ≠ cp.ζ * r := by
    intro h
    apply hζ
    exact mul_right_cancel₀ hr (by simpa using h.symm)
  obtain ⟨D, hd⟩ : ∃ D, digitPointUnsigned cp r e1 e2 = some D := by
    by_cases he1 : e1 = 1 <;> by_cases he2 : e2 = 1
    all_goals
      simp only [digitPointUnsigned, he1, he2, if_true, if_false,
        Point.add_incomplete, Point.endo, Point.negate, hxe]
      exact ⟨_, rfl⟩
  have hD := digitPointUnsigned_isOnCurve cp r e1 e2 D hbase hd
  refine ⟨D, hD, hd, ?_⟩
  have hpoly := CoordinateMap.endo_quadratic E hA cp.ζ cp.h_small_order hζ
    (ι P hbase) hr
  by_cases he1 : e1 = 1 <;> by_cases he2 : e2 = 1
  · have hadd : P.add_incomplete (P.endo cp).negate = some D := by
      simpa only [digitPointUnsigned, he1, he2, if_true] using hd
    rw [Point.Group.embed_add E hA cp hB P (P.endo cp).negate D hbase hen hD hadd,
      Point.Group.embed_negate E hA cp hB (P.endo cp) he,
      Point.Group.embed_endo E hA cp hB P hbase]
    simp only [he1, he2, decide_true, digitIndex, Bool.false_eq_true, if_false]
    dsimp [EndoscalarGroup.eval, P]
    module
  · have h : P.endo cp = D := by
      simpa only [digitPointUnsigned, he1, he2, if_true, if_false, Option.some.injEq] using hd
    subst D
    rw [Point.Group.embed_endo E hA cp hB P hbase]
    simp [he1, he2, digitIndex, EndoscalarGroup.eval, P]
  · have h : (P.endo cp).endo cp = D := by
      simpa only [digitPointUnsigned, he1, he2, if_true, if_false, Option.some.injEq] using hd
    subst D
    rw [Point.Group.embed_endo E hA cp hB (P.endo cp) he,
      Point.Group.embed_endo E hA cp hB P hbase]
    simp only [he1, he2, decide_true, decide_false, digitIndex, Bool.false_eq_true,
      if_false, EndoscalarGroup.eval, neg_one_zsmul]
    calc
      φ (φ (ι P hbase)) = (φ (φ (ι P hbase)) + φ (ι P hbase) + ι P hbase) -
          φ (ι P hbase) - ι P hbase := by abel
      _ = _ := by rw [hpoly]; simp [sub_eq_add_neg, P]
  · have h : P = D := by
      simpa only [digitPointUnsigned, he1, he2, if_true, if_false, Option.some.injEq] using hd
    subst D
    simp [he1, he2, digitIndex, EndoscalarGroup.eval, P]

/-- The sign selector negates the same integer action as the point. -/
theorem digit_exists (r s e1 e2 : F p) (hr : r ≠ 0) (hζ : cp.ζ ≠ 1)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve cp) :
    ∃ (D : Point (F p)) (hD : D.isOnCurve cp),
      digitPoint cp r s e1 e2 = some D ∧
      ι D hD = EndoscalarGroup.eval φ (ι ⟨r, r⟩ hbase) (digitIndex (nativeDigit s e1 e2)) := by
  obtain ⟨U, hU, hu, hg⟩ := unsigned_digit_exists E hA cp hB r e1 e2 hr hζ hbase
  by_cases hs : s = 1
  · have hUn := negate_isOnCurve cp U hU
    refine ⟨U.negate, hUn, ?_, ?_⟩
    · simp only [digitPoint, hu, Option.map_some, hs, if_true]
    rw [Point.Group.embed_negate E hA cp hB U hU, hg]
    by_cases he1 : e1 = 1 <;> by_cases he2 : e2 = 1
    all_goals simp [nativeDigit, hs, he1, he2, digitIndex, EndoscalarGroup.eval] <;> abel
  · refine ⟨U, hU, ?_, ?_⟩
    · simp only [digitPoint, hu, Option.map_some, hs, if_false]
    simpa only [nativeDigit, hs, decide_false] using hg

/-- The digit prefix consumed in exactly the same order as `accAfter`. -/
def digitPrefix (bits : Vector (F p) numBits) : ℕ → List Digit
  | 0 => []
  | m + 1 =>
    if h : 4 + 3 * m < numBits then
      digitPrefix bits m ++ [nativeDigit (bits[2 + 3 * m]'(by omega))
        (bits[3 + 3 * m]'(by omega)) (bits[4 + 3 * m]'h)]
    else digitPrefix bits m

/-- A prefix of `m ≤ numDigits` digits has length `m`, supplying the
`≤ 46` length bound the collision lemma needs at every step. -/
theorem digitPrefix_length (bits : Vector (F p) numBits) (m : ℕ) (hm : m ≤ numDigits) :
    (digitPrefix bits m).length = m := by
  induction m with
  | zero => rfl
  | succ m ih =>
    have hidx := walk_index_lt m (by omega)
    simp only [digitPrefix, dif_pos hidx, List.length_append, List.length_singleton, ih (by omega)]

/-- Every prefix succeeds and its affine accumulator equals the action of
the integer index. No affine-success premise occurs in this invariant. -/
theorem accAfter_exists [NeZero (2 : F p)] {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card (SWPoint E) = q) (hq : groupScaleCollisionBound < q)
    (r : F p) (hr : r ≠ 0) (hζ : cp.ζ ≠ 1)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve cp) (hno2 : cp.noOrderTwoPoints)
    (bits : Vector (F p) numBits) (m : ℕ) (hm : m ≤ numDigits) :
    ∃ (A : Point (F p)) (hAc : A.isOnCurve cp),
      accAfter cp r bits m = some A ∧
      ι A hAc = EndoscalarGroup.eval φ (ι ⟨r, r⟩ hbase)
        (accIndex (initIndex (decide (bits[0] = 1)) (decide (bits[1] = 1))) (digitPrefix bits m)) := by
  induction m with
  | zero =>
    simpa only [digitPrefix, accIndex, List.foldl_nil, accAfter] using
      initial_exists E hA cp hB r bits[0] bits[1] hbase hno2
  | succ m ih =>
    have hm' : m < numDigits := by omega
    have hidx := walk_index_lt m hm'
    obtain ⟨A, hAc, hacc, hg⟩ := ih (by omega)
    obtain ⟨D, hDc, hd, hdg⟩ := digit_exists E hA cp hB r
      (bits[2 + 3 * m]'(by omega)) (bits[3 + 3 * m]'(by omega))
      (bits[4 + 3 * m]'hidx) hr hζ hbase
    have hpoly := CoordinateMap.endo_quadratic E hA cp.ζ cp.h_small_order hζ
      (ι ⟨r, r⟩ hbase) hr
    have hlen : (digitPrefix bits m).length ≤ 46 := by
      rw [digitPrefix_length bits m (by omega)]
      have hm'' : m < 47 := hm'
      omega
    have hnoncollision := EndoscalarGroup.collision_combinations_ne_zero hcard hq φ
      (ι ⟨r, r⟩ hbase) (Point.Group.embed_ne_zero E hA cp hB _ hbase) hpoly
      (decide (bits[0] = 1)) (decide (bits[1] = 1)) (digitPrefix bits m) hlen
      (nativeDigit (bits[2 + 3 * m]'(by omega)) (bits[3 + 3 * m]'(by omega))
        (bits[4 + 3 * m]'hidx))
    change (_ ≠ 0 ∧ _ ≠ 0 ∧ _ ≠ 0 ∧ _ ≠ 0) at hnoncollision
    rw [← hg, ← hdg] at hnoncollision
    obtain ⟨R, hR, htriple, hrg⟩ := Point.Group.tripleAdd_exists E hA cp hB A D hAc hDc
      hnoncollision.1 hnoncollision.2.1 hnoncollision.2.2.1 hnoncollision.2.2.2
    refine ⟨R, hR, ?_, ?_⟩
    · simp only [accAfter, hacc, dif_pos hidx, stepNative, hd, htriple]
    · rw [hrg, hg, hdg]
      simp only [digitPrefix, dif_pos hidx, accIndex, List.foldl_append, List.foldl_cons,
        List.foldl_nil, step, EndoscalarGroup.eval]
      module

include hA hB in
/-- Normalize to the isomorphic curve, apply the invariant, and move back.
The only curve-order premise is a prime cardinality exceeding the already
proved integer bound. In particular, walk success is a conclusion. -/
theorem groupScaleNative_ne_none [NeZero (2 : F p)] {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card (SWPoint E) = q) (hq : groupScaleCollisionBound < q)
    (hζ : cp.ζ ≠ 1) (hnz : cp.nonzeroCoordinates)
    (pt : Point (F p)) (hpt : pt.isOnCurve cp) (bits : Vector (F p) numBits) :
    groupScaleNative cp pt bits ≠ none := by
  let norm := normalizeNative pt
  have hx := hnz.1 pt hpt
  have hy := hnz.2 pt hpt
  have hc : norm.c ≠ 0 := div_ne_zero hx hy
  have hr : norm.r ≠ 0 := mul_ne_zero (pow_ne_zero 2 hc) hx
  let Et := CoordinateMap.curve E norm.c hc
  have hAt : Et.A = 0 := by simp only [Et, CoordinateMap.curve, hA, mul_zero]
  have hBt : Et.B = (twist cp norm.c).b := by simp only [Et, CoordinateMap.curve, twist, hB]
  have hcardt : Nat.card (SWPoint Et) = q :=
    (CoordinateMap.card_curve E hA norm.c hc).trans hcard
  obtain ⟨A, _, ha, _⟩ := accAfter_exists Et hAt (twist cp norm.c) hBt hcardt hq norm.r hr hζ
    (normalized_isOnCurve cp pt hpt hy) (twist_noOrderTwoPoints cp norm.c hc hnz.2)
    bits numDigits le_rfl
  rw [accAfter_twist] at ha
  change accAfter cp (normalizeNative pt).r bits numDigits = some A at ha
  simp only [groupScaleNative, ha, Option.map_some, ne_eq, reduceCtorEq, not_false_eq_true]

end Ragu.Circuits.Endoscalar.WalkGroup
