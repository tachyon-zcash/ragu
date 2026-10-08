import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Gadgets.Boolean
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Endoscalar.Initial
import Ragu.Circuits.Point.Spec
import Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked

/-!
# The radix-3 endoscaling walk, natively

What `Endoscalar::group_scale` and `HoistedEndoscalar::group_scale` compute,
as affine curve arithmetic over `Option`, and the lemmas their proofs share:
the digit points in closed form, curve membership along the walk, and the
peeling of Clean's `foldlRange` accumulator one iteration at a time.

The endoscalar has `numBits = 143` bits: two initial bits `(s₀, e₀)` and
`numDigits = 47` three-bit digits `(s, e₁, e₂)`, least significant first.
-/

namespace Ragu.Circuits.Endoscalar.Walk
open Point.Spec
variable {p : ℕ} [Fact p.Prime]

/-- The width of an endoscalar: `ENDOSCALAR_BITS`. -/
abbrev numBits : ℕ := 143

/-- The radix-3 digits after the two initial bits: `ENDOSCALAR_DIGITS`. -/
abbrev numDigits : ℕ := 47

/-! `omega` treats the two abbreviations as atoms, so the index bounds the
walk needs are proved once, over the literals. -/

lemma numDigits_pred_lt : numDigits - 1 < numDigits := by decide

/-- The three bit indices of digit `i` lie in the endoscalar. -/
lemma bit_index_lt (i : Fin numDigits) {j : ℕ} (hj : j ≤ 4) : j + 3 * i.val < numBits := by
  have hi : i.val < 47 := i.isLt
  show j + 3 * i.val < 143
  omega

/-- The last bit index of digit `m` lies in the endoscalar. -/
lemma walk_index_lt (m : ℕ) (hm : m < numDigits) : 4 + 3 * m < numBits := by
  have hm' : m < 47 := hm
  show 4 + 3 * m < 143
  omega

/-- The hoisted product wires, two per digit: `ENDOSCALAR_PRODUCTS`. -/
abbrev numProducts : ℕ := 94

/-- Digit `i`'s `e₁ e₂` wire lies among the products. -/
lemma product_index_lt (i : Fin numDigits) : 2 * i.val < numProducts := by
  have hi : i.val < 47 := i.isLt
  show 2 * i.val < 94
  omega

/-- Digit `i`'s `e₁ e₂ s` wire lies among the products. -/
lemma product_index_succ_lt (i : Fin numDigits) : 2 * i.val + 1 < numProducts := by
  have hi : i.val < 47 := i.isLt
  show 2 * i.val + 1 < 94
  omega

/-- The curve the normalized walk runs on: `y² = x³ + c⁶ b`, isomorphic to
the original under `(x, y) ↦ (c² x, c³ y)`. -/
def twist (curveParams : CurveParams p) (c : F p) : CurveParams p :=
  { b := c ^ 6 * curveParams.b, ζ := curveParams.ζ, h_small_order := curveParams.h_small_order }

/-- `c = x / y` and `r = c² x`: the normalization that moves a point to
`(r, r)`. -/
def normalizeNative (pt : Point (F p)) : F p × F p :=
  (pt.x / pt.y, (pt.x / pt.y) ^ 2 * pt.x)

/-- The unsigned digit point `{P̂, φP̂, φ²P̂, P̂ - φP̂}[e₁, e₂]` on the
normalized base `P̂ = (r, r)`, `none` only if `P̂ - φP̂` is degenerate, which
`r ≠ 0` and `ζ ≠ 1` rule out. -/
def digitPointUnsigned (curveParams : CurveParams p) (r e1 e2 : F p) : Option (Point (F p)) :=
  let base : Point (F p) := ⟨r, r⟩
  if e1 = 1 then
    if e2 = 1 then base.add_incomplete (base.endo curveParams).negate
    else some (base.endo curveParams)
  else if e2 = 1 then some ((base.endo curveParams).endo curveParams)
  else some base

/-- The digit point `(-1)^s {P̂, φP̂, φ²P̂, P̂ - φP̂}[e₁, e₂]`. -/
def digitPoint (curveParams : CurveParams p) (r s e1 e2 : F p) : Option (Point (F p)) :=
  (digitPointUnsigned curveParams r e1 e2).map fun d => if s = 1 then d.negate else d

/-- On a boolean sign bit, the conditional negation is the scaling of `y` by
`1 - 2s`. -/
lemma negate_if_eq (s : F p) (hs : IsBool s) (d : Point (F p)) :
    (if s = 1 then d.negate else d) = ⟨d.x, (1 + -2 * s) * d.y⟩ := by
  rcases hs with hs | hs <;> subst hs <;> cases d with
  | mk x y =>
    simp only [zero_ne_one, if_true, if_false, Point.negate]
    congr 1
    ring

/-- One step of the walk: `[3] acc + D` for the digit's point `D`. -/
def stepNative (curveParams : CurveParams p) (r : F p) (acc : Point (F p)) (s e1 e2 : F p)
    : Option (Point (F p)) :=
  match digitPoint curveParams r s e1 e2 with
  | none => none
  | some d => Point.TripleAndAddIncompleteUnchecked.tripleAddNative acc d

/-- The accumulator after `m` digits, from the initial point. -/
def accAfter (curveParams : CurveParams p) (r : F p) (bits : Vector (F p) numBits)
    : ℕ → Option (Point (F p))
  | 0 => Initial.initNative curveParams r bits[0] bits[1]
  | m + 1 =>
    match accAfter curveParams r bits m with
    | none => none
    | some acc =>
      if h : 4 + 3 * m < numBits then
        stepNative curveParams r acc (bits[2 + 3 * m]'(by omega)) (bits[3 + 3 * m]'(by omega))
          (bits[4 + 3 * m]'h)
      else
        none

/-- The walk's result on the original curve: normalize, walk, move back.
Stated with `Option.map` rather than a `match`, so that no tactic is tempted
to reduce it by unrolling the `numDigits`-deep recursion of `accAfter`. -/
def groupScaleNative (curveParams : CurveParams p) (pt : Point (F p))
    (bits : Vector (F p) numBits) : Option (Point (F p)) :=
  (accAfter curveParams (normalizeNative pt).2 bits numDigits).map fun acc =>
    ⟨acc.x / (normalizeNative pt).1 ^ 2, acc.y / (normalizeNative pt).1 ^ 3⟩

/-! ## Curve membership along the walk -/

/-- `ζ² + ζ + 1 = 0` for a nontrivial cube root of unity. -/
lemma zeta_quadratic (curveParams : CurveParams p) (hζ : curveParams.ζ ≠ 1) :
    curveParams.ζ ^ 2 + curveParams.ζ + 1 = 0 := by
  have h3 := curveParams.h_small_order
  have : (curveParams.ζ - 1) * (curveParams.ζ ^ 2 + curveParams.ζ + 1) = 0 := by
    linear_combination h3
  rcases mul_eq_zero.mp this with h | h
  · exact absurd (sub_eq_zero.mp h) hζ
  · exact h

lemma endo_isOnCurve (curveParams : CurveParams p) (pt : Point (F p))
    (h : pt.isOnCurve curveParams) : (pt.endo curveParams).isOnCurve curveParams := by
  simp only [Point.isOnCurve, Point.endo] at h ⊢
  rw [mul_pow, curveParams.h_small_order, one_mul]
  exact h

lemma negate_isOnCurve (curveParams : CurveParams p) (pt : Point (F p))
    (h : pt.isOnCurve curveParams) : pt.negate.isOnCurve curveParams := by
  simp only [Point.isOnCurve, Point.negate] at h ⊢
  rw [neg_sq]
  exact h

/-- The normalized base lies on the twisted curve. -/
lemma normalized_isOnCurve (curveParams : CurveParams p) (pt : Point (F p))
    (h : pt.isOnCurve curveParams) (hy : pt.y ≠ 0) :
    (⟨(normalizeNative pt).2, (normalizeNative pt).2⟩ : Point (F p)).isOnCurve
      (twist curveParams (normalizeNative pt).1) := by
  simp only [Point.isOnCurve, normalizeNative, twist] at h ⊢
  field_simp
  linear_combination (pt.x ^ 6) * h

/-- An unsigned digit point lies on the curve of its base. -/
lemma digitPointUnsigned_isOnCurve (curveParams : CurveParams p) (r e1 e2 : F p)
    (d : Point (F p)) (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve curveParams)
    (h : digitPointUnsigned curveParams r e1 e2 = some d) : d.isOnCurve curveParams := by
  simp only [digitPointUnsigned] at h
  have h_endo := endo_isOnCurve curveParams ⟨r, r⟩ hbase
  have h_endo2 := endo_isOnCurve curveParams _ h_endo
  have h_neg := negate_isOnCurve curveParams _ h_endo
  by_cases he1 : e1 = 1 <;> by_cases he2 : e2 = 1 <;>
    simp only [he1, he2, if_true, if_false, Option.some.injEq] at h
  · have hx : (⟨r, r⟩ : Point (F p)).x ≠ ((⟨r, r⟩ : Point (F p)).endo curveParams).negate.x := by
      intro hx
      rw [Point.add_incomplete, if_pos hx] at h
      cases h
    have hm := Point.Lemmas.add_incomplete_preserves_membership ⟨r, r⟩
      ((⟨r, r⟩ : Point (F p)).endo curveParams).negate curveParams hx hbase h_neg
    rw [h] at hm
    exact hm
  · subst h; exact h_endo
  · subst h; exact h_endo2
  · subst h; exact hbase

/-- A digit point lies on the curve of its base. -/
lemma digitPoint_isOnCurve (curveParams : CurveParams p) (r s e1 e2 : F p) (d : Point (F p))
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve curveParams)
    (h : digitPoint curveParams r s e1 e2 = some d) : d.isOnCurve curveParams := by
  simp only [digitPoint, Option.map_eq_some_iff] at h
  obtain ⟨u, hu, rfl⟩ := h
  have hu' := digitPointUnsigned_isOnCurve curveParams r e1 e2 u hbase hu
  split_ifs
  · exact negate_isOnCurve curveParams _ hu'
  · exact hu'

lemma stepNative_isOnCurve (curveParams : CurveParams p) (r : F p) (acc out : Point (F p))
    (s e1 e2 : F p)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve curveParams)
    (hacc : acc.isOnCurve curveParams)
    (h : stepNative curveParams r acc s e1 e2 = some out) : out.isOnCurve curveParams := by
  simp only [stepNative] at h
  rcases hd : digitPoint curveParams r s e1 e2 with _ | d
  · rw [hd] at h; simp at h
  · rw [hd] at h
    exact Point.TripleAndAddIncompleteUnchecked.tripleAddNative_isOnCurve curveParams acc d out
      hacc (digitPoint_isOnCurve curveParams r s e1 e2 d hbase hd) h

lemma initNative_isOnCurve [NeZero (2 : F p)] (curveParams : CurveParams p) (r s0 e0 : F p)
    (out : Point (F p))
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve curveParams)
    (h_no2 : curveParams.noOrderTwoPoints)
    (h : Initial.initNative curveParams r s0 e0 = some out) : out.isOnCurve curveParams := by
  simp only [Initial.initNative] at h
  have hd := Point.Lemmas.double_preserves_membership ⟨r, r⟩ curveParams hbase h_no2
  rcases hdd : (⟨r, r⟩ : Point (F p)).double with _ | d
  · rw [hdd] at hd; simp at hd
  · rw [hdd] at h hd
    simp only [Option.some.injEq] at h
    subst h
    split_ifs
    all_goals first
      | exact negate_isOnCurve curveParams _ (endo_isOnCurve curveParams _ hd)
      | exact endo_isOnCurve curveParams _ hd
      | exact negate_isOnCurve curveParams _ hd
      | exact hd

/-- Every accumulator the walk produces lies on the twisted curve. -/
lemma accAfter_isOnCurve [NeZero (2 : F p)] (curveParams : CurveParams p) (r : F p)
    (bits : Vector (F p) numBits)
    (hbase : (⟨r, r⟩ : Point (F p)).isOnCurve curveParams)
    (h_no2 : curveParams.noOrderTwoPoints) :
    ∀ m (acc : Point (F p)), accAfter curveParams r bits m = some acc →
      acc.isOnCurve curveParams := by
  intro m
  induction m with
  | zero =>
    intro acc h
    exact initNative_isOnCurve curveParams r _ _ acc hbase h_no2 h
  | succ m ih =>
    intro acc h
    simp only [accAfter] at h
    rcases hprev : accAfter curveParams r bits m with _ | prev
    · rw [hprev] at h; simp at h
    · rw [hprev] at h
      split_ifs at h with hm
      exact stepNative_isOnCurve curveParams r prev acc _ _ _ hbase (ih prev hprev) h

/-- Moving back from the twisted curve lands on the original one. -/
lemma denormalize_isOnCurve (curveParams : CurveParams p) (c : F p) (hc : c ≠ 0)
    (pt : Point (F p)) (h : pt.isOnCurve (twist curveParams c)) :
    (⟨pt.x / c ^ 2, pt.y / c ^ 3⟩ : Point (F p)).isOnCurve curveParams := by
  simp only [Point.isOnCurve, twist] at h ⊢
  field_simp
  linear_combination h

/-! ## The digit points in closed form

For boolean bits and a nontrivial cube root of unity, the digit point's
coordinates are what the selectors compute. -/

/-- `P̂ - φP̂ = (ζ² (r - 4/3), (1 + 2ζ)(r - 8/9))`: the chord through
`(r, r)` and `(ζr, -r)` has slope `-2/(ζ - 1) = 2(ζ + 2)/3`. -/
lemma base_sub_endo (curveParams : CurveParams p) (r : F p) (hr : r ≠ 0)
    (hζ : curveParams.ζ ≠ 1) (h3 : (3 : F p) ≠ 0) :
    (⟨r, r⟩ : Point (F p)).add_incomplete ((⟨r, r⟩ : Point (F p)).endo curveParams).negate =
      some ⟨curveParams.ζ ^ 2 * (r - 4 * (3 : F p)⁻¹),
        (1 + 2 * curveParams.ζ) * (r - 8 * (3 : F p)⁻¹ ^ 2)⟩ := by
  have hq := zeta_quadratic curveParams hζ
  have h3t : (3 : F p) * (3 : F p)⁻¹ = 1 := mul_inv_cancel₀ h3
  have hne : r ≠ curveParams.ζ * r := by
    intro h
    apply hζ
    have : (curveParams.ζ - 1) * r = 0 := by linear_combination -h
    rcases mul_eq_zero.mp this with h' | h'
    · exact sub_eq_zero.mp h'
    · exact absurd h' hr
  have hd : curveParams.ζ * r - r ≠ 0 := by
    intro h; apply hne; linear_combination -h
  have hlam : (-r - r) / (curveParams.ζ * r - r) = 2 * (curveParams.ζ + 2) * (3 : F p)⁻¹ := by
    rw [div_eq_iff hd]
    linear_combination (-2 * (3 : F p)⁻¹ * r) * hq + (2 * r) * h3t
  have hx : (2 * (curveParams.ζ + 2) * (3 : F p)⁻¹) ^ 2 - r - curveParams.ζ * r =
      curveParams.ζ ^ 2 * (r - 4 * (3 : F p)⁻¹) := by
    linear_combination (4 * (3 : F p)⁻¹ ^ 2 - r + 4 * (3 : F p)⁻¹) * hq +
      (4 * (3 : F p)⁻¹ * (curveParams.ζ + 1)) * h3t
  simp only [Point.add_incomplete, Point.endo, Point.negate, if_neg hne, Option.some.injEq,
    Point.mk.injEq]
  rw [hlam, hx]
  refine ⟨rfl, ?_⟩
  linear_combination ((curveParams.ζ + 1) * (8 * (3 : F p)⁻¹ ^ 2 - 2 * (3 : F p)⁻¹ * r)) * hq +
    (2 * r * (curveParams.ζ + 1)) * h3t

/-! ## Non-degeneracy along the walk -/

lemma accAfter_none_persists (curveParams : CurveParams p) (r : F p)
    (bits : Vector (F p) numBits) :
    ∀ k m, k ≤ m → accAfter curveParams r bits k = none →
      accAfter curveParams r bits m = none := by
  intro k m hkm h_none
  induction m with
  | zero =>
    interval_cases k; exact h_none
  | succ m ih =>
    by_cases hkm' : k ≤ m
    · simp only [accAfter, ih hkm']
    · have : k = m + 1 := by omega
      rw [this] at h_none; exact h_none

lemma all_accAfter_ne (curveParams : CurveParams p) (r : F p) (bits : Vector (F p) numBits)
    (h : accAfter curveParams r bits numDigits ≠ none) :
    ∀ m ≤ numDigits, accAfter curveParams r bits m ≠ none := by
  intro m hm hm_none
  apply h
  exact accAfter_none_persists curveParams r bits m numDigits hm hm_none

/-- One-step unfolding of `accAfter` at a known `some` accumulator. -/
lemma accAfter_succ_of_some (curveParams : CurveParams p) (r : F p)
    (bits : Vector (F p) numBits) (m : ℕ) (prev : Point (F p))
    (h : accAfter curveParams r bits m = some prev) (hm : 4 + 3 * m < numBits) :
    accAfter curveParams r bits (m + 1) =
      stepNative curveParams r prev (bits[2 + 3 * m]'(by omega)) (bits[3 + 3 * m]'(by omega))
        (bits[4 + 3 * m]'hm) := by
  simp only [accAfter, h]
  rw [dif_pos hm]

/-- `groupScaleNative ≠ none` is `accAfter numDigits ≠ none` for the
normalized base. -/
lemma accAfter_ne_of_groupScale (curveParams : CurveParams p) (pt : Point (F p))
    (bits : Vector (F p) numBits) (h : groupScaleNative curveParams pt bits ≠ none) :
    accAfter curveParams (normalizeNative pt).2 bits numDigits ≠ none := by
  intro h_none
  apply h
  simp only [groupScaleNative, h_none]
  rfl

/-- The walk reads only `ζ` from its curve parameters, so it is the same walk
on the twisted curve. -/
lemma accAfter_twist (curveParams : CurveParams p) (c r : F p) (bits : Vector (F p) numBits) :
    ∀ m, accAfter (twist curveParams c) r bits m = accAfter curveParams r bits m
  | 0 => rfl
  | m + 1 => by
    simp only [accAfter, accAfter_twist curveParams c r bits m]
    rfl

/-! ## The symbolic accumulator of the `foldlRange`

`Circuit.foldlRange` has no `ConstantOutput`, so its `circuit_norm` lemmas
leave the accumulator entering iteration `i` as Clean's
`Circuit.FoldlM.foldlAcc … i`: a `Fin.foldl` of the body's symbolic outputs.
The lemmas below peel that fold one iteration at a time and thread the
per-iteration step facts through the native `accAfter` recursion. They are
stated for an arbitrary fold body of constant length `stepLen` whose output
evaluates to `stepOut i acc off` on the evaluated accumulator `acc`, so both
walk circuits use them. -/

/-- The symbolic accumulator entering iteration `i` of the fold with body
`body`, starting from `init` at wire offset `n`. -/
abbrev accVar (n : ℕ)
    (body : Var Point (F p) → Fin numDigits → Circuit (F p) (Var Point (F p)))
    (init : Var Point (F p)) (i : Fin numDigits) : Var Point (F p) :=
  Circuit.FoldlM.foldlAcc n (Vector.finRange numDigits) body init i

/-- Evaluate a symbolic point. -/
abbrev evalPt (env : Environment (F p)) (v : Var Point (F p)) : Point (F p) :=
  ⟨Expression.eval env v.x, Expression.eval env v.y⟩

/-- Iteration `i + 1`'s accumulator is the body's output on iteration `i`'s. -/
lemma accVar_succ (n stepLen : ℕ)
    (body : Var Point (F p) → Fin numDigits → Circuit (F p) (Var Point (F p)))
    (init : Var Point (F p)) (hlen : ∀ acc i, (body acc i).localLength = stepLen)
    (i : ℕ) (hi : i + 1 < numDigits) :
    accVar n body init ⟨i + 1, hi⟩ =
      (body (accVar n body init ⟨i, by omega⟩) ⟨i, by omega⟩).output (n + i * stepLen) := by
  simp only [accVar, Circuit.FoldlM.foldlAcc, Fin.val_mk]
  rw [Fin.foldl_succ_last]
  simp only [Vector.getElem_finRange, Fin.val_castSucc, Fin.val_last, hlen]

/-- The fold's final output is the body's output on the last accumulator. -/
lemma fin_foldl_eq_last (n stepLen : ℕ)
    (body : Var Point (F p) → Fin numDigits → Circuit (F p) (Var Point (F p)))
    (init : Var Point (F p)) (hlen : ∀ acc i, (body acc i).localLength = stepLen) :
    Fin.foldl numDigits (fun acc i => (body acc i).output (n + i.val * stepLen)) init =
      (body (accVar n body init ⟨numDigits - 1, numDigits_pred_lt⟩)
          ⟨numDigits - 1, numDigits_pred_lt⟩).output
        (n + (⟨numDigits - 1, numDigits_pred_lt⟩ : Fin numDigits).val * stepLen) := by
  rw [Fin.foldl_succ_last]
  simp only [accVar, Circuit.FoldlM.foldlAcc, Vector.getElem_finRange, Fin.last, Fin.val_mk,
    Fin.castSucc, Fin.castAdd, Fin.castLE, hlen]
  rfl

/-- Threading the per-iteration step facts through `accAfter`: for every
`m < numDigits`, the symbolic accumulator entering iteration `m` evaluates
to `accAfter m`, which is `some`. `h_steps` is what the fold's `circuit_norm`
residue gives once the per-step assumptions other than non-degeneracy are
discharged, `h_link` the evaluation of the body's output, `h0` the initial
point. -/
lemma fold_inv (curveParams : CurveParams p) (env : Environment (F p))
    (bits : Vector (F p) numBits) (r : F p)
    (body : Var Point (F p) → Fin numDigits → Circuit (F p) (Var Point (F p)))
    (init : Var Point (F p)) (n stepLen : ℕ)
    (stepOut : Fin numDigits → Point (F p) → ℕ → Point (F p))
    (h_ne : accAfter curveParams r bits numDigits ≠ none)
    (h_steps : ∀ i : Fin numDigits,
      stepNative curveParams r (evalPt env (accVar n body init i))
          (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) ≠ none →
      stepNative curveParams r (evalPt env (accVar n body init i))
          (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) =
        some (stepOut i (evalPt env (accVar n body init i)) (n + i.val * stepLen)))
    (hlen : ∀ acc i, (body acc i).localLength = stepLen)
    (h_link : ∀ acc (i : Fin numDigits),
      evalPt env ((body acc i).output (n + i.val * stepLen)) =
        stepOut i (evalPt env acc) (n + i.val * stepLen))
    (h0 : accAfter curveParams r bits 0 = some (evalPt env init)) :
    ∀ (m : ℕ) (hm : m < numDigits),
      accAfter curveParams r bits m = some (evalPt env (accVar n body init ⟨m, hm⟩)) := by
  intro m
  induction m with
  | zero =>
    intro hm
    simpa only [accVar, Circuit.FoldlM.foldlAcc, Fin.val_mk, Fin.foldl_zero] using h0
  | succ k ih =>
    intro hm
    have hk : k < numDigits := by omega
    have h_prev := ih hk
    have h_acck := accAfter_succ_of_some curveParams r bits k _ h_prev (walk_index_lt k (by omega))
    have h_nek := all_accAfter_ne curveParams r bits h_ne (k + 1) (by omega)
    rw [h_acck] at h_nek
    have h := h_steps ⟨k, hk⟩ h_nek
    rw [accVar_succ n stepLen body init hlen k hm, h_link, h_acck]
    exact h

/-- The fold's final output evaluates to `accAfter numDigits`. -/
lemma fold_final (curveParams : CurveParams p) (env : Environment (F p))
    (bits : Vector (F p) numBits) (r : F p)
    (body : Var Point (F p) → Fin numDigits → Circuit (F p) (Var Point (F p)))
    (init : Var Point (F p)) (n stepLen : ℕ)
    (stepOut : Fin numDigits → Point (F p) → ℕ → Point (F p))
    (h_ne : accAfter curveParams r bits numDigits ≠ none)
    (h_steps : ∀ i : Fin numDigits,
      stepNative curveParams r (evalPt env (accVar n body init i))
          (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) ≠ none →
      stepNative curveParams r (evalPt env (accVar n body init i))
          (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) =
        some (stepOut i (evalPt env (accVar n body init i)) (n + i.val * stepLen)))
    (hlen : ∀ acc i, (body acc i).localLength = stepLen)
    (h_link : ∀ acc (i : Fin numDigits),
      evalPt env ((body acc i).output (n + i.val * stepLen)) =
        stepOut i (evalPt env acc) (n + i.val * stepLen))
    (h0 : accAfter curveParams r bits 0 = some (evalPt env init)) :
    accAfter curveParams r bits numDigits =
      some (evalPt env
        (Fin.foldl numDigits (fun acc i => (body acc i).output (n + i.val * stepLen)) init)) := by
  have h_last := fold_inv curveParams env bits r body init n stepLen stepOut h_ne h_steps hlen
    h_link h0 (numDigits - 1) numDigits_pred_lt
  have h_acc := accAfter_succ_of_some curveParams r bits (numDigits - 1) _ h_last
    (walk_index_lt _ numDigits_pred_lt)
  have hnd : numDigits - 1 + 1 = numDigits := rfl
  rw [hnd] at h_acc
  have h_ne_last := all_accAfter_ne curveParams r bits h_ne numDigits le_rfl
  rw [h_acc] at h_ne_last
  have h := h_steps ⟨numDigits - 1, numDigits_pred_lt⟩ h_ne_last
  rw [fin_foldl_eq_last n stepLen body init hlen, h_link]
  show accAfter curveParams r bits numDigits = _
  rw [h_acc]
  exact h

/-- The twisted curve has no points of order two when the original has none:
such a point would move back to one. -/
lemma twist_noOrderTwoPoints (curveParams : CurveParams p) (c : F p) (hc : c ≠ 0)
    (h : curveParams.noOrderTwoPoints) : (twist curveParams c).noOrderTwoPoints := by
  intro pt hpt hy
  have := denormalize_isOnCurve curveParams c hc pt hpt
  apply h ⟨pt.x / c ^ 2, pt.y / c ^ 3⟩ this
  simp only [hy, zero_div]

end Ragu.Circuits.Endoscalar.Walk
