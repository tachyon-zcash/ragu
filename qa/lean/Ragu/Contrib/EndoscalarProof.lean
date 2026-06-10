import Mathlib.Algebra.CharP.Defs
import Mathlib.Data.Fintype.Pi
import Mathlib.GroupTheory.OrderOfElement
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Ring

/-!
* `EndoscaleInput n` is an input with exactly `n` two-bit pairs.
* `endoscaleN ζ input` is the endoscaling algorithm.
* `endoscaleCharacteristicBound n = 4 * (2 ^ n - 1) ^ 2`.
* `endoscaleN_injective_of_characteristicBound_lt` proves that if
  `ζ` has multiplicative order `3` and the field characteristic is larger than
  `endoscaleCharacteristicBound n`, then `endoscaleN ζ` is injective.
-/

namespace Ragu.Contrib.EndoscalarProof

/-- An endoscaling input with exactly `n` two-bit pairs. -/
def EndoscaleInput (n : ℕ) :=
  Fin n → Bool × Bool

instance (n : ℕ) : Fintype (EndoscaleInput n) :=
  inferInstanceAs (Fintype (Fin n → Bool × Bool))

/-- The endoscaling algorithm on an exactly-sized input.

For each input pair `(a_j, b_j)`, it updates an integer accumulator `(x, y)` by
doubling both coordinates and adding `2 * b_j - 1` to the coordinate selected by
`a_j`. It returns `x * ζ + y`. -/
def endoscaleN {R : Type*} [Ring R] (ζ : R) {n : ℕ} (input : EndoscaleInput n) : R :=
  let bitSign : Bool → ℤ := fun b => if b then 1 else -1
  let digit : Bool × Bool → ℤ × ℤ := fun ab =>
    let s := bitSign ab.2
    if ab.1 then (0, s) else (s, 0)
  let step : ℤ × ℤ → Bool × Bool → ℤ × ℤ := fun acc ab =>
    let d := digit ab
    (2 * acc.1 + d.1, 2 * acc.2 + d.2)
  let acc := (List.ofFn input).foldl step (2, 2)
  (acc.1 : R) * ζ + acc.2

/-- A uniform sufficient characteristic bound for length-n endoscaling. If a
field containing a multiplicative-order-3 element has characteristic exceeding
this bound, then length-n two-bit-pair endoscaling is injective.

Established by endoscaleN_injective_of_characteristicBound_lt below. -/
def endoscaleCharacteristicBound (n : ℕ) : ℕ :=
  4 * (2 ^ n - 1) ^ 2

/-! ## Private proof support -/

private def bitSign (b : Bool) : ℤ :=
  if b then 1 else -1

namespace EndoscaleInput

private def toList {n : ℕ} (input : EndoscaleInput n) : List (Bool × Bool) :=
  List.ofFn input

end EndoscaleInput

private def endoscaleDigit (ab : Bool × Bool) : ℤ × ℤ :=
  let s := bitSign ab.2
  if ab.1 then (0, s) else (s, 0)

private def endoscaleStep (acc : ℤ × ℤ) (ab : Bool × Bool) : ℤ × ℤ :=
  let digit := endoscaleDigit ab
  (2 * acc.1 + digit.1, 2 * acc.2 + digit.2)

private def endoscaleAcc (pairs : List (Bool × Bool)) : ℤ × ℤ :=
  pairs.foldl endoscaleStep (2, 2)

private def endoscale {R : Type*} [Ring R] (ζ : R) (pairs : List (Bool × Bool)) : R :=
  (endoscaleAcc pairs).1 * ζ + (endoscaleAcc pairs).2

private theorem endoscaleN_eq_endoscale {R : Type*} [Ring R] (ζ : R) {n : ℕ}
    (input : EndoscaleInput n) :
    endoscaleN ζ input = endoscale ζ input.toList := by
  rfl

private def eisensteinNorm (dx dy : ℤ) : ℤ :=
  dx ^ 2 - dx * dy + dy ^ 2

private def EndoscaleRelationFree {R : Type*} [Ring R] (ζ : R) (n : ℕ) : Prop :=
  ∀ input input' : EndoscaleInput n,
    input ≠ input' →
      let acc := endoscaleAcc input.toList
      let acc' := endoscaleAcc input'.toList
      (acc.1 - acc'.1 : R) * ζ + (acc.2 - acc'.2 : R) ≠ 0

private theorem endoscaleN_injective_of_relationFree {R : Type*} [Ring R] {ζ : R} {n : ℕ}
    (hζ : EndoscaleRelationFree ζ n) :
    Function.Injective (endoscaleN ζ (n := n)) := by
  intro input input' h
  by_contra hne
  have hrel :
      let acc := endoscaleAcc input.toList
      let acc' := endoscaleAcc input'.toList
      (acc.1 - acc'.1 : R) * ζ + (acc.2 - acc'.2 : R) = 0 := by
    rw [endoscaleN_eq_endoscale] at h
    rw [endoscaleN_eq_endoscale] at h
    dsimp [endoscale] at h ⊢
    rw [← sub_eq_zero] at h
    simpa [sub_eq_add_neg, add_assoc, add_left_comm, add_comm, mul_add, add_mul] using h
  exact hζ input input' hne hrel

private def signedFold {α : Type*} (f : α → ℤ) (start : ℤ) (xs : List α) : ℤ :=
  xs.foldl (fun z a => 2 * z + f a) start

private theorem signedFold_bound {α : Type*} {f : α → ℤ} (hf : ∀ a, |f a| ≤ 1)
    (xs : List α) (start : ℤ) :
    |signedFold f start xs - (2 : ℤ) ^ xs.length * start| ≤
      (2 : ℤ) ^ xs.length - 1 := by
  induction xs generalizing start with
  | nil => simp [signedFold]
  | cons a xs ih =>
    dsimp [signedFold, List.foldl]
    have hih := ih (2 * start + f a)
    let A := signedFold f (2 * start + f a) xs -
      (2 : ℤ) ^ xs.length * (2 * start + f a)
    have hA : |A| ≤ (2 : ℤ) ^ xs.length - 1 := by
      simpa [A] using hih
    have hf' : |(2 : ℤ) ^ xs.length * f a| ≤ (2 : ℤ) ^ xs.length := by
      rw [abs_mul]
      have hpow_nonneg : 0 ≤ (2 : ℤ) ^ xs.length := pow_nonneg (by norm_num) _
      have habs_pow : |(2 : ℤ) ^ xs.length| = (2 : ℤ) ^ xs.length :=
        abs_of_nonneg hpow_nonneg
      rw [habs_pow]
      nlinarith [hf a, hpow_nonneg]
    have htri : |A + (2 : ℤ) ^ xs.length * f a| ≤
        |A| + |(2 : ℤ) ^ xs.length * f a| :=
      abs_add_le A ((2 : ℤ) ^ xs.length * f a)
    have hcalc : |A + (2 : ℤ) ^ xs.length * f a| ≤
        (2 : ℤ) ^ (xs.length + 1) - 1 := by
      rw [pow_succ]
      nlinarith
    have hrewrite :
        signedFold f (2 * start + f a) xs - (2 : ℤ) ^ (xs.length + 1) * start =
          A + (2 : ℤ) ^ xs.length * f a := by
      dsimp [A]
      rw [pow_succ]
      ring
    change |signedFold f (2 * start + f a) xs -
        (2 : ℤ) ^ (xs.length + 1) * start| ≤ (2 : ℤ) ^ (xs.length + 1) - 1
    rw [hrewrite]
    exact hcalc

private theorem signedFold_sub_bound {α : Type*} {f : α → ℤ} (hf : ∀ a, |f a| ≤ 1)
    {xs ys : List α} (hlen : xs.length = ys.length) (start : ℤ) :
    |signedFold f start xs - signedFold f start ys| ≤
      2 * ((2 : ℤ) ^ xs.length - 1) := by
  let center := (2 : ℤ) ^ xs.length * start
  have hx : |signedFold f start xs - center| ≤ (2 : ℤ) ^ xs.length - 1 := by
    simpa [center] using signedFold_bound hf xs start
  have hy : |signedFold f start ys - center| ≤ (2 : ℤ) ^ xs.length - 1 := by
    simpa [center, hlen] using signedFold_bound hf ys start
  have htri0 := abs_sub_le (signedFold f start xs) center (signedFold f start ys)
  have htri : |signedFold f start xs - signedFold f start ys| ≤
      |signedFold f start xs - center| + |signedFold f start ys - center| := by
    rw [abs_sub_comm center (signedFold f start ys)] at htri0
    simpa [add_comm] using htri0
  linarith

private def signedFoldFin {n : ℕ} (f : Fin n → ℤ) (start : ℤ) : ℤ :=
  signedFold f start (List.finRange n)

private theorem signedFold_toList {n : ℕ} (f : Bool × Bool → ℤ) (start : ℤ)
    (input : EndoscaleInput n) :
    signedFold f start input.toList = signedFoldFin (fun i => f (input i)) start := by
  rw [EndoscaleInput.toList, List.ofFn_eq_map]
  simp [signedFoldFin, signedFold, List.foldl_map]

private theorem center_close {x c d r : ℤ} (hx : |x - c| ≤ r) (hy : |x - d| ≤ r) :
    |c - d| ≤ 2 * r := by
  have htri0 := abs_sub_le c x d
  have hx' : |c - x| ≤ r := by
    simpa [abs_sub_comm] using hx
  nlinarith [htri0, hx', hy]

private theorem signedFoldFin_injective {n : ℕ} {f g : Fin n → ℤ} (start : ℤ)
    (hf : ∀ i, f i = 1 ∨ f i = -1) (hg : ∀ i, g i = 1 ∨ g i = -1)
    (h : signedFoldFin f start = signedFoldFin g start) :
    f = g := by
  induction n generalizing start with
  | zero =>
    funext i
    exact Fin.elim0 i
  | succ n ih =>
    dsimp [signedFoldFin, signedFold] at h
    rw [List.finRange_succ] at h
    simp only [List.foldl_cons, List.foldl_map] at h
    have hf0_eq_g0 : f 0 = g 0 := by
      by_contra hneq
      let ftail : Fin n → ℤ := fun i => f i.succ
      let gtail : Fin n → ℤ := fun i => g i.succ
      let fstart := 2 * start + f 0
      let gstart := 2 * start + g 0
      let final := signedFold ftail fstart (List.finRange n)
      have hfinal : final = signedFold gtail gstart (List.finRange n) := by
        simpa [final, ftail, gtail, fstart, gstart, signedFold] using h
      have hftail_bound : ∀ i, |ftail i| ≤ 1 := by
        intro i
        rcases hf i.succ with hi | hi <;> simp [ftail, hi]
      have hgtail_bound : ∀ i, |gtail i| ≤ 1 := by
        intro i
        rcases hg i.succ with hi | hi <;> simp [gtail, hi]
      let r : ℤ := (2 : ℤ) ^ n - 1
      let cf : ℤ := (2 : ℤ) ^ n * fstart
      let cg : ℤ := (2 : ℤ) ^ n * gstart
      have hfclose : |final - cf| ≤ r := by
        simpa [final, cf, r] using signedFold_bound hftail_bound (List.finRange n) fstart
      have hgclose : |final - cg| ≤ r := by
        have hb := signedFold_bound hgtail_bound (List.finRange n) gstart
        simpa [cg, r, hfinal] using hb
      have hcenters : |cf - cg| ≤ 2 * r := center_close hfclose hgclose
      have hpow_nonneg : 0 ≤ (2 : ℤ) ^ n := pow_nonneg (by norm_num) _
      rcases hf 0 with hf0 | hf0 <;> rcases hg 0 with hg0 | hg0
      · exact hneq (by simp [hf0, hg0])
      · have hcenter :
            |cf - cg| = (2 : ℤ) ^ n * 2 := by
          have hnonneg : 0 ≤ (2 : ℤ) ^ n * 2 := by nlinarith
          rw [show cf - cg = (2 : ℤ) ^ n * 2 by
            simp [cf, cg, fstart, gstart, hf0, hg0]
            ring]
          exact abs_of_nonneg hnonneg
        rw [hcenter] at hcenters
        nlinarith
      · have hcenter :
            |cf - cg| = (2 : ℤ) ^ n * 2 := by
          have hnonneg : 0 ≤ (2 : ℤ) ^ n * 2 := by nlinarith
          rw [show cf - cg = -((2 : ℤ) ^ n * 2) by
            simp [cf, cg, fstart, gstart, hf0, hg0]
            ring]
          rw [abs_neg]
          exact abs_of_nonneg hnonneg
        rw [hcenter] at hcenters
        nlinarith
      · exact hneq (by simp [hf0, hg0])
    have htail :
        signedFoldFin (fun i : Fin n => f i.succ) (2 * start + f 0) =
          signedFoldFin (fun i : Fin n => g i.succ) (2 * start + f 0) := by
      dsimp [signedFoldFin, signedFold]
      simpa [hf0_eq_g0, signedFold] using h
    have htail_fun : (fun i : Fin n => f i.succ) = (fun i : Fin n => g i.succ) := by
      apply ih (2 * start + f 0)
      · intro i
        exact hf i.succ
      · intro i
        exact hg i.succ
      · exact htail
    funext i
    exact Fin.cases hf0_eq_g0 (fun j => congrFun htail_fun j) i

private def endoscaleDigitSum (ab : Bool × Bool) : ℤ :=
  (endoscaleDigit ab).1 + (endoscaleDigit ab).2

private def endoscaleDigitDiff (ab : Bool × Bool) : ℤ :=
  (endoscaleDigit ab).1 - (endoscaleDigit ab).2

private theorem abs_endoscaleDigitSum_le_one (ab : Bool × Bool) :
    |endoscaleDigitSum ab| ≤ 1 := by
  cases ab with
  | mk a b =>
    cases a <;> cases b <;> norm_num [endoscaleDigitSum, endoscaleDigit, bitSign]

private theorem abs_endoscaleDigitDiff_le_one (ab : Bool × Bool) :
    |endoscaleDigitDiff ab| ≤ 1 := by
  cases ab with
  | mk a b =>
    cases a <;> cases b <;> norm_num [endoscaleDigitDiff, endoscaleDigit, bitSign]

private theorem endoscaleDigitSum_eq_one_or_neg_one (ab : Bool × Bool) :
    endoscaleDigitSum ab = 1 ∨ endoscaleDigitSum ab = -1 := by
  cases ab with
  | mk a b =>
    cases a <;> cases b <;> norm_num [endoscaleDigitSum, endoscaleDigit, bitSign]

private theorem endoscaleDigitDiff_eq_one_or_neg_one (ab : Bool × Bool) :
    endoscaleDigitDiff ab = 1 ∨ endoscaleDigitDiff ab = -1 := by
  cases ab with
  | mk a b =>
    cases a <;> cases b <;> norm_num [endoscaleDigitDiff, endoscaleDigit, bitSign]

private theorem eq_of_endoscaleDigitSum_eq_of_endoscaleDigitDiff_eq {ab ab' : Bool × Bool}
    (hsum : endoscaleDigitSum ab = endoscaleDigitSum ab')
    (hdiff : endoscaleDigitDiff ab = endoscaleDigitDiff ab') :
    ab = ab' := by
  cases ab with
  | mk a b =>
    cases ab' with
    | mk a' b' =>
      cases a <;> cases b <;> cases a' <;> cases b' <;>
        simp [endoscaleDigitSum, endoscaleDigitDiff, endoscaleDigit, bitSign] at hsum hdiff ⊢

private theorem endoscale_fold_sum_eq_signedFold (pairs : List (Bool × Bool)) (acc : ℤ × ℤ) :
    (pairs.foldl endoscaleStep acc).1 + (pairs.foldl endoscaleStep acc).2 =
      signedFold endoscaleDigitSum (acc.1 + acc.2) pairs := by
  induction pairs generalizing acc with
  | nil => simp [signedFold]
  | cons ab pairs ih =>
    simp only [List.foldl]
    rw [ih]
    simp [signedFold, endoscaleStep, endoscaleDigitSum]
    ring_nf

private theorem endoscale_fold_diff_eq_signedFold (pairs : List (Bool × Bool)) (acc : ℤ × ℤ) :
    (pairs.foldl endoscaleStep acc).1 - (pairs.foldl endoscaleStep acc).2 =
      signedFold endoscaleDigitDiff (acc.1 - acc.2) pairs := by
  induction pairs generalizing acc with
  | nil => simp [signedFold]
  | cons ab pairs ih =>
    simp only [List.foldl]
    rw [ih]
    simp [signedFold, endoscaleStep, endoscaleDigitDiff]
    ring_nf

private theorem endoscaleAcc_input_injective {n : ℕ} :
    Function.Injective (fun input : EndoscaleInput n => endoscaleAcc input.toList) := by
  intro input input' hacc
  change endoscaleAcc input.toList = endoscaleAcc input'.toList at hacc
  have hsumList :
      signedFold endoscaleDigitSum 4 input.toList =
        signedFold endoscaleDigitSum 4 input'.toList := by
    calc
      signedFold endoscaleDigitSum 4 input.toList =
          (endoscaleAcc input.toList).1 + (endoscaleAcc input.toList).2 := by
        symm
        simpa [endoscaleAcc] using endoscale_fold_sum_eq_signedFold input.toList (2, 2)
      _ = (endoscaleAcc input'.toList).1 + (endoscaleAcc input'.toList).2 := by
        rw [hacc]
      _ = signedFold endoscaleDigitSum 4 input'.toList := by
        simpa [endoscaleAcc] using endoscale_fold_sum_eq_signedFold input'.toList (2, 2)
  have hdiffList :
      signedFold endoscaleDigitDiff 0 input.toList =
        signedFold endoscaleDigitDiff 0 input'.toList := by
    calc
      signedFold endoscaleDigitDiff 0 input.toList =
          (endoscaleAcc input.toList).1 - (endoscaleAcc input.toList).2 := by
        symm
        simpa [endoscaleAcc] using endoscale_fold_diff_eq_signedFold input.toList (2, 2)
      _ = (endoscaleAcc input'.toList).1 - (endoscaleAcc input'.toList).2 := by
        rw [hacc]
      _ = signedFold endoscaleDigitDiff 0 input'.toList := by
        simpa [endoscaleAcc] using endoscale_fold_diff_eq_signedFold input'.toList (2, 2)
  have hsumFin :
      signedFoldFin (fun i => endoscaleDigitSum (input i)) 4 =
        signedFoldFin (fun i => endoscaleDigitSum (input' i)) 4 := by
    simpa [signedFold_toList] using hsumList
  have hdiffFin :
      signedFoldFin (fun i => endoscaleDigitDiff (input i)) 0 =
        signedFoldFin (fun i => endoscaleDigitDiff (input' i)) 0 := by
    simpa [signedFold_toList] using hdiffList
  have hsumFun :
      (fun i => endoscaleDigitSum (input i)) =
        fun i => endoscaleDigitSum (input' i) :=
    signedFoldFin_injective 4
      (fun i => endoscaleDigitSum_eq_one_or_neg_one (input i))
      (fun i => endoscaleDigitSum_eq_one_or_neg_one (input' i))
      hsumFin
  have hdiffFun :
      (fun i => endoscaleDigitDiff (input i)) =
        fun i => endoscaleDigitDiff (input' i) :=
    signedFoldFin_injective 0
      (fun i => endoscaleDigitDiff_eq_one_or_neg_one (input i))
      (fun i => endoscaleDigitDiff_eq_one_or_neg_one (input' i))
      hdiffFin
  funext i
  exact eq_of_endoscaleDigitSum_eq_of_endoscaleDigitDiff_eq
    (congrFun hsumFun i) (congrFun hdiffFun i)

private theorem endoscale_eisensteinNorm_natAbs_le
    (n : ℕ) (input input' : EndoscaleInput n) :
    (eisensteinNorm
      ((endoscaleAcc input.toList).1 - (endoscaleAcc input'.toList).1)
      ((endoscaleAcc input.toList).2 - (endoscaleAcc input'.toList).2)).natAbs ≤
        endoscaleCharacteristicBound n := by
  let acc := endoscaleAcc input.toList
  let acc' := endoscaleAcc input'.toList
  let dx := acc.1 - acc'.1
  let dy := acc.2 - acc'.2
  let s := dx + dy
  let t := dx - dy
  let Bz : ℤ := (2 : ℤ) ^ n - 1
  have hlen : input.toList.length = input'.toList.length := by
    simp [EndoscaleInput.toList]
  have hsumFold :
      acc.1 + acc.2 = signedFold endoscaleDigitSum 4 input.toList := by
    simpa [acc, endoscaleAcc] using
      endoscale_fold_sum_eq_signedFold input.toList (2, 2)
  have hsumFold' :
      acc'.1 + acc'.2 = signedFold endoscaleDigitSum 4 input'.toList := by
    simpa [acc', endoscaleAcc] using
      endoscale_fold_sum_eq_signedFold input'.toList (2, 2)
  have hdiffFold :
      acc.1 - acc.2 = signedFold endoscaleDigitDiff 0 input.toList := by
    simpa [acc, endoscaleAcc] using
      endoscale_fold_diff_eq_signedFold input.toList (2, 2)
  have hdiffFold' :
      acc'.1 - acc'.2 = signedFold endoscaleDigitDiff 0 input'.toList := by
    simpa [acc', endoscaleAcc] using
      endoscale_fold_diff_eq_signedFold input'.toList (2, 2)
  have hsumBound : |s| ≤ 2 * Bz := by
    have h := signedFold_sub_bound abs_endoscaleDigitSum_le_one hlen 4
    have hlenInput : input.toList.length = n := by simp [EndoscaleInput.toList]
    rw [hlenInput] at h
    rw [← hsumFold, ← hsumFold'] at h
    have hs_eq : s = (acc.1 + acc.2) - (acc'.1 + acc'.2) := by
      dsimp [s, dx, dy]
      ring
    simpa [Bz, hs_eq]
      using h
  have hdiffBound : |t| ≤ 2 * Bz := by
    have h := signedFold_sub_bound abs_endoscaleDigitDiff_le_one hlen 0
    have hlenInput : input.toList.length = n := by simp [EndoscaleInput.toList]
    rw [hlenInput] at h
    rw [← hdiffFold, ← hdiffFold'] at h
    have ht_eq : t = (acc.1 - acc.2) - (acc'.1 - acc'.2) := by
      dsimp [t, dx, dy]
      ring
    simpa [Bz, ht_eq]
      using h
  have hBz_nonneg : 0 ≤ Bz := by
    dsimp [Bz]
    have hpow : (1 : ℤ) ≤ (2 : ℤ) ^ n := by
      exact one_le_pow₀ (a := (2 : ℤ)) (by norm_num)
    omega
  have h2Bz_nonneg : 0 ≤ 2 * Bz := by
    nlinarith
  have hs_sq : s ^ 2 ≤ (2 * Bz) ^ 2 := by
    exact sq_le_sq.mpr (by simpa [abs_of_nonneg h2Bz_nonneg] using hsumBound)
  have ht_sq : t ^ 2 ≤ (2 * Bz) ^ 2 := by
    exact sq_le_sq.mpr (by simpa [abs_of_nonneg h2Bz_nonneg] using hdiffBound)
  let norm := eisensteinNorm dx dy
  have hidentity : 4 * norm = s ^ 2 + 3 * t ^ 2 := by
    dsimp [norm, eisensteinNorm, s, t, dx, dy]
    ring
  have hnorm_nonneg : 0 ≤ norm := by
    have hs_nonneg : 0 ≤ s ^ 2 := sq_nonneg s
    have ht_nonneg : 0 ≤ t ^ 2 := sq_nonneg t
    nlinarith
  have hnorm_le : norm ≤ 4 * Bz ^ 2 := by
    nlinarith
  have habs : |norm| ≤ 4 * Bz ^ 2 := by
    rwa [abs_of_nonneg hnorm_nonneg]
  have htarget :
      (eisensteinNorm
        ((endoscaleAcc input.toList).1 - (endoscaleAcc input'.toList).1)
        ((endoscaleAcc input.toList).2 - (endoscaleAcc input'.toList).2)).natAbs ≤
          4 * (2 ^ n - 1) ^ 2 := by
    apply Int.le_of_ofNat_le_ofNat
    simpa [norm, dx, dy, acc, acc', Bz, Int.natCast_natAbs] using habs
  simpa [endoscaleCharacteristicBound] using htarget

private theorem endoscale_eisensteinNorm_natAbs_pos_of_ne {n : ℕ}
    {input input' : EndoscaleInput n} (hne : input ≠ input') :
    0 <
      (eisensteinNorm
        ((endoscaleAcc input.toList).1 - (endoscaleAcc input'.toList).1)
        ((endoscaleAcc input.toList).2 - (endoscaleAcc input'.toList).2)).natAbs := by
  rw [Int.natAbs_pos]
  intro hnorm_zero
  apply hne
  apply endoscaleAcc_input_injective
  let acc := endoscaleAcc input.toList
  let acc' := endoscaleAcc input'.toList
  let dx := acc.1 - acc'.1
  let dy := acc.2 - acc'.2
  let s := dx + dy
  let t := dx - dy
  let norm := eisensteinNorm dx dy
  have hnorm_zero' : norm = 0 := by
    simpa [norm, dx, dy, acc, acc'] using hnorm_zero
  have hidentity : 4 * norm = s ^ 2 + 3 * t ^ 2 := by
    dsimp [norm, eisensteinNorm, s, t, dx, dy]
    ring
  have hs_sq_zero : s ^ 2 = 0 := by
    have hs_nonneg : 0 ≤ s ^ 2 := sq_nonneg s
    have ht_nonneg : 0 ≤ t ^ 2 := sq_nonneg t
    nlinarith
  have ht_sq_zero : t ^ 2 = 0 := by
    have hs_nonneg : 0 ≤ s ^ 2 := sq_nonneg s
    have ht_nonneg : 0 ≤ t ^ 2 := sq_nonneg t
    nlinarith
  have hs_zero : s = 0 := sq_eq_zero_iff.mp hs_sq_zero
  have ht_zero : t = 0 := sq_eq_zero_iff.mp ht_sq_zero
  have hdx_zero : dx = 0 := by
    dsimp [s, t] at hs_zero ht_zero
    nlinarith
  have hdy_zero : dy = 0 := by
    dsimp [s, t] at hs_zero ht_zero
    nlinarith
  apply Prod.ext
  · dsimp [dx] at hdx_zero
    exact sub_eq_zero.mp hdx_zero
  · dsimp [dy] at hdy_zero
    exact sub_eq_zero.mp hdy_zero

private theorem endoscale_eisensteinNorm_bound {n : ℕ} {input input' : EndoscaleInput n}
    (hne : input ≠ input') :
    let acc := endoscaleAcc input.toList
    let acc' := endoscaleAcc input'.toList
    0 < (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ∧
      (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ≤
        endoscaleCharacteristicBound n := by
  constructor
  · exact endoscale_eisensteinNorm_natAbs_pos_of_ne hne
  · exact endoscale_eisensteinNorm_natAbs_le n input input'

private theorem zeta_sq_add_zeta_add_one_eq_zero_of_orderOf_three
    {F : Type*} [Field F] {ζ : F}
    (hζ : orderOf ζ = 3) :
    ζ ^ 2 + ζ + 1 = 0 := by
  have hpow : ζ ^ 3 = 1 := by
    exact ((orderOf_eq_iff (x := ζ) (n := 3) (by norm_num)).mp hζ).1
  have hne : ζ - 1 ≠ 0 := by
    intro h
    have hone : ζ = 1 := sub_eq_zero.mp h
    have horder : orderOf ζ = 1 := by
      simp [hone]
    omega
  have hfactor : (ζ - 1) * (ζ ^ 2 + ζ + 1) = 0 := by
    calc
      (ζ - 1) * (ζ ^ 2 + ζ + 1) = ζ ^ 3 - 1 := by ring
      _ = 0 := by rw [hpow]; ring
  exact (mul_eq_zero.mp hfactor).resolve_left hne

private theorem eisensteinNorm_cast_eq_zero_of_collision {F : Type*} [Field F] {ζ : F}
    (hζpoly : ζ ^ 2 + ζ + 1 = 0) {dx dy : ℤ}
    (h : (dx : F) * ζ + (dy : F) = 0) :
    (eisensteinNorm dx dy : F) = 0 := by
  have hdy : (dy : F) = -((dx : F) * ζ) := by
    rw [eq_neg_iff_add_eq_zero]
    simpa [add_comm] using h
  simp only [eisensteinNorm, Int.cast_add, Int.cast_sub, Int.cast_mul, Int.cast_pow]
  rw [hdy]
  calc
    (dx : F) ^ 2 - (dx : F) * (-((dx : F) * ζ)) + (-((dx : F) * ζ)) ^ 2 =
        (dx : F) ^ 2 * (ζ ^ 2 + ζ + 1) := by ring
    _ = 0 := by rw [hζpoly]; ring

private theorem endoscaleRelationFree_of_eisensteinNorm_bound
    {F : Type*} [Field F] {p B n : ℕ} [CharP F p] {ζ : F}
    (hζ : orderOf ζ = 3) (hB : B < p)
    (hnorm : ∀ input input' : EndoscaleInput n,
      input ≠ input' →
        let acc := endoscaleAcc input.toList
        let acc' := endoscaleAcc input'.toList
        0 < (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ∧
          (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ≤ B) :
    EndoscaleRelationFree ζ n := by
  intro input input' hne
  dsimp only
  intro hcollision
  let acc := endoscaleAcc input.toList
  let acc' := endoscaleAcc input'.toList
  let norm := eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)
  have hnorm' := hnorm input input' hne
  have hpos : 0 < norm.natAbs := by
    simpa [norm, acc, acc'] using hnorm'.1
  have hle : norm.natAbs ≤ B := by
    simpa [norm, acc, acc'] using hnorm'.2
  have hcollision' : ((acc.1 - acc'.1 : F) * ζ + (acc.2 - acc'.2 : F) = 0) := by
    simpa [acc, acc'] using hcollision
  have hcollision'' :
      (((acc.1 - acc'.1 : ℤ) : F) * ζ + ((acc.2 - acc'.2 : ℤ) : F) = 0) := by
    simpa only [Int.cast_sub] using hcollision'
  have hnormCast : (norm : F) = 0 := by
    exact eisensteinNorm_cast_eq_zero_of_collision
      (zeta_sq_add_zeta_add_one_eq_zero_of_orderOf_three hζ) hcollision''
  have hdvd : (p : ℤ) ∣ norm := (CharP.intCast_eq_zero_iff F p norm).mp hnormCast
  have hneNorm : norm ≠ 0 := Int.natAbs_pos.mp hpos
  have hp_le : p ≤ norm.natAbs := by
    simpa using (Int.natAbs_le_of_dvd_ne_zero hdvd hneNorm)
  omega

private theorem endoscaleN_injective_of_eisensteinNorm_bound
    {F : Type*} [Field F] {p B n : ℕ} [CharP F p] {ζ : F}
    (hζ : orderOf ζ = 3) (hB : B < p)
    (hnorm : ∀ input input' : EndoscaleInput n,
      input ≠ input' →
        let acc := endoscaleAcc input.toList
        let acc' := endoscaleAcc input'.toList
        0 < (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ∧
          (eisensteinNorm (acc.1 - acc'.1) (acc.2 - acc'.2)).natAbs ≤ B) :
    Function.Injective (endoscaleN ζ (n := n)) :=
  endoscaleN_injective_of_relationFree
    (endoscaleRelationFree_of_eisensteinNorm_bound hζ hB hnorm)

/-- If the characteristic is larger than `endoscaleCharacteristicBound n`, then
length-`n` endoscaling by a multiplicative order-`3` element is injective. -/
theorem endoscaleN_injective_of_characteristicBound_lt
    {F : Type*} [Field F] {p n : ℕ} [CharP F p] {ζ : F}
    (hζ : orderOf ζ = 3) (hp : endoscaleCharacteristicBound n < p) :
    Function.Injective (endoscaleN ζ (n := n)) :=
  endoscaleN_injective_of_eisensteinNorm_bound hζ hp
    (fun _ _ hne => endoscale_eisensteinNorm_bound hne)

end Ragu.Contrib.EndoscalarProof
