import Mathlib.Algebra.CharP.Defs
import Mathlib.Data.List.OfFn
import Mathlib.GroupTheory.OrderOfElement
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.LinearCombination
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Ring

/-!
# Injectivity and non-degeneracy of radix-3 endoscaling

A radix-3 endoscalar (`crates/ragu_primitives/src/endoscalar.rs`) is two
initial bits `(s₀, e₀)` and `n` three-bit digits `(s, e₁, e₂)`, most
significant first. Writing `λ` for a cube root of unity it stands for

  `k = 2·3ⁿ·(-1)^{s₀} λ^{e₀} + Σᵢ 3^{n-1-i} dᵢ`,  `dᵢ = (-1)^s {1, λ, λ², 1 - λ}[e₁, e₂]`,

the scalar `Endoscalar::lift` computes and `Endoscalar::group_scale` applies to
a point. Both live in the Eisenstein integers `ℤ[ω]`, written here as index
pairs `(a, b) ↦ a·ω + b` with `ω² = -ω - 1`.

* `EndoscaleInput n` is an input with exactly `n` digits.
* `endoscaleN ζ input` is the endoscaling algorithm: Horner's rule on index
  pairs, evaluated at `ζ`.
* `endoscaleCharacteristicBound n = 3·(5·3ⁿ - 1)²`.
* `endoscaleN_injective_of_characteristicBound_lt`: if `ζ` has multiplicative
  order `3` and the characteristic exceeds the bound, `endoscaleN ζ` is
  injective. The eight digits are the eight nonzero residues of `ℤ[ω]` mod
  `3`, so distinct inputs have distinct accumulators in `ℤ[ω]`; the Eisenstein
  norm of the difference is then a positive integer below the characteristic.
* `groupScale_collision_combinations_ne_zero`: the integer core of the
  no-collision argument for `group_scale`'s unchecked triple-and-add
  `((A + D) + A) + A`: the accumulator's Eisenstein norm never drops below
  `4` while a digit point's is at most `3`, so none of the exceptional
  combinations `A ∓ D`, `2A + D`, `3A + D` vanishes.
-/

namespace Ragu.Lemmas.EndoscalarProof

/-- A digit `(s, e₁, e₂)`: the sign bit and the two endomorphism bits. -/
structure Digit where
  sign : Bool
  endo1 : Bool
  endo2 : Bool
  deriving DecidableEq

/-- An endoscaling input: the initial bits `(s₀, e₀)` and `n` digits, most
significant first. -/
@[ext]
structure EndoscaleInput (n : ℕ) where
  initialSign : Bool
  initialEndo : Bool
  digits : Fin n → Digit

/-- Coefficients of an Eisenstein integer, interpreted as `a·λ + b`.
The named fields distinguish the endomorphism and constant contributions. -/
@[ext]
structure Index where
  a : ℤ
  b : ℤ
  deriving DecidableEq

/-- The index `(a, b)` of a digit, meaning `a·λ + b`:
`(-1)^s {1, λ, λ², 1 - λ}[e₁, e₂]` with `λ² = -λ - 1`. -/
def digitIndex (d : Digit) : Index :=
  let unsigned : Index :=
    match d.endo1, d.endo2 with
    | false, false => ⟨0, 1⟩
    | false, true => ⟨-1, -1⟩
    | true, false => ⟨1, 0⟩
    | true, true => ⟨-1, 1⟩
  if d.sign then ⟨-unsigned.a, -unsigned.b⟩ else unsigned

/-- The index of the initial accumulator `2·(-1)^{s₀} λ^{e₀}`. -/
def initIndex (s0 e0 : Bool) : Index :=
  let unsigned : Index := if e0 then ⟨2, 0⟩ else ⟨0, 2⟩
  if s0 then ⟨-unsigned.a, -unsigned.b⟩ else unsigned

/-- One Horner step `acc ↦ 3·acc + d` on indices. -/
def step (acc d : Index) : Index :=
  ⟨3 * acc.a + d.a, 3 * acc.b + d.b⟩

/-- The accumulator index after consuming `digits` from `init`. -/
def accIndex (init : Index) (digits : List Digit) : Index :=
  digits.foldl (fun acc d => step acc (digitIndex d)) init

/-- The endoscaling algorithm: the accumulator index `(a, b)` of the input,
read as `a·ζ + b`. -/
def endoscaleN {R : Type*} [Ring R] (ζ : R) {n : ℕ} (input : EndoscaleInput n) : R :=
  let acc := accIndex (initIndex input.initialSign input.initialEndo) (List.ofFn input.digits)
  (acc.a : R) * ζ + acc.b

/-- A uniform sufficient characteristic bound for length-`n` endoscaling. If a
field containing a multiplicative-order-3 element has characteristic exceeding
this bound, then length-`n` endoscaling is injective
(`endoscaleN_injective_of_characteristicBound_lt`). For the deployed
`n = 47` it is below `2^156`. -/
def endoscaleCharacteristicBound (n : ℕ) : ℕ :=
  3 * (5 * 3 ^ n - 1) ^ 2

/-- The Eisenstein norm `|a·ω + b|² = a² - ab + b²`. -/
def eisensteinNorm (a b : ℤ) : ℤ :=
  a ^ 2 - a * b + b ^ 2

/-! ## The digits as residues mod 3 -/

/-- The eight digit indices are the eight nonzero residues of `ℤ[ω]` mod `3`:
digits with congruent indices are equal. -/
private theorem digit_eq_of_mod_eq : ∀ d d' : Digit,
    (digitIndex d).a % 3 = (digitIndex d').a % 3 →
    (digitIndex d).b % 3 = (digitIndex d').b % 3 → d = d' := by
  rintro ⟨s, e1, e2⟩ ⟨s', e1', e2'⟩
  cases s <;> cases e1 <;> cases e2 <;> cases s' <;> cases e1' <;> cases e2' <;> decide

/-- The four initial choices have distinct integer indices, so recovering
the initial index recovers its sign and endomorphism bits. -/
private theorem initIndex_injective : ∀ s0 e0 s0' e0' : Bool,
    initIndex s0 e0 = initIndex s0' e0' → s0 = s0' ∧ e0 = e0' := by
  decide

/-- The empty suffix preserves the accumulator, providing the base case
for induction over the digit string. -/
private theorem accIndex_nil (init : Index) : accIndex init [] = init := rfl

/-- Expose the first Horner step so injectivity and magnitude proofs
can recurse on the remaining digits. -/
private theorem accIndex_cons (init : Index) (d : Digit) (ds : List Digit) :
    accIndex init (d :: ds) = accIndex (step init (digitIndex d)) ds := rfl

/-- Horner's rule in radix 3 is injective on equal-length digit strings: the
least significant digit is the accumulator mod `3`. -/
private theorem accIndex_injective :
    ∀ (ds ds' : List Digit) (init init' : Index), ds.length = ds'.length →
      accIndex init ds = accIndex init' ds' → init = init' ∧ ds = ds'
  | [], [], _, _, _, h => ⟨h, rfl⟩
  | [], _ :: _, _, _, hlen, _ => by simp at hlen
  | _ :: _, [], _, _, hlen, _ => by simp at hlen
  | d :: ds, d' :: ds', init, init', hlen, h => by
    rw [accIndex_cons, accIndex_cons] at h
    obtain ⟨hstep, hds⟩ := accIndex_injective ds ds' _ _ (by simpa using hlen) h
    have h1 := congrArg Index.a hstep
    have h2 := congrArg Index.b hstep
    simp only [step] at h1 h2
    have hd : d = d' := digit_eq_of_mod_eq d d' (by omega) (by omega)
    subst hd
    exact ⟨Index.ext (by omega) (by omega), by rw [hds]⟩

/-! ## Magnitude bounds -/

/-- Each digit changes either coefficient by at most one, bounding the
additive contribution to each radix-3 magnitude step. -/
private theorem abs_digitIndex_le (d : Digit) :
    |(digitIndex d).a| ≤ 1 ∧ |(digitIndex d).b| ≤ 1 := by
  rcases d with ⟨s, e1, e2⟩
  cases s <;> cases e1 <;> cases e2 <;>
    exact ⟨abs_le.mpr (by norm_num [digitIndex]), abs_le.mpr (by norm_num [digitIndex])⟩

/-- The initial factor of two bounds each coefficient by two, providing
the starting magnitude bound independently of the initial bits. -/
private theorem abs_initIndex_le' (s0 e0 : Bool) :
    |(initIndex s0 e0).a| ≤ 2 ∧ |(initIndex s0 e0).b| ≤ 2 := by
  cases s0 <;> cases e0 <;>
    exact ⟨abs_le.mpr (by norm_num [initIndex]), abs_le.mpr (by norm_num [initIndex])⟩

/-- The initial index in the form `accIndex_bound` consumes, at `m = 0`. -/
private theorem abs_initIndex_le (s0 e0 : Bool) :
    2 * |(initIndex s0 e0).a| ≤ 5 * 3 ^ 0 - 1 ∧ 2 * |(initIndex s0 e0).b| ≤ 5 * 3 ^ 0 - 1 := by
  obtain ⟨h1, h2⟩ := abs_initIndex_le' s0 e0
  constructor <;> norm_num <;> linarith

/-- After `m` digits from an initial index of magnitude at most `2`, each
component is at most `(5·3^m - 1)/2` in absolute value. -/
private theorem accIndex_bound :
    ∀ (ds : List Digit) (init : Index) (k : ℕ),
      2 * |init.a| ≤ 5 * 3 ^ k - 1 → 2 * |init.b| ≤ 5 * 3 ^ k - 1 →
      2 * |(accIndex init ds).a| ≤ 5 * 3 ^ (k + ds.length) - 1 ∧
      2 * |(accIndex init ds).b| ≤ 5 * 3 ^ (k + ds.length) - 1
  | [], init, k, h1, h2 => by simpa [accIndex_nil] using And.intro h1 h2
  | d :: ds, init, k, h1, h2 => by
    rw [accIndex_cons]
    have hd := abs_digitIndex_le d
    have hstep : ∀ a e : ℤ, 2 * |a| ≤ 5 * 3 ^ k - 1 → |e| ≤ 1 →
        2 * |3 * a + e| ≤ 5 * 3 ^ (k + 1) - 1 := by
      intro a e ha he
      have htri := abs_add_le (3 * a) e
      rw [abs_mul, abs_of_pos (by norm_num : (0 : ℤ) < 3)] at htri
      rw [pow_succ]
      linarith
    have hlen : k + (d :: ds).length = k + 1 + ds.length := by
      simp only [List.length_cons]
      omega
    rw [hlen]
    exact accIndex_bound ds _ (k + 1) (hstep _ _ h1 hd.1) (hstep _ _ h2 hd.2)

/-- Nonnegativity gives a nonzero index a positive norm, needed to exclude
nonzero multiples of the field characteristic. -/
private theorem eisensteinNorm_nonneg (a b : ℤ) : 0 ≤ eisensteinNorm a b := by
  unfold eisensteinNorm
  nlinarith [sq_nonneg (a - b), sq_nonneg a, sq_nonneg b]

/-- Only the zero coefficient pair has zero norm, so an integer collision
can be excluded by a positive lower bound on its norm. -/
private theorem eisensteinNorm_eq_zero_iff (a b : ℤ) :
    eisensteinNorm a b = 0 ↔ a = 0 ∧ b = 0 := by
  constructor
  · intro h
    unfold eisensteinNorm at h
    have ha : a ^ 2 = 0 := by nlinarith [sq_nonneg (a - b), sq_nonneg a, sq_nonneg b]
    have hb : b ^ 2 = 0 := by nlinarith [sq_nonneg (a - b), sq_nonneg a, sq_nonneg b]
    exact ⟨pow_eq_zero_iff (by norm_num) |>.mp ha, pow_eq_zero_iff (by norm_num) |>.mp hb⟩
  · rintro ⟨rfl, rfl⟩
    simp [eisensteinNorm]

/-- `|a|, |b| ≤ M` bounds the norm by `3M²`. -/
private theorem eisensteinNorm_le_of_abs_le {a b M : ℤ} (ha : |a| ≤ M) (hb : |b| ≤ M) :
    eisensteinNorm a b ≤ 3 * M ^ 2 := by
  have hM : 0 ≤ M := le_trans (abs_nonneg a) ha
  have ha2 : a ^ 2 ≤ M ^ 2 := by
    rw [← sq_abs a]
    exact pow_le_pow_left₀ (abs_nonneg a) ha 2
  have hb2 : b ^ 2 ≤ M ^ 2 := by
    rw [← sq_abs b]
    exact pow_le_pow_left₀ (abs_nonneg b) hb 2
  have hab : -(a * b) ≤ M * M := by
    calc -(a * b) ≤ |a * b| := neg_le_abs (a * b)
      _ = |a| * |b| := abs_mul a b
      _ ≤ M * M := mul_le_mul ha hb (abs_nonneg b) hM
  unfold eisensteinNorm
  nlinarith

/-! ## From `ℤ[ω]` to the field -/

/-- An element of exact order three satisfies the Eisenstein quadratic,
connecting the field root to the integer coefficient arithmetic. -/
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

/-- A vanishing field evaluation makes the integer norm vanish modulo the
characteristic, allowing the magnitude bound to exclude collisions. -/
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

/-- The modular engine: a nonzero index pair whose norm is below the
characteristic is nonzero in the field. -/
private theorem index_ne_zero_of_norm_lt {F : Type*} [Field F] {p : ℕ} [CharP F p] {ζ : F}
    (hζ : ζ ^ 2 + ζ + 1 = 0) {a b : ℤ} (hne : ¬(a = 0 ∧ b = 0))
    (hlt : eisensteinNorm a b < p) : (a : F) * ζ + (b : F) ≠ 0 := by
  intro hcol
  have hcast := eisensteinNorm_cast_eq_zero_of_collision hζ hcol
  have hdvd : (p : ℤ) ∣ eisensteinNorm a b := (CharP.intCast_eq_zero_iff F p _).mp hcast
  have hpos : 0 < eisensteinNorm a b := by
    rcases lt_or_eq_of_le (eisensteinNorm_nonneg a b) with h | h
    · exact h
    · exact absurd ((eisensteinNorm_eq_zero_iff a b).mp h.symm) hne
  have := Int.le_of_dvd hpos hdvd
  omega

/-! ## Injectivity -/

/-- If the characteristic is larger than `endoscaleCharacteristicBound n`, then
length-`n` endoscaling by a multiplicative order-`3` element is injective. -/
theorem endoscaleN_injective_of_characteristicBound_lt
    {F : Type*} [Field F] {p n : ℕ} [CharP F p] {ζ : F}
    (hζ : orderOf ζ = 3) (hp : endoscaleCharacteristicBound n < p) :
    Function.Injective (endoscaleN ζ (n := n)) := by
  intro input input' h
  have hζpoly := zeta_sq_add_zeta_add_one_eq_zero_of_orderOf_three hζ
  set acc := accIndex (initIndex input.initialSign input.initialEndo) (List.ofFn input.digits) with hacc
  set acc' := accIndex (initIndex input'.initialSign input'.initialEndo) (List.ofFn input'.digits) with hacc'
  have hcol : ((acc.a - acc'.a : ℤ) : F) * ζ + ((acc.b - acc'.b : ℤ) : F) = 0 := by
    simp only [endoscaleN] at h
    push_cast
    linear_combination h
  by_contra hne
  refine index_ne_zero_of_norm_lt hζpoly ?_ ?_ hcol
  · -- Distinct inputs have distinct accumulators.
    rintro ⟨h1, h2⟩
    have hacc_eq : acc = acc' := Index.ext (by omega) (by omega)
    obtain ⟨hinit, hds⟩ := accIndex_injective _ _ _ _ (by simp) hacc_eq
    obtain ⟨hs0, he0⟩ := initIndex_injective _ _ _ _ hinit
    exact hne (EndoscaleInput.ext hs0 he0 (List.ofFn_injective hds))
  · -- The difference's norm is below the characteristic.
    obtain ⟨hb1, hb2⟩ := accIndex_bound (List.ofFn input.digits) _ 0
      (abs_initIndex_le _ _).1 (abs_initIndex_le _ _).2
    obtain ⟨hb1', hb2'⟩ := accIndex_bound (List.ofFn input'.digits) _ 0
      (abs_initIndex_le _ _).1 (abs_initIndex_le _ _).2
    simp only [List.length_ofFn, Nat.zero_add] at hb1 hb2 hb1' hb2'
    have hM1 : |acc.a - acc'.a| ≤ 5 * 3 ^ n - 1 := by
      have := abs_sub (acc.a) (acc'.a)
      linarith
    have hM2 : |acc.b - acc'.b| ≤ 5 * 3 ^ n - 1 := by
      have := abs_sub (acc.b) (acc'.b)
      linarith
    have hnorm := eisensteinNorm_le_of_abs_le hM1 hM2
    have hbound : ((endoscaleCharacteristicBound n : ℕ) : ℤ) = 3 * (5 * 3 ^ n - 1) ^ 2 := by
      have h5 : 1 ≤ 5 * 3 ^ n := by
        have : 1 ≤ 3 ^ n := Nat.one_le_pow _ _ (by norm_num)
        omega
      simp only [endoscaleCharacteristicBound]
      push_cast [Nat.cast_sub h5]
      ring
    have hp' : ((endoscaleCharacteristicBound n : ℕ) : ℤ) < p := by exact_mod_cast hp
    omega

/-! ## No-collision integer core for the radix-3 `Endoscalar::group_scale`

`group_scale` runs over a prime-order-`q` group on which the curve
endomorphism `φ(x, y) = (ζ·x, y)` acts as `[λ]` for an order-3 scalar `λ`.
Writing the accumulator after `m` consumed digits as `[u·λ + v]P̂` with
`(u, v) = accIndex (initIndex s₀ e₀) (digits.take m)` and the digit point as
`[δu·λ + δv]P̂`, the unchecked chain `((A + D) + A) + A` fails only when one
of `A ∓ D`, `2A + D`, `3A + D` is the identity, i.e. when the integer
combination `(u ∓ δu, v ∓ δv)`, `(2u + δu, 2v + δv)` or `(3u + δu, 3v + δv)`
vanishes mod `q`.

This section proves all of these are nonzero in `F` whenever the
characteristic exceeds `groupScaleCollisionBound`: the accumulator's
Eisenstein norm is at least `4` throughout while a digit's is at most `3`, so
none vanishes in `ℤ[ω]`, and their norms are far below the characteristic.
The connection between the affine accumulator and `[u·λ + v]P̂` via the
group law is not proved here. The circuit contracts retain
`groupScaleNative ≠ none` as a caller obligation. -/

/-- Step-point indices: the digit point `D ∈ ±{P̂, φP̂, φ²P̂, P̂ - φP̂}` has the
index of its digit. -/
def StepIndex (δ : Index) : Prop :=
  ∃ d : Digit, δ = digitIndex d

/-- Uniform characteristic bound for the 47-digit group-scale collision
families: every exceptional combination has components below `5·3^47`, so
Eisenstein norm at most `3·(5·3^47)²`, below `2^156` and comfortably under
the Pasta characteristics (≈ 2^254). -/
def groupScaleCollisionBound : ℕ := 3 * (5 * 3 ^ 47) ^ 2

/-- Every signed digit has norm between one and three, separating digit
indices from the accumulator's lower bound of four. -/
private theorem eisensteinNorm_digitIndex_le (d : Digit) :
    1 ≤ eisensteinNorm (digitIndex d).a (digitIndex d).b ∧
    eisensteinNorm (digitIndex d).a (digitIndex d).b ≤ 3 := by
  rcases d with ⟨s, e1, e2⟩
  cases s <;> cases e1 <;> cases e2 <;> norm_num [digitIndex, eisensteinNorm]

/-- Every initial choice has norm four, seeding the invariant that
separates accumulators from digit points. -/
private theorem eisensteinNorm_initIndex (s0 e0 : Bool) :
    eisensteinNorm (initIndex s0 e0).a (initIndex s0 e0).b = 4 := by
  cases s0 <;> cases e0 <;> norm_num [initIndex, eisensteinNorm]

/-- A step at least triples the magnitude and a digit adds at most `√3`, so
norm `≥ 4` is preserved: `N(3a + d) = 9N(a) + 3B(a, d) + N(d)` with
`B(a, d)² ≤ 4N(a)N(d)`. -/
private theorem four_le_eisensteinNorm_step {a1 a2 d1 d2 : ℤ}
    (ha : 4 ≤ eisensteinNorm a1 a2) (hd1 : 1 ≤ eisensteinNorm d1 d2)
    (hd3 : eisensteinNorm d1 d2 ≤ 3) :
    4 ≤ eisensteinNorm (3 * a1 + d1) (3 * a2 + d2) := by
  unfold eisensteinNorm at *
  -- `B` is the bilinear form; Cauchy–Schwarz for the Eisenstein lattice.
  have hcs : (2 * a1 * d1 - a1 * d2 - a2 * d1 + 2 * a2 * d2) ^ 2 ≤
      4 * (a1 ^ 2 - a1 * a2 + a2 ^ 2) * (d1 ^ 2 - d1 * d2 + d2 ^ 2) := by
    nlinarith [sq_nonneg (a1 * d2 - a2 * d1)]
  by_contra hlt
  have hlt := not_le.mp hlt
  have hexp : (3 * a1 + d1) ^ 2 - (3 * a1 + d1) * (3 * a2 + d2) + (3 * a2 + d2) ^ 2 =
      9 * (a1 ^ 2 - a1 * a2 + a2 ^ 2) + 3 * (2 * a1 * d1 - a1 * d2 - a2 * d1 + 2 * a2 * d2) +
        (d1 ^ 2 - d1 * d2 + d2 ^ 2) := by ring
  rw [hexp] at hlt
  set Na := a1 ^ 2 - a1 * a2 + a2 ^ 2 with hNa
  set Nd := d1 ^ 2 - d1 * d2 + d2 ^ 2 with hNd
  set B := 2 * a1 * d1 - a1 * d2 - a2 * d1 + 2 * a2 * d2 with hB
  have h1 : 0 < -3 * B - (9 * Na + Nd - 4) := by linarith
  have h2 : 0 < -3 * B + (9 * Na + Nd - 4) := by linarith
  have hprod := mul_pos h1 h2
  nlinarith [hcs, hprod, mul_nonneg (by linarith : (0 : ℤ) ≤ 3 - Nd) (by linarith : (0 : ℤ) ≤ Na),
    mul_nonneg (by linarith : (0 : ℤ) ≤ Na - 4) (by linarith : (0 : ℤ) ≤ Na),
    sq_nonneg (Nd - 4)]

/-- The accumulator's Eisenstein norm is at least `4` after any number of
digits: no accumulator index ever degenerates to (plus or minus) a step
index, nor to half or a third of one. -/
theorem four_le_eisensteinNorm_accIndex (s0 e0 : Bool) : ∀ ds : List Digit,
    4 ≤ eisensteinNorm (accIndex (initIndex s0 e0) ds).a (accIndex (initIndex s0 e0) ds).b := by
  suffices h : ∀ (ds : List Digit) (init : Index), 4 ≤ eisensteinNorm init.a init.b →
      4 ≤ eisensteinNorm (accIndex init ds).a (accIndex init ds).b from
    fun ds => h ds _ (eisensteinNorm_initIndex s0 e0).ge
  intro ds
  induction ds with
  | nil => intro init h; simpa [accIndex_nil] using h
  | cons d ds ih =>
    intro init h
    rw [accIndex_cons]
    apply ih
    obtain ⟨hd1, hd3⟩ := eisensteinNorm_digitIndex_le d
    exact four_le_eisensteinNorm_step h hd1 hd3

/-- Scaling an index by `k` scales its norm by `k²`; negation preserves it. -/
private theorem eisensteinNorm_smul (k a b : ℤ) :
    eisensteinNorm (k * a) (k * b) = k ^ 2 * eisensteinNorm a b := by
  unfold eisensteinNorm; ring

/-- Negating an index preserves its norm, so one lower bound handles both
signs of the exceptional collision combinations. -/
private theorem eisensteinNorm_neg (a b : ℤ) :
    eisensteinNorm (-a) (-b) = eisensteinNorm a b := by
  unfold eisensteinNorm; ring

/-- `k·acc + δ ≠ 0` and `acc - δ ≠ 0` in `ℤ[ω]` for `k ∈ {1, 2, 3}`: the
norms `k²·N(acc) ≥ 4` and `N(δ) ≤ 3` differ. -/
private theorem combination_ne_zero_int {u v δu δv : ℤ} (hacc : 4 ≤ eisensteinNorm u v)
    (hδ : eisensteinNorm δu δv ≤ 3) {k : ℤ} (hk : 1 ≤ k) :
    ¬(k * u + δu = 0 ∧ k * v + δv = 0) := by
  rintro ⟨h1, h2⟩
  have hku : k * u = -δu := by linarith
  have hkv : k * v = -δv := by linarith
  have h := eisensteinNorm_smul k u v
  rw [hku, hkv, eisensteinNorm_neg] at h
  nlinarith [eisensteinNorm_nonneg u v]

/-- The radix-3 no-collision integer core for `group_scale`'s 47-step walk:
for any prefix of at most 46 digits and any step index `δ`, the four
exceptional-case combinations — accumulator equals `D` (`(u − δu, v − δv)`),
accumulator equals `−D` (`(u + δu, v + δv)`), `2A + D = 0` and `3A + D = 0` —
are all nonzero in characteristic above `groupScaleCollisionBound`. -/
theorem groupScale_collision_combinations_ne_zero
    {F : Type*} [Field F] {q : ℕ} [CharP F q] {ζ : F}
    (hζ : orderOf ζ = 3) (hq : groupScaleCollisionBound < q)
    (s0 e0 : Bool) (digits : List Digit) (h_len : digits.length ≤ 46)
    {δ : Index} (hδ : StepIndex δ) :
    let acc := accIndex (initIndex s0 e0) digits
    (((acc.a - δ.a : ℤ) : F) * ζ + ((acc.b - δ.b : ℤ) : F) ≠ 0) ∧
    (((acc.a + δ.a : ℤ) : F) * ζ + ((acc.b + δ.b : ℤ) : F) ≠ 0) ∧
    (((2 * acc.a + δ.a : ℤ) : F) * ζ + ((2 * acc.b + δ.b : ℤ) : F) ≠ 0) ∧
    (((3 * acc.a + δ.a : ℤ) : F) * ζ + ((3 * acc.b + δ.b : ℤ) : F) ≠ 0) := by
  intro acc
  obtain ⟨d, rfl⟩ := hδ
  have hζpoly := zeta_sq_add_zeta_add_one_eq_zero_of_orderOf_three hζ
  have hacc := four_le_eisensteinNorm_accIndex s0 e0 digits
  obtain ⟨hδ1, hδ3⟩ := eisensteinNorm_digitIndex_le d
  obtain ⟨hδu, hδv⟩ := abs_digitIndex_le d
  -- Magnitudes: components of the accumulator are below `(5·3^46)/2`.
  obtain ⟨hu, hv⟩ := accIndex_bound digits _ 0 (abs_initIndex_le _ _).1 (abs_initIndex_le _ _).2
  simp only [Nat.zero_add] at hu hv
  have hpow : (3 : ℤ) ^ digits.length ≤ 3 ^ 46 := pow_le_pow_right₀ (by norm_num) h_len
  have h46 : (3 : ℤ) ^ 46 = 8862938119652501095929 := by norm_num
  have h47 : (3 : ℤ) ^ 47 = 26588814358957503287787 := by norm_num
  have hM : ((groupScaleCollisionBound : ℕ) : ℤ) = 3 * (5 * 3 ^ 47) ^ 2 := by
    norm_num [groupScaleCollisionBound]
  have hq' : ((groupScaleCollisionBound : ℕ) : ℤ) < q := by exact_mod_cast hq
  rw [hM, h47] at hq'
  rw [h46] at hpow
  -- Each combination: nonzero in `ℤ[ω]`, with norm below the characteristic.
  have key : ∀ (k : ℤ), 1 ≤ k → k ≤ 3 → ∀ (σ : ℤ), σ = 1 ∨ σ = -1 →
      ((k * acc.a + σ * (digitIndex d).a : ℤ) : F) * ζ +
        ((k * acc.b + σ * (digitIndex d).b : ℤ) : F) ≠ 0 := by
    intro k hk1 hk3 σ hσ
    have hσ' : eisensteinNorm (σ * (digitIndex d).a) (σ * (digitIndex d).b) ≤ 3 := by
      rcases hσ with rfl | rfl
      · simpa using hδ3
      · rw [eisensteinNorm_smul, neg_one_sq, one_mul]; exact hδ3
    refine index_ne_zero_of_norm_lt hζpoly (combination_ne_zero_int hacc hσ' hk1) ?_
    have hσabs : |σ| = 1 := by rcases hσ with rfl | rfl <;> norm_num
    have hc1 : |k * acc.a + σ * (digitIndex d).a| ≤ 5 * 26588814358957503287787 := by
      have := abs_add_le (k * acc.a) (σ * (digitIndex d).a)
      rw [abs_mul, abs_mul, hσabs, abs_of_pos (by linarith : (0 : ℤ) < k)] at this
      nlinarith [abs_nonneg acc.a, abs_nonneg (digitIndex d).a]
    have hc2 : |k * acc.b + σ * (digitIndex d).b| ≤ 5 * 26588814358957503287787 := by
      have := abs_add_le (k * acc.b) (σ * (digitIndex d).b)
      rw [abs_mul, abs_mul, hσabs, abs_of_pos (by linarith : (0 : ℤ) < k)] at this
      nlinarith [abs_nonneg acc.b, abs_nonneg (digitIndex d).b]
    have := eisensteinNorm_le_of_abs_le hc1 hc2
    omega
  refine ⟨?_, ?_, ?_, ?_⟩
  · have := key 1 (by norm_num) (by norm_num) (-1) (by norm_num)
    simpa [sub_eq_add_neg] using this
  · have := key 1 (by norm_num) (by norm_num) 1 (by norm_num)
    simpa using this
  · have := key 2 (by norm_num) (by norm_num) 1 (by norm_num)
    simpa using this
  · have := key 3 (by norm_num) (by norm_num) 1 (by norm_num)
    simpa using this

end Ragu.Lemmas.EndoscalarProof
