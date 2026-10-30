import Ragu.Lemmas.EndoscalarProof
import Mathlib.GroupTheory.SpecificGroups.Cyclic.Basic
import Mathlib.Tactic.Module

/-!
# The radix-3 integer bounds in a prime-order group

An endomorphism satisfying `φ²P + φP + P = 0` lets an Eisenstein index
act as `a • φP + b • P`. A vanishing action would make its integer norm
annihilate `P`. The positive norm bound therefore rules out the collision
in a group of prime order larger than that bound, without an eigenvalue
certificate or an assumption about the affine walk's success.
-/

namespace Ragu.Lemmas.EndoscalarGroup

open EndoscalarProof

variable {G : Type*} [AddCommGroup G]

/-- An additive map on a prime-order group is determined by any nonzero
point, so checking one generator pins the scalar action everywhere. -/
theorem eq_nsmul_of_generator {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card G = q) (φ : G →+ G) (k : ℕ) (g : G) (hg : g ≠ 0)
    (hgen : φ g = k • g) (P : G) : φ P = k • P := by
  have hmem : P ∈ AddSubgroup.zmultiples g := mem_zmultiples_of_prime_card hcard hg
  obtain ⟨n, hn⟩ := AddSubgroup.mem_zmultiples_iff.mp hmem
  rw [← hn, map_zsmul, hgen, smul_comm]

/-- The action of an Eisenstein index on the chosen base point. -/
def eval (φ : G →+ G) (P : G) (i : Index) : G := i.a • φ P + i.b • P

/-- A nonzero point in a prime-order group cannot be killed by a smaller
positive integer. -/
theorem zsmul_ne_zero_of_prime_card {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card G = q) {P : G} (hP : P ≠ 0) {n : ℤ}
    (hpos : 0 < n) (hlt : n < q) : n • P ≠ 0 := by
  have horder : addOrderOf P = q := addOrderOf_eq_prime
    (by simpa only [hcard] using (card_nsmul_eq_zero' (x := P))) hP
  intro h
  have hdvd := (addOrderOf_dvd_iff_zsmul_eq_zero).mpr h
  rw [horder] at hdvd
  have := Int.le_of_dvd hpos hdvd
  omega

/-- Conjugating a vanishing Eisenstein action makes its norm annihilate
the base point. All scalar arithmetic here is over the integers. -/
theorem norm_zsmul_eq_zero (φ : G →+ G) (P : G)
    (hpoly : φ (φ P) + φ P + P = 0) (i : Index) (h : eval φ P i = 0) :
    eisensteinNorm i.a i.b • P = 0 := by
  have hφ : i.a • φ (φ P) + i.b • φ P = 0 := by
    simpa only [eval, map_add, map_zsmul, map_zero] using congrArg φ h
  calc
    eisensteinNorm i.a i.b • P =
        (i.b - i.a) • eval φ P i - i.a • (i.a • φ (φ P) + i.b • φ P) +
          (i.a * i.a) • (φ (φ P) + φ P + P) := by
      unfold eisensteinNorm eval
      module
    _ = 0 := by rw [h, hφ, hpoly]; simp

/-- Positive norms below the group order give nonzero point actions. -/
theorem eval_ne_zero {q : ℕ} [Fact q.Prime] (hcard : Nat.card G = q)
    (φ : G →+ G) (P : G) (hP : P ≠ 0) (hpoly : φ (φ P) + φ P + P = 0)
    (i : Index) (hpos : 0 < eisensteinNorm i.a i.b)
    (hlt : eisensteinNorm i.a i.b < q) : eval φ P i ≠ 0 := by
  intro h
  exact zsmul_ne_zero_of_prime_card hcard hP hpos hlt (norm_zsmul_eq_zero φ P hpoly i h)

/-- The four exceptional triple-and-add combinations are nonzero in the
complete curve group, using exactly the integer bound proved for the walk. -/
theorem collision_combinations_ne_zero {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card G = q) (hq : groupScaleCollisionBound < q)
    (φ : G →+ G) (P : G) (hP : P ≠ 0) (hpoly : φ (φ P) + φ P + P = 0)
    (s0 e0 : Bool) (digits : List Digit) (h_len : digits.length ≤ 46) (d : Digit) :
    let A := eval φ P (accIndex (initIndex s0 e0) digits)
    let D := eval φ P (digitIndex d)
    A - D ≠ 0 ∧ A + D ≠ 0 ∧ (2 : ℤ) • A + D ≠ 0 ∧ (3 : ℤ) • A + D ≠ 0 := by
  intro A D
  have key (k : ℤ) (hk1 : 1 ≤ k) (hk3 : k ≤ 3) (σ : ℤ) (hσ : σ = 1 ∨ σ = -1) :
      k • A + σ • D ≠ 0 := by
    obtain ⟨hpos, hbound⟩ := groupScale_collision_norm_bounds s0 e0 digits h_len d k hk1 hk3 σ hσ
    have hne := eval_ne_zero hcard φ P hP hpoly
      ⟨k * (accIndex (initIndex s0 e0) digits).a + σ * (digitIndex d).a,
       k * (accIndex (initIndex s0 e0) digits).b + σ * (digitIndex d).b⟩
      hpos (hbound.trans_lt (by exact_mod_cast hq))
    convert hne using 1
    dsimp [A, D, eval]
    module
  refine ⟨?_, ?_, ?_, ?_⟩
  · simpa only [one_zsmul, neg_one_zsmul, sub_eq_add_neg] using
      key 1 (by norm_num) (by norm_num) (-1) (by norm_num)
  · simpa using key 1 (by norm_num) (by norm_num) 1 (by norm_num)
  · simpa using key 2 (by norm_num) (by norm_num) 1 (by norm_num)
  · simpa using key 3 (by norm_num) (by norm_num) 1 (by norm_num)

end Ragu.Lemmas.EndoscalarGroup
