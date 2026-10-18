import Ragu.Circuits.Endoscalar.Lift
import Ragu.Circuits.Endoscalar.HoistedLift
import Ragu.Lemmas.EndoscalarProof

/-!
# Injectivity of the verified scalar lift

The integer theorem and the circuit's scalar model use different input
types. `decode` connects their bit order and digit tables, and
`liftNative_eq_endoscaleN` connects their Horner folds. Consequently, equal
outputs of the verified lift determine the same Boolean input bits.

The concrete field bounds below are kernel-checked arithmetic. These
results do not assume an affine walk, a group-order certificate, or an
identification of a curve endomorphism with a scalar-field root.
-/

namespace Ragu.Circuits.Endoscalar.LiftInjectivity

open Walk Point.Spec Ragu.Lemmas.EndoscalarProof

variable {p : ℕ} [Fact p.Prime]

/-- Decode the exact wire order used by the plain and hoisted lifts. -/
def decode (bits : Vector (F p) numBits) : EndoscaleInput numDigits where
  initialSign := decide (bits[0] = 1)
  initialEndo := decide (bits[1] = 1)
  digits i :=
    ⟨decide (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)) = 1),
     decide (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)) = 1),
     decide (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)) = 1)⟩

/-- Evaluate an Eisenstein index in the target scalar field. -/
def indexValue (ζ : F p) (v : Index) : F p := (v.a : F p) * ζ + v.b

theorem initial_eq (ζ s e : F p) :
    Lift.initValue ζ s e = indexValue ζ (initIndex (decide (s = 1)) (decide (e = 1))) := by
  by_cases hs : s = 1 <;> by_cases he : e = 1
  all_goals simp [Lift.initValue, initIndex, indexValue, hs, he]

theorem digit_eq (ζ s e1 e2 : F p) (hζ : ζ ^ 2 + ζ + 1 = 0) :
    Lift.digitValue ζ s e1 e2 = indexValue ζ
      (digitIndex ⟨decide (s = 1), decide (e1 = 1), decide (e2 = 1)⟩) := by
  by_cases hs : s = 1 <;> by_cases he1 : e1 = 1 <;> by_cases he2 : e2 = 1
  all_goals simp [Lift.digitValue, digitIndex, indexValue, hs, he1, he2]
  all_goals first | (solve | ring) | linear_combination hζ | linear_combination -hζ

/-- Evaluation commutes with the index fold, including its digit order. -/
theorem index_fold (ζ : F p) (n : ℕ) (digits : Fin n → Digit) (init : Index) :
    indexValue ζ (accIndex init (List.ofFn digits)) =
      Fin.foldl n (fun acc i => 3 * acc + indexValue ζ (digitIndex (digits i)))
        (indexValue ζ init) := by
  induction n with
  | zero => simp [accIndex, Fin.foldl_zero]
  | succ n ih =>
    rw [List.ofFn_succ_last, Fin.foldl_succ_last]
    simp only [accIndex, List.foldl_append, List.foldl_cons, List.foldl_nil]
    rw [← ih]
    simp only [accIndex, step, indexValue, Int.cast_add, Int.cast_mul, Int.cast_ofNat]
    ring

/-- The circuit model is exactly the integer theorem's model, evaluated
at the same nontrivial cube root. Booleanity is needed for injectivity,
but not for this equality: both native models branch on equality to one. -/
theorem liftNative_eq_endoscaleN (cp : CurveParams p) (hζ : cp.ζ ≠ 1)
    (bits : Vector (F p) numBits) :
    Lift.liftNative cp.ζ bits = endoscaleN cp.ζ (decode bits) := by
  change Lift.liftNative cp.ζ bits = indexValue cp.ζ _
  rw [index_fold]
  simp only [Lift.liftNative, decode, ← initial_eq]
  apply Lift.fin_foldl_congr
  intro acc i
  rw [digit_eq cp.ζ _ _ _ (zeta_quadratic cp hζ)]

private theorem bool_eq_of_decide_eq (a b : F p) (ha : IsBool a) (hb : IsBool b)
    (h : decide (a = 1) = decide (b = 1)) : a = b := by
  rcases ha with ha | ha <;> rcases hb with hb | hb <;> simp_all

/-- Decoding loses no information on the Boolean input domain. -/
theorem decode_injective {a b : Vector (F p) numBits}
    (ha : ∀ i : Fin numBits, IsBool a[i]) (hb : ∀ i : Fin numBits, IsBool b[i])
    (h : decode a = decode b) : a = b := by
  apply Vector.ext
  intro i hi
  apply bool_eq_of_decide_eq _ _ (ha ⟨i, hi⟩) (hb ⟨i, hi⟩)
  by_cases h0 : i = 0
  · subst i
    exact congrArg EndoscaleInput.initialSign h
  by_cases h1 : i = 1
  · subst i
    exact congrArg EndoscaleInput.initialEndo h
  have hi2 : 2 ≤ i := by omega
  let j : Fin numDigits := ⟨(i - 2) / 3, by change (i - 2) / 3 < 47; change i < 143 at hi; omega⟩
  have hd := congrArg (fun input => input.digits j) h
  have hj : j.val = (i - 2) / 3 := rfl
  have hm := Nat.mod_add_div (i - 2) 3
  have hr := Nat.mod_lt (i - 2) (by decide : 0 < 3)
  by_cases hs : i = 2 + 3 * j.val
  · simpa only [decode, ← hs] using congrArg Digit.sign hd
  by_cases he : i = 3 + 3 * j.val
  · simpa only [decode, ← he] using congrArg Digit.endo1 hd
  have he2 : i = 4 + 3 * j.val := by omega
  simpa only [decode, ← he2] using congrArg Digit.endo2 hd

/-- The verified lift's native specification is injective on Boolean
vectors whenever the field exceeds the integer characteristic bound. -/
theorem liftNative_injective (cp : CurveParams p) (hζ : cp.ζ ≠ 1)
    (hbound : endoscaleCharacteristicBound numDigits < p)
    {a b : Vector (F p) numBits}
    (ha : ∀ i : Fin numBits, IsBool a[i]) (hb : ∀ i : Fin numBits, IsBool b[i])
    (h : Lift.liftNative cp.ζ a = Lift.liftNative cp.ζ b) : a = b := by
  apply decode_injective ha hb
  apply endoscaleN_injective_of_characteristicBound_lt (orderOf_eq_prime cp.h_small_order hζ) hbound
  simpa only [← liftNative_eq_endoscaleN cp hζ] using h

/-- Deployed 47-digit lift bound in the Pallas base field. -/
theorem characteristicBound_lt_p : endoscaleCharacteristicBound numDigits < Core.Primes.p := by
  decide

/-- Deployed 47-digit lift bound in the Vesta base field. -/
theorem characteristicBound_lt_q : endoscaleCharacteristicBound numDigits < Core.Primes.q := by
  decide

/-- The output determines the input among all Boolean endoscalars. -/
def UniqueLift (ζ : F p) (bits : Vector (F p) numBits) (out : F p) : Prop :=
  out = Lift.liftNative ζ bits ∧
  ∀ other : Vector (F p) numBits, (∀ i : Fin numBits, IsBool other[i]) →
    Lift.liftNative ζ other = out → other = bits

end Ragu.Circuits.Endoscalar.LiftInjectivity

namespace Ragu.Circuits.Endoscalar.Lift

open Walk Point.Spec LiftInjectivity Ragu.Lemmas.EndoscalarProof
variable {p : ℕ} [Fact p.Prime]

/-- Plain circuit soundness strengthened with uniqueness of its Boolean
input, using the existing circuit theorem and the integer model bridge. -/
theorem injective_soundness (cp : CurveParams p)
    (hbound : endoscaleCharacteristicBound numDigits < p) :
    Soundness (F p) (Input := Input) (Output := field)
      (main cp) (Assumptions cp) (fun input => UniqueLift cp.ζ input.bits) := by
  intro offset env vars input hin hass hholds
  obtain ⟨hspec, hreq⟩ := Lift.soundness cp offset env vars input hin hass hholds
  refine ⟨⟨hspec, ?_⟩, hreq⟩
  intro other hother heq
  exact liftNative_injective cp hass.1 hbound hother hass.2 (heq.trans hspec)

/-- Plain lift uniqueness for the deployed Fp parameters. -/
theorem ep_injective_soundness : Soundness (F Core.Primes.p) (Input := Input) (Output := field)
    (main EpAffineParams) (Assumptions EpAffineParams)
    (fun input => UniqueLift EpAffineParams.ζ input.bits) :=
  injective_soundness EpAffineParams characteristicBound_lt_p

/-- Plain lift uniqueness for the deployed Fq parameters. -/
theorem eq_injective_soundness : Soundness (F Core.Primes.q) (Input := Input) (Output := field)
    (main EqAffineParams) (Assumptions EqAffineParams)
    (fun input => UniqueLift EqAffineParams.ζ input.bits) :=
  injective_soundness EqAffineParams characteristicBound_lt_q

end Ragu.Circuits.Endoscalar.Lift

namespace Ragu.Circuits.Endoscalar.HoistedLift

open Walk Point.Spec LiftInjectivity Ragu.Lemmas.EndoscalarProof
variable {p : ℕ} [Fact p.Prime]

/-- Hoisted lift soundness has the same uniqueness conclusion; its product
relations remain explicit premises supplied by the stage owner. -/
theorem injective_soundness (cp : CurveParams p)
    (hbound : endoscaleCharacteristicBound numDigits < p) :
    Soundness (F p) (Input := Input) (Output := field)
      (main cp) (Assumptions cp) (fun input => UniqueLift cp.ζ input.bits) := by
  intro offset env vars input hin hass hholds
  obtain ⟨hspec, hreq⟩ := soundness cp offset env vars input hin hass hholds
  refine ⟨⟨hspec, ?_⟩, hreq⟩
  intro other hother heq
  exact liftNative_injective cp hass.1 hbound hother hass.2.1 (heq.trans hspec)

/-- Hoisted lift uniqueness for the deployed Fp parameters. -/
theorem ep_injective_soundness :
    Soundness (F Core.Primes.p) (Input := Input) (Output := field)
      (main EpAffineParams) (Assumptions EpAffineParams)
      (fun input => UniqueLift EpAffineParams.ζ input.bits) :=
  injective_soundness EpAffineParams characteristicBound_lt_p

/-- Hoisted lift uniqueness for the deployed Fq parameters. -/
theorem eq_injective_soundness :
    Soundness (F Core.Primes.q) (Input := Input) (Output := field)
      (main EqAffineParams) (Assumptions EqAffineParams)
      (fun input => UniqueLift EqAffineParams.ζ input.bits) :=
  injective_soundness EqAffineParams characteristicBound_lt_q

end Ragu.Circuits.Endoscalar.HoistedLift
