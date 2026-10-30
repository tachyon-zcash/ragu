import Ragu.Circuits.Endoscalar.LiftInjectivity
import Ragu.Circuits.Endoscalar.GroupScale
import Ragu.Circuits.Endoscalar.HoistedGroupScale
import Ragu.Circuits.Point.Endomorphism

/-!
# The affine circuit walk computes scalar multiplication

Carry the complete-group accumulator invariant back through normalization,
identify its index with the lift's encoding, and use the certified Pasta
endomorphism eigenvalue. The resulting contract is about multiplication by
`Lift.liftNative`, not merely agreement with an affine-formula evaluator.
-/

namespace Ragu.Circuits.Endoscalar.WalkScalar

open Walk Point.Spec LiftInjectivity Ragu.Lemmas.EndoscalarProof
open Ragu.Lemmas Ragu.Foundation.Pasta CompElliptic.CurveForms.ShortWeierstrass

variable {p : ℕ} [Fact p.Prime]

/-- The walk and lift consume the identical prefix in the identical order. -/
theorem digitPrefix_eq (bits : Vector (F p) numBits) (m : ℕ) (hm : m ≤ numDigits) :
    WalkGroup.digitPrefix bits m =
      List.ofFn (fun i : Fin m => (decode bits).digits ⟨i.val, by omega⟩) := by
  induction m with
  | zero => simp [WalkGroup.digitPrefix]
  | succ m ih =>
    have hidx := walk_index_lt m (by omega)
    rw [WalkGroup.digitPrefix, dif_pos hidx, List.ofFn_succ_last, ih (by omega)]
    rfl

/-- Preserve the group meaning through normalization and denormalization. -/
theorem groupScaleNative_eq_index [NeZero (2 : F p)] {q : ℕ} [Fact q.Prime]
    (E : SWCurve (F p)) (hA : E.A = 0) (cp : CurveParams p) (hB : E.B = cp.b)
    (hcard : Nat.card (SWPoint E) = q) (hq : groupScaleCollisionBound < q)
    (hζ : cp.ζ ≠ 1) (hnz : cp.nonzeroCoordinates)
    (pt : Point (F p)) (hpt : pt.isOnCurve cp) (bits : Vector (F p) numBits) :
    ∃ (out : Point (F p)) (hout : out.isOnCurve cp),
      groupScaleNative cp pt bits = some out ∧
      Point.Group.embed E hA cp hB out hout =
        EndoscalarGroup.eval (CoordinateMap.endo E hA cp.ζ cp.h_small_order)
          (Point.Group.embed E hA cp hB pt hpt)
          (accIndex (initIndex (decode bits).initialSign (decode bits).initialEndo)
            (List.ofFn (decode bits).digits)) := by
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
  have hbase := normalized_isOnCurve cp pt hpt hy
  obtain ⟨A, hAc, ha, hg⟩ := WalkGroup.accAfter_exists Et hAt (twist cp norm.c) hBt
    hcardt hq norm.r hr hζ hbase (twist_noOrderTwoPoints cp norm.c hc hnz.2)
    bits numDigits le_rfl
  rw [digitPrefix_eq bits numDigits le_rfl] at hg
  let ψ := CoordinateMap.hom E hA norm.c hc
  let P := Point.Group.embed E hA cp hB pt hpt
  let φ := CoordinateMap.endo E hA cp.ζ cp.h_small_order
  let φt := CoordinateMap.endo Et hAt cp.ζ cp.h_small_order
  have hcomm (Q : SWPoint E) : ψ (φ Q) = φt (ψ Q) := by
    apply SWPoint.ext_pair
    change (norm.c ^ 2 * (cp.ζ * Q.x), norm.c ^ 3 * Q.y) =
      (cp.ζ * (norm.c ^ 2 * Q.x), norm.c ^ 3 * Q.y)
    congr 1
    ring
  have hnorm : ψ P = Point.Group.embed Et hAt (twist cp norm.c) hBt ⟨norm.r, norm.r⟩ hbase := by
    apply SWPoint.ext_pair
    change (norm.c ^ 2 * pt.x, norm.c ^ 3 * pt.y) = (norm.r, norm.r)
    apply Prod.ext
    · rfl
    · dsimp [norm, normalizeNative]
      field_simp
  let out : Point (F p) := ⟨A.x / norm.c ^ 2, A.y / norm.c ^ 3⟩
  have hout : out.isOnCurve cp := denormalize_isOnCurve cp norm.c hc A hAc
  have hdenorm : ψ (Point.Group.embed E hA cp hB out hout) =
      Point.Group.embed Et hAt (twist cp norm.c) hBt A hAc := by
    apply SWPoint.ext_pair
    change (norm.c ^ 2 * (A.x / norm.c ^ 2), norm.c ^ 3 * (A.y / norm.c ^ 3)) = (A.x, A.y)
    apply Prod.ext <;> field_simp
  refine ⟨out, hout, ?_, ?_⟩
  · rw [accAfter_twist] at ha
    change accAfter cp (normalizeNative pt).r bits numDigits = some A at ha
    simp only [groupScaleNative, ha, Option.map_some]
    rfl
  · apply (CoordinateMap.hom_bijective E hA norm.c hc).1
    rw [hdenorm, hg]
    simp only [EndoscalarGroup.eval, map_add, map_zsmul, ← hnorm]
    rw [hcomm]
    rfl

/-- Evaluate an index modulo the group order after identifying the
endomorphism eigenvalue. This also handles negative index coefficients. -/
theorem eval_eq_scalar {G : Type*} [AddCommGroup G] {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card G = q) (φ : G →+ G) (P : G) (eigenvalue : F q)
    (hφ : φ P = eigenvalue.val • P) (i : Index) :
    EndoscalarGroup.eval φ P i = (indexValue eigenvalue i).val • P := by
  let k : ℤ := i.a * (eigenvalue.val : ℤ) + i.b
  have hcast : (k : F q) = indexValue eigenvalue i := by
    simp [k, indexValue]
  have hmod : (k % (q : ℤ)) • P = k • P := by
    simpa only [hcard] using mod_natCard_zsmul P k
  calc
    EndoscalarGroup.eval φ P i = k • P := by
      dsimp [EndoscalarGroup.eval, k]
      rw [hφ]
      module
    _ = (k % (q : ℤ)) • P := hmod.symm
    _ = (indexValue eigenvalue i).val • P := by
      rw [← ZMod.val_intCast, hcast, natCast_zsmul]

/-- Reinterpret the selector choices in the opposite field. On Boolean
inputs this preserves every bit; the native models use the same `= 1` test. -/
def scalarBits (q : ℕ) [Fact q.Prime] (bits : Vector (F p) numBits) : Vector (F q) numBits :=
  bits.map fun b => if b = 1 then 1 else 0

/-- Reinterpreting a bit in the opposite field preserves its `= 1` test. -/
private theorem decide_scalarBit {q : ℕ} [Fact q.Prime] (b : F p) :
    decide ((if b = 1 then (1 : F q) else 0) = 1) = decide (b = 1) := by
  by_cases hb : b = 1 <;> simp [hb]

/-- The lift in the opposite field reads the same digits as the walk's
selector bits, which lets `groupScaleNative_eq_lift` apply the scalar-field
lift to base-field wires. -/
theorem decode_scalarBits {q : ℕ} [Fact q.Prime] (bits : Vector (F p) numBits) :
    decode (scalarBits q bits) = decode bits := by
  apply EndoscaleInput.ext
  · simp only [decode, scalarBits, Vector.getElem_map, decide_scalarBit]
  · simp only [decode, scalarBits, Vector.getElem_map, decide_scalarBit]
  · funext i
    simp only [decode, scalarBits, Vector.getElem_map, decide_scalarBit]

/-- The successful affine walk equals multiplication by the circuit lift
in the opposite field. Non-degeneracy and the bit-order bridge are derived. -/
theorem groupScaleNative_eq_lift [NeZero (2 : F p)] {q : ℕ} [Fact q.Prime]
    (E : SWCurve (F p)) (hA : E.A = 0) (cp : CurveParams p) (hB : E.B = cp.b)
    (scalar : CurveParams q) (hscalar : scalar.ζ ≠ 1)
    (hcard : Nat.card (SWPoint E) = q) (hq : groupScaleCollisionBound < q)
    (hζ : cp.ζ ≠ 1) (hnz : cp.nonzeroCoordinates)
    (hφ : ∀ P : SWPoint E, CoordinateMap.endo E hA cp.ζ cp.h_small_order P = scalar.ζ.val • P)
    (pt : Point (F p)) (hpt : pt.isOnCurve cp) (bits : Vector (F p) numBits) :
    ∃ (out : Point (F p)) (hout : out.isOnCurve cp),
      groupScaleNative cp pt bits = some out ∧
      Point.Group.embed E hA cp hB out hout =
        (Lift.liftNative scalar.ζ (scalarBits q bits)).val • Point.Group.embed E hA cp hB pt hpt := by
  obtain ⟨out, hout, hwalk, hgroup⟩ := groupScaleNative_eq_index E hA cp hB hcard hq hζ hnz pt hpt bits
  refine ⟨out, hout, hwalk, ?_⟩
  rw [hgroup, eval_eq_scalar hcard _ _ scalar.ζ (hφ _),
    liftNative_eq_endoscaleN scalar hscalar, decode_scalarBits]
  rfl

end Ragu.Circuits.Endoscalar.WalkScalar

namespace Ragu.Circuits.Endoscalar.WalkScalar

open Walk Point.Spec Core.Primes Ragu.Foundation.Pasta CompElliptic.Curves.Pasta

/-- Scalar multiplication by the lift, on Pallas. -/
def EpScalarSpec (pt : Point (F p)) (bits : Vector (F p) numBits) (out : Point (F p)) : Prop :=
  ∃ (hpt : pt.isOnCurve EpAffineParams) (hout : out.isOnCurve EpAffineParams),
    Point.Group.embed Pallas.curve rfl EpAffineParams rfl out hout =
      (Lift.liftNative EqAffineParams.ζ (scalarBits q bits)).val •
        Point.Group.embed Pallas.curve rfl EpAffineParams rfl pt hpt

/-- Scalar multiplication by the lift, on Vesta. -/
def EqScalarSpec (pt : Point (F q)) (bits : Vector (F q) numBits) (out : Point (F q)) : Prop :=
  ∃ (hpt : pt.isOnCurve EqAffineParams) (hout : out.isOnCurve EqAffineParams),
    Point.Group.embed Vesta.curve rfl EqAffineParams rfl out hout =
      (Lift.liftNative EpAffineParams.ζ (scalarBits p bits)).val •
        Point.Group.embed Vesta.curve rfl EqAffineParams rfl pt hpt

/-- Identify the Pallas affine result with its lifted scalar action. -/
theorem ep_spec (pt : Point (F p)) (bits : Vector (F p) numBits) (out : Point (F p))
    (hpt : pt.isOnCurve EpAffineParams) (h : groupScaleNative EpAffineParams pt bits = some out) :
    EpScalarSpec pt bits out := by
  obtain ⟨result, hresult, hwalk, hgroup⟩ := groupScaleNative_eq_lift (p := p) (q := q)
    Pallas.curve rfl EpAffineParams rfl EqAffineParams (by decide)
    pallas_group_order WalkPasta.collisionBound_lt_q (by decide)
    epAffineParams_nonzeroCoordinates Point.Endomorphism.pallas_endo pt hpt bits
  have heq := Option.some.inj (hwalk.symm.trans h)
  subst result
  exact ⟨hpt, hresult, hgroup⟩

/-- Identify the Vesta affine result with its lifted scalar action. -/
theorem eq_spec (pt : Point (F q)) (bits : Vector (F q) numBits) (out : Point (F q))
    (hpt : pt.isOnCurve EqAffineParams) (h : groupScaleNative EqAffineParams pt bits = some out) :
    EqScalarSpec pt bits out := by
  obtain ⟨result, hresult, hwalk, hgroup⟩ := groupScaleNative_eq_lift (p := q) (q := p)
    Vesta.curve rfl EqAffineParams rfl EpAffineParams (by decide)
    vesta_group_order WalkPasta.collisionBound_lt_p (by decide)
    eqAffineParams_nonzeroCoordinates Point.Endomorphism.vesta_endo pt hpt bits
  have heq := Option.some.inj (hwalk.symm.trans h)
  subst result
  exact ⟨hpt, hresult, hgroup⟩

end Ragu.Circuits.Endoscalar.WalkScalar

namespace Ragu.Circuits.Endoscalar.GroupScale

open Core.Primes Point.Spec

/-- The verified plain Pallas circuit computes multiplication by the Fq lift. -/
theorem ep_scalar_soundness : Soundness (F p) (Input := Input) (Output := Point)
    (main EpAffineParams) (PastaAssumptions EpAffineParams)
    (fun input out => WalkScalar.EpScalarSpec input.pt input.bits out) := by
  intro offset env vars input hin hassume hholds
  obtain ⟨hspec, hreq⟩ := ep_soundness offset env vars input hin hassume hholds
  exact ⟨WalkScalar.ep_spec _ _ _ hassume.1 hspec.1, hreq⟩

/-- The verified plain Vesta circuit computes multiplication by the Fp lift. -/
theorem eq_scalar_soundness : Soundness (F q) (Input := Input) (Output := Point)
    (main EqAffineParams) (PastaAssumptions EqAffineParams)
    (fun input out => WalkScalar.EqScalarSpec input.pt input.bits out) := by
  intro offset env vars input hin hassume hholds
  obtain ⟨hspec, hreq⟩ := eq_soundness offset env vars input hin hassume hholds
  exact ⟨WalkScalar.eq_spec _ _ _ hassume.1 hspec.1, hreq⟩

end Ragu.Circuits.Endoscalar.GroupScale

namespace Ragu.Circuits.Endoscalar.HoistedGroupScale

open Core.Primes Point.Spec

/-- The verified hoisted Pallas circuit computes multiplication by the Fq lift. -/
theorem ep_scalar_soundness : Soundness (F p) (Input := Input) (Output := Point)
    (main EpAffineParams) (PastaAssumptions EpAffineParams)
    (fun input out => WalkScalar.EpScalarSpec input.pt input.bits out) := by
  intro offset env vars input hin hassume hholds
  obtain ⟨hspec, hreq⟩ := ep_soundness offset env vars input hin hassume hholds
  exact ⟨WalkScalar.ep_spec _ _ _ hassume.1 hspec.1, hreq⟩

/-- The verified hoisted Vesta circuit computes multiplication by the Fp lift. -/
theorem eq_scalar_soundness : Soundness (F q) (Input := Input) (Output := Point)
    (main EqAffineParams) (PastaAssumptions EqAffineParams)
    (fun input out => WalkScalar.EqScalarSpec input.pt input.bits out) := by
  intro offset env vars input hin hassume hholds
  obtain ⟨hspec, hreq⟩ := eq_soundness offset env vars input hin hassume hholds
  exact ⟨WalkScalar.eq_spec _ _ _ hassume.1 hspec.1, hreq⟩

end Ragu.Circuits.Endoscalar.HoistedGroupScale
