import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Gadgets.Boolean
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Endoscalar.Initial
import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Endoscalar.WalkPasta
import Ragu.Circuits.Point.Denormalize
import Ragu.Circuits.Point.Normalize
import Ragu.Circuits.Point.Spec
import Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked

/-!
# `Endoscalar::group_scale`

Scales a curve point by a `numBits`-bit endoscalar in radix 3. Mirrors
`crates/ragu_primitives/src/endoscalar.rs::Endoscalar::group_scale` and the
`walk` it shares with the hoisted gadget:

* `Point.Normalize`: `c = x / y`, `c²`, `r = c² x` move the point to
  `(r, r)` on the isomorphic curve `y² = x³ + c⁶ b` (3 gates);
* `Initial`: `A₀ = [2] (-1)^{s₀} φ^{e₀} (r, r)` from the two initial bits
  (4 gates);
* `numDigits` iterations of `Step`: the three-gate eight-way selection of the
  digit's point among `±(r, r), ±φ(r, r), ±φ²(r, r), ±((r, r) - φ(r, r))`,
  all affine in `r` on the normalized curve, then the seven-gate
  `[3] A + D` chain (10 gates);
* `Point.Denormalize`: back to the original curve (3 gates).

Non-degeneracy: the deployed gadget creates its `NonzeroBank` with
`NonzeroBank::new_unchecked()`, so no fold or discharge constraints are
emitted: every incomplete addition's distinct-x condition rests on the
magnitude argument in `Endoscalar::group_scale`, not on the constraint
system. This reimpl models exactly that via the unchecked triple-and-add,
and carries `groupScaleNative ≠ none` in the generic `Assumptions`.
`WalkGroup` proves the magnitude argument in the complete curve group and
connects it to every affine step. The concrete Pasta soundness and
completeness endpoints below discharge this premise.
-/

namespace Ragu.Circuits.Endoscalar.GroupScale
open Walk
variable {p : ℕ} [Fact p.Prime] [NeZero (2 : F p)]

structure Input (F : Type) where
  bits : Vector F numBits
  pt : Point.Spec.Point F
deriving ProvableStruct

/-! ## The three-gate selector in closed form -/

/-- `(4/9)(ζ - 1)`. -/
def c49 (ζ : F p) : F p := (ζ - 1) * ((3 : F p)⁻¹ ^ 2 * 4)
/-- `(ζ - 1)/3`. -/
def kj (ζ : F p) : F p := (ζ - 1) * (3 : F p)⁻¹
/-- `4ζ/3`. -/
def ku (ζ : F p) : F p := ζ * ((3 : F p)⁻¹ * 4)
/-- `-2ζ/3`. -/
def ky (ζ : F p) : F p := -(ζ * ((3 : F p)⁻¹ * 2))

/-- `h = (r + (4/9)(ζ-1) u) ((ζ-1) u + (ζ²-1) v)`. -/
def selH (ζ r u v : F p) : F p := (r + c49 ζ * u) * ((ζ - 1) * u + (ζ ^ 2 - 1) * v)
/-- `j = (u + v - 1) h`. -/
def selJ (ζ r u v : F p) : F p := (u + v - 1) * selH ζ r u v
/-- `x_D = r + h + ((ζ-1)/3) j + (4ζ/3) u`. -/
def selX (ζ r u v : F p) : F p := r + selH ζ r u v + kj ζ * selJ ζ r u v + ku ζ * u
/-- `y_D = (1 - 2s)(r - (2ζ/3) j)`. -/
def selY (ζ r s u v : F p) : F p := (1 + -2 * s) * (r + ky ζ * selJ ζ r u v)

omit [NeZero (2 : F p)] in
/-- On boolean bits, the selector computes the unsigned digit point: its
`y` before the sign is `r - (2ζ/3) j`. The `(1, 0)` and `(1, 1)` cases use
`ζ² + ζ + 1 = 0` and `3 · 3⁻¹ = 1`. -/
lemma digitPointUnsigned_eq_sel (curveParams : Point.Spec.CurveParams p) (r u v : F p)
    (hr : r ≠ 0) (hζ : curveParams.ζ ≠ 1) (h3 : (3 : F p) ≠ 0)
    (hu : IsBool u) (hv : IsBool v) :
    digitPointUnsigned curveParams r u v =
      some ⟨selX curveParams.ζ r u v, r + ky curveParams.ζ * selJ curveParams.ζ r u v⟩ := by
  have hq := zeta_quadratic curveParams hζ
  have h3t : (3 : F p) * (3 : F p)⁻¹ = 1 := mul_inv_cancel₀ h3
  rcases hu with hu | hu <;> rcases hv with hv | hv <;> subst hu hv
  · -- (0, 0): the base.
    simp only [digitPointUnsigned, zero_ne_one, if_false, Option.some.injEq,
      Point.Spec.Point.mk.injEq, selX, selH, selJ]
    exact ⟨by ring, by ring⟩
  · -- (0, 1): φ²P̂.
    simp only [digitPointUnsigned, zero_ne_one, if_true, if_false, Option.some.injEq,
      Point.Spec.Point.endo, Point.Spec.Point.mk.injEq, selX, selH, selJ]
    exact ⟨by ring, by ring⟩
  · -- (1, 0): φP̂.
    simp only [digitPointUnsigned, zero_ne_one, if_true, if_false, Option.some.injEq,
      Point.Spec.Point.endo, Point.Spec.Point.mk.injEq, selX, selH, selJ, c49, kj, ku, ky]
    refine ⟨?_, by ring⟩
    linear_combination (-4 * (3 : F p)⁻¹ ^ 2) * hq + (4 * (3 : F p)⁻¹ * curveParams.ζ) * h3t
  · -- (1, 1): P̂ - φP̂.
    simp only [digitPointUnsigned, if_true]
    rw [base_sub_endo curveParams r hr hζ h3]
    simp only [Option.some.injEq, Point.Spec.Point.mk.injEq, selX, selH, selJ, c49, kj, ku, ky]
    refine ⟨?_, ?_⟩
    · linear_combination
        (r - 4 * (3 : F p)⁻¹ + 4 * (3 : F p)⁻¹ ^ 2 -
          (r + 4 * (3 : F p)⁻¹ ^ 2 * (curveParams.ζ - 1)) *
            (1 + (curveParams.ζ - 1) * (3 : F p)⁻¹)) * hq +
        (4 * (3 : F p)⁻¹ ^ 2 * (curveParams.ζ - 1) ^ 2 - 4 * (3 : F p)⁻¹ +
          r * (curveParams.ζ - 1)) * h3t
    · linear_combination
        (2 * (3 : F p)⁻¹ * curveParams.ζ * (r + 4 * (3 : F p)⁻¹ ^ 2 * (curveParams.ζ - 1)) -
          8 * (3 : F p)⁻¹ ^ 2) * hq +
        (-2 * curveParams.ζ * r -
          8 * (3 : F p)⁻¹ ^ 2 * curveParams.ζ * (curveParams.ζ - 1)) * h3t

omit [NeZero (2 : F p)] in
/-- On boolean bits, the selector computes the digit point. -/
lemma digitPoint_eq_sel (curveParams : Point.Spec.CurveParams p) (r s u v : F p)
    (hr : r ≠ 0) (hζ : curveParams.ζ ≠ 1) (h3 : (3 : F p) ≠ 0)
    (hs : IsBool s) (hu : IsBool u) (hv : IsBool v) :
    digitPoint curveParams r s u v =
      some ⟨selX curveParams.ζ r u v, selY curveParams.ζ r s u v⟩ := by
  simp only [digitPoint, digitPointUnsigned_eq_sel curveParams r u v hr hζ h3 hu hv,
    Option.map_some, negate_if_eq s hs]
  rfl

/-! ## One loop iteration, bundled as its own subcircuit. -/
namespace Step

/-- One iteration's inputs: the digit `(s, e₁, e₂)`, the normalized base's
coordinate `r`, and the running accumulator. -/
structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
  r : F
  acc : Point.Spec.Point F
deriving ProvableStruct

/-- The three selector muls, then the unchecked triple-and-add. -/
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Var Point.Spec.Point (F p)) := do
  let ⟨s, u, v, r, acc⟩ := input
  let ζ := curveParams.ζ
  let h ← Element.Mul.circuit
    ⟨r + Expression.const (c49 ζ) * u,
     Expression.const (ζ - 1) * u + Expression.const (ζ ^ 2 - 1) * v⟩
  let j ← Element.Mul.circuit ⟨u + v - 1, h⟩
  let xd := r + h + Expression.const (kj ζ) * j + Expression.const (ku ζ) * u
  let yd ← Element.Mul.circuit
    ⟨1 + Expression.const (-2) * s, r + Expression.const (ky ζ) * j⟩
  Point.TripleAndAddIncompleteUnchecked.circuit ⟨acc, ⟨xd, yd⟩⟩

/-- Caller obligations: boolean bits, a nonzero base coordinate, a nontrivial
cube root of unity, and the step's non-degeneracy. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2 ∧
  input.r ≠ 0 ∧ curveParams.ζ ≠ 1 ∧ (3 : F p) ≠ 0 ∧
  stepNative curveParams input.r input.acc input.s input.e1 input.e2 ≠ none

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p))
    (output : Point.Spec.Point (F p)) :=
  stepNative curveParams input.r input.acc input.s input.e1 input.e2 = some output

/-- The digit point's expressions on the layout: `x_D` over the `h` and `j`
product wires, `y_D` the third Mul's product wire. -/
@[circuit_norm]
def digitVar (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p)) (offset : ℕ)
    : Var Point.Spec.Point (F p) :=
  ⟨input.r + varFromOffset field (offset + 2) +
      Expression.const (kj curveParams.ζ) * varFromOffset field (offset + 3 + 2) +
      Expression.const (ku curveParams.ζ) * input.e1,
   varFromOffset field (offset + 3 + 3 + 2)⟩

/-- The step's output: the triple-and-add's on the digit point. -/
@[circuit_norm]
def output (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p)) (offset : ℕ)
    : Var Point.Spec.Point (F p) :=
  Point.TripleAndAddIncompleteUnchecked.output ⟨input.acc, digitVar curveParams input offset⟩
    (offset + 9)

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input Point.Spec.Point (main curveParams) where
  -- three Muls (9) + triple-and-add (21)
  localLength _ := 30
  output input offset := output curveParams input offset
  localLength_eq := by
    simp +arith [main, circuit_norm, Element.Mul.circuit,
      Point.TripleAndAddIncompleteUnchecked.circuit]
  output_eq := by
    intro input offset
    simp +arith [main, output, digitVar, circuit_norm, Element.Mul.circuit,
      Point.TripleAndAddIncompleteUnchecked.circuit,
      Point.TripleAndAddIncompleteUnchecked.output]
  subcircuitsConsistent := by
    simp +arith [main, circuit_norm, Element.Mul.circuit,
      Point.TripleAndAddIncompleteUnchecked.circuit]

omit [NeZero (2 : F p)] in
/-- Under the boolean-selector and non-degeneracy obligations, the selected
digit and unchecked triple-and-add compute one native walk step. -/
theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Point.TripleAndAddIncompleteUnchecked.circuit,
    Point.TripleAndAddIncompleteUnchecked.Assumptions,
    Point.TripleAndAddIncompleteUnchecked.Spec, output, digitVar]
  obtain ⟨hs, hu, hv, hr, hζ, h3, h_step⟩ := h_assumptions
  obtain ⟨h_h, h_j, h_yd, h_tri⟩ := h_holds
  -- The wires are the selector's closed forms.
  have hx : input_r + env.get i₀.succ.succ +
      kj curveParams.ζ * env.get (i₀ + 3 + 2) + ku curveParams.ζ * input_e1 =
      selX curveParams.ζ input_r input_e1 input_e2 := by
    simp only [selX, selH, selJ]
    rw [h_j, h_h]
  have hy : env.get (i₀ + 3 + 3 + 2) = selY curveParams.ζ input_r input_s input_e1 input_e2 := by
    simp only [selY, selH, selJ]
    rw [h_yd, h_j, h_h]
    ring
  have hd := digitPoint_eq_sel curveParams input_r input_s input_e1 input_e2 hr hζ h3 hs hu hv
  simp only [stepNative, hd] at h_step ⊢
  rw [← hx, ← hy] at h_step ⊢
  exact h_tri h_step

omit [NeZero (2 : F p)] in
/-- When the native step succeeds and the selector preconditions hold, honest
witnesses satisfy the selector and unchecked addition constraints. -/
theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Point.TripleAndAddIncompleteUnchecked.circuit,
    Point.TripleAndAddIncompleteUnchecked.Assumptions,
    Point.TripleAndAddIncompleteUnchecked.Spec, output, digitVar]
  obtain ⟨hs, hu, hv, hr, hζ, h3, h_step⟩ := h_assumptions
  obtain ⟨h_h, h_j, h_yd, _⟩ := h_env
  have hx : input_r + env.get i₀.succ.succ +
      kj curveParams.ζ * env.get (i₀ + 3 + 2) + ku curveParams.ζ * input_e1 =
      selX curveParams.ζ input_r input_e1 input_e2 := by
    simp only [selX, selH, selJ]
    rw [h_j, h_h]
  have hy : env.get (i₀ + 3 + 3 + 2) = selY curveParams.ζ input_r input_s input_e1 input_e2 := by
    simp only [selY, selH, selJ]
    rw [h_yd, h_j, h_h]
    ring
  have hd := digitPoint_eq_sel curveParams input_r input_s input_e1 input_e2 hr hζ h3 hs hu hv
  simp only [stepNative, hd] at h_step
  rw [← hx, ← hy] at h_step
  exact h_step

def circuit (curveParams : Point.Spec.CurveParams p) :
    FormalCircuit (F p) Input Point.Spec.Point :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Step

/-- `Circuit.foldlRange` needs an inhabited accumulator type; file-local so
it leaks into no importer. -/
local instance : Inhabited (Var Point.Spec.Point (F p)) := ⟨⟨0, 0⟩⟩

/-- `@[irreducible]` is a defeq seal only: it stops the unifier/kernel from
whnf-unrolling the `numDigits`-iteration fold during structure-update type
checks, which exceeds the default heartbeat budget. Proofs still unfold
`main` via its equation lemma. -/
@[irreducible]
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Var Point.Spec.Point (F p)) := do
  let norm ← Point.Normalize.circuit input.pt
  let acc_0 ← Initial.circuit curveParams ⟨norm.r, input.bits[0], input.bits[1]⟩
  let acc ← Circuit.foldlRange numDigits acc_0
    (fun acc i =>
      Step.circuit curveParams
        ⟨input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
         input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
         input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
         norm.r, acc⟩)
    (by
      apply Circuit.ConstantLength.fromConstantLength'
      intros
      simp only [circuit_norm, Step.circuit, Step.elaborated])
  Point.Denormalize.circuit ⟨acc, norm.c, norm.c2⟩

/-- Generic caller obligations. The unchecked additions emit no distinct-x
constraints. `WalkGroup.groupScaleNative_ne_none` derives their non-degeneracy
from the integer norm bound and the complete group's prime order;
`WalkPasta` discharges it for both Pasta curves. The concrete `ep_soundness`
and `eq_soundness` endpoints below therefore require only `PastaAssumptions`. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  input.pt.isOnCurve curveParams ∧
  curveParams.nonzeroCoordinates ∧
  curveParams.ζ ≠ 1 ∧
  (3 : F p) ≠ 0 ∧
  (∀ i : Fin numBits, IsBool input.bits[i]) ∧
  groupScaleNative curveParams input.pt input.bits ≠ none

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p))
    (output : Point.Spec.Point (F p)) :=
  groupScaleNative curveParams input.pt input.bits = some output ∧
  output.isOnCurve curveParams

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input Point.Spec.Point (main curveParams) where
  -- 9 (Normalize) + 12 (Initial) + numDigits × 30 (Step) + 9 (Denormalize)
  localLength _ := 9 + 12 + numDigits * 30 + 9
  localLength_eq := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]
  subcircuitsConsistent := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]
  channelsLawful := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]

omit [NeZero (2 : F p)] in
/-- The facts about the normalization shared by both proof directions. -/
lemma normalization_facts (curveParams : Point.Spec.CurveParams p)
    (x y c c2 r : F p)
    (h_curve : (⟨x, y⟩ : Point.Spec.Point (F p)).isOnCurve curveParams)
    (h_nz : curveParams.nonzeroCoordinates)
    (h_c : c = x / y) (h_c2 : c2 = c ^ 2) (h_r : r = c2 * x) :
    y ≠ 0 ∧ c ≠ 0 ∧ r ≠ 0 ∧ c = (normalizeNative ⟨x, y⟩).c ∧ r = (normalizeNative ⟨x, y⟩).r := by
  have hy : y ≠ 0 := h_nz.2 _ h_curve
  have hx : x ≠ 0 := h_nz.1 _ h_curve
  have hc : c ≠ 0 := by rw [h_c]; exact div_ne_zero hx hy
  have hr : r ≠ 0 := by rw [h_r, h_c2]; exact mul_ne_zero (pow_ne_zero 2 hc) hx
  refine ⟨hy, hc, hr, ?_, ?_⟩
  · simp only [normalizeNative]; exact h_c
  · simp only [normalizeNative]; rw [h_r, h_c2, h_c]

/-- For an on-curve base, boolean bits, and the curve and no-collision
preconditions, the constraints compute the native walk on the original curve.
The concrete Pasta endpoints below discharge the no-collision obligation. -/
theorem soundness (curveParams : Point.Spec.CurveParams p)
    : Soundness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
        (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [main, Step.circuit,
    Point.Normalize.circuit, Point.Normalize.Assumptions, Point.Normalize.Spec,
    Initial.circuit, Initial.Assumptions, Initial.Spec, Initial.output,
    Point.Denormalize.circuit, Point.Denormalize.Assumptions, Point.Denormalize.Spec]
  obtain ⟨h_pt_curve, h_nz, hζ, h3, h_bits, h_native_ne⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (hj : j < numBits), IsBool (input_bits[j]'hj) :=
    fun j hj => h_bits ⟨j, hj⟩
  obtain ⟨h_norm, h_init, h_steps, h_denorm⟩ := h_holds
  obtain ⟨h_bits_eval, h_px, h_py⟩ := h_input
  have h_bit : ∀ (j : ℕ) (hj : j < numBits),
      Expression.eval env (input_var_bits[j]'hj) = input_bits[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_bits_eval
    simpa [Vector.getElem_map] using this
  have hy : input_pt_y ≠ 0 := h_nz.2 _ h_pt_curve
  obtain ⟨h_c, h_c2, h_r⟩ := h_norm hy
  obtain ⟨_, hc, hr, h_c_nat, h_r_nat⟩ :=
    normalization_facts curveParams input_pt_x input_pt_y _ _ _ h_pt_curve h_nz h_c h_c2 h_r
  set c := env.get i₀ with hc_def
  set r := env.get (i₀ + 3 + 3 + 2) with hr_def
  -- The initial point.
  have h_acc0 := h_init ⟨by rw [h_bit 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bit 1 (by decide)]; exact h_bool 1 (by decide), hr⟩
  rw [h_bit 0 (by decide), h_bit 1 (by decide)] at h_acc0
  -- The walk.
  have h_ne := accAfter_ne_of_groupScale curveParams ⟨input_pt_x, input_pt_y⟩ input_bits
    h_native_ne
  rw [← h_r_nat] at h_ne
  have h_walk := fold_final curveParams env input_bits r
    (fun acc i => Step.circuit curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       varFromOffset field (i₀ + 3 + 3 + 2), acc⟩)
    (Initial.output (i₀ + 9)) (i₀ + 9 + 12) 30
    (fun i acc off => evalPt env (Step.output curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       varFromOffset field (i₀ + 3 + 3 + 2), ⟨Expression.const acc.x, Expression.const acc.y⟩⟩ off))
    h_ne
    (by
      intro i h_step_ne
      have h := h_steps i
      simp only [Step.Assumptions, Step.Spec, h_bit] at h
      have := h ⟨h_bool _ _, h_bool _ _, h_bool _ _, hr, hζ, h3, h_step_ne⟩
      simpa only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval, h_bit,
        ← hr_def] using this)
    (fun _ _ => rfl)
    (fun acc i => by
      simp only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval])
    (by simpa only [accAfter, evalPt, Initial.output, Expression.eval] using h_acc0)
  -- Back to the original curve.
  obtain ⟨h_ox, h_oy⟩ := h_denorm ⟨hc, h_c2⟩
  refine ⟨?_, ?_⟩
  · simp only [groupScaleNative, ← h_c_nat, ← h_r_nat]
    rw [h_walk]
    simp only [Option.map_some, Option.some.injEq, Point.Spec.Point.mk.injEq]
    exact ⟨h_ox.symm, h_oy.symm⟩
  · have h_base := normalized_isOnCurve curveParams ⟨input_pt_x, input_pt_y⟩ h_pt_curve hy
    rw [← h_c_nat, ← h_r_nat] at h_base
    have h_no2 := twist_noOrderTwoPoints curveParams c hc h_nz.2
    rw [← accAfter_twist curveParams c r input_bits numDigits] at h_walk
    have h_final := accAfter_isOnCurve (twist curveParams c) r input_bits h_base h_no2
      numDigits _ h_walk
    rw [h_ox, h_oy]
    exact denormalize_isOnCurve curveParams c hc _ h_final

/-- The caller's curve, booleanity, and no-collision assumptions make each
normalized step defined, yielding honest witnesses for the full circuit. -/
theorem completeness (curveParams : Point.Spec.CurveParams p)
    : Completeness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
        (Assumptions curveParams) := by
  circuit_proof_start [main, Step.circuit,
    Point.Normalize.circuit, Point.Normalize.Assumptions, Point.Normalize.Spec,
    Initial.circuit, Initial.Assumptions, Initial.Spec, Initial.output,
    Point.Denormalize.circuit, Point.Denormalize.Assumptions, Point.Denormalize.Spec]
  obtain ⟨h_pt_curve, h_nz, hζ, h3, h_bits, h_native_ne⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (hj : j < numBits), IsBool (input_bits[j]'hj) :=
    fun j hj => h_bits ⟨j, hj⟩
  obtain ⟨h_norm_env, h_init_env, h_steps_env, _⟩ := h_env
  obtain ⟨h_bits_eval, h_px, h_py⟩ := h_input
  have h_bit : ∀ (j : ℕ) (hj : j < numBits),
      Expression.eval env.toEnvironment (input_var_bits[j]'hj) = input_bits[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_bits_eval
    simpa [Vector.getElem_map] using this
  have hy : input_pt_y ≠ 0 := h_nz.2 _ h_pt_curve
  obtain ⟨h_c, h_c2, h_r⟩ := h_norm_env hy
  obtain ⟨_, hc, hr, h_c_nat, h_r_nat⟩ :=
    normalization_facts curveParams input_pt_x input_pt_y _ _ _ h_pt_curve h_nz h_c h_c2 h_r
  set c := env.get i₀ with hc_def
  set r := env.get (i₀ + 3 + 3 + 2) with hr_def
  have h_acc0 := h_init_env ⟨by rw [h_bit 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bit 1 (by decide)]; exact h_bool 1 (by decide), hr⟩
  rw [h_bit 0 (by decide), h_bit 1 (by decide)] at h_acc0
  have h_ne := accAfter_ne_of_groupScale curveParams ⟨input_pt_x, input_pt_y⟩ input_bits
    h_native_ne
  rw [← h_r_nat] at h_ne
  have h_inv := fold_inv curveParams env.toEnvironment input_bits r
    (fun acc i => Step.circuit curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       varFromOffset field (i₀ + 3 + 3 + 2), acc⟩)
    (Initial.output (i₀ + 9)) (i₀ + 9 + 12) 30
    (fun i acc off => evalPt env.toEnvironment (Step.output curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       varFromOffset field (i₀ + 3 + 3 + 2), ⟨Expression.const acc.x, Expression.const acc.y⟩⟩ off))
    h_ne
    (by
      intro i h_step_ne
      have h := h_steps_env i
      simp only [Step.Assumptions, Step.Spec, h_bit] at h
      have := h ⟨h_bool _ _, h_bool _ _, h_bool _ _, hr, hζ, h3, h_step_ne⟩
      simpa only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval, h_bit,
        ← hr_def] using this)
    (fun _ _ => rfl)
    (fun acc i => by
      simp only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval])
    (by simpa only [accAfter, evalPt, Initial.output, Expression.eval] using h_acc0)
  refine ⟨hy, ⟨by rw [h_bit 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bit 1 (by decide)]; exact h_bool 1 (by decide), hr⟩, ?_, ⟨hc, h_c2⟩⟩
  intro i
  have h_prev := h_inv i.val i.isLt
  have h_acci := accAfter_succ_of_some curveParams r input_bits i.val _ h_prev
    (walk_index_lt i.val i.isLt)
  have h_nei := all_accAfter_ne curveParams r input_bits h_ne (i.val + 1) i.isLt
  rw [h_acci] at h_nei
  simp only [Step.Assumptions, h_bit]
  exact ⟨h_bool _ _, h_bool _ _, h_bool _ _, hr, hζ, h3, h_nei⟩

def circuit (curveParams : Point.Spec.CurveParams p) : FormalCircuit (F p) Input Point.Spec.Point :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    requirementsChannelsLawful := by
      simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
        Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Ragu.Circuits.Endoscalar.GroupScale

namespace Ragu.Circuits.Endoscalar.GroupScale

open Point.Spec Walk Core.Primes

/-- Valid Pasta inputs: an affine on-curve point and boolean scalar bits.
Walk success and curve certificates are derived by the concrete endpoints. -/
def PastaAssumptions {p : ℕ} [Fact p.Prime] (cp : CurveParams p) (input : Input (F p)) :=
  input.pt.isOnCurve cp ∧ ∀ i : Fin numBits, IsBool input.bits[i]

/-- Derive the generic Pallas walk preconditions from an on-curve input and
Boolean bits, supplying concrete soundness and completeness with the
curve's coordinate and collision bounds. -/
theorem ep_assumptions (input : Input (F p)) (h : PastaAssumptions EpAffineParams input) :
    Assumptions EpAffineParams input :=
  ⟨h.1, epAffineParams_nonzeroCoordinates, by decide, by decide, h.2,
    WalkPasta.ep_groupScaleNative_ne_none input.pt h.1 input.bits⟩

/-- Derive the generic Vesta walk preconditions from an on-curve input and
Boolean bits, supplying concrete soundness and completeness with the
curve's coordinate and collision bounds. -/
theorem eq_assumptions (input : Input (F q)) (h : PastaAssumptions EqAffineParams input) :
    Assumptions EqAffineParams input :=
  ⟨h.1, eqAffineParams_nonzeroCoordinates, by decide, by decide, h.2,
    WalkPasta.eq_groupScaleNative_ne_none input.pt h.1 input.bits⟩

/-- Pallas soundness with the affine-success premise discharged. -/
theorem ep_soundness : Soundness (F p) (Input := Input) (Output := Point)
    (main EpAffineParams) (PastaAssumptions EpAffineParams) (Spec EpAffineParams) := by
  intro offset env vars input hin hassume
  exact soundness EpAffineParams offset env vars input hin (ep_assumptions input hassume)

/-- Vesta soundness with the affine-success premise discharged. -/
theorem eq_soundness : Soundness (F q) (Input := Input) (Output := Point)
    (main EqAffineParams) (PastaAssumptions EqAffineParams) (Spec EqAffineParams) := by
  intro offset env vars input hin hassume
  exact soundness EqAffineParams offset env vars input hin (eq_assumptions input hassume)

/-- Every valid Pallas input admits honest witnesses for the full walk. -/
theorem ep_completeness : Completeness (F p) (Input := Input) (Output := Point)
    (main EpAffineParams) (PastaAssumptions EpAffineParams) := by
  intro offset env vars henv input hin hassume
  exact completeness EpAffineParams offset env vars henv input hin (ep_assumptions input hassume)

/-- Every valid Vesta input admits honest witnesses for the full walk. -/
theorem eq_completeness : Completeness (F q) (Input := Input) (Output := Point)
    (main EqAffineParams) (PastaAssumptions EqAffineParams) := by
  intro offset env vars henv input hin hassume
  exact completeness EqAffineParams offset env vars henv input hin (eq_assumptions input hassume)

end Ragu.Circuits.Endoscalar.GroupScale
