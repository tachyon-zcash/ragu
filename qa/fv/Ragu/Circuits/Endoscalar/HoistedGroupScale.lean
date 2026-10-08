import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Gadgets.Boolean
import Mathlib.Tactic.IntervalCases
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Endoscalar.GroupScale
import Ragu.Circuits.Endoscalar.Initial
import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Point.Denormalize
import Ragu.Circuits.Point.Normalize
import Ragu.Circuits.Point.Spec
import Ragu.Circuits.Point.TripleAndAddIncompleteUnchecked

/-!
# `HoistedEndoscalar::group_scale`

The walk of `Endoscalar::group_scale` with each digit's point selected in
two gates from the hoisted product wires `e₁ e₂` and `e₁ e₂ s`: with those
in hand, both coordinates of the digit point are `r` times a linear form
plus a linear form. Mirrors
`crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::group_scale`.

The product wires are inputs here; that they are the products of the bits
is the `EnforceProducts` contract, carried as an assumption. Everything else
is `GroupScale`'s: the normalization, the initial point, the native walk
and its non-degeneracy, and the move back.
-/

namespace Ragu.Circuits.Endoscalar.HoistedGroupScale
open Walk
variable {p : ℕ} [Fact p.Prime] [NeZero (2 : F p)]

/-- The bits, the hoisted products per digit in digit order, and the point. -/
structure Input (F : Type) where
  bits : Vector F numBits
  products : Vector F numProducts
  pt : Point.Spec.Point F
deriving ProvableStruct

/-! ## The two-gate selector in closed form -/

/-- `x` of `P̂ - φP̂` is `ζ² r + xq0`: `xq0 = -4ζ²/3`. -/
def xq0 (ζ : F p) : F p := -(ζ ^ 2 * ((3 : F p)⁻¹ * 4))
/-- `y` of `P̂ - φP̂` is `c1 r + yq0`: `c1 = 1 + 2ζ`. -/
def c1 (ζ : F p) : F p := 1 + 2 * ζ
/-- `yq0 = -(8/9)(1 + 2ζ)`. -/
def yq0 (ζ : F p) : F p := -(c1 ζ * ((3 : F p)⁻¹ ^ 2 * 8))

/-- `x_D = r (1 + (ζ-1) e₁ + (ζ²-1) e₂ + (1-ζ) p) + xq0 p`. -/
def selX (ζ r e1 e2 pw : F p) : F p :=
  r * (1 + (ζ - 1) * e1 + (ζ ^ 2 - 1) * e2 + (1 - ζ) * pw) + xq0 ζ * pw
/-- `y_D = r ((1 - 2s) + (c1 - 1)(p - 2q)) + yq0 (p - 2q)`. -/
def selY (ζ r s pw qw : F p) : F p :=
  r * (1 + -2 * s + (c1 ζ - 1) * (pw + -2 * qw)) + yq0 ζ * (pw + -2 * qw)

/-- The digit point's `y` before the sign: `r (1 + (c1 - 1) p) + yq0 p`. -/
def selYU (ζ r pw : F p) : F p := r * (1 + (c1 ζ - 1) * pw) + yq0 ζ * pw

omit [NeZero (2 : F p)] in
/-- On boolean bits with their product, the hoisted selector computes the
unsigned digit point. -/
lemma digitPointUnsigned_eq_sel (curveParams : Point.Spec.CurveParams p) (r u v : F p)
    (hr : r ≠ 0) (hζ : curveParams.ζ ≠ 1) (h3 : (3 : F p) ≠ 0)
    (hu : IsBool u) (hv : IsBool v) :
    digitPointUnsigned curveParams r u v =
      some ⟨selX curveParams.ζ r u v (u * v), selYU curveParams.ζ r (u * v)⟩ := by
  rcases hu with hu | hu <;> rcases hv with hv | hv <;> subst hu hv
  · simp only [digitPointUnsigned, zero_ne_one, if_false, Option.some.injEq,
      Point.Spec.Point.mk.injEq, selX, selYU]
    exact ⟨by ring, by ring⟩
  · simp only [digitPointUnsigned, zero_ne_one, if_true, if_false, Option.some.injEq,
      Point.Spec.Point.endo, Point.Spec.Point.mk.injEq, selX, selYU]
    exact ⟨by ring, by ring⟩
  · simp only [digitPointUnsigned, zero_ne_one, if_true, if_false, Option.some.injEq,
      Point.Spec.Point.endo, Point.Spec.Point.mk.injEq, selX, selYU]
    exact ⟨by ring, by ring⟩
  · simp only [digitPointUnsigned, if_true]
    rw [base_sub_endo curveParams r hr hζ h3]
    simp only [Option.some.injEq, Point.Spec.Point.mk.injEq, selX, selYU, xq0, c1, yq0]
    exact ⟨by ring, by ring⟩

omit [NeZero (2 : F p)] in
/-- On boolean bits with their products, the hoisted selector computes the
digit point. -/
lemma digitPoint_eq_sel (curveParams : Point.Spec.CurveParams p) (r s u v : F p)
    (hr : r ≠ 0) (hζ : curveParams.ζ ≠ 1) (h3 : (3 : F p) ≠ 0)
    (hs : IsBool s) (hu : IsBool u) (hv : IsBool v) :
    digitPoint curveParams r s u v =
      some ⟨selX curveParams.ζ r u v (u * v), selY curveParams.ζ r s (u * v) (u * v * s)⟩ := by
  simp only [digitPoint, digitPointUnsigned_eq_sel curveParams r u v hr hζ h3 hu hv,
    Option.map_some, negate_if_eq s hs]
  rw [Option.some_inj, Point.Spec.Point.mk.injEq]
  refine ⟨rfl, ?_⟩
  simp only [selY, selYU]
  ring

/-! ## One loop iteration, bundled as its own subcircuit. -/
namespace Step

/-- One iteration's inputs: the digit `(s, e₁, e₂)` with its hoisted products
`pw = e₁ e₂` and `qw = e₁ e₂ s`, the normalized base's coordinate `r`, and
the running accumulator. -/
structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
  pw : F
  qw : F
  r : F
  acc : Point.Spec.Point F
deriving ProvableStruct

/-- The two selector muls, then the unchecked triple-and-add. -/
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Var Point.Spec.Point (F p)) := do
  let ⟨s, e1, e2, pw, qw, r, acc⟩ := input
  let ζ := curveParams.ζ
  let lx := 1 + Expression.const (ζ - 1) * e1 + Expression.const (ζ ^ 2 - 1) * e2 +
    Expression.const (1 - ζ) * pw
  let xm ← Element.Mul.circuit ⟨r, lx⟩
  let xd := xm + Expression.const (xq0 ζ) * pw
  let pm2q := pw + Expression.const (-2) * qw
  let ly := 1 + Expression.const (-2) * s + Expression.const (c1 ζ - 1) * pm2q
  let ym ← Element.Mul.circuit ⟨r, ly⟩
  let yd := ym + Expression.const (yq0 ζ) * pm2q
  Point.TripleAndAddIncompleteUnchecked.circuit ⟨acc, ⟨xd, yd⟩⟩

/-- Caller obligations: boolean bits whose product wires are their products,
a nonzero base coordinate, a nontrivial cube root of unity, and the step's
non-degeneracy. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2 ∧
  input.pw = input.e1 * input.e2 ∧ input.qw = input.pw * input.s ∧
  input.r ≠ 0 ∧ curveParams.ζ ≠ 1 ∧ (3 : F p) ≠ 0 ∧
  stepNative curveParams input.r input.acc input.s input.e1 input.e2 ≠ none

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p))
    (output : Point.Spec.Point (F p)) :=
  stepNative curveParams input.r input.acc input.s input.e1 input.e2 = some output

/-- The digit point's expressions on the layout: the two Muls' product wires
with the products' linear terms. -/
@[circuit_norm]
def digitVar (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p)) (offset : ℕ)
    : Var Point.Spec.Point (F p) :=
  ⟨varFromOffset field (offset + 2) + Expression.const (xq0 curveParams.ζ) * input.pw,
   varFromOffset field (offset + 3 + 2) +
     Expression.const (yq0 curveParams.ζ) * (input.pw + Expression.const (-2) * input.qw)⟩

/-- The step's output: the triple-and-add's on the digit point. -/
@[circuit_norm]
def output (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p)) (offset : ℕ)
    : Var Point.Spec.Point (F p) :=
  Point.TripleAndAddIncompleteUnchecked.output ⟨input.acc, digitVar curveParams input offset⟩
    (offset + 6)

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input Point.Spec.Point (main curveParams) where
  -- two Muls (6) + triple-and-add (21)
  localLength _ := 27
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
theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Point.TripleAndAddIncompleteUnchecked.circuit,
    Point.TripleAndAddIncompleteUnchecked.Assumptions,
    Point.TripleAndAddIncompleteUnchecked.Spec, output, digitVar]
  obtain ⟨hs, hu, hv, hpw, hqw, hr, hζ, h3, h_step⟩ := h_assumptions
  obtain ⟨h_xm, h_ym, h_tri⟩ := h_holds
  have hx : env.get i₀.succ.succ + xq0 curveParams.ζ * input_pw =
      selX curveParams.ζ input_r input_e1 input_e2 (input_e1 * input_e2) := by
    simp only [selX]
    rw [h_xm, hpw]
  have hy : env.get (i₀ + 3 + 2) + yq0 curveParams.ζ * (input_pw - 2 * input_qw) =
      selY curveParams.ζ input_r input_s (input_e1 * input_e2) (input_e1 * input_e2 * input_s) := by
    simp only [selY]
    rw [h_ym, hqw, hpw]
    ring
  have hd := digitPoint_eq_sel curveParams input_r input_s input_e1 input_e2 hr hζ h3 hs hu hv
  simp only [stepNative, hd] at h_step ⊢
  rw [← hx, ← hy] at h_step ⊢
  exact h_tri h_step

omit [NeZero (2 : F p)] in
theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec,
    Point.TripleAndAddIncompleteUnchecked.circuit,
    Point.TripleAndAddIncompleteUnchecked.Assumptions,
    Point.TripleAndAddIncompleteUnchecked.Spec, output, digitVar]
  obtain ⟨hs, hu, hv, hpw, hqw, hr, hζ, h3, h_step⟩ := h_assumptions
  obtain ⟨h_xm, h_ym, _⟩ := h_env
  have hx : env.get i₀.succ.succ + xq0 curveParams.ζ * input_pw =
      selX curveParams.ζ input_r input_e1 input_e2 (input_e1 * input_e2) := by
    simp only [selX]
    rw [h_xm, hpw]
  have hy : env.get (i₀ + 3 + 2) + yq0 curveParams.ζ * (input_pw - 2 * input_qw) =
      selY curveParams.ζ input_r input_s (input_e1 * input_e2) (input_e1 * input_e2 * input_s) := by
    simp only [selY]
    rw [h_ym, hqw, hpw]
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

local instance : Inhabited (Var Point.Spec.Point (F p)) := ⟨⟨0, 0⟩⟩

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
         input.products[2 * i.val]'(product_index_lt i),
         input.products[2 * i.val + 1]'(product_index_succ_lt i),
         norm.r, acc⟩)
    (by
      apply Circuit.ConstantLength.fromConstantLength'
      intros
      simp only [circuit_norm, Step.circuit, Step.elaborated])
  Point.Denormalize.circuit ⟨acc, norm.c, norm.c2⟩

/-- `GroupScale`'s obligations, plus the `EnforceProducts` contract on the
product wires. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  input.pt.isOnCurve curveParams ∧
  curveParams.nonzeroCoordinates ∧
  curveParams.ζ ≠ 1 ∧
  (3 : F p) ≠ 0 ∧
  (∀ i : Fin numBits, IsBool input.bits[i]) ∧
  (∀ i : Fin numDigits,
    input.products[2 * i.val]'(product_index_lt i) =
      input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)) *
        input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)) ∧
    input.products[2 * i.val + 1]'(product_index_succ_lt i) =
      input.products[2 * i.val]'(product_index_lt i) *
        input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num))) ∧
  groupScaleNative curveParams input.pt input.bits ≠ none

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p))
    (output : Point.Spec.Point (F p)) :=
  groupScaleNative curveParams input.pt input.bits = some output ∧
  output.isOnCurve curveParams

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input Point.Spec.Point (main curveParams) where
  -- 9 (Normalize) + 12 (Initial) + numDigits × 27 (Step) + 9 (Denormalize)
  localLength _ := 9 + 12 + numDigits * 27 + 9
  localLength_eq := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]
  subcircuitsConsistent := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]
  channelsLawful := by
    simp +arith [main, circuit_norm, Point.Normalize.circuit, Initial.circuit,
      Initial.elaborated, Step.circuit, Step.elaborated, Point.Denormalize.circuit]

theorem soundness (curveParams : Point.Spec.CurveParams p)
    : Soundness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
        (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [main, Step.circuit,
    Point.Normalize.circuit, Point.Normalize.Assumptions, Point.Normalize.Spec,
    Initial.circuit, Initial.Assumptions, Initial.Spec, Initial.output,
    Point.Denormalize.circuit, Point.Denormalize.Assumptions, Point.Denormalize.Spec]
  obtain ⟨h_pt_curve, h_nz, hζ, h3, h_bits, h_prods, h_native_ne⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (hj : j < numBits), IsBool (input_bits[j]'hj) :=
    fun j hj => h_bits ⟨j, hj⟩
  obtain ⟨h_norm, h_init, h_steps, h_denorm⟩ := h_holds
  obtain ⟨h_bits_eval, h_products_eval, h_px, h_py⟩ := h_input
  have h_bit : ∀ (j : ℕ) (hj : j < numBits),
      Expression.eval env (input_var_bits[j]'hj) = input_bits[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_bits_eval
    simpa [Vector.getElem_map] using this
  have h_prod : ∀ (j : ℕ) (hj : j < numProducts),
      Expression.eval env (input_var_products[j]'hj) = input_products[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_products_eval
    simpa [Vector.getElem_map] using this
  have hy : input_pt_y ≠ 0 := h_nz.2 _ h_pt_curve
  obtain ⟨h_c, h_c2, h_r⟩ := h_norm hy
  obtain ⟨_, hc, hr, h_c_nat, h_r_nat⟩ :=
    GroupScale.normalization_facts curveParams input_pt_x input_pt_y _ _ _ h_pt_curve h_nz
      h_c h_c2 h_r
  set c := env.get i₀ with hc_def
  set r := env.get (i₀ + 3 + 3 + 2) with hr_def
  have h_acc0 := h_init ⟨by rw [h_bit 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bit 1 (by decide)]; exact h_bool 1 (by decide), hr⟩
  rw [h_bit 0 (by decide), h_bit 1 (by decide)] at h_acc0
  have h_ne := accAfter_ne_of_groupScale curveParams ⟨input_pt_x, input_pt_y⟩ input_bits
    h_native_ne
  rw [← h_r_nat] at h_ne
  have h_walk := fold_final curveParams env input_bits r
    (fun acc i => Step.circuit curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_products[2 * i.val]'(product_index_lt i),
       input_var_products[2 * i.val + 1]'(product_index_succ_lt i),
       varFromOffset field (i₀ + 3 + 3 + 2), acc⟩)
    (Initial.output (i₀ + 9)) (i₀ + 9 + 12) 27
    (fun i acc off => evalPt env (Step.output curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_products[2 * i.val]'(product_index_lt i),
       input_var_products[2 * i.val + 1]'(product_index_succ_lt i),
       varFromOffset field (i₀ + 3 + 3 + 2), ⟨Expression.const acc.x, Expression.const acc.y⟩⟩ off))
    h_ne
    (by
      intro i h_step_ne
      have h := h_steps i
      simp only [Step.Assumptions, Step.Spec, h_bit, h_prod] at h
      have := h ⟨h_bool _ _, h_bool _ _, h_bool _ _, (h_prods i).1, (h_prods i).2,
        hr, hζ, h3, h_step_ne⟩
      simpa only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval, h_bit, h_prod,
        ← hr_def] using this)
    (fun _ _ => rfl)
    (fun acc i => by
      simp only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval])
    (by simpa only [accAfter, evalPt, Initial.output, Expression.eval] using h_acc0)
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

theorem completeness (curveParams : Point.Spec.CurveParams p)
    : Completeness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
        (Assumptions curveParams) := by
  circuit_proof_start [main, Step.circuit,
    Point.Normalize.circuit, Point.Normalize.Assumptions, Point.Normalize.Spec,
    Initial.circuit, Initial.Assumptions, Initial.Spec, Initial.output,
    Point.Denormalize.circuit, Point.Denormalize.Assumptions, Point.Denormalize.Spec]
  obtain ⟨h_pt_curve, h_nz, hζ, h3, h_bits, h_prods, h_native_ne⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (hj : j < numBits), IsBool (input_bits[j]'hj) :=
    fun j hj => h_bits ⟨j, hj⟩
  obtain ⟨h_norm_env, h_init_env, h_steps_env, _⟩ := h_env
  obtain ⟨h_bits_eval, h_products_eval, h_px, h_py⟩ := h_input
  have h_bit : ∀ (j : ℕ) (hj : j < numBits),
      Expression.eval env.toEnvironment (input_var_bits[j]'hj) = input_bits[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_bits_eval
    simpa [Vector.getElem_map] using this
  have h_prod : ∀ (j : ℕ) (hj : j < numProducts),
      Expression.eval env.toEnvironment (input_var_products[j]'hj) = input_products[j]'hj := by
    intro j hj
    have := congrArg (fun v => v[j]'hj) h_products_eval
    simpa [Vector.getElem_map] using this
  have hy : input_pt_y ≠ 0 := h_nz.2 _ h_pt_curve
  obtain ⟨h_c, h_c2, h_r⟩ := h_norm_env hy
  obtain ⟨_, hc, hr, h_c_nat, h_r_nat⟩ :=
    GroupScale.normalization_facts curveParams input_pt_x input_pt_y _ _ _ h_pt_curve h_nz
      h_c h_c2 h_r
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
       input_var_products[2 * i.val]'(product_index_lt i),
       input_var_products[2 * i.val + 1]'(product_index_succ_lt i),
       varFromOffset field (i₀ + 3 + 3 + 2), acc⟩)
    (Initial.output (i₀ + 9)) (i₀ + 9 + 12) 27
    (fun i acc off => evalPt env.toEnvironment (Step.output curveParams
      ⟨input_var_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input_var_products[2 * i.val]'(product_index_lt i),
       input_var_products[2 * i.val + 1]'(product_index_succ_lt i),
       varFromOffset field (i₀ + 3 + 3 + 2), ⟨Expression.const acc.x, Expression.const acc.y⟩⟩ off))
    h_ne
    (by
      intro i h_step_ne
      have h := h_steps_env i
      simp only [Step.Assumptions, Step.Spec, h_bit, h_prod] at h
      have := h ⟨h_bool _ _, h_bool _ _, h_bool _ _, (h_prods i).1, (h_prods i).2,
        hr, hζ, h3, h_step_ne⟩
      simpa only [circuit_norm, Step.circuit, Step.output, Step.digitVar,
        Point.TripleAndAddIncompleteUnchecked.output, evalPt, Expression.eval, h_bit, h_prod,
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
  simp only [Step.Assumptions, h_bit, h_prod]
  exact ⟨h_bool _ _, h_bool _ _, h_bool _ _, (h_prods i).1, (h_prods i).2, hr, hζ, h3, h_nei⟩

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

end Ragu.Circuits.Endoscalar.HoistedGroupScale
