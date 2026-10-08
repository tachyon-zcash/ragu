import Clean.Circuit
import Clean.Circuit.Loops
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Boolean.And
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Point.Spec

/-!
# `Endoscalar::lift`

Lifts a `numBits`-bit endoscalar to the scalar its radix-3 walk multiplies
by. Mirrors `crates/ragu_primitives/src/endoscalar.rs::Endoscalar::lift`,
which is `lift_init` followed by `lift_digits`:

* `lift_init`: one `Boolean::and` for `s₀ e₀`, then the affine initial
  accumulator `2 (1 - 2 s₀)(1 + (λ - 1) e₀)` expanded over `s₀`, `e₀` and
  the product wire.
* `lift_digits`: per digit, one `Boolean::and` for `e₁ e₂`, the affine
  unsigned value `1 + (λ - 1) e₁ + (λ² - 1) e₂ + (3 - λ) e₁ e₂`, one mul for
  its sign, and the affine Horner step `acc ← 3 acc + d`.

The per-digit work is the `Digit` sub-gadget; the Horner accumulation is a
pure symbolic fold, exactly as the deployed gadget chains virtual wires.
The fingerprint hashes polynomial normal forms, so the tree shape in which
either side builds the accumulator is irrelevant.
-/

namespace Ragu.Circuits.Endoscalar.Lift
open Walk
variable {p : ℕ} [Fact p.Prime]

/-- The digit's scalar `(-1)^s {1, λ, λ², 1 - λ}[e₁, e₂]`. -/
def digitValue (ζ s e1 e2 : F p) : F p :=
  (if s = 1 then -1 else 1) *
    (if e1 = 1 then (if e2 = 1 then 1 - ζ else ζ) else if e2 = 1 then ζ ^ 2 else 1)

/-- The initial accumulator `2 (-1)^{s₀} λ^{e₀}`. -/
def initValue (ζ s0 e0 : F p) : F p :=
  2 * (if s0 = 1 then -1 else 1) * (if e0 = 1 then ζ else 1)

/-- The native lift: Horner's rule in radix 3 over the digits. -/
def liftNative (ζ : F p) (bits : Vector (F p) numBits) : F p :=
  Fin.foldl numDigits (fun acc (i : Fin numDigits) =>
      3 * acc + digitValue ζ (bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
        (bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
        (bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))))
    (initValue ζ bits[0] bits[1])

/-! ## One digit, bundled as its own subcircuit. -/
namespace Digit

structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
deriving ProvableStruct

/-- `Boolean::and` for `e₁ e₂`, then the mul of the sign `1 - 2s` with the
unsigned value. -/
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Expression (F p)) := do
  let ⟨s, e1, e2⟩ := input
  let ζ := curveParams.ζ
  let e1e2 ← Boolean.And.circuit ⟨e1, e2⟩
  let v := 1 + Expression.const (ζ - 1) * e1 + Expression.const (ζ ^ 2 - 1) * e2 +
    Expression.const (3 - ζ) * e1e2
  let sign := 1 + Expression.const (-2) * s
  Element.Mul.circuit ⟨sign, v⟩

/-- Boolean bits and a nontrivial cube root of unity: the `(1, 1)` digit's
affine value is `1 - λ` only modulo `λ² + λ + 1 = 0`. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  curveParams.ζ ≠ 1 ∧ IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) (out : F p) :=
  out = digitValue curveParams.ζ input.s input.e1 input.e2

/-- The output expression: the Mul's product wire. -/
@[circuit_norm]
def output (offset : ℕ) : Expression (F p) :=
  varFromOffset field (offset + 3 + 2)

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input field (main curveParams) where
  -- And (3) + Mul (3)
  localLength _ := 6
  output _ offset := output offset
  output_eq := by
    intro input offset
    rcases input with ⟨s, e1, e2⟩
    simp [main, output, circuit_norm, Boolean.And.circuit, Element.Mul.circuit]

/-- For boolean `a, b, out`, `out.val = a.val &&& b.val` forces `out = a * b`. -/
lemma and_eq_mul_of_isBool (a b out : F p) (ha : IsBool a) (hb : IsBool b)
    (h_out : IsBool out) (h : ZMod.val out = ZMod.val a &&& ZMod.val b) :
    out = a * b := by
  rcases ha with ha | ha <;> rcases hb with hb | hb <;>
    rcases h_out with h_out | h_out <;>
    simp_all [ZMod.val_zero, ZMod.val_one]

/-- The unsigned affine form agrees with the table on booleans, given
`ζ² + ζ + 1 = 0`: its `(1, 1)` value `2 + ζ²` is `1 - ζ`. -/
lemma unsigned_eq (ζ e1 e2 : F p) (hq : ζ ^ 2 + ζ + 1 = 0) (he1 : IsBool e1) (he2 : IsBool e2) :
    1 + (ζ - 1) * e1 + (ζ ^ 2 - 1) * e2 + (3 - ζ) * (e1 * e2) =
      (if e1 = 1 then (if e2 = 1 then 1 - ζ else ζ) else if e2 = 1 then ζ ^ 2 else 1) := by
  rcases he1 with h1 | h1 <;> rcases he2 with h2 | h2 <;> subst h1 h2 <;>
    simp only [zero_ne_one, if_true, if_false]
  · ring
  · ring
  · ring
  · linear_combination hq

theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec, output]
  obtain ⟨hζ, hs, he1, he2⟩ := h_assumptions
  obtain ⟨h_and, h_mul⟩ := h_holds
  obtain ⟨h_val, h_bool⟩ := h_and ⟨he1, he2⟩
  have h_e1e2 := and_eq_mul_of_isBool _ _ _ he1 he2 h_bool h_val
  rw [h_mul, h_e1e2, digitValue,
    ← unsigned_eq curveParams.ζ _ _ (zeta_quadratic curveParams hζ) he1 he2]
  rcases hs with hs | hs <;> subst hs <;> simp only [zero_ne_one, if_true, if_false]
  · ring
  · ring

theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions,
    Element.Mul.circuit, Element.Mul.Assumptions]
  obtain ⟨_, _, he1, he2⟩ := h_assumptions
  exact ⟨he1, he2⟩

def circuit (curveParams : Point.Spec.CurveParams p) : FormalCircuit (F p) Input field :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Digit

structure Input (F : Type) where
  bits : Vector F numBits
deriving ProvableStruct

/-- The symbolic initial accumulator `2 + 2 (λ - 1) e₀ - 4 s₀ - 4 (λ - 1) s₀e₀`
over the two initial bits and their product wire. -/
def initCircuit (ζ : F p) (s0 e0 s0e0 : Expression (F p)) : Expression (F p) :=
  Expression.const 2 + Expression.const (2 * (ζ - 1)) * e0 +
    Expression.const (-4) * s0 + Expression.const (-4 * (ζ - 1)) * s0e0

def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Expression (F p)) := do
  let s0e0 ← Boolean.And.circuit ⟨input.bits[0], input.bits[1]⟩
  let digits ← Circuit.mapFinRange numDigits fun (i : Fin numDigits) =>
    Digit.circuit curveParams
      ⟨input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))⟩
  let acc : Expression (F p) := Fin.foldl numDigits
    (fun (acc : Expression (F p)) (i : Fin numDigits) =>
      Expression.const 3 * acc + digits[i])
    (initCircuit curveParams.ζ input.bits[0] input.bits[1] s0e0)
  return acc

def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  curveParams.ζ ≠ 1 ∧ ∀ i : Fin numBits, IsBool input.bits[i]

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) (out : F p) :=
  out = liftNative curveParams.ζ input.bits

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input field (main curveParams) where
  localLength _ := 3 + numDigits * 6
  localLength_eq input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit, Digit.circuit, Digit.elaborated]
  subcircuitsConsistent input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit, Digit.circuit, Digit.elaborated]

/-- The initial accumulator's affine form agrees with `initValue` on
booleans. -/
lemma init_eq (ζ s0 e0 : F p) (hs : IsBool s0) (he : IsBool e0) :
    2 + 2 * (ζ - 1) * e0 + -4 * s0 + -4 * (ζ - 1) * (s0 * e0) = initValue ζ s0 e0 := by
  rcases hs with h1 | h1 <;> rcases he with h2 | h2 <;> simp [initValue, h1, h2] <;> ring

/-- `Fin.foldl` is congruent in its body up to pointwise equality. -/
lemma fin_foldl_congr {α : Type*} (n : ℕ)
    (f g : α → Fin n → α) (init : α)
    (h : ∀ acc i, f acc i = g acc i) :
    Fin.foldl n f init = Fin.foldl n g init := by
  induction n generalizing init with
  | zero => simp [Fin.foldl_zero]
  | succ n ih =>
    rw [Fin.foldl_succ_last, Fin.foldl_succ_last]
    rw [ih (fun acc i => f acc i.castSucc) (fun acc i => g acc i.castSucc) init
      (fun acc i => h acc i.castSucc)]
    rw [h _ (Fin.last n)]

/-- Evaluating a symbolic Horner fold is the Horner fold of the evaluations. -/
lemma eval_foldl (env : Environment (F p)) (n : ℕ)
    (d : Fin n → Expression (F p)) (init : Expression (F p)) :
    Expression.eval env
        (Fin.foldl n (fun (acc : Expression (F p)) i => Expression.const 3 * acc + d i) init) =
      Fin.foldl n (fun (acc : F p) i => 3 * acc + Expression.eval env (d i))
        (Expression.eval env init) := by
  induction n generalizing init with
  | zero => simp [Fin.foldl_zero]
  | succ n ih =>
    rw [Fin.foldl_succ_last, Fin.foldl_succ_last]
    simp only [Expression.eval]
    rw [ih (fun i => d i.castSucc) init]

theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Digit.circuit, Digit.Assumptions, Digit.Spec, Digit.output, Digit.elaborated]
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_input
    simpa [Vector.getElem_map] using this
  obtain ⟨hζ, h_assumptions⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_assumptions ⟨j, h⟩
  obtain ⟨h_and, h_digits⟩ := h_holds
  -- The initial product wire.
  obtain ⟨h_val, h_isbool⟩ := h_and ⟨by rw [h_bits_eq 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bits_eq 1 (by decide)]; exact h_bool 1 (by decide)⟩
  rw [h_bits_eq 0 (by decide), h_bits_eq 1 (by decide)] at h_val
  have h_s0e0 := Digit.and_eq_mul_of_isBool _ _ _ (h_bool 0 (by decide)) (h_bool 1 (by decide))
    h_isbool h_val
  -- Each digit wire.
  have h_digit : ∀ i : Fin numDigits,
      env.get (i₀ + 3 + i.val * 6 + 3 + 2) =
        digitValue curveParams.ζ (input_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (input_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (input_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) := by
    intro i
    have h := h_digits i
    simp only [h_bits_eq] at h
    exact h ⟨hζ, h_bool _ _, h_bool _ _, h_bool _ _⟩
  simp only [liftNative]
  rw [eval_foldl]
  simp only [initCircuit, Expression.eval, h_bits_eq, h_s0e0]
  rw [init_eq curveParams.ζ _ _ (h_bool 0 (by decide)) (h_bool 1 (by decide))]
  apply fin_foldl_congr
  intro acc i
  rw [h_digit i]

theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions,
    Digit.circuit, Digit.Assumptions, Digit.elaborated]
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env.toEnvironment (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_input
    simpa [Vector.getElem_map] using this
  obtain ⟨hζ, h_assumptions⟩ := h_assumptions
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_assumptions ⟨j, h⟩
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · rw [h_bits_eq 0 (by decide)]; exact h_bool 0 (by decide)
  · rw [h_bits_eq 1 (by decide)]; exact h_bool 1 (by decide)
  · intro i
    simp only [h_bits_eq]
    exact ⟨hζ, h_bool _ _, h_bool _ _, h_bool _ _⟩

def circuit (curveParams : Point.Spec.CurveParams p) : FormalCircuit (F p) Input field :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Ragu.Circuits.Endoscalar.Lift
