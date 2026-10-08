import Clean.Circuit
import Clean.Circuit.Loops
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Boolean.And
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Endoscalar.Lift
import Ragu.Circuits.Endoscalar.Walk
import Ragu.Circuits.Point.Spec

/-!
# `HoistedEndoscalar::lift`

The lift of a `HoistedEndoscalar`: the same `lift_init` as
`Endoscalar::lift`, then per digit only the sign mul, the digit's `e₁ e₂`
being read from the hoisted product wires rather than computed. Mirrors
`crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::lift`.

The product wires are inputs here; that they are the products of the bits
is the `EnforceProducts` contract, carried as an assumption.
-/

namespace Ragu.Circuits.Endoscalar.HoistedLift
open Walk
variable {p : ℕ} [Fact p.Prime]

/-! ## One digit, bundled as its own subcircuit. -/
namespace Digit

structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
  e1e2 : F
deriving ProvableStruct

/-- The mul of the sign `1 - 2s` with the unsigned value over the hoisted
`e₁ e₂` wire. -/
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Expression (F p)) := do
  let ⟨s, e1, e2, e1e2⟩ := input
  let ζ := curveParams.ζ
  let v := 1 + Expression.const (ζ - 1) * e1 + Expression.const (ζ ^ 2 - 1) * e2 +
    Expression.const (3 - ζ) * e1e2
  let sign := 1 + Expression.const (-2) * s
  Element.Mul.circuit ⟨sign, v⟩

/-- A nontrivial cube root of unity, boolean bits, and a product wire that is
the product of its bits. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  curveParams.ζ ≠ 1 ∧ IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2 ∧
  input.e1e2 = input.e1 * input.e2

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) (out : F p) :=
  out = Lift.digitValue curveParams.ζ input.s input.e1 input.e2

/-- The output expression: the Mul's product wire. -/
@[circuit_norm]
def output (offset : ℕ) : Expression (F p) :=
  varFromOffset field (offset + 2)

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input field (main curveParams) where
  localLength _ := 3
  output _ offset := output offset
  output_eq := by
    intro input offset
    rcases input with ⟨s, e1, e2, e1e2⟩
    simp [main, output, circuit_norm, Element.Mul.circuit]

theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec, output]
  obtain ⟨hζ, hs, he1, he2, hp⟩ := h_assumptions
  rw [h_holds, hp, Lift.digitValue,
    ← Lift.Digit.unsigned_eq curveParams.ζ _ _ (zeta_quadratic curveParams hζ) he1 he2]
  rcases hs with hs | hs <;> subst hs <;> simp only [zero_ne_one, if_true, if_false]
  · ring
  · ring

theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Element.Mul.circuit, Element.Mul.Assumptions]

def circuit (curveParams : Point.Spec.CurveParams p) : FormalCircuit (F p) Input field :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Digit

/-- The bits and, per digit in digit order, the hoisted `e₁ e₂` and
`e₁ e₂ s` wires. -/
structure Input (F : Type) where
  bits : Vector F numBits
  products : Vector F numProducts
deriving ProvableStruct

def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Expression (F p)) := do
  let s0e0 ← Boolean.And.circuit ⟨input.bits[0], input.bits[1]⟩
  let digits ← Circuit.mapFinRange numDigits fun (i : Fin numDigits) =>
    Digit.circuit curveParams
      ⟨input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.products[2 * i.val]'(product_index_lt i)⟩
  let acc : Expression (F p) := Fin.foldl numDigits
    (fun (acc : Expression (F p)) (i : Fin numDigits) =>
      Expression.const 3 * acc + digits[i])
    (Lift.initCircuit curveParams.ζ input.bits[0] input.bits[1] s0e0)
  return acc

/-- Boolean bits, and product wires that are the products of their bits:
the `EnforceProducts` contract. -/
def Assumptions (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  curveParams.ζ ≠ 1 ∧
  (∀ i : Fin numBits, IsBool input.bits[i]) ∧
  ∀ i : Fin numDigits,
    input.products[2 * i.val]'(product_index_lt i) =
      input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)) *
        input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p)) (out : F p) :=
  out = Lift.liftNative curveParams.ζ input.bits

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input field (main curveParams) where
  localLength _ := 3 + numDigits * 3
  localLength_eq input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit, Digit.circuit, Digit.elaborated]
  subcircuitsConsistent input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit, Digit.circuit, Digit.elaborated]

theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Digit.circuit, Digit.Assumptions, Digit.Spec, Digit.output, Digit.elaborated]
  obtain ⟨hζ, h_bool_all, h_prod⟩ := h_assumptions
  obtain ⟨h_bits_eval, h_products_eval⟩ := h_input
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_bits_eval
    simpa [Vector.getElem_map] using this
  have h_prod_eq : ∀ (j : ℕ) (h : j < numProducts),
      Expression.eval env (input_var_products[j]'h) = (input_products[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_products_eval
    simpa [Vector.getElem_map] using this
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_bool_all ⟨j, h⟩
  obtain ⟨h_and, h_digits⟩ := h_holds
  obtain ⟨h_val, h_isbool⟩ := h_and ⟨by rw [h_bits_eq 0 (by decide)]; exact h_bool 0 (by decide),
    by rw [h_bits_eq 1 (by decide)]; exact h_bool 1 (by decide)⟩
  rw [h_bits_eq 0 (by decide), h_bits_eq 1 (by decide)] at h_val
  have h_s0e0 := Lift.Digit.and_eq_mul_of_isBool _ _ _ (h_bool 0 (by decide))
    (h_bool 1 (by decide)) h_isbool h_val
  have h_digit : ∀ i : Fin numDigits,
      env.get (i₀ + 3 + i.val * 3 + 2) =
        Lift.digitValue curveParams.ζ (input_bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (input_bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)))
          (input_bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))) := by
    intro i
    have h := h_digits i
    simp only [h_bits_eq, h_prod_eq] at h
    exact h ⟨hζ, h_bool _ _, h_bool _ _, h_bool _ _, h_prod i⟩
  simp only [Lift.liftNative]
  rw [Lift.eval_foldl]
  simp only [Lift.initCircuit, Expression.eval, h_bits_eq, h_s0e0]
  rw [Lift.init_eq curveParams.ζ _ _ (h_bool 0 (by decide)) (h_bool 1 (by decide))]
  apply Lift.fin_foldl_congr
  intro acc i
  rw [h_digit i]

theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := field) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions,
    Digit.circuit, Digit.Assumptions, Digit.elaborated]
  obtain ⟨hζ, h_bool_all, h_prod⟩ := h_assumptions
  obtain ⟨h_bits_eval, h_products_eval⟩ := h_input
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_bool_all ⟨j, h⟩
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env.toEnvironment (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_bits_eval
    simpa [Vector.getElem_map] using this
  have h_prod_eq : ∀ (j : ℕ) (h : j < numProducts),
      Expression.eval env.toEnvironment (input_var_products[j]'h) = (input_products[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_products_eval
    simpa [Vector.getElem_map] using this
  refine ⟨⟨?_, ?_⟩, ?_⟩
  · rw [h_bits_eq 0 (by decide)]; exact h_bool 0 (by decide)
  · rw [h_bits_eq 1 (by decide)]; exact h_bool 1 (by decide)
  · intro i
    simp only [h_bits_eq, h_prod_eq]
    exact ⟨hζ, h_bool _ _, h_bool _ _, h_bool _ _, h_prod i⟩

def circuit (curveParams : Point.Spec.CurveParams p) : FormalCircuit (F p) Input field :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Ragu.Circuits.Endoscalar.HoistedLift
