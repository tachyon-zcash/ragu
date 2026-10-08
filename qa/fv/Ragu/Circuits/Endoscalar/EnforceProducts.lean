import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Gadgets.Boolean
import Ragu.Circuits.Boolean.And
import Ragu.Circuits.Endoscalar.Lift
import Ragu.Circuits.Endoscalar.Walk

/-!
# `HoistedEndoscalar::enforce_products`

The contract a `HoistedEndoscalar`'s product wires rest on: per digit, the
wire `e₁ e₂` equals `Boolean::and(e₁, e₂)` and the wire `e₁ e₂ s` equals
`Boolean::and(e₁ e₂, s)`, two gates and two equalities. Mirrors
`crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::enforce_products`.
-/

namespace Ragu.Circuits.Endoscalar.EnforceProducts
open Walk
variable {p : ℕ} [Fact p.Prime]

/-! ## One digit's two products, bundled as its own subcircuit. -/
namespace Digit

structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
  e1e2 : F
  e1e2s : F
deriving ProvableStruct

/-- `and(e₁, e₂)` held equal to the `e₁ e₂` wire, then `and(e₁ e₂, s)` held
equal to the `e₁ e₂ s` wire. Each equality is `gate wire - stage wire`, as
`Driver::enforce_equal` emits it. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var unit (F p)) := do
  let ⟨s, e1, e2, e1e2, e1e2s⟩ := input
  let fresh_p ← Boolean.And.circuit ⟨e1, e2⟩
  assertZero (fresh_p - e1e2)
  let fresh_q ← Boolean.And.circuit ⟨e1e2, s⟩
  assertZero (fresh_q - e1e2s)

def Assumptions (input : Input (F p)) :=
  IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2

/-- The two product wires are the products of the bits they stand for. -/
def Spec (input : Input (F p)) :=
  input.e1e2 = input.e1 * input.e2 ∧ input.e1e2s = input.e1e2 * input.s

instance elaborated : ElaboratedCircuit (F p) Input unit main where
  -- And (3) + And (3)
  localLength _ := 6
  localLength_eq input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit]
  subcircuitsConsistent input offset := by
    simp +arith [main, circuit_norm, Boolean.And.circuit]

theorem soundness : FormalAssertion.Soundness (F p) (Input := Input) main Assumptions Spec := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Boolean.And.output]
  obtain ⟨hs, he1, he2⟩ := h_assumptions
  obtain ⟨h_and1, h_eq1, h_and2, h_eq2⟩ := h_holds
  obtain ⟨h_val1, h_bool1⟩ := h_and1 ⟨he1, he2⟩
  have hp : env.get (i₀ + 2) = input_e1 * input_e2 :=
    Lift.Digit.and_eq_mul_of_isBool _ _ _ he1 he2 h_bool1 h_val1
  have h_e1e2 : input_e1e2 = input_e1 * input_e2 := by
    rw [← hp]; linear_combination -h_eq1
  have hp_bool : IsBool input_e1e2 := by
    rw [h_e1e2]; exact IsBool.and_is_bool he1 he2
  obtain ⟨h_val2, h_bool2⟩ := h_and2 ⟨hp_bool, hs⟩
  have hq : env.get (i₀ + 3 + 2) = input_e1e2 * input_s :=
    Lift.Digit.and_eq_mul_of_isBool _ _ _ hp_bool hs h_bool2 h_val2
  refine ⟨h_e1e2, ?_⟩
  rw [← hq]; linear_combination -h_eq2

theorem completeness : FormalAssertion.Completeness (F p) (Input := Input) main Assumptions Spec := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Boolean.And.output]
  obtain ⟨hs, he1, he2⟩ := h_assumptions
  obtain ⟨h_e1e2, h_e1e2s⟩ := h_spec
  obtain ⟨h_and1_env, h_and2_env⟩ := h_env
  have hp_bool : IsBool input_e1e2 := by
    rw [h_e1e2]; exact IsBool.and_is_bool he1 he2
  refine ⟨⟨he1, he2⟩, ?_, ⟨hp_bool, hs⟩, ?_⟩
  · obtain ⟨h_val1, h_bool1⟩ := h_and1_env ⟨he1, he2⟩
    have hp := Lift.Digit.and_eq_mul_of_isBool _ _ _ he1 he2 h_bool1 h_val1
    rw [hp, h_e1e2]; ring
  · obtain ⟨h_val2, h_bool2⟩ := h_and2_env ⟨hp_bool, hs⟩
    have hq := Lift.Digit.and_eq_mul_of_isBool _ _ _ hp_bool hs h_bool2 h_val2
    rw [hq, h_e1e2s]; ring

def circuit : FormalAssertion (F p) Input :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    soundness := soundness,
    completeness := completeness }

end Digit

/-- The bits and, per digit in digit order, the hoisted `e₁ e₂` and
`e₁ e₂ s` wires. -/
structure Input (F : Type) where
  bits : Vector F numBits
  products : Vector F numProducts
deriving ProvableStruct

/-- `@[irreducible]` is a defeq seal only: it stops the unifier from
whnf-unrolling the `numDigits` iterations during structure type checks,
which exceeds the default heartbeat budget. Proofs still unfold `main` via
its equation lemma. -/
@[irreducible]
def main (input : Var Input (F p)) : Circuit (F p) (Var unit (F p)) :=
  Circuit.forEach (Vector.finRange numDigits) fun (i : Fin numDigits) =>
    Digit.circuit
      ⟨input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.products[2 * i.val]'(product_index_lt i),
       input.products[2 * i.val + 1]'(product_index_succ_lt i)⟩

def Assumptions (input : Input (F p)) :=
  ∀ i : Fin numBits, IsBool input.bits[i]

/-- Every product wire is the product of the bits it stands for. -/
def Spec (input : Input (F p)) :=
  ∀ i : Fin numDigits,
    input.products[2 * i.val]'(product_index_lt i) =
      input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)) *
        input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)) ∧
    input.products[2 * i.val + 1]'(product_index_succ_lt i) =
      input.products[2 * i.val]'(product_index_lt i) *
        input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num))

instance elaborated : ElaboratedCircuit (F p) Input unit main where
  localLength _ := numDigits * 6
  localLength_eq input offset := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]
  subcircuitsConsistent input offset := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]
  channelsLawful := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]

theorem soundness : FormalAssertion.Soundness (F p) (Input := Input) main Assumptions Spec := by
  circuit_proof_start [main, Digit.circuit, Digit.Assumptions, Digit.Spec, Digit.elaborated]
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
    fun j h => h_assumptions ⟨j, h⟩
  intro i
  have h := h_holds i
  simp only [h_bits_eq, h_prod_eq] at h
  exact h ⟨h_bool _ _, h_bool _ _, h_bool _ _⟩

theorem completeness : FormalAssertion.Completeness (F p) (Input := Input) main Assumptions Spec := by
  circuit_proof_start [main, Digit.circuit, Digit.Assumptions, Digit.Spec, Digit.elaborated]
  obtain ⟨h_bits_eval, h_products_eval⟩ := h_input
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
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_assumptions ⟨j, h⟩
  intro i
  simp only [h_bits_eq, h_prod_eq]
  exact ⟨⟨h_bool _ _, h_bool _ _, h_bool _ _⟩, h_spec i⟩

def circuit : FormalAssertion (F p) Input :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Endoscalar.EnforceProducts
