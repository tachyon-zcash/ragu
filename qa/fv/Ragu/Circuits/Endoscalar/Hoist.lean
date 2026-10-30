import Clean.Circuit
import Clean.Circuit.Loops
import Clean.Gadgets.Boolean
import Ragu.Circuits.Boolean.And
import Ragu.Circuits.Endoscalar.Walk

/-!
# `HoistedEndoscalar::hoist`

The product wires of a `HoistedEndoscalar`, derived from its bits: per digit
`(s, e₁, e₂)`, the wire `e₁ e₂` is `Boolean::and(e₁, e₂)` and the wire
`e₁ e₂ s` is `Boolean::and(e₁ e₂, s)`, two gates. `HoistedEndoscalar::alloc`
is `Endoscalar::alloc` followed by this, so the products' relation to the
bits is part of the gadget's wire contract. A stage owner re-establishes
that contract through `HoistedConsistent` when it substitutes stage wires.
Mirrors
`crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::hoist`.
-/

namespace Ragu.Circuits.Endoscalar.Hoist
open Walk
variable {p : ℕ} [Fact p.Prime]

/-! ## One digit's two products, bundled as its own subcircuit. -/
namespace Digit

structure Input (F : Type) where
  s : F
  e1 : F
  e2 : F
deriving ProvableStruct

/-- `and(e₁, e₂)`, then `and(e₁ e₂, s)`: the digit's `e₁ e₂` and `e₁ e₂ s`
wires, in that order. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var (fields 2) (F p)) := do
  let ⟨s, e1, e2⟩ := input
  let e1e2 ← Boolean.And.circuit ⟨e1, e2⟩
  let e1e2s ← Boolean.And.circuit ⟨e1e2, s⟩
  return #v[e1e2, e1e2s]

def Assumptions (input : Input (F p)) :=
  IsBool input.s ∧ IsBool input.e1 ∧ IsBool input.e2

/-- The two product wires are the products of the bits they stand for. -/
def Spec (input : Input (F p)) (out : Vector (F p) 2) :=
  out[0] = input.e1 * input.e2 ∧ out[1] = out[0] * input.s

/-- The output wires: each `And`'s product wire. -/
@[circuit_norm]
def output (offset : ℕ) : Var (fields 2) (F p) :=
  #v[Boolean.And.output offset, Boolean.And.output (offset + 3)]

instance elaborated : ElaboratedCircuit (F p) Input (fields 2) main where
  -- And (3) + And (3)
  localLength _ := 6
  output _ offset := output offset
  output_eq := by
    intro input offset
    rcases input with ⟨s, e1, e2⟩
    simp [main, output, circuit_norm, Boolean.And.circuit]

/-- Given boolean digit bits, the two gates pin both hoisted products to the
products of their bits. -/
theorem soundness : Soundness (F p) (Input := Input) (Output := (fields 2)) main Assumptions Spec := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Boolean.And.output, output]
  obtain ⟨hs, he1, he2⟩ := h_assumptions
  obtain ⟨h_and1, h_and2⟩ := h_holds
  obtain ⟨h_val1, h_bool1⟩ := h_and1 ⟨he1, he2⟩
  have hp : env.get (i₀ + 2) = input_e1 * input_e2 :=
    ZMod.val_injective p (h_val1.trans (IsBool.and_eq_val_and he1 he2).symm)
  obtain ⟨h_val2, _⟩ := h_and2 ⟨h_bool1, hs⟩
  have hq : env.get (i₀ + 3 + 2) = env.get (i₀ + 2) * input_s :=
    ZMod.val_injective p (h_val2.trans (IsBool.and_eq_val_and h_bool1 hs).symm)
  exact ⟨hp, hq⟩

/-- Boolean digit bits admit the honest AND witnesses: the first product is
boolean, so the second gate's precondition holds. -/
theorem completeness : Completeness (F p) (Input := Input) (Output := (fields 2)) main Assumptions := by
  circuit_proof_start [Boolean.And.circuit, Boolean.And.Assumptions, Boolean.And.Spec,
    Boolean.And.output]
  obtain ⟨hs, he1, he2⟩ := h_assumptions
  obtain ⟨h_and1_env, _⟩ := h_env
  obtain ⟨_, h_bool1⟩ := h_and1_env ⟨he1, he2⟩
  exact ⟨⟨he1, he2⟩, ⟨h_bool1, hs⟩⟩

def circuit : FormalCircuit (F p) Input (fields 2) :=
  { main, elaborated, Assumptions, Spec, soundness, completeness }

end Digit

/-- The bits of the endoscalar whose products are hoisted. -/
structure Input (F : Type) where
  bits : Vector F numBits
deriving ProvableStruct

/-- The digits' product pairs flattened into the `numProducts` product wires:
wire `k` is digit `k / 2`'s `e₁ e₂` for even `k` and its `e₁ e₂ s` for odd
`k`. A definition rather than an inline `Vector.ofFn`, so normalizing `main`
never unrolls the `numProducts` entries. -/
def flatten (digits : Vector (Var (fields 2) (F p)) numDigits) :
    Var (fields numProducts) (F p) :=
  Vector.ofFn fun (k : Fin numProducts) =>
    (digits[k.val / 2]'(product_digit_lt k))[k.val % 2]'(Nat.mod_lt _ (by decide))

/-- Per digit in digit order, the `Digit` subcircuit on its three bits; the
output flattens the digits' pairs into the `numProducts` product wires. -/
def main (input : Var Input (F p)) : Circuit (F p) (Var (fields numProducts) (F p)) := do
  let digits ← Circuit.mapFinRange numDigits fun (i : Fin numDigits) =>
    Digit.circuit
      ⟨input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)),
       input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num))⟩
  return flatten digits

def Assumptions (input : Input (F p)) :=
  ∀ i : Fin numBits, IsBool input.bits[i]

/-- Every product wire is the product of the bits it stands for: the relation
`HoistedLift` and `HoistedGroupScale` assume of their product inputs. -/
def Spec (input : Input (F p)) (products : Vector (F p) numProducts) :=
  ∀ i : Fin numDigits,
    products[2 * i.val]'(product_index_lt i) =
      input.bits[3 + 3 * i.val]'(bit_index_lt i (by norm_num)) *
        input.bits[4 + 3 * i.val]'(bit_index_lt i (by norm_num)) ∧
    products[2 * i.val + 1]'(product_index_succ_lt i) =
      products[2 * i.val]'(product_index_lt i) *
        input.bits[2 + 3 * i.val]'(bit_index_lt i (by norm_num))

/-- The output wires: digit `i`'s two `And` product wires start at
`offset + 6 i`, flattened in digit order. -/
def output (offset : ℕ) : Var (fields numProducts) (F p) :=
  flatten (Vector.mapFinRange numDigits fun (i : Fin numDigits) =>
    Digit.output (offset + i.val * 6))

instance elaborated : ElaboratedCircuit (F p) Input (fields numProducts) main where
  localLength _ := numDigits * 6
  localLength_eq input offset := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]
  output _ offset := output offset
  output_eq input offset := by
    simp [main, output, circuit_norm, Digit.circuit, Digit.elaborated]
  subcircuitsConsistent input offset := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]
  channelsLawful := by
    simp +arith [main, circuit_norm, Digit.circuit, Digit.elaborated]

/-- Given boolean bits, every digit's gates pin its two product wires. -/
theorem soundness : Soundness (F p) (Input := Input) (Output := (fields numProducts)) main
    Assumptions Spec := by
  circuit_proof_start [Digit.circuit, Digit.Assumptions, Digit.Spec, Digit.elaborated]
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_input
    simpa [Vector.getElem_map] using this
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_assumptions ⟨j, h⟩
  intro i
  have h := h_holds i
  simp only [h_bits_eq] at h
  obtain ⟨hp, hq⟩ := h ⟨h_bool _ _, h_bool _ _, h_bool _ _⟩
  have hd1 : 2 * i.val / 2 = i.val := by omega
  have hm1 : 2 * i.val % 2 = 0 := by omega
  have hd2 : (2 * i.val + 1) / 2 = i.val := by omega
  have hm2 : (2 * i.val + 1) % 2 = 1 := by omega
  simp only [output, flatten, Vector.getElem_ofFn, Vector.getElem_mapFinRange, hd1, hm1, hd2, hm2]
  simpa [Digit.output, Boolean.And.output, circuit_norm] using And.intro hp hq

/-- Boolean bits satisfy every digit's precondition. -/
theorem completeness : Completeness (F p) (Input := Input) (Output := (fields numProducts)) main
    Assumptions := by
  circuit_proof_start [Digit.circuit, Digit.Assumptions, Digit.elaborated]
  have h_bits_eq : ∀ (j : ℕ) (h : j < numBits),
      Expression.eval env.toEnvironment (input_var_bits[j]'h) = (input_bits[j]'h) := by
    intro j h
    have := congrArg (fun v => v[j]'h) h_input
    simpa [Vector.getElem_map] using this
  have h_bool : ∀ (j : ℕ) (h : j < numBits), IsBool (input_bits[j]'h) :=
    fun j h => h_assumptions ⟨j, h⟩
  intro i
  simp only [h_bits_eq]
  exact ⟨h_bool _ _, h_bool _ _, h_bool _ _⟩

def circuit : FormalCircuit (F p) Input (fields numProducts) :=
  { main, elaborated, Assumptions, Spec, soundness, completeness }

end Ragu.Circuits.Endoscalar.Hoist
