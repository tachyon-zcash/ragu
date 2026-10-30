import Clean.Circuit
import Ragu.Circuits.Endoscalar.Alloc
import Ragu.Circuits.Endoscalar.Hoist
import Ragu.Circuits.Endoscalar.Walk

namespace Ragu.Circuits.Endoscalar.HoistedAlloc
open Walk
variable {p : ℕ} [Fact p.Prime]

/-- The wires `HoistedEndoscalar::alloc` allocates: the `numBits` bits, then
per digit the products `e₁ e₂` and `e₁ e₂ s`. -/
structure Output (F : Type) where
  bits : Vector F numBits
  products : Vector F numProducts
deriving ProvableStruct

/-- `HoistedEndoscalar::alloc(value)` is `Endoscalar::alloc(value)` followed
by `HoistedEndoscalar::hoist`: one `Boolean::alloc` per bit, then two
`Boolean::and` per digit. Mirrors
`crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::alloc`. -/
def main (value : ProverEnvironment (F p) → BitVec numBits) : Circuit (F p) (Var Output (F p)) := do
  let bits ← Alloc.circuit value
  let products ← Hoist.circuit ⟨bits⟩
  return ⟨bits, products⟩

def Assumptions (_input : Unit) (_data : ProverData (F p)) := True

def ProverAssumptions (_input : BitVec numBits) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) := True

/-- The gadget's wire contract: every bit wire is boolean, and every product
wire is the product of the bits it stands for. -/
def Spec (_input : Unit) (out : Output (F p)) (_data : ProverData (F p)) :=
  (∀ i : Fin numBits, IsBool out.bits[i]) ∧ Hoist.Spec ⟨out.bits⟩ out.products

/-- The honest prover's bit `i` is bit `i` of the hint, and its products are
the products of those bits. -/
def ProverSpec (input : BitVec numBits) (out : Output (F p)) (_hint : ProverHint (F p)) :=
  (∀ i : Fin numBits, out.bits[i] = if input[i.val] then 1 else 0) ∧
    Hoist.Spec ⟨out.bits⟩ out.products

instance elaborated
    : ElaboratedCircuit (F p) (UnconstrainedNative (BitVec numBits)) Output main where
  localLength _ := numBits * 3 + numDigits * 6
  localLength_eq _ _ := by
    simp +arith [main, circuit_norm, Alloc.circuit, Alloc.elaborated, Hoist.circuit,
      Hoist.elaborated, numBits]
  output _ offset := ⟨Alloc.output offset, Hoist.output (offset + numBits * 3)⟩
  output_eq _ offset := by
    simp +arith [main, circuit_norm, Alloc.circuit, Alloc.elaborated, Hoist.circuit,
      Hoist.elaborated, numBits]
  subcircuitsConsistent _ _ := by
    simp +arith [main, circuit_norm, Alloc.circuit, Alloc.elaborated, Hoist.circuit,
      Hoist.elaborated]

/-- Allocation constrains every bit wire to be boolean, which is what
`Hoist` needs to pin every product wire. -/
theorem soundness
    : GeneralFormalCircuit.WithHint.Soundness (F p) (Input := (UnconstrainedNative (BitVec numBits)))
        (Output := Output) main Assumptions Spec := by
  circuit_proof_start [Alloc.circuit, Alloc.Assumptions, Alloc.Spec, Hoist.circuit,
    Hoist.Assumptions, Hoist.Spec]
  obtain ⟨h_bits, h_products⟩ := h_holds
  exact ⟨h_bits, h_products h_bits⟩

/-- Any `numBits`-bit hint yields a satisfying allocation of its bits, which
are boolean, and of their honestly computed products. -/
theorem completeness
    : GeneralFormalCircuit.WithHint.Completeness (F p) (Input := (UnconstrainedNative (BitVec numBits)))
        (Output := Output) main ProverAssumptions ProverSpec := by
  circuit_proof_start [Alloc.circuit, Alloc.Assumptions, Alloc.Spec, Alloc.ProverAssumptions,
    Alloc.ProverSpec, Hoist.circuit, Hoist.Assumptions, Hoist.Spec]
  obtain ⟨⟨_, h_bits⟩, h_products⟩ := h_env
  have h_bool : ∀ i : Fin numBits, IsBool (if input[i.val] then (1 : F p) else 0) := by
    intro i
    by_cases h : input[i.val] <;> simp [h, IsBool]
  have h_bits_bool := fun i : Fin numBits => (h_bits i) ▸ h_bool i
  exact ⟨h_bits_bool, h_bits, h_products h_bits_bool⟩

def circuit : GeneralFormalCircuit.WithHint (F p) (UnconstrainedNative (BitVec numBits)) Output :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    ProverAssumptions := ProverAssumptions,
    ProverSpec := ProverSpec,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Endoscalar.HoistedAlloc
