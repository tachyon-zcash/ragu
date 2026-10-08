import Clean.Circuit
import Clean.Circuit.Loops
import Ragu.Circuits.Boolean.Alloc
import Ragu.Circuits.Endoscalar.Walk

namespace Ragu.Circuits.Endoscalar.HoistedAlloc
open Walk
variable {p : ℕ} [Fact p.Prime]

/-- The wires `HoistedEndoscalar::alloc` allocates: the `numBits` bits, then
per digit the products `e₁ e₂` and `e₁ e₂ s`. -/
abbrev numWires : ℕ := numBits + 2 * numDigits

/-- Wire `i`'s honest value: bit `i` below `numBits`, else digit
`(i - numBits) / 2`'s `e₁ e₂` or `e₁ e₂ s`. -/
def wireBit (value : BitVec numBits) (i : ℕ) : Bool :=
  if h : i < numBits then value[i]
  else
    let d := (i - numBits) / 2
    let pb := value[3 + 3 * d]! && value[4 + 3 * d]!
    if (i - numBits) % 2 = 0 then pb else pb && value[2 + 3 * d]!

/-- `HoistedEndoscalar::alloc(value)` is `Endoscalar::alloc(value)` followed
by one `Boolean::alloc` per product wire, `numWires` boolean allocations in
all. Mirrors `crates/ragu_primitives/src/endoscalar.rs::HoistedEndoscalar::alloc`. -/
def main (value : ProverEnvironment (F p) → BitVec numBits)
    : Circuit (F p) (Vector (Expression (F p)) numWires) :=
  Circuit.mapFinRange numWires fun (i : Fin numWires) =>
    Boolean.Alloc.circuit (fun env => wireBit (value env) i.val)

def Assumptions (_input : Unit) (_data : ProverData (F p)) := True

def ProverAssumptions (_input : BitVec numBits) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) := True

/-- The verifier learns that every output wire is boolean; the products'
relation to the bits is `EnforceProducts`' contract, not this one's. -/
def Spec (_input : Unit) (out : Vector (F p) numWires) (_data : ProverData (F p)) :=
  ∀ i : Fin numWires, IsBool out[i]

/-- The honest prover's wire `i` holds `wireBit value i`. -/
def ProverSpec (input : BitVec numBits) (out : Vector (F p) numWires) (_hint : ProverHint (F p)) :=
  ∀ i : Fin numWires, out[i] = if wireBit input i.val then 1 else 0

instance elaborated
    : ElaboratedCircuit (F p) (UnconstrainedNative (BitVec numBits)) (fields numWires) main where
  localLength _ := numWires * 3
  localLength_eq _ _ := by
    simp [main, circuit_norm, Boolean.Alloc.circuit]
  subcircuitsConsistent _ _ := by
    simp [main, circuit_norm, Boolean.Alloc.circuit]

theorem soundness
    : GeneralFormalCircuit.WithHint.Soundness (F p) (Input := (UnconstrainedNative (BitVec numBits)))
        (Output := (fields numWires)) main Assumptions Spec := by
  circuit_proof_start [Boolean.Alloc.circuit, Boolean.Alloc.Assumptions, Boolean.Alloc.Spec]
  exact h_holds

theorem completeness
    : GeneralFormalCircuit.WithHint.Completeness (F p) (Input := (UnconstrainedNative (BitVec numBits)))
        (Output := (fields numWires)) main ProverAssumptions ProverSpec := by
  circuit_proof_start [Boolean.Alloc.circuit, Boolean.Alloc.Assumptions, Boolean.Alloc.Spec,
    Boolean.Alloc.ProverAssumptions, Boolean.Alloc.ProverSpec]
  intro i
  exact (h_env i).2

def circuit : GeneralFormalCircuit.WithHint (F p) (UnconstrainedNative (BitVec numBits)) (fields numWires) :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    ProverAssumptions := ProverAssumptions,
    ProverSpec := ProverSpec,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Endoscalar.HoistedAlloc
