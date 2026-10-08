import Clean.Circuit
import Clean.Circuit.Loops
import Ragu.Circuits.Boolean.Alloc

namespace Ragu.Circuits.Endoscalar.Alloc
variable {p : ℕ} [Fact p.Prime]

/-- `Endoscalar::alloc(value)` allocates `ENDOSCALAR_BITS = 143` boolean
wires, each carrying the corresponding bit of the prover hint `value`, a
`Uendo`. Mirrors the Rust loop
`for i in 0..ENDOSCALAR_BITS { Boolean::alloc(value.bit(i)) }` in
`crates/ragu_primitives/src/endoscalar.rs::Endoscalar::alloc`. This Lean
reimpl is monomorphic at 143.

Extraction instance: `qa/fv/extraction/src/instances/endoscalar_alloc.rs`
(which drives the real `Endoscalar::alloc` directly). Tied to this reimpl by the
fingerprint equivalence check via the formal instance in
`qa/fv/Ragu/Instances/Endoscalar/Alloc.lean`. -/
def main (value : ProverEnvironment (F p) → BitVec 143)
    : Circuit (F p) (Vector (Expression (F p)) 143) :=
  Circuit.mapFinRange 143 fun (i : Fin 143) =>
    Boolean.Alloc.circuit (fun env => (value env)[i.val])

def Assumptions (_input : Unit) (_data : ProverData (F p)) := True

def ProverAssumptions (_input : BitVec 143) (_data : ProverData (F p))
    (_hint : ProverHint (F p)) := True

/-- The verifier learns that all 143 output wires are boolean. -/
def Spec (_input : Unit) (out : Vector (F p) 143) (_data : ProverData (F p)) :=
  ∀ i : Fin 143, IsBool out[i]

/-- The honest prover's wire `i` holds bit `i` of the 143-bit hint
(LSB-first, matching the Rust `(value >> i) & 1`). Callers use this to chain
the allocated endoscalar's value through composed completeness proofs. -/
def ProverSpec (input : BitVec 143) (out : Vector (F p) 143) (_hint : ProverHint (F p)) :=
  ∀ i : Fin 143, out[i] = if input[i.val] then 1 else 0

instance elaborated
    : ElaboratedCircuit (F p) (UnconstrainedNative (BitVec 143)) (fields 143) main where
  localLength _ := 143 * 3
  localLength_eq _ _ := by
    simp [main, circuit_norm, Boolean.Alloc.circuit]
  subcircuitsConsistent _ _ := by
    simp [main, circuit_norm, Boolean.Alloc.circuit]

theorem soundness
    : GeneralFormalCircuit.WithHint.Soundness (F p) (Input := (UnconstrainedNative (BitVec 143))) (Output := (fields 143)) main Assumptions Spec := by
  circuit_proof_start [Boolean.Alloc.circuit, Boolean.Alloc.Assumptions, Boolean.Alloc.Spec]
  exact h_holds

theorem completeness
    : GeneralFormalCircuit.WithHint.Completeness (F p) (Input := (UnconstrainedNative (BitVec 143))) (Output := (fields 143)) main
        ProverAssumptions ProverSpec := by
  circuit_proof_start [Boolean.Alloc.circuit, Boolean.Alloc.Assumptions, Boolean.Alloc.Spec,
    Boolean.Alloc.ProverAssumptions, Boolean.Alloc.ProverSpec]
  intro i
  exact (h_env i).2

def circuit : GeneralFormalCircuit.WithHint (F p) (UnconstrainedNative (BitVec 143)) (fields 143) :=
  { main := main,
    elaborated := elaborated,
    Assumptions := Assumptions,
    Spec := Spec,
    ProverAssumptions := ProverAssumptions,
    ProverSpec := ProverSpec,
    soundness := soundness,
    completeness := completeness }

end Ragu.Circuits.Endoscalar.Alloc
