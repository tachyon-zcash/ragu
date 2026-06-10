import Clean.Circuit
import Clean.Circuit.Loops

namespace Ragu.CircuitFlattening

variable {F : Type} [Field F]

/-!
Helpers for comparing generated flat operation lists with hand-written Clean circuits.

Proofs of generated instances tend to fail from normalization shape, not missing arithmetic facts. A
useful pattern is:

* Normalize only the circuit side first with `conv_lhs => simp [...]`. If `exportedOperations` is
  in scope too early, generated definitions can become looping simp rules.
* Flatten in phases. The first pass usually exposes loop bodies and subcircuits; a second pass,
  after reducing finite accumulators, is often what turns those exposed subcircuits into the
  generated flat list.
* When adding a helper here, prefer projection lemmas such as `..._output_eq`,
  `..._localLength_eq`, and `..._toFlat_eq` over one huge circuit-specific rewrite. They compose
  better with `simp` and keep generated instance proofs local.
-/

lemma subcircuitWithHintAssertion_toFlat {α β : TypeMap} [CircuitType α] [CircuitType β]
    (circuit : GeneralFormalCircuit.WithHint F β α) (input : Var β F) (n : ℕ) :
    ((subcircuitWithHintAssertion circuit input).operations n).toFlat =
      (circuit.main input |>.operations n).toFlat := by
  dsimp [subcircuitWithHintAssertion, GeneralFormalCircuit.WithHint.toSubcircuit,
    Circuit.operations, Operations.toFlat]
  simp [Operations.toNested_toFlat]

lemma subcircuitWithHintAssertion_output_eq {α β : TypeMap} [CircuitType α] [CircuitType β]
    (circuit : GeneralFormalCircuit.WithHint F β α) (input : Var β F) (offset : ℕ) :
    (subcircuitWithHintAssertion circuit input).output offset = circuit.output input offset := by
  rfl

lemma subcircuitWithHintAssertion_localLength_eq {α β : TypeMap} [CircuitType α] [CircuitType β]
    (circuit : GeneralFormalCircuit.WithHint F β α) (input : Var β F) (offset : ℕ) :
    (subcircuitWithHintAssertion circuit input).localLength offset = circuit.localLength input := by
  simp [subcircuitWithHintAssertion, Circuit.localLength, Circuit.operations, Operations.localLength,
    GeneralFormalCircuit.WithHint.toSubcircuit]

lemma formal_toSubcircuit_toFlat {α β : TypeMap} [ProvableType α] [ProvableType β]
    (circuit : FormalCircuit F β α) (input : Var β F) (n : ℕ) :
    (circuit.toSubcircuit n input).ops.toFlat = (circuit.main input |>.operations n).toFlat := by
  dsimp [FormalCircuit.toSubcircuit]
  simp [Operations.toNested_toFlat]

lemma general_toSubcircuit_toFlat {α β : TypeMap} [ProvableType α] [ProvableType β]
    (circuit : GeneralFormalCircuit F β α) (input : Var β F) (n : ℕ) :
    (circuit.toSubcircuit n input).ops.toFlat = (circuit.main input |>.operations n).toFlat := by
  dsimp [GeneralFormalCircuit.toSubcircuit, GeneralFormalCircuit.toWithHint,
    GeneralFormalCircuit.WithHint.toSubcircuit]
  simp [Operations.toNested_toFlat]

lemma withHint_toSubcircuit_toFlat {α β : TypeMap} [CircuitType α] [CircuitType β]
    (circuit : GeneralFormalCircuit.WithHint F β α) (input : Var β F) (n : ℕ) :
    (circuit.toSubcircuit n input).ops.toFlat = (circuit.main input |>.operations n).toFlat := by
  dsimp [GeneralFormalCircuit.WithHint.toSubcircuit]
  simp [Operations.toNested_toFlat]

-- `Operations.toFlat` does not unfold through append unless we tell it to. This is the small
-- distributivity fact that lets a second flattening pass see each exposed subcircuit separately.
lemma operations_toFlat_append (xs ys : Operations F) :
    Operations.toFlat (xs ++ ys) = Operations.toFlat xs ++ Operations.toFlat ys := by
  induction xs with
  | nil => rfl
  | cons x xs ih =>
    cases x <;> simp [Operations.toFlat, ih, List.append_assoc]

lemma subcircuit_output_eq {α β : TypeMap} [ProvableType α] [ProvableType β]
    (circuit : FormalCircuit F β α) (input : Var β F) (offset : ℕ) :
    (subcircuit circuit input).output offset = circuit.output input offset := by
  rfl

lemma subcircuit_operations_toFlat_eq {α β : TypeMap} [ProvableType α] [ProvableType β]
    (circuit : FormalCircuit F β α) (input : Var β F) (offset : ℕ) :
    ((subcircuit circuit input).operations offset).toFlat =
      (circuit.main input |>.operations offset).toFlat := by
  simp [subcircuit, Circuit.operations, Operations.toFlat, formal_toSubcircuit_toFlat]

lemma subcircuit_localLength_eq {α β : TypeMap} [ProvableType α] [ProvableType β]
    (circuit : FormalCircuit F β α) (input : Var β F) (offset : ℕ) :
    (subcircuit circuit input).localLength offset = circuit.localLength input := by
  simp [subcircuit, Circuit.localLength, Circuit.operations, Operations.localLength,
    FormalCircuit.toSubcircuit]

-- `Circuit.foldlRange` hides the `ConstantLength` argument that the lower-level
-- `Circuit.FoldlM.operations_eq` theorem needs. This bridge exposes the operations without making
-- each generated instance restate the same `foldlRange` unfolding and constant-length bookkeeping.
lemma foldlRange_operations_eq {β : Type} [Inhabited β] {m : ℕ} (init : β)
    (body : β → Fin m → Circuit F β)
    (constant : Circuit.ConstantLength (fun t : β × Fin m => body t.1 t.2)) (n : ℕ) :
    (Circuit.foldlRange m init body constant).operations n =
      (List.ofFn fun i : Fin m =>
        (body (Circuit.FoldlM.foldlAcc n (Vector.finRange m) body init i) i).operations
          (n + i * (body init i).localLength)).flatten := by
  rw [Circuit.foldlRange, Circuit.FoldlM.operations_eq (constant := constant)]
  simp only [Vector.getElem_finRange, Fin.eta]
  congr! 5
  rw [constant.localLength_eq (_, _)]

end Ragu.CircuitFlattening
