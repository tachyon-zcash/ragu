import Ragu.Circuits.Element.EnforceRootOfUnity
import Ragu.Instances.Autogen.Element.EnforceRootOfUnityK2
import Ragu.Core

namespace Ragu.Instances.Element.EnforceRootOfUnityK2
open Ragu.Instances.Autogen.Element.EnforceRootOfUnityK2

def deserializeInput (input : Vector (Expression (F p)) inputLen) : Var field (F p) :=
  input[0]

def serializeOutput (_output : Var unit (F p)) : Vector (Expression (F p)) 0 :=
  #v[]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := (Circuits.Element.EnforceRootOfUnity.circuit 2).isGeneralFormalCircuit.toWithHint

  same_constraints := by
    intro input
    -- Unfold the `Circuit.foldl` chain into a flat list of `Mul.circuit`
    -- subcircuits + the final `assertZero`, matching the autogen byte-for-byte.
    -- The key unfolds are `Vector.foldlM_toList` (foldl over Vector → List)
    -- then `List.foldlM_cons` reduces the 2-element list iteration.
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      FormalAssertion.isGeneralFormalCircuit,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.EnforceRootOfUnity.circuit,
      Circuits.Element.EnforceRootOfUnity.elaborated,
      Circuits.Element.EnforceRootOfUnity.main,
      Circuit.foldl, Vector.foldlM_toList,
      Vector.finRange, Vector.ofFn, Vector.toList,
      List.foldlM, List.foldlM_cons,
      Circuits.Element.Mul.circuit, Circuits.Element.Mul.main]
    constructor
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.EnforceRootOfUnityK2
