import Ragu.Circuits.Element.EnforceRootOfUnity
import Ragu.Instances.Autogen.Element.EnforceRootOfUnityK5
import Ragu.Core

namespace Ragu.Instances.Element.EnforceRootOfUnityK5
open Ragu.Instances.Autogen.Element.EnforceRootOfUnityK5

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

  reimplementation := (Circuits.Element.EnforceRootOfUnity.circuit 5).isGeneralFormalCircuit.toWithHint

  same_constraints := by
    intro input
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

end Ragu.Instances.Element.EnforceRootOfUnityK5
