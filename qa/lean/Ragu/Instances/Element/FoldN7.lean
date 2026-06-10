import Ragu.Circuits.Element.Fold
import Ragu.Instances.Autogen.Element.FoldN7
import Ragu.Core

namespace Ragu.Instances.Element.FoldN7
open Ragu.Instances.Autogen.Element.FoldN7

def deserializeInput (input : Vector (Expression (F p)) inputLen)
    : Var (Circuits.Element.Fold.Input 7) (F p) :=
  { xs := #v[input[0], input[1], input[2], input[3], input[4], input[5], input[6]],
    s := input[7] }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := (Circuits.Element.Fold.circuit 7).isGeneralFormalCircuit.toWithHint

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      FormalCircuit.isGeneralFormalCircuit,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.Fold.circuit,
      Circuits.Element.Fold.elaborated,
      Circuits.Element.Fold.main,
      Circuit.foldl, Vector.foldlM_toList,
      Vector.finRange, Vector.ofFn, Vector.toList,
      List.foldlM, List.foldlM_cons,
      Circuits.Element.Mul.circuit, Circuits.Element.Mul.main]
    constructor
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.FoldN7
