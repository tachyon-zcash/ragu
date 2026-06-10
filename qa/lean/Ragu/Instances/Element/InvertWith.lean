import Ragu.Circuits.Element.InvertWith
import Ragu.Instances.Autogen.Element.InvertWith
import Ragu.Core

namespace Ragu.Instances.Element.InvertWith
open Ragu.Instances.Autogen.Element.InvertWith

def deserializeInput (input : Vector (Expression (F p)) inputLen) :
    Var Circuits.Element.InvertWith.Input (F p) :=
  { input := input[0], inverse := fun _ => 0 }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.Element.InvertWith.circuit

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.WithHint.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.InvertWith.circuit,
      Circuits.Element.InvertWith.elaborated,
      Circuits.Element.InvertWith.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.InvertWith
