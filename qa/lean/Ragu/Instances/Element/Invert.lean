import Ragu.Circuits.Element.Invert
import Ragu.Instances.Autogen.Element.Invert
import Ragu.Core

namespace Ragu.Instances.Element.Invert
open Ragu.Instances.Autogen.Element.Invert

def deserializeInput (input : Vector (Expression (F p)) inputLen) :
    Var field (F p) :=
  input[0]

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.Element.Invert.circuit.toWithHint

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.Invert.circuit,
      Circuits.Element.Invert.elaborated,
      Circuits.Element.Invert.main,
      Circuits.Element.InvertWith.circuit,
      Circuits.Element.InvertWith.elaborated,
      Circuits.Element.InvertWith.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.Invert
