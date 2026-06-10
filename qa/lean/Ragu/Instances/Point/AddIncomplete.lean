import Ragu.Circuits.Point.AddIncomplete
import Ragu.Instances.Autogen.Point.AddIncomplete
import Ragu.Core

namespace Ragu.Instances.Point.AddIncomplete
open Ragu.Instances.Autogen.Point.AddIncomplete

def deserializeInput (input : Vector (Expression (F p)) 4) :
    Var Circuits.Point.AddIncomplete.Inputs (F p) :=
  { P1 := ⟨input[0], input[1]⟩,
    P2 := ⟨input[2], input[3]⟩,
    inverse := fun _ => 0 }

def serializeOutput (output : Var Circuits.Point.Spec.Point (F p)) :
    Vector (Expression (F p)) 2 :=
  #v[output.x, output.y]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.Point.AddIncomplete.circuit Circuits.Point.Spec.EpAffineParams

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
      GeneralFormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Point.AddIncomplete.circuit,
      Circuits.Point.AddIncomplete.elaborated,
      Circuits.Point.AddIncomplete.main,
      Circuits.Element.Mul.circuit,
      Circuits.Element.Mul.elaborated,
      Circuits.Element.Mul.main,
      Circuits.Element.Divide.circuit,
      Circuits.Element.Divide.elaborated,
      Circuits.Element.Divide.main,
      Circuits.Element.Square.circuit,
      Circuits.Element.Square.elaborated,
      Circuits.Element.Square.main,
      Circuits.Element.EnforceNonzero.circuit,
      Circuits.Element.EnforceNonzero.elaborated,
      Circuits.Element.EnforceNonzero.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Point.AddIncomplete
