import Ragu.Circuits.Point.Double
import Ragu.Instances.Autogen.Point.Double
import Ragu.Core

namespace Ragu.Instances.Point.Double
open Ragu.Instances.Autogen.Point.Double

def deserializeInput (input : Vector (Expression (F p)) 2) : Var Circuits.Point.Spec.Point (F p) :=
  { x := input[0], y := input[1] }

def serializeOutput (output : Var Circuits.Point.Spec.Point (F p)) : Vector (Expression (F p)) 2 :=
  #v[ output.x, output.y ]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := (Circuits.Point.Double.circuit Circuits.Point.Spec.EpAffineParams).isGeneralFormalCircuit.toWithHint

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      FormalCircuit.isGeneralFormalCircuit,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
      GeneralFormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Point.Double.circuit,
      Circuits.Point.Double.elaborated,
      Circuits.Point.Double.main,
      Circuits.Element.Square.circuit,
      Circuits.Element.Square.elaborated,
      Circuits.Element.Square.main,
      Circuits.Element.Divide.circuit,
      Circuits.Element.Divide.elaborated,
      Circuits.Element.Divide.main,
      Circuits.Element.Mul.circuit,
      Circuits.Element.Mul.elaborated,
      Circuits.Element.Mul.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl
end Ragu.Instances.Point.Double
