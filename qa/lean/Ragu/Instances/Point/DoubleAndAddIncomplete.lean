import Ragu.Circuits.Point.DoubleAndAddIncomplete
import Ragu.Instances.Autogen.Point.DoubleAndAddIncomplete
import Ragu.CircuitFlattening
import Ragu.Core

namespace Ragu.Instances.Point.DoubleAndAddIncomplete
open Ragu.Instances.Autogen.Point.DoubleAndAddIncomplete

def deserializeInput (input : Vector (Expression (F p)) inputLen)
    : Var Circuits.Point.DoubleAndAddIncomplete.Inputs (F p) :=
  { P1 := { x := input[0], y := input[1] },
    P2 := { x := input[2], y := input[3] },
    inverse := fun _ => 0 }

def serializeOutput (output : Var Circuits.Point.Spec.Point (F p))
    : Vector (Expression (F p)) 2 :=
  #v[output.x, output.y]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation :=
    Circuits.Point.DoubleAndAddIncomplete.circuit Circuits.Point.Spec.EpAffineParams

  same_constraints := by
    intro input
    rw [CircuitFlattening.subcircuitWithHintAssertion_toFlat]
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      deserializeInput, exportedOperations,
      Circuits.Point.DoubleAndAddIncomplete.circuit,
      Circuits.Point.DoubleAndAddIncomplete.elaborated,
      Circuits.Point.DoubleAndAddIncomplete.main,
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
      Circuits.Core.Mul.main,
      CircuitFlattening.formal_toSubcircuit_toFlat,
      CircuitFlattening.general_toSubcircuit_toFlat,
      CircuitFlattening.withHint_toSubcircuit_toFlat]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
            ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Point.DoubleAndAddIncomplete
