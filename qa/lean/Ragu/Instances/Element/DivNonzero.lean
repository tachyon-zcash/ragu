import Ragu.Circuits.Element.DivNonzero
import Ragu.Instances.Autogen.Element.DivNonzero
import Ragu.Core

namespace Ragu.Instances.Element.DivNonzero
open Ragu.Instances.Autogen.Element.DivNonzero

def deserializeInput (input : Vector (Expression (F p)) inputLen) :
    Var Circuits.Element.DivNonzero.Input (F p) :=
  { x := input[0], y := input[1], inverse := fun _ => 0 }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.Element.DivNonzero.circuit

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.toWithHint,
      GeneralFormalCircuit.WithHint.toSubcircuit,
      GeneralFormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.DivNonzero.circuit,
      Circuits.Element.DivNonzero.elaborated,
      Circuits.Element.DivNonzero.main,
      Circuits.Element.EnforceNonzero.circuit,
      Circuits.Element.EnforceNonzero.elaborated,
      Circuits.Element.EnforceNonzero.main,
      Circuits.Element.Divide.circuit,
      Circuits.Element.Divide.elaborated,
      Circuits.Element.Divide.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.DivNonzero
