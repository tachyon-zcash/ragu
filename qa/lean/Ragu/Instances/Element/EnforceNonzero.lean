import Ragu.Circuits.Element.EnforceNonzero
import Ragu.Instances.Autogen.Element.EnforceNonzero
import Ragu.Core

namespace Ragu.Instances.Element.EnforceNonzero
open Ragu.Instances.Autogen.Element.EnforceNonzero

def deserializeInput (input : Vector (Expression (F p)) inputLen) :
    Var Circuits.Element.EnforceNonzero.Input (F p) :=
  { input := input[0], inverse := fun _ => 0 }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.Element.EnforceNonzero.circuit

  same_constraints := by
    intro input
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.WithHint.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.Element.EnforceNonzero.circuit,
      Circuits.Element.EnforceNonzero.elaborated,
      Circuits.Element.EnforceNonzero.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.Element.EnforceNonzero
