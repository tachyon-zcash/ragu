import Ragu.Circuits.Endoscalar.Hoist
import Ragu.Core

namespace Ragu.Instances.Endoscalar.HoistFq

@[reducible]
def p := Core.Primes.q

/-- Deserialize the flat 143-wire input: the endoscalar bits. -/
def deserializeInput (input : Vector (Expression (F p)) 143)
    : Var Circuits.Endoscalar.Hoist.Input (F p) :=
  { bits := input }

/-- The 94 product wires, per digit `e₁ e₂` then `e₁ e₂ s`. -/
def serializeOutput (output : Var (fields 94) (F p)) : Vector (Expression (F p)) 94 :=
  output

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    Circuits.Endoscalar.Hoist.circuit.isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.HoistFq
