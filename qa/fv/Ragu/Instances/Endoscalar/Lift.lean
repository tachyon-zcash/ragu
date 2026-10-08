import Ragu.Circuits.Endoscalar.Lift
import Ragu.Core

namespace Ragu.Instances.Endoscalar.Lift

@[reducible]
def p := Core.Primes.p

def deserializeInput (input : Vector (Expression (F p)) 143)
    : Var Circuits.Endoscalar.Lift.Input (F p) :=
  { bits := input }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    (Circuits.Endoscalar.Lift.circuit
      Circuits.Point.Spec.EpAffineParams).isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.Lift
