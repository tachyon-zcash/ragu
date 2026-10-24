import Ragu.Circuits.Endoscalar.HoistedLift
import Ragu.Core

namespace Ragu.Instances.Endoscalar.HoistedLift

@[reducible]
def p := Core.Primes.p

/-- Deserialize the flat 237-wire input: 143 endoscalar bits, then 94
hoisted product wires. -/
def deserializeInput (input : Vector (Expression (F p)) 237)
    : Var Circuits.Endoscalar.HoistedLift.Input (F p) :=
  { bits := Vector.ofFn (fun (i : Fin 143) => input[i.val]'(by have := i.isLt; omega))
    products := Vector.ofFn (fun (i : Fin 94) => input[143 + i.val]'(by have := i.isLt; omega)) }

def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    (Circuits.Endoscalar.HoistedLift.circuit
      Circuits.Point.Spec.EpAffineParams).isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.HoistedLift
