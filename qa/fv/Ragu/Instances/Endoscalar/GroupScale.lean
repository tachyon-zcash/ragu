import Ragu.Circuits.Endoscalar.GroupScale
import Ragu.Core

namespace Ragu.Instances.Endoscalar.GroupScale

@[reducible]
def p := Core.Primes.p

/-- Deserialize the flat 145-wire input: first 143 are endoscalar bits, last 2
are the curve point's `(x, y)` coordinates. -/
def deserializeInput (input : Vector (Expression (F p)) 145)
    : Var Circuits.Endoscalar.GroupScale.Input (F p) :=
  { bits := Vector.ofFn (fun (i : Fin 143) => input[i.val]'(by have := i.isLt; omega))
    pt := ⟨input[143], input[144]⟩ }

/-- Serialize the output point as a 2-wire vector. -/
def serializeOutput (output : Var Circuits.Point.Spec.Point (F p))
    : Vector (Expression (F p)) 2 :=
  #v[output.x, output.y]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    (Circuits.Endoscalar.GroupScale.circuit
      Circuits.Point.Spec.EpAffineParams).isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.GroupScale
