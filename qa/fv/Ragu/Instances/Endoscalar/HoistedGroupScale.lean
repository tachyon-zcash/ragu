import Ragu.Circuits.Endoscalar.HoistedGroupScale
import Ragu.Core

namespace Ragu.Instances.Endoscalar.HoistedGroupScale

@[reducible]
def p := Core.Primes.p

/-- Deserialize the flat 239-wire input: 143 endoscalar bits, then 94
hoisted product wires (per digit, `e₁ e₂` then `e₁ e₂ s`), then the curve
point's `(x, y)` coordinates. -/
def deserializeInput (input : Vector (Expression (F p)) 239)
    : Var Circuits.Endoscalar.HoistedGroupScale.Input (F p) :=
  { bits := Vector.ofFn (fun (i : Fin 143) => input[i.val]'(by have := i.isLt; omega))
    products := Vector.ofFn (fun (i : Fin 94) => input[143 + i.val]'(by have := i.isLt; omega))
    pt := ⟨input[237], input[238]⟩ }

/-- Serialize the output point as a 2-wire vector. -/
def serializeOutput (output : Var Circuits.Point.Spec.Point (F p))
    : Vector (Expression (F p)) 2 :=
  #v[output.x, output.y]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    (Circuits.Endoscalar.HoistedGroupScale.circuit
      Circuits.Point.Spec.EpAffineParams).isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.HoistedGroupScale
