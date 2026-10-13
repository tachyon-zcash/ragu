import Ragu.Circuits.Endoscalar.EnforceProducts
import Ragu.Core

namespace Ragu.Instances.Endoscalar.EnforceProducts

@[reducible]
def p := Core.Primes.p

/-- Deserialize the flat 237-wire input: 143 endoscalar bits, then 94
hoisted product wires. -/
def deserializeInput (input : Vector (Expression (F p)) 237)
    : Var Circuits.Endoscalar.EnforceProducts.Input (F p) :=
  { bits := Vector.ofFn (fun (i : Fin 143) => input[i.val]'(by have := i.isLt; omega))
    products := Vector.ofFn (fun (i : Fin 94) => input[143 + i.val]'(by have := i.isLt; omega)) }

/-- The circuit only constrains; it has no output wires. -/
def serializeOutput (_ : Var unit (F p)) : Vector (Expression (F p)) 0 :=
  #v[]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    Circuits.Endoscalar.EnforceProducts.circuit.isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.EnforceProducts
