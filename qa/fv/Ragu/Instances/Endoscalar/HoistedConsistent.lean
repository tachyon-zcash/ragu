import Ragu.Circuits.Endoscalar.HoistedConsistent
import Ragu.Core

/-!
`ragu_primitives::endoscalar::HoistedEndoscalar::enforce_consistent`: a fresh
`HoistedEndoscalar::alloc` seeded from the gadget's own witness, linked to it
wire by wire — the constraints the staging machinery re-emits when it
substitutes the gadget's wires into a context where `alloc` never ran.
-/

namespace Ragu.Instances.Endoscalar.HoistedConsistent

@[reducible]
def p := Core.Primes.p

/-- Deserialize the flat 237-wire input: 143 endoscalar bits, then 94
hoisted product wires. -/
def deserializeInput (input : Vector (Expression (F p)) 237)
    : Var Circuits.Endoscalar.HoistedConsistent.Input (F p) :=
  { bits := Vector.ofFn (fun (i : Fin 143) => input[i.val]'(by have := i.isLt; omega))
    products := Vector.ofFn (fun (i : Fin 94) => input[143 + i.val]'(by have := i.isLt; omega)) }

/-- An assertion returns nothing. -/
def serializeOutput (_ : Var unit (F p)) : Vector (Expression (F p)) 0 :=
  #v[]

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation :=
    Circuits.Endoscalar.HoistedConsistent.circuit.isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Endoscalar.HoistedConsistent
