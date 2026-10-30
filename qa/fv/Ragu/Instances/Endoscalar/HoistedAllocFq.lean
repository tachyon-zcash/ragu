import Ragu.Circuits.Endoscalar.HoistedAlloc
import Ragu.Core

namespace Ragu.Instances.Endoscalar.HoistedAllocFq

@[reducible]
def p := Core.Primes.q

def deserializeInput (_ : Vector (Expression (F p)) 0)
    : Var (UnconstrainedNative (BitVec 143)) (F p) :=
  fun _ => 0#143

/-- The gadget's wires in order: the 143 bits, then the 94 product wires. -/
def serializeOutput (output : Var Circuits.Endoscalar.HoistedAlloc.Output (F p))
    : Vector (Expression (F p)) 237 :=
  output.bits ++ output.products

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation := Circuits.Endoscalar.HoistedAlloc.circuit

end Ragu.Instances.Endoscalar.HoistedAllocFq
