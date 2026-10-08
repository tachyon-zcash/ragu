import Ragu.Circuits.Endoscalar.HoistedAlloc
import Ragu.Core

namespace Ragu.Instances.Endoscalar.HoistedAlloc

@[reducible]
def p := Core.Primes.p

def deserializeInput (_ : Vector (Expression (F p)) 0)
    : Var (UnconstrainedNative (BitVec 143)) (F p) :=
  fun _ => 0#143

def serializeOutput (output : Var (fields 237) (F p))
    : Vector (Expression (F p)) 237 :=
  output

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation := Circuits.Endoscalar.HoistedAlloc.circuit

end Ragu.Instances.Endoscalar.HoistedAlloc
