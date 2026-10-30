import Ragu.Circuits.Endoscalar.Alloc
import Ragu.Core

namespace Ragu.Instances.Endoscalar.Alloc

@[reducible]
def p := Core.Primes.p

def deserializeInput (_ : Vector (Expression (F p)) 0)
    : Var (UnconstrainedNative (BitVec 143)) (F p) :=
  fun _ => 0#143

def serializeOutput (output : Var (fields 143) (F p))
    : Vector (Expression (F p)) 143 :=
  output

def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation := Circuits.Endoscalar.Alloc.circuit

end Ragu.Instances.Endoscalar.Alloc
