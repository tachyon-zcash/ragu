import Ragu.Core

namespace Ragu.Instances.Autogen.Element.Invert
open Core.Primes

@[reducible]
def p := Core.Primes.p

@[reducible]
def inputLen := 1

@[reducible]
def outputLen := 1

set_option linter.unusedVariables false in
def exportedOperations (input_var : Vector (Expression (F p)) inputLen) : Operations (F p) := [
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨0⟩) * (var ⟨1⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨2⟩)))),
  Operation.assert (((var ⟨2⟩) + (((-1 : F p) : Expression (F p)) * ((1 : F p) : Expression (F p))))),
  Operation.assert (((input_var[0]) + (((-1 : F p) : Expression (F p)) * (var ⟨0⟩)))),
]

set_option linter.unusedVariables false in
@[reducible]
def exportedOutput (input_var : Vector (Expression (F p)) inputLen) : Vector (Expression (F p)) outputLen := #v[
  (var ⟨1⟩)
]

end Ragu.Instances.Autogen.Element.Invert
