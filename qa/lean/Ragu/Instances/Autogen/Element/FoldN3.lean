import Ragu.Core

namespace Ragu.Instances.Autogen.Element.FoldN3
open Core.Primes

@[reducible]
def p := Core.Primes.p

@[reducible]
def inputLen := 4

@[reducible]
def outputLen := 1

set_option linter.unusedVariables false in
def exportedOperations (input_var : Vector (Expression (F p)) inputLen) : Operations (F p) := [
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨0⟩) * (var ⟨1⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨2⟩)))),
  Operation.assert (((var ⟨0⟩) + (((-1 : F p) : Expression (F p)) * (input_var[0])))),
  Operation.assert (((var ⟨1⟩) + (((-1 : F p) : Expression (F p)) * (input_var[3])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨3⟩) * (var ⟨4⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨5⟩)))),
  Operation.assert (((var ⟨3⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨2⟩) + (input_var[1]))))),
  Operation.assert (((var ⟨4⟩) + (((-1 : F p) : Expression (F p)) * (input_var[3])))),
]

set_option linter.unusedVariables false in
@[reducible]
def exportedOutput (input_var : Vector (Expression (F p)) inputLen) : Vector (Expression (F p)) outputLen := #v[
  ((var ⟨5⟩) + (input_var[2]))
]

end Ragu.Instances.Autogen.Element.FoldN3
