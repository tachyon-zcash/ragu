import Ragu.Core

namespace Ragu.Instances.Autogen.NonzeroBank.ScopeK2
open Core.Primes

@[reducible]
def p := Core.Primes.p

@[reducible]
def inputLen := 2

@[reducible]
def outputLen := 0

set_option linter.unusedVariables false in
def exportedOperations (input_var : Vector (Expression (F p)) inputLen) : Operations (F p) := [
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨0⟩) * (var ⟨1⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨2⟩)))),
  Operation.assert (((var ⟨0⟩) + (((-1 : F p) : Expression (F p)) * ((1 : F p) : Expression (F p))))),
  Operation.assert (((var ⟨1⟩) + (((-1 : F p) : Expression (F p)) * (input_var[0])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨3⟩) * (var ⟨4⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨5⟩)))),
  Operation.assert (((var ⟨3⟩) + (((-1 : F p) : Expression (F p)) * (var ⟨2⟩)))),
  Operation.assert (((var ⟨4⟩) + (((-1 : F p) : Expression (F p)) * (input_var[1])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨6⟩) * (var ⟨7⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨8⟩)))),
  Operation.assert (((var ⟨8⟩) + (((-1 : F p) : Expression (F p)) * ((1 : F p) : Expression (F p))))),
  Operation.assert (((var ⟨5⟩) + (((-1 : F p) : Expression (F p)) * (var ⟨6⟩)))),
]

set_option linter.unusedVariables false in
@[reducible]
def exportedOutput (input_var : Vector (Expression (F p)) inputLen) : Vector (Expression (F p)) outputLen := #v[
]

end Ragu.Instances.Autogen.NonzeroBank.ScopeK2
