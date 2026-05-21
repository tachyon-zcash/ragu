import Ragu.Core

namespace Ragu.Instances.Autogen.Element.FoldN7
open Core.Primes

@[reducible]
def p := Core.Primes.p

@[reducible]
def inputLen := 8

@[reducible]
def outputLen := 1

set_option linter.unusedVariables false in
def exportedOperations (input_var : Vector (Expression (F p)) inputLen) : Operations (F p) := [
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨0⟩) * (var ⟨1⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨2⟩)))),
  Operation.assert (((var ⟨0⟩) + (((-1 : F p) : Expression (F p)) * (input_var[0])))),
  Operation.assert (((var ⟨1⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨3⟩) * (var ⟨4⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨5⟩)))),
  Operation.assert (((var ⟨3⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨2⟩) + (input_var[1]))))),
  Operation.assert (((var ⟨4⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨6⟩) * (var ⟨7⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨8⟩)))),
  Operation.assert (((var ⟨6⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨5⟩) + (input_var[2]))))),
  Operation.assert (((var ⟨7⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨9⟩) * (var ⟨10⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨11⟩)))),
  Operation.assert (((var ⟨9⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨8⟩) + (input_var[3]))))),
  Operation.assert (((var ⟨10⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨12⟩) * (var ⟨13⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨14⟩)))),
  Operation.assert (((var ⟨12⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨11⟩) + (input_var[4]))))),
  Operation.assert (((var ⟨13⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
  Operation.witness 3 (fun _env => default),
  Operation.assert ((((var ⟨15⟩) * (var ⟨16⟩)) + (((-1 : F p) : Expression (F p)) * (var ⟨17⟩)))),
  Operation.assert (((var ⟨15⟩) + (((-1 : F p) : Expression (F p)) * ((var ⟨14⟩) + (input_var[5]))))),
  Operation.assert (((var ⟨16⟩) + (((-1 : F p) : Expression (F p)) * (input_var[7])))),
]

set_option linter.unusedVariables false in
@[reducible]
def exportedOutput (input_var : Vector (Expression (F p)) inputLen) : Vector (Expression (F p)) outputLen := #v[
  ((var ⟨17⟩) + (input_var[6]))
]

end Ragu.Instances.Autogen.Element.FoldN7
