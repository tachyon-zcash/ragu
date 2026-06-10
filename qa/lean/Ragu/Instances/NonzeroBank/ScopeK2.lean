import Ragu.Circuits.NonzeroBank.Scope
import Ragu.Instances.Autogen.NonzeroBank.ScopeK2
import Ragu.Core

namespace Ragu.Instances.NonzeroBank.ScopeK2
open Ragu.Instances.Autogen.NonzeroBank.ScopeK2

def deserializeInput (input : Vector (Expression (F p)) inputLen) :
    Var (Circuits.NonzeroBank.Scope.Input 2) (F p) :=
  { factors := #v[input[0], input[1]], inverse := fun _ => 0 }

def serializeOutput (_output : Var unit (F p)) : Vector (Expression (F p)) 0 :=
  #v[]

def formal_instance : Core.Statements.FormalInstance where
  p
  exportedOperations
  exportedOutput

  deserializeInput
  serializeOutput

  reimplementation := Circuits.NonzeroBank.Scope.circuit 2

  same_constraints := by
    intro input
    -- Unfold the `Circuit.foldl` chain (two `Mul.circuit` folds) plus the
    -- trailing `EnforceNonzero` discharge into the flat autogen list. The
    -- foldl peels via `Vector.foldlM_toList` → `List.foldlM_cons` (×2),
    -- mirroring the `EnforceRootOfUnityK2` recipe.
    simp [Core.Statements.FlatOperation.eraseCompute, List.map,
      Operations.toFlat, circuit_norm,
      GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
      deserializeInput, exportedOperations,
      Circuits.NonzeroBank.Scope.circuit,
      Circuits.NonzeroBank.Scope.elaborated,
      Circuits.NonzeroBank.Scope.main,
      Circuit.foldl, Vector.foldlM_toList,
      Vector.finRange, Vector.ofFn, Vector.toList,
      List.foldlM, List.foldlM_cons,
      Circuits.Element.Mul.circuit,
      Circuits.Element.Mul.elaborated,
      Circuits.Element.Mul.main,
      Circuits.Element.EnforceNonzero.circuit,
      Circuits.Element.EnforceNonzero.elaborated,
      Circuits.Element.EnforceNonzero.main,
      Circuits.Core.Mul.main]
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> rfl
  same_output := by
    intro input
    rfl

end Ragu.Instances.NonzeroBank.ScopeK2
