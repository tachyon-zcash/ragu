import Ragu.Circuits.Element.Fold
import Ragu.Core

/-!
`ragu_circuits::horner::Horner` at seven coefficients, the `GroupSize` shape
`protocol/revdot/fold.rs` uses. See `Ragu.Instances.Horner.N3` for why the
reimplementation is `Fold.circuit` itself.
-/

namespace Ragu.Instances.Horner.N7

/-- The prime this instance is fixed at. -/
@[reducible]
def p := Core.Primes.p

/-- Reads the extractor's flat input wires into the reimplementation's
structured input. -/
def deserializeInput (input : Vector (Expression (F p)) 8)
    : Var (Circuits.Element.Fold.Input 7) (F p) :=
  { xs := #v[input[0], input[1], input[2], input[3], input[4], input[5], input[6]],
    s := input[7] }

/-- Writes the reimplementation's output back to the extractor's flat
output wires. -/
def serializeOutput (output : Var field (F p)) : Vector (Expression (F p)) 1 :=
  #v[output]

/-- The formal instance the fingerprint check compares against the Rust
extractor's trace. -/
def formal_instance : Core.Statements.FormalInstance where
  p
  deserializeInput
  serializeOutput

  reimplementation := (Circuits.Element.Fold.circuit 7).isGeneralFormalCircuit.toWithHint

end Ragu.Instances.Horner.N7
