import Lean.Util.FoldConsts
import Ragu.Meta.TrustBoundary

/-!
# Elaborated contract-composition census

The source lint catches qualified `.main` references as written. This check
complements it against Lean's elaborated environment: it finds every
project-owned definition whose final result is `Circuit`, independent of the
definition's name, pins the registered count, and rejects direct references to a
different Ragu circuit's `main` or to the raw `FormalCircuitBase.main`
projection.
-/

namespace Ragu.Meta

open Lean Elab Command

/-- The head constant of a declaration's final result type. -/
def finalResultHead? : Expr → Option Name
  | .forallE _ _ body _ => finalResultHead? body
  | .letE _ _ _ body _ => finalResultHead? body
  | type => type.consumeMData.getAppFn.constName?

/-- Whether an elaborated declaration is a Ragu circuit-building definition. -/
def isCircuitBuilder (name : Name) (info : ConstantInfo) : Bool :=
  !name.isInternal &&
    (`Ragu.Circuits).isPrefixOf name &&
    info.value?.isSome &&
    finalResultHead? info.type == some ``Circuit

/-- All imported Ragu circuit builders, sorted for stable diagnostics. -/
def circuitBuilders (env : Environment) : Array Name := Id.run do
  let mut builders := #[]
  for (name, info) in env.constants.toList do
    if isCircuitBuilder name info then
      builders := builders.push name
  return builders.qsort Name.lt

/-- Constants directly present in a declaration body, without unfolding them. -/
def directConstants (info : ConstantInfo) : Array Name :=
  match info.value? with
  | none => #[]
  | some value => Expr.foldConsts value #[] fun name names => names.push name

/-- A direct reference that bypasses a packaged child circuit. -/
def isDirectMainBypass (builder referenced : Name) : Bool :=
  (referenced != builder && (`Ragu.Circuits).isPrefixOf referenced &&
    match referenced with
    | .str _ "main" => true
    | _ => false) ||
  referenced == ``FormalCircuitBase.main

/-- Builder/direct-reference pairs that bypass the packaged contract boundary. -/
def contractCompositionBypasses (env : Environment) : Array (Name × Name) := Id.run do
  let mut bypasses := #[]
  for builder in circuitBuilders env do
    let some info := env.find? builder | continue
    for referenced in directConstants info do
      if isDirectMainBypass builder referenced then
        bypasses := bypasses.push (builder, referenced)
  return bypasses.qsort fun a b =>
    if a.1 == b.1 then Name.lt a.2 b.2 else Name.lt a.1 b.1

/-- Fail unless the elaborated circuit-builder census and composition boundary
match the reviewed state. -/
elab "assert_contract_composition " expected:num : command => do
  let env ← getEnv
  let builders := circuitBuilders env
  unless builders.size == expected.getNat do
    throwError "expected {expected.getNat} registered Ragu circuit builders, found \
      {builders.size}: {builders.toList}"
  let bypasses := contractCompositionBypasses env
  unless bypasses.isEmpty do
    throwError "circuit builder(s) directly reference a child implementation \
      instead of its packaged contract: {bypasses.toList}"

end Ragu.Meta

assert_contract_composition 62
