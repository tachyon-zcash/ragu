---
name: clean-circuits
description: Explicitly invoked only. Loads context for the Verified-zkEVM `clean` codebase — an embedded Lean DSL for formally verified zk circuits (AIR/PLONK/R1CS) with Circuit monad, ProvableType/ProvableStruct, FormalCircuit (soundness/completeness), and gadget composition. Do NOT auto-trigger on general Lean, ZK, or circuit questions; only invoke when the user explicitly types `/clean-circuits` or asks by name to use this skill.
---

# AGENTS.md - AI Agent Context for Clean

This document provides context for AI coding agents working on the `clean` codebase.

## What is Clean?

Clean is an embedded Lean DSL for writing formally verified zk (zero-knowledge) circuits. It targets popular arithmetizations like AIR, PLONK, and R1CS. The key value proposition is producing **formally verified, bug-free circuits** with proofs of soundness and completeness.

## Project Structure

```
Clean/
├── Circuit/           # Core circuit DSL and monad
│   ├── Basic.lean     # Circuit monad, FormalCircuit, soundness/completeness definitions
│   ├── Expression.lean # Expression AST (var, const, add, mul)
│   ├── Operations.lean # Operation types (witness, assert, lookup, subcircuit)
│   ├── Provable.lean  # ProvableType, ProvableStruct - typed circuit values
│   ├── Subcircuit.lean # Composing formal circuits
│   ├── Lookup.lean    # Lookup table support
│   └── Theorems.lean  # Core theorems about circuit semantics
├── Gadgets/           # Reusable verified circuit components
│   ├── Boolean.lean   # Boolean constraints (IsBool, assertBool)
│   ├── Equality.lean  # Equality assertions (===)
│   ├── IsZero.lean    # Zero-check circuits
│   ├── ByteDecomposition/ # Byte manipulation
│   ├── BLAKE3/        # BLAKE3 hash function circuits
│   ├── Keccak/        # Keccak hash circuits
│   └── ...
├── Types/             # Domain-specific types (U32, U64, etc.)
├── Tables/            # Lookup tables and table-based circuits
├── Specs/             # Pure specifications (BLAKE3, Keccak specs)
├── Utils/             # Utilities and tactics
│   └── Tactics/
│       ├── CircuitProofStart.lean  # Main proof automation
│       └── ProvableStructDeriving.lean # Deriving handler
└── Circomlib/         # Circom library ports
```

## Core Concepts

### The Circuit Monad

Circuits are written using the `Circuit F α` monad, which accumulates operations:

```lean
def myCircuit (x : Expression F) : Circuit F (Expression F) := do
  let y ← witness fun env => env x + 1  -- witness a new variable
  y === x + 1                           -- add constraint: y = x + 1
  return y
```

In that example, `===` is custom syntax which adds an `assertZero` operation.

### Key Operations

- `witness` / `witnessVar` / `witnessField`: Create new witness variables
- `lookup`: Add lookup constraint (value must be in table)
- `===`: Assert equality between two values
- `<==`: Witness and constrain equal to expression

### ProvableType and ProvableStruct

Types that can appear in circuits implement `ProvableType`:

- `field`: Single field element
- `fieldPair`, `fieldTriple`: 2- and 3-tuples of field elements
- `fields n`: Vector of n field elements
- `ProvableVector α n`: Vector of n elements of type α
- Custom structures via `ProvableStruct`

Use `deriving ProvableStruct` for automatic instance generation:

```lean
structure MyInputs (F : Type) where
  x : F
  y : U32 F
  data : Vector (U32 F) 16
deriving ProvableStruct
```

**Prover-hint inputs.** Some circuits accept prover-only auxiliary data via `Unconstrained T` (a free `T` value the prover supplies, with no constraint linking it to a wire) or `UnconstrainedDep T` (the same, but allowed to depend on already-computed wires through an `eval` closure). These are useful for parameterizing witness generation — the prover supplies a hint, the gadget body uses it inside `Operation.witness` closures. Verifier reasoning never sees these values.

### FormalCircuit

A `FormalCircuit` bundles a circuit with its correctness proofs:

```lean
structure FormalCircuit (F : Type) (Input Output : TypeMap) where
  main : Var Input F → Circuit F (Var Output F)
  Assumptions : Input F → Prop      -- preconditions
  Spec : Input F → Output F → Prop  -- postcondition (input-output relation)
  soundness : Soundness F ...       -- constraints → assumptions → spec
  completeness : Completeness F ... -- assumptions → constraints satisfiable
```

**Soundness**: For any witness assignment satisfying constraints, the spec holds.
**Completeness**: Given assumptions, there exists a witness satisfying constraints.

**`GeneralFormalCircuit` and `FormalAssertion`.** Two siblings of `FormalCircuit` exist for cases where the basic shape doesn't fit. `FormalAssertion` is for assertion-shaped gadgets where the constraints intentionally narrow inputs (`Assumptions ↔ Spec`). `GeneralFormalCircuit` adds two extra prover-side fields, `ProverAssumptions` (preconditions visible only to completeness) and `ProverSpec` (extra prover-side conclusions), for circuits where the prover and verifier need different precondition/conclusion bodies.

### Subcircuits

Compose formal circuits using the subcircuit mechanism and the `CoeFun` instance for `FormalCircuit`:

```lean
def main (input : Var Inputs F) : Circuit F (Var Outputs F) := do
  let result ← innerCircuit input.someField -- `innerCircuit : FormalCircuit ..` being used like a function
  ...
```

### Loop combinators (`Clean/Circuit/Loops.lean`)

Clean ships five loop combinators with `circuit_norm`-tagged simp lemmas. **Use these for any iteration**; don't write recursive helper functions (`fooStep` / `barIter` patterns) — they require manual induction proofs and bypass the auto-simp path that `circuit_proof_start` is designed around.

| Combinator | Signature (sketch) | Use when |
|---|---|---|
| `Circuit.forEach xs body` | `Vector α m → (α → Circuit F Unit)` | Constraint-only iteration; body emits constraints, no accumulator. |
| `Circuit.map xs body` | `Vector α m → (α → Circuit F β) → Circuit F (Vector β m)` | Element-wise transform; per-iter output collected into a Vector. |
| `Circuit.mapFinRange m body` | `(Fin m → Circuit F β) → Circuit F (Vector β m)` | Like `map` but iterates over `Fin m` indices directly. |
| `Circuit.foldl xs init body` | `Vector α m → β → (β → α → Circuit F β) → Circuit F β` | Accumulating fold; threads `β` through iterations. |
| `Circuit.foldlRange m init body` | `(Fin m → ...)` | Like `foldl` but iterates over `Fin m` instead of an element vector. |

**Typeclass requirements.** All of `foldl`, `foldlRange`, `mapFinRange` require `[Inhabited β]`; `foldl` additionally requires `[Inhabited α]` for the element type. `Fin k` has no `Inhabited` instance when `k = 0` — so a polymorphic gadget using `Circuit.foldl (.finRange k)` typically rcases `k` to handle the `k = 0` case separately, then invokes the foldl in the `k+1` branch where `Fin (k+1)` IS `Inhabited`.

**`ConstantOutput` requirement (foldl only).** `Circuit.foldl` carries a default-tactic argument
```lean
(_const_out : ConstantOutput (fun (s, a) => body s a) := by simp only [circuit_norm]; intros; rfl)
```
which asserts the body's *symbolic output* is invariant under (acc, element). This is what unlocks `foldl.output_eq` in `circuit_norm` — the foldl collapses to a single body application at the last index, cleanly threadable through `circuit_proof_start`. If your body returns a fresh wire (`Mul.circuit` output is `var ⟨offset + 2⟩`), `ConstantOutput` holds trivially. If it returns `wire + xs[i+1]` (index-dependent), `ConstantOutput` fails and `Circuit.foldl` won't elaborate.

**`foldlRange` lacks `ConstantOutput`.** Its corresponding `foldlRange.output_eq` leaves `Circuit.FoldlM.foldlAcc` unexpanded — proofs work but require manual induction over the foldl. Prefer `foldl` when the body's output happens to be acc/index-independent (often achievable by restructuring: pull the index-dependent addition *outside* the loop, or push it into the *input* of a subcircuit so its output is just a fresh wire).

### Auto-simp philosophy

The intended UX (per mitschabaude): `circuit_proof_start` yields a goal that looks like *normal Lean/Mathlib math* — the circuit-specific machinery (loop combinators, subcircuit calls, witness/assert offsets) has already been collapsed by `circuit_norm`. Users then reason with `induction`, `ring`, `simp`, mathlib lemmas, etc. If you find yourself invoking circuit-specific simp lemmas explicitly (e.g., `simp [foldlRange.output_eq, Circuit.FoldlM.foldlAcc]`), you're off the happy path — either pick a different combinator (one whose lemmas already fire under `circuit_norm`) or restructure the gadget so the auto-simp path applies.

## Proof Patterns

### Starting a Proof

Use `circuit_proof_start` tactic to set up soundness/completeness proofs:

```lean
theorem soundness : Soundness F elaborated Assumptions Spec := by
  circuit_proof_start
  -- Now have: h_input, h_assumptions, h_holds
  ...
```

### Key Simp Sets

- `circuit_norm`: Main simplification set for circuit reasoning
- `explicit_provable_type`: Unfolds ProvableType definitions when needed

## Conventions

- Use `F p` for field type where `p` is prime
- Use `Var α F` for circuit variables of type `α`
- Specs are pure Lean propositions relating inputs to outputs
- Assumptions capture preconditions (e.g., value ranges)
- Follow Mathlib naming conventions

## Key Files to Understand

1. `Clean/Circuit/Basic.lean` - Circuit monad and FormalCircuit
2. `Clean/Circuit/Provable.lean` - ProvableType/ProvableStruct system
3. `Clean/Circuit/Subcircuit.lean` - Circuit composition
4. `Clean/Gadgets/Boolean.lean` - Simple gadget example
5. `Clean/Gadgets/ByteDecomposition/ByteDecomposition.lean` - Complex gadget with lookups

## Common Tasks

### Adding a New Gadget

1. Define the `main` circuit function
2. Define `Assumptions` and `Spec`
3. Create `ElaboratedCircuit` instance with `localLength` and `output`
4. Prove `soundness` and `completeness`
5. Bundle into `FormalCircuit`
