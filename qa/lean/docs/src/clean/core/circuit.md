# The Circuit monad

At the lowest level, Clean represents a circuit as a monadic program that produces two things:

- a return value, usually the circuit outputs represented as variables, and
- a list of low-level operations such as witnesses, assertions, and subcircuits.

In the Lean code, the definition is:

```lean
def Circuit (F : Type) [Field F] (α : Type) := ℕ → α × List (Operation F)
```

So a `Circuit F α` is a function from an `offset` to a pair:

- an output of type `α`, and
- the operations emitted by the circuit.

The `offset` tracks where newly introduced witness variables start. This is why the circuit monad behaves like a combination of a writer monad, because it accumulates `Operation`s, and a state monad, because it threads the current witness offset through the computation.

The key definition for the `Circuit` monad is `bind`, which defines how circuits are constructed.

```lean
def bind {α β} (f : Circuit F α) (g : α → Circuit F β) : Circuit F β := fun (n : ℕ) =>
  let (a, ops) := f n
  let (b, ops') := g a (n + Operations.localLength ops)
  (b, ops ++ ops')
```

This is the mechanism behind `do` notation. If a circuit fragment `f` emits some operations, then the next fragment `g` starts at the offset after the local witnesses introduced by `f`.
Clean computes that offset with `Operations.localLength`.
The intuitive idea for this behavior is that circuits allocate variables sequentially on the environment.
We will discuss the environment in a later section, for now it can be thought of as a tape of empty slots circuits can fill with variables during allocation, and reference during constraint definition.

Notice that when writing circuits, those details will be mostly hidden behind a high-level API, so the user rarely needs to reason about such low-level concepts.
We still describe them because they may come up when proving.

## Primitive circuit operations

The most important primitive operations for defining circuits are:

```lean
def ProvableType.witness {α : TypeMap} [ProvableType α]
    (compute : ProverEnvironment F → α F) : Circuit F (α (Expression F)) :=
  fun (offset : ℕ) =>
    let var := varFromOffset α offset
    (var, [.witness (size α) (fun env => compute env |> toElements)])

def assertZero (e : Expression F) : Circuit F Unit := fun _ =>
  ((), [.assert e])
```

These two operations correspond to exactly two fundamental circuit definition operations:

- **Allocating new variables** by witnessing some prover-provided values. We will talk about `ProvableType` in a later section, for now it suffices to say that this is a structured collection of field elements. Examples of provable types could be an elliptic curve point, composed of two field elements, or a `U32`, composed of four byte limbs.
- **Enforcing some constraints** on the allocated variables. The `Expression` passed to `assertZero` is enforced implicitly to be equal to zero.


Finally, Clean exposes helper projections for results of a circuit:

```lean
def operations (circuit : Circuit F α) (offset : ℕ) : Operations F := (circuit offset).2
def output (circuit : Circuit F α) (offset : ℕ) : α := (circuit offset).1
def localLength (circuit : Circuit F α) (offset := 0) : ℕ :=
  Operations.localLength (circuit offset).2
```

## Iteration: use Clean's loop combinators

For any iterative circuit body, use one of Clean's built-in loop combinators — `Circuit.forEach`, `Circuit.map`, `Circuit.mapFinRange`, `Circuit.foldl`, `Circuit.foldlRange` — rather than writing a custom recursive helper. The combinators carry `circuit_norm`-tagged simp lemmas so that `circuit_proof_start` collapses the loop machinery for free, leaving you with goals expressed in plain Lean/Mathlib terms. See [Clean's loop combinators reference](https://deepwiki.com/Verified-zkEVM/clean/2.5-circuit-loops-and-iteration) for the menu and semantics. `EnforceRootOfUnity` and `Fold` in the Ragu repository (`qa/lean/Ragu/Circuits/Element/`) are worked examples of the `Circuit.foldl (.finRange (k + 1))` pattern, including the standard rcases for the `Fin 0`-not-`Inhabited` boundary.
