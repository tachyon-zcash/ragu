---
name: fv-review
description: Explicitly invoked only. Lessons learned from porting Ragu Rust circuits to Clean Lean formal verification reimpls — when not to formalize an empty circuit, picking FormalCircuit vs FormalAssertion vs GeneralFormalCircuit, mirroring Rust delegation, length polymorphism, naming conventions, and reading proof failures (stuck goals, hypotheses you're forced to add) as under-constraint / undocumented-precondition bug signals. Distilled from PR review feedback (mitschabaude et al.) and refined over time. Do NOT auto-trigger on general formal verification, Lean, or Ragu questions; only invoke when the user explicitly types `/fv-review` or asks by name.
---

# Ragu Formal Verification: Lessons Learned

Hints for adding Clean Lean formal verification reimpls to Ragu Rust circuits. Distilled from reviewer feedback. Append new lessons as they emerge.

Sections fall into three groups: **Trust model** frames what's trusted vs untrusted and what reviewers must inspect by hand; **per-reimpl tactics** (Core principle through Watch for false justifications) covers how to write a single reimpl correctly; **workflow** (Per-gadget extension workflow + Workflow checklist) covers how to construct the artifact set across files, plus a per-reimpl quality checklist. Sources at the bottom trace each lesson to a specific PR review thread.

## Trust model

the clean reimplementation and formal instance can be black-boxed and LLM-generated since they’re untrusted. the latter (formal instance) proves that the reimpl equals the autogen using equivalence theorems, and the former (reimpl) proves the soundness / completeness against the spec (loosely an IO contract). so this transitively reduces trust to just manually inspecting that the spec is correct, and assuming the trusted extractor and serialization impl is correct, everything else follows

**Artifact map.** Spelling out trusted/untrusted by artifact:
- *Trusted (must be manually inspected):* Rust circuit instance (`CircuitInstance`), extractor / extraction driver, serialization impl, and — on the Lean side — `Inputs` / `Outputs` struct definitions, `Spec`, `Assumptions`.
- *Untrusted (can be LLM-generated):* Lean reimpl body (`main`), soundness / completeness theorems, formal-instance equivalence proofs. The autogen Lean file (flat op trace) is mechanically extractor-produced, not human-written.

**Subtlety: input/output *struct shape* is part of the trusted spec; wire *order* is not.**
- Wire ordering is checked by the equivalence proof — constraints are tied to specific wires, and both Ragu and Clean derivers map struct fields to wires in field-definition order. Reorder the wires on either side and the formal instance fails.
- The *meaning* assigned to those wires (which wire is `x` vs `y`, which input is "first") is trusted. Extraction operates on raw wires; the high-level struct shape is not preserved through it. A Rust bug — say, `assertLt(x, y)` accidentally checking `x > y` — can be **shadowed** by an inverse Lean bug: define `Inputs := { y, x }` and prove `x < y`. Variable names line up, equivalence still holds, the spec reads exactly like the intended behavior. **Reviewer obligation:** verify both that the spec captures the gadget's *intended* behavior *and* that input/output naming matches what callers actually pass.

**Mitigation: composition surfaces bad specs.** A wrong spec or wrong input order on a leaf gadget tends to surface when that gadget is used as a subcircuit in a parent — the child spec won't compose to the statement the parent needs. A second reason (beyond the proof-composability argument in "Mirror Rust delegation") to lean on subcircuit composition: it catches bugs, not just enables proofs.

## Core principle: don't formalize what has no content

A Rust "circuit" that only builds expressions (e.g., `negate`, `add`, `sub`, `double`, `scale`, `add_coeff`, `sum`, `Point::constant`) emits **no constraints and no witnesses** — it's pure expression manipulation. A Lean reimpl produces an empty body with a trivially-true spec, which proves nothing useful.

**Rule:** before writing a Lean reimpl, check whether the Rust function actually emits operations (witnesses, lookups, asserts). If not, skip it. Don't reflexively mirror every Rust helper as a trivial Lean circuit.

## Circuit Statements: `Assumptions`, `Spec`, `ProverAssumptions`, `ProverSpec`

`GeneralFormalCircuit` and `GeneralFormalCircuit.WithHint` have to most flexible statement shape, essentially allowing independent statements for soundness and completeness. Apart from the constraints/witness hypotheses and goals, we have:

- `GeneralFormalCircuit.Soundness`: `Assumptions → Spec`
- `GeneralFormalCircuit.Completeness`: `ProverAssumptions → ProverSpec`

In the simpler `FormalCircuit` and `FormalAssertion` flavors, these are collapsed:

- Neither has a `ProverSpec`. Completeness only proves that the constraints hold.
- In `FormalCircuit`, prover assumptions are just `Assumptions`.
- In `FormalAssertion`, prover assumptions are `Assumptions ∧ Spec` because the honest prover must satisfy both the caller precondition and the asserted input predicate.

To summarize the statements of `GeneralFormalCircuit` as a table:

| Field | Visible to | Role |
|---|---|---|
| `Assumptions` | soundness only | Verifier-side precondition: the contract every caller must satisfy. |
| `Spec` | soundness only | The contract the gadget promises to callers. |
| `ProverAssumptions` | completeness only | Prover-side precondition needed to satisfy the constraints. |
| `ProverSpec` | completeness only | Extra prover-side conclusion completeness establishes. |

When a circuit is used as a subcircuit, Clean packages the verifier-side fact `Assumptions → Spec` into the subcircuit payload. Parent soundness and completeness proofs can therefore use child `Assumptions` and `Spec` facts, even though top-level completeness itself is stated in terms of `ProverAssumptions` and `ProverSpec`.

`FormalCircuit` and `FormalAssertion` keep a simpler picture: a single `Assumptions` field shared by both halves (no separate prover side).

## Pick the right circuit type

Three flavors, in order of specificity:

| Type | Use when | Pitfall |
|---|---|---|
| `FormalCircuit` | Function-like: prover and verifier share one precondition body. | Default for input → output gadgets. Single `Assumptions` field, seen by both halves. |
| `FormalAssertion` | Assertion-like: constraints intentionally narrow the allowed input (e.g., `enforce_root_of_unity`, `enforce_zero`). | When `Assumptions ∧ Spec` are enough to satisfy the prover preconditions, and there is no circuit output, this is what you actually want.  `Boolean.ConditionalEnforceEqual` (commit `feda3096`) is the worked example: dropping one prover assumption made `ProverAssumptions = Spec`, enabling the downgrade. |
| `GeneralFormalCircuit` | Most flexible — `ProverAssumptions ≠ Assumptions`, or you need `ProverSpec`. | Reach for this only when the prover genuinely needs preconditions or conclusions the verifier doesn't. If the prover side is the same as the verifier side and `ProverSpec` is degenerate, use `FormalCircuit`. |
| `GeneralFormalCircuit.WithHint` | Like `GeneralFormalCircuit` but also enables prover hint inputs (`Unconstrained` or `UnconstrainedDep`). |

**Heuristic:** `ProverAssumptions ↔ Spec` and no output → `FormalAssertion`. Single precondition body, no prover/verifier asymmetry → `FormalCircuit`. Distinct `ProverAssumptions` or non-degenerate `ProverSpec` needed → `GeneralFormalCircuit`.

## Specs lift to high-level operations, not low-level constraints

**The single most repeated review note.** A spec is the contract presented to callers; it should describe *what the gadget computes*, not *what equations it emits*. If your spec reads like the constraint system, it's wrong.

**Anti-patterns and rewrites:**

| Gadget | ❌ Constraint-level spec | ✓ Operation-level spec |
|---|---|---|
| `Boolean.And` | `out = a * b ∧ (out = 0 ∨ out = 1)` | `out.val = a.val &&& b.val ∧ IsBool out` |
| `Boolean.ConditionalEnforceEqual` | `cond * (a - b) = 0` | `cond ≠ 0 → a = b` |
| `Boolean.ConditionalSelect` | `out = a + cond * (b - a)` | `out = if cond = 1 then b else a` |
| `Multipack` | raw `field = sum of weighted bits` | `output.val` equals the bit-decomposition encoded by `input` |

The high-level form is what callers reason against. The constraint-level form is what soundness *proves* — internally, not externally.

Reusable building blocks: `IsBool x` (from `Clean.Gadgets.Boolean`) for "0 or 1"; `&&&` / `|||` for bitwise ops on `.val`; `if … then … else …` for conditional outputs; `IsBool.and_eq_val_and` / `IsBool.and_is_bool` to bridge field multiplication to boolean operations in soundness proofs.

**Partial operations.** When a `Spec` involves a possibly-failing operation (point doubling, inversion), prefer `lhs = some output` over `match lhs with | none => False | some o => output = o`. Logically equivalent; the equality form composes cleanly with `simp` and `rw`, the `match` form leaves goals stuck on case analysis. Commits `fd3dd437`, `6e29e465`.

## Specs are unconditional; caller obligations live in `Assumptions`

A close cousin of the previous lesson, but distinct: a spec should be an **unconditional** fact about the input/output relation. Premises the *caller* must establish belong in `Assumptions`, not as antecedents inside `Spec`.

**Anti-pattern (pre-PR-#690 `Point.Double.Spec`):**

```lean
def Spec (curveParams) (input) (output) :=
  input.isOnCurve curveParams →                       ← caller obligation
  curveParams.noOrderTwoPoints →                      ← caller obligation
  (match input.double with | some d => output = d | none => False) ∧ ...
```

**Better (post-PR-#690):**

```lean
def Assumptions (curveParams) (input) :=
  input.isOnCurve curveParams ∧ curveParams.noOrderTwoPoints

def Spec (curveParams) (input) (output) :=
  input.double = some output ∧ output.isOnCurve curveParams
```

Same logical content; preconditions now live where they belong.

**Why this matters for downstream proofs.** A `Spec` with antecedents forces every caller — including the parent gadget's soundness proof — to discharge those premises *at every call site* before the child's spec yields useful information. You see this in old code as constructions like `have h_d := c2 (by simp [h2y_ne])` — manually feeding the precondition into the child's `Spec` to peel off an antecedent. Migrating preconditions to `Assumptions` lets the framework discharge them once, at the bundle's `Soundness` boundary, and downstream subcircuit-spec uses become clean rewrites.

**Heuristic.** Test each antecedent: is it a **static caller obligation** (something the caller must establish before invocation, independent of the gadget's behavior — `isOnCurve`, `IsBool`, `y ≠ 0`)? → move to `Assumptions`. Or is it **input-dependent behavior** (the gadget genuinely does different things at different input values — `cond ≠ 0 → a = b` for `ConditionalEnforceEqual`)? → keep in `Spec`.

## Assumptions encode preconditions, not constraints

`Assumptions` is the *contract the caller must satisfy*. Like `Spec`, it should be a high-level statement, not a math identity from the constraint system.

| ❌ | ✓ |
|---|---|
| `r.x + r.y = 1 ∧ r.x * r.y = 0` | `IsBool input.cond` (or `True` if the precondition is established by the *hint type itself*) |

**A spurious low-level Assumption is almost always a smell that the interface is wrong** — usually the hint type leaks an internal sub-gadget shape. Fix the interface and the bogus Assumption disappears (sometimes to `True`).

## Hint types mirror the Rust interface

If `Rust::alloc` takes `bool`, the Lean reimpl should expose that as the circuit input hint shape — *not* `Row` or any other internal sub-gadget shape.
In current Clean code this usually means an input field such as `Unconstrained Bool` or `UnconstrainedDep SomeType`.

```lean
-- Wrong: leaks the internal multiplication row to every caller
structure Input (F : Type) where
  row : UnconstrainedDep Row F

-- Right: matches Rust's `value: DriverValue<D, bool>` parameter
structure Input (F : Type) where
  value : Unconstrained Bool F
```

If a sub-gadget needs a row, *compute it inside the gadget body* from the higher-level hint:

```lean
let ⟨a, b, c⟩ ← Core.mul fun env =>
  let v : F p := if input.value env then 1 else 0
  ⟨v, 1 - v, 0⟩
```

This keeps the public interface aligned with Rust and prevents Assumption inflation (see previous section).

**Calling convention.** `Core.mul` (and Clean's other hint-aware primitives) take a closure of shape `(eval : Expression F → F) → Row` — given a way to evaluate already-allocated wires, return the new row's values. Witness derivation always lives inside this closure; there is no parameter or callback shape to plumb through signatures.

## Naming conventions

- **No `General*` prefix.** Use plain `circuit`, `Spec`, `Assumptions`, `soundness`, `completeness`. The prefix is noise even when the underlying type is `GeneralFormalCircuit`.
- **Drop unused template arguments.** If a parameter isn't used in a definition, don't take it as an argument at all. For unused arguments in pure props, underscore-prefix them:
  ```lean
  def Assumptions (_input : Unit) (_data : ProverData (F p)) (_hint : ProverHint (F p)) := True
  ```

## Composition: don't wrap in `subcircuit`

A `FormalCircuit` is already callable as a function via its `CoeFun` instance. Don't wrap calls:

```lean
-- Wrong
let acc ← subcircuit (Mul.circuit ⟨input.x0, input.s⟩)

-- Right
let acc ← Mul.circuit ⟨input.x0, input.s⟩
```

## Mirror Rust circuit structure in Lean

The Lean reimpl should mirror the circuit-emitting structure on the Rust side.
If Rust delegates to a sub-gadget (e.g., `Element::invert` calls `Element::invert_with`), Lean should delegate the same way.
If Rust calls the driver primitive `dr.mul()`, Lean should call `Core.mul`.

This keeps the abstraction boundary aligned across Rust and Lean and avoids duplicate proofs.

**Current pattern: use `Core.mul` for env-aware rows.** `Core.mul` takes an `UnconstrainedDep Row` input, so callers can pass a function of the prover environment and compute the row locally from `eval`ed inputs.

## Pass subcircuit lemmas to `circuit_proof_start`

Composed gadgets — anything that calls another gadget as a subcircuit — need their soundness / completeness proofs to know about the children's `Spec` and `Assumptions`. The vehicle is `circuit_proof_start`'s argument list.

**Pattern.** For every subcircuit you compose with, pass its `circuit`, `Assumptions`, and `Spec` to `circuit_proof_start`:

```lean
theorem soundness (curveParams : Spec.CurveParams p) :
    Soundness (F p) elaborated (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [
    Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.DivNonzero.circuit, Element.DivNonzero.Assumptions, Element.DivNonzero.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec
  ]
  ...
```

Without these in the list, the proof state stalls on un-unfolded subcircuit terms — `simp` can't see through `Element.DivNonzero.circuit` to apply its `Spec`, and you end up manually unfolding each one with `dsimp [...]` calls.

**Why this matters for complex gadgets.** A leaf gadget with no subcircuits passes `circuit_proof_start` with no arguments. A four-deep composition like `DoubleAndAddIncomplete` needs ~12 lemmas — three per subcircuit. Getting the list right is the difference between a one-shot proof and an hour of manual unfolding. Forgetting a subcircuit's `Spec` is the most common cause of "the proof was almost there but `simp` got stuck" frustration.

**Heuristic.** Before writing a soundness or completeness proof for a composed gadget, enumerate every gadget you call as a subcircuit. For each, add `<Sub>.circuit`, `<Sub>.Assumptions`, `<Sub>.Spec` to the `circuit_proof_start` argument list. If your proof later stalls on a goal mentioning `(<Sub>.circuit input).output ...` or unfolded `Sub.Spec`, you missed a triple — add it.

**What NOT to pass.** Clean's prover-proof expansion auto-unfolds _local_ `main`, `Spec`, `Assumptions`, `ProverSpec` and `ProverAssumptions` everywhere — but only your gadget's own, not for subcircuits. Don't include any of these in `circuit_proof_start [..]`, `circuit_proof_all [..]`, or follow-up `simp [..]` lists; doing so is redundant noise.

## Length polymorphism is supported

Clean has plenty of length-polymorphic circuits. Don't claim "Clean can't express this" as a reason to specialize.

**Pattern:** make the Lean circuit length-polymorphic naturally, even if the Rust↔Lean extraction bridge only checks one fixed length at a time. Extract several concrete instances (e.g., n = 2, 4, 8, 16) for extra confidence.

The Lean formalization should represent the Rust circuit in its **full generality**, regardless of extraction limits.

## Use Clean's loop combinators, not recursive helpers

The single repeated review note across PR #710: **never** write a recursive helper function (`squareIter`, `hornerStep`, `for_step`, …) to express an iteration. Clean ships five loop combinators with `circuit_norm`-tagged simp lemmas (`Circuit.forEach`, `Circuit.map`, `Circuit.mapFinRange`, `Circuit.foldl`, `Circuit.foldlRange`); use those. See [Clean's loop combinators reference](https://deepwiki.com/Verified-zkEVM/clean/2.5-circuit-loops-and-iteration) for the full menu.

**Why this matters.** Recursive helpers force you to write your own length / consistency / soundness / completeness lemmas by induction. The combinators bring those lemmas with them, tagged into `circuit_norm`, so `circuit_proof_start` collapses the loop machinery automatically and leaves you with a goal that looks like plain Lean math (a `Fin.foldl` equation, a per-iteration recurrence on `env.get` values).

**The reviewer principle (Gregor, PR #710 Slack thread):** *"clean users are not supposed to have to call simplification lemmas explicitly. `circuit_proof_start` is supposed to yield a nice simplified version of the statement, after which your agent can just reason about normal lean/mathlib instead of our library."* If you find yourself manually invoking `simp [foldlRange.output_eq, Circuit.FoldlM.foldlAcc, …]` to make progress, that's a smell — either pick a different combinator or restructure the gadget so the auto-simp path applies.

### Pick `foldl` over `foldlRange` when both work

`Circuit.foldl xs init body` requires `ConstantOutput` on the body — the body's *symbolic* output must be invariant under (acc, element). When this holds, `foldl.output_eq` fires under `circuit_norm` and the proof environment is clean. `Circuit.foldlRange` doesn't require `ConstantOutput`, but its corresponding lemma leaves `Circuit.FoldlM.foldlAcc` unexpanded, forcing manual induction.

**Default to `foldl`.** Reach for `foldlRange` only when the body genuinely produces an index-dependent output that can't be restructured.

### Handle `Inhabited (Fin 0)` with an outer rcases

`Circuit.foldl (.finRange k)` requires `[Inhabited (Fin k)]`, which fails when `k = 0`. The fix is the same shape every time: split the polymorphic parameter at the boundary and handle the empty case structurally.

```lean
def main : (k : ℕ) → Var Inputs (F p) → Circuit (F p) (...)
  | 0, input => /- structural empty case, no loop -/
  | k + 1, input => do
    let result ← Circuit.foldl (.finRange (k + 1)) init body
    /- continue -/
```

`EnforceRootOfUnity` in `qa/lean/Ragu/Circuits/Element/EnforceRootOfUnity.lean` is the canonical worked example (k=0 → `assertZero (input - 1)`, k+1 → `Circuit.foldl (.finRange (k+1)) input fun x _ => Mul.circuit ⟨x, x⟩`).

### Restructure the body to make `ConstantOutput` hold

If a naïve translation produces a body like
```lean
fun acc i => do
  let scaled ← Mul.circuit ⟨acc, s⟩
  pure (scaled + xs[i + 1])   -- output depends on i → ConstantOutput FAILS
```
the post-Mul addition makes the body output index-dependent and `Circuit.foldl`'s `_const_out` autotactic fails to synthesize. **Don't fall back to `foldlRange`** — restructure.

The trick is to make the body's *last action* a subcircuit call whose output is a fresh wire (constant). For an `acc * s + xs[i+1]` Horner step:

1. Do the first Horner step (`xs[0] * s`) as an *explicit* `Mul.circuit ⟨xs[0], s⟩` **outside** the foldl. Its output wire becomes the foldl's `init`.
2. The foldl body is `fun acc i => Mul.circuit ⟨acc + xs[i+1], s⟩` — the index-dependent addition is now *inside* the Mul's input expression, and the body's output is just the fresh Mul wire (`var ⟨offset + 2⟩`), trivially `ConstantOutput`.
3. After the foldl, add the trailing `xs[n]` via a free expression.

`Fold` in `qa/lean/Ragu/Circuits/Element/Fold.lean` is the worked example (4-way rcases: 0, 1, 2, n+3 — the extra cases handle `Fin 0`/`Fin 1` boundaries cleanly). The autogen extractor sees the same `Mul`-per-Horner-step structure as a recursive-helper translation, so this restructure remains byte-for-byte compatible with the autogen instance proofs.

### Sidestep `field (F p)` HPow synthesis in helper lemmas

After `circuit_proof_start`, the loop's per-iteration witness is typed as `input : field (F p)` (where `field := id`). Lean's typeclass elaborator doesn't always unfold the `field` abbrev when synthesizing instances like `HPow (field (F p)) ℕ (F p)`, so writing `have wire_eq : ... = input ^ (2 ^ (i + 1)) := …` directly inside the proof fails with a typeclass synthesis error.

**Workaround:** extract the inductive lemma as a `private` declaration parameterized over an explicit `env : Environment (F p)` and `x_val : F p`:

```lean
private lemma wire_value_eq_pow (k : ℕ) (env : Environment (F p))
    (x_val : F p) (i₀ : ℕ)
    (h0 : env.get (i₀ + 2) = x_val * x_val)
    (hk : ∀ i, i + 1 < k + 1 → …) :
    ∀ i, i ≤ k → env.get (i₀ + i * 3 + 2) = x_val ^ (2 ^ (i + 1)) := …

theorem soundness (k : ℕ) : Soundness … := by
  circuit_proof_start [Mul.circuit, …]
  …
  have wire_k := wire_value_eq_pow k env input i₀ h0 hk k (le_refl k)
  …
```

Lean unifies `input : field (F p)` with the lemma's `x_val : F p` parameter cleanly at the call site (`field (F p)` *is* `F p` definitionally via `abbrev`), so the inner proof sees an honest `F p` and HPow synthesis works. Both `EnforceRootOfUnity.wire_value_eq_pow` and `Fold.wire_value_eq_horner` follow this pattern.

A related warning to expect: `automatically included section variable(s) unused — [Fact (Nat.Prime p)]`. The helper does pure ring/field arithmetic, no primality. Suppress with `omit [Fact p.Prime] in` immediately before the lemma declaration (line-comment any docstring out — `omit` doesn't bind through `/-- … -/`).

### Autogen instance proofs for `Circuit.foldl`

When `main` uses `Circuit.foldl`, the `same_constraints` proof in the corresponding `qa/lean/Ragu/Instances/<Module>/<Gadget>.lean` file needs to unfold the foldl iteratively to byte-match the autogen's flat op list. The recipe:

```lean
same_constraints := by
  intro input
  simp [Core.Statements.FlatOperation.eraseCompute, List.map,
    Operations.toFlat, circuit_norm,
    FormalCircuit.isGeneralFormalCircuit,   -- or FormalAssertion.… for assertion-shaped gadgets
    GeneralFormalCircuit.toWithHint,
    GeneralFormalCircuit.WithHint.toSubcircuit, FormalCircuit.toSubcircuit,
    deserializeInput, exportedOperations,
    Circuits.Element.<Gadget>.circuit,
    Circuits.Element.<Gadget>.elaborated,
    Circuits.Element.<Gadget>.main,
    Circuit.foldl, Vector.foldlM_toList,
    Vector.finRange, Vector.ofFn, Vector.toList,
    List.foldlM, List.foldlM_cons,
    Circuits.Element.<Sub>.circuit, Circuits.Element.<Sub>.main]
  constructor
same_output := by intro input; rfl
```

The key unfolds: `Circuit.foldl` → `Vector.foldlM` → `Vector.foldlM_toList` → `List.foldlM_cons` (peels one iteration at a time until the list is exhausted). Lake's linter will flag any of `Vector.cast`, `List.foldlM_nil`, `Vector.finRange` etc. as unused if a particular gadget's shape doesn't need them — trim the list per the lint. CI treats those linter warnings as errors.

## Watch for false justifications

Reviewers flag explanatory comments that aren't actually true (literal review verdict: "lie"). If a doc comment claims "Clean doesn't support X" or "this requires dependent types we don't expose", verify against the Clean codebase before writing it — those claims tend to be wrong.

## Per-gadget extension workflow

How the artifacts fit together when adding a new gadget to FV. This is *per-gadget construction*; the **Workflow checklist** below is *per-reimpl quality gates* — different axes, both apply.

**Artifacts per top-level gadget** (e.g., `Point.AddIncomplete`):

| File | Trust | What it is |
|---|---|---|
| `qa/crates/lean_extraction/src/instances/<gadget>.rs` | trusted | Rust `CircuitInstance` impl: thin wrapper that calls Ragu types / gadgets through `ExtractionDriver`. |
| `qa/lean/Ragu/Instances/Autogen/<Module>/<Gadget>.lean` | mechanical (CI-checked) | Extractor-produced flat op trace. Regenerated via `cargo run -p lean_extraction -- export`; `check` enforces byte-equality. |
| `qa/lean/Ragu/Circuits/<Module>/<Gadget>.lean` | reimpl untrusted; `Inputs` / `Outputs` / `Spec` / `Assumptions` trusted | The reimpl: `main`, `Spec`, `Assumptions`, `elaborated`, `soundness`, `completeness`. |
| `qa/lean/Ragu/Instances/<Module>/<Gadget>.lean` | untrusted | `FormalInstance` packaging: proves reimpl ≡ autogen, exposes the spec. |
| circuit input types containing `Unconstrained` / `UnconstrainedDep` | trusted | The hint shape exposed to callers; should mirror the Rust API and avoid leaking internal rows. |

**Sub-gadget carve-out — the scaling lesson.** Gadgets used only as subcircuits inside other gadgets can live **only as Lean reimpls + soundness / completeness**. Their correctness reaches the top via composition: the parent reimpl's proof uses the child's `Spec`. Top-level gadgets — the ones a Ragu consumer composes with — get the full pipeline. Some core gates such as `Core.mul` still have extractor instances because they are useful as direct equivalence anchors, but that should be an intentional choice rather than the default for every helper.

**Canonical per-gadget commit sequence** (PR #642 followed this ~6 times):
1. Reimpl skeleton in `qa/lean/Ragu/Circuits/<Module>/<Gadget>.lean` — `main`, `Spec`, `Assumptions`, `elaborated`.
2. Rust `CircuitInstance` in `qa/crates/lean_extraction/src/instances/<gadget>.rs` (top-level only).
3. Run `cargo run -p lean_extraction -- export` → autogen file appears under `qa/lean/Ragu/Instances/Autogen/<Module>/<Gadget>.lean`.
4. Write `soundness`.
5. Write `completeness` (define honest witness gen if needed).
6. Add formal-instance packaging in `qa/lean/Ragu/Instances/<Module>/<Gadget>.lean` (top-level only).

Steps 1–2 can swap. Sub-gadgets stop after step 5.

**Framework co-evolution is part of the workflow.** Several PR #642 commits are *upstream Clean changes* pulled back into Ragu — the `ProverAssumptions` / `ProverSpec` split, hint-aware `CircuitType` inputs, the `ProverHint` / `Environment` rename, weakening `DivNonzero` assumptions. When Clean can't express what a Ragu reimpl needs — most commonly around hint shape, completeness contracts, or assumption polymorphism — **PR upstream first, bump the dep in `qa/lean/lakefile.lean`, then continue**. Don't paper over with workarounds in Ragu (bogus Assumptions, leaked sub-gadget shapes — see "Hint types mirror the Rust interface"). The positive counterpart to checklist item 11 below.

**Compositionality scales the pipeline ([PR #674](https://github.com/tachyon-zcash/ragu/pull/674#pullrequestreview-4171812720)).** As gadgets get more complex, the *single most important* discipline is delegating to existing Lean sub-gadgets instead of inlining their math. Skipping the step-1 homework — surveying what's already there before writing new `main` / `Spec` — is exactly the failure mode the PR #674 reviewer flagged ("agents missed the compositionality of clean and wrote specs that just repeat the math equations"). The lessons under "Mirror Rust delegation" and "Specs lift to high-level operations" enforce this; the per-gadget workflow only scales if those are followed religiously.

## Workflow checklist

1. **Audit the Rust circuit first** — does it emit operations? If no, skip the Lean reimpl entirely.
2. **Pick the circuit type** — `FormalCircuit` (default), `FormalAssertion` (narrowing input), `GeneralFormalCircuit` (last resort).
3. **Match the Rust hint type** — if Rust takes `bool`, Lean takes `Bool`. Don't expose internal sub-gadget shapes.
4. **Mirror Rust call structure** — delegate to the same sub-gadgets Rust delegates to; use `Core.mul` for Rust `dr.mul()` calls.
5. **Write the spec at the operation level** — boolean / Nat / `if`-`then`-`else` / "input.cond = 1 → output equals X". If your spec reads like the constraint system, rewrite it.
6. **Sanity-check `Assumptions`** — should be a high-level precondition (`IsBool x`, often `True`). A complex math identity in `Assumptions` is a smell; suspect the interface.
7. **Sort preconditions into the right slot** — verifier-visible preconditions go in `Assumptions`; prover-side witness conditions go in `ProverAssumptions`. If the two end up equal, downgrade to `FormalCircuit`; if there is no meaningful output and the gadget enforces an input predicate (which means `ProverAssumptions` are just the `Spec`), downgrade to `FormalAssertion` instead.
8. **Drop unused parameters**; underscore-prefix unused props arguments.
9. **Use plain names** (`circuit`, `Spec`, `soundness`) — no `General*` prefix.
10. **Run `lake build` after each commit**; audit specs for correctness.
11. **Before claiming a Clean limitation, grep the Clean codebase** — most "limits" are mistaken.
12. **If `soundness` only closes after adding an input hypothesis, stop and classify it** — legitimate caller obligation (→ `Assumptions`, and confirm the caller actually guarantees it) or missing constraint (→ add it; the gadget was under-constrained)? Don't bury a discovered precondition in `Assumptions` just to turn the proof green. If the proof *wedges* instead, prove the negation before concluding "bug." See "Formalizing is an under-constraint audit."

## Sources

- [tachyon-zcash/ragu#642](https://github.com/tachyon-zcash/ragu/pull/642) — clean integration foundation. Trust-model artifact map (r3102920311); input/output struct shape is part of the trusted spec, wire order is not (r3105702381, r3115790860 — `assertLt` shadowed-bug example, composition-as-mitigation side note); per-gadget extension workflow distilled from the 102-commit history (artifact set, sub-gadget carve-out per Tal's approval comment, framework co-evolution via upstream Clean PRs).
- [tachyon-zcash/ragu#672](https://github.com/tachyon-zcash/ragu/pull/672) — mitschabaude review (initial extraction)
- [tachyon-zcash/ragu#674](https://github.com/tachyon-zcash/ragu/pull/674) — mitschabaude review (Boolean gadget). Verdict: "agents missed the compositionality of clean and wrote specs that just repeat the math equations instead of translating them into higher-level programming statements." Threads: r3138867768, r3138904103, r3138963958, r3138965755, r3138972958, r3138991793, r3139002146, r3139003436, r3139007420, r3139012715.
- [tachyon-zcash/ragu#710](https://github.com/tachyon-zcash/ragu/pull/710) — mitschabaude review (`EnforceRootOfUnity`, `Fold` polymorphism). Top-level note: "clean has a couple of loop constructs with simp support in `circuit_proof_start` / `circuit_norm`. We use these whenever we need a loop: `Circuit.forEach`, `Circuit.map`, `Circuit.mapFinRange`, `Circuit.foldl`, `Circuit.foldlRange`." Inline suggestions r3265194082, r3265194093. Slack follow-up clarified the principle: "use foldl which behaves well" (not "make foldlRange behave better"); "clean users are not supposed to have to call simplification lemmas explicitly." Worked examples in `qa/lean/Ragu/Circuits/Element/{EnforceRootOfUnity,Fold}.lean`.
- [tachyon-zcash/ragu#761](https://github.com/tachyon-zcash/ragu/pull/761) — endoscalar `Endoscalar::extract` under-constraint, surfaced by formalization (demonstration spike, not merged). The per-bit QR-branch constraint is satisfied by *both* bit values at `elem + i = 0`, leaving the bit forgeable. Reading proof failures as bug signals: unconditional soundness wedges at `⊢ False` (`ExtractStuckDemo`), the negation is provable (`extract_unsound` — `elem=0, bit=0, sqrt=0` satisfies every constraint but the bit should be `1`), and conditional soundness surfaces the precondition `elem + i ≠ 0` (`extract_sound_of_shifted_ne_zero`) — true in Ragu only because `elem` is a Fiat-Shamir hash, so sound in usage but unsound in isolation. Spike: `qa/lean/Ragu/Contrib/ExtractSoundnessSpike.lean`.

<!-- Append new lessons below this line as they emerge from review feedback. -->

## Formalizing is an under-constraint audit — read proof failures as bug signals

Proving a gadget's `soundness` doubles as an adversarial-prover audit: it asks *can a witness satisfy every constraint yet violate the `Spec`?* — which is the soundness question. So **how the proof behaves is itself a finding.** Trying to prove `soundness` with no extra input hypotheses has three outcomes, each meaningful:

| Outcome | Meaning | Action |
|---|---|---|
| Closes | Gadget is sound as specified. | Done. |
| Closes **only after you add a hypothesis** on the input | You've surfaced a precondition the gadget *silently relies on*. | Classify it (below) — do **not** reflexively bury it in `Assumptions` to go green. |
| **Wedges** at a goal you can't honestly close | Strong smell of an under-constraint — but a *lead*, not a verdict (could equally be a missing lemma or a mis-stated spec). | Read the stuck goal: it names the missing fact. Turn that fact into a witness and **prove the negation**. |

**A stuck goal is a lead; a proven negation is the conviction.** Failure-to-prove ≠ disproof — the same trap as "the constraint *exists*" ≠ "the constraint *suffices*." Don't let "I couldn't close it" masquerade as "it's broken," and **never `sorry` past the wedge** — the open hole *is* the finding, and `#print axioms` will expose a `sorryAx` if you try. To *convict*, exhibit a concrete assignment that satisfies every constraint but violates the `Spec` (the circuit is satisfiable yet admits a forged witness it should reject). Build that counterexample from exactly the fact the stuck goal said was missing.

**Name the three statements — keep them distinct:**
- *Unconditional soundness* — the spec holds for **all** inputs, no added hypothesis. This is what you attempt first. If the gadget is under-constrained the statement is **false**, so the proof can only wedge — you hit a stuck goal *precisely because* you're trying to prove a false statement (which is why you must never `sorry` it shut).
- *Its negation* — some input satisfies every constraint yet violates the spec. Proving this is the **verdict** that convicts the under-constraint.
- *Conditional soundness* — the spec holds **given** an explicit input precondition (an `Assumptions` antecedent). This statement is **true**, and proving it names the precondition that rescues the gadget.

A clean audit of a suspect gadget therefore yields a *pair*: the negation (convicts the gap) **and** conditional soundness (names the precondition) — together saying "under-constrained in isolation, sound under this assumption." That pair is then the constraint-vs-document decision below.

**The fix is one of two shapes, and the proof tells you which:**
- **Add a constraint** — close the goal *from inside the circuit*. The gadget was genuinely under-constrained; the new constraint pins the witness, and unconditional soundness then proves with no hypothesis.
- **Add a hypothesis** — the gadget legitimately assumes a caller precondition. Promote it to `Assumptions` (see "Specs are unconditional; caller obligations live in `Assumptions`") **and** verify the caller actually guarantees it. A precondition that holds only "in practice" (e.g. because the input is a hash output) is sound *in usage* but unsound *in isolation* — it must become an explicit, justified assumption, never a silent one.

**The danger move** is adding an input antecedent purely to make a stuck proof go green, without asking whether it should instead be a *constraint*. That silently converts a soundness bug into an unstated precondition — exactly the bug class this lesson guards against. An antecedent you were *forced* to add is a *discovered* obligation; classify it, don't paper over it. This is the bug-finding face of the `Assumptions` lessons.

**Rust-side hygiene first.** These gaps hide because gadget preconditions are often undocumented. Before formalizing, write down each gadget's `Spec` and the assumptions it makes on its inputs (relates to [#759](https://github.com/tachyon-zcash/ragu/issues/759)). An honest, up-front `Spec` / `Assumptions` means the Lean proof either *confirms* it or *surfaces* the gap — instead of the agent inventing a hypothesis to close the proof and thereby hiding the bug.

**Make sure the proof actually runs in CI.** A `.lean` that no aggregator imports (and that the lib's globs don't cover) is silently skipped by `lake build` — the proof exists but nothing checks it, and a non-compiling file can sit green. PR #763 switches `qa/lean/lakefile.lean` to `globs := #[\`Ragu.*]` so every module under `Ragu/` is built; regardless, confirm a new reimpl is actually reached by the build before trusting that CI gates it.

**Worked example — `Endoscalar::extract` ([PR #761](https://github.com/tachyon-zcash/ragu/pull/761)).** The per-bit QR-branch constraint `sqrt² = bit·(elem+i) + (1−bit)·((elem+i)·g)` is satisfied by *both* bit values when `elem + i = 0` (both branches collapse to `0 = 0`), so the extracted bit is under-constrained — a malicious prover can forge it.
- Unconditional soundness is **unprovable** — wedges at `⊢ False` (`ExtractStuckDemo`).
- The **negation is provable** (`extract_unsound`): `elem = 0, bit = 0, sqrt = 0` satisfies every constraint, yet `IsSquare 0` holds so the honest bit is `1`. Circuit satisfiable; forged witness admitted.
- **Conditional** soundness holds once `elem + i ≠ 0` is assumed (`extract_sound_of_shifted_ne_zero`) — the surfaced precondition.

The precondition is true in Ragu *only* because `elem` is a Fiat-Shamir hash (landing on one of the 128 bad points is negligible), so it isn't exploitable in the live circuits — but the primitive is unsound in isolation. The honest fix **adds the missing constraint** (a conditional inverse forcing `elem + i ≠ 0` when `bit = 0`), rather than leaving the precondition implicit.
