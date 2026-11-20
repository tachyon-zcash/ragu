---
name: fv-docs
description: Explicitly invoked only. Authoritative reference for the Ragu formal-verification project — Clean DSL semantics (Circuit monad, Expression, Operation, ProvableType, FormalCircuit) and Ragu-side concepts (extraction driver, formal instances, input/output serialization, assumptions, CI). Routes to the live FV docs in the `fv` repository's book; the docs are the spec, not opinion. Pair with /fv-review for opinion / pattern-matching guidance. Invoke when the user types `/fv-docs` or asks for the canonical definition of a Clean / Ragu-FV concept.
---

# fv-docs: Ragu Formal Verification reference

The FV documentation lives in the mdBook of the `fv` repository. This skill is a routing layer: pick the right doc and `Read` it from the live source — don't paraphrase. The docs are authoritative; they define what `FormalCircuit`, formal instances, `ExtractionDriver`, etc. *mean*.

**Pairing.** For *definitions* → fv-docs (this skill). For *opinion / pitfalls / pattern-matching* (e.g., "should I use `FormalCircuit` or `GeneralFormalCircuit`?", "what's a clean spec style?") → `/fv-review`. Don't compete on the same question.

## Where the docs live

The FV docs are Part I of the mdBook in the separate `fv` repository, rooted at **`src/fv/`** there. Treat `<docs>` below as that path in a local checkout of that repository, such as `../fv/src/fv/` when it sits beside this one.

Checkouts of this repository from before the split have the docs as Part IV of the Ragu book, at `book/src/fv/`. Still older ones predate the merge into the book and have the docs as a standalone mdBook at `qa/lean/docs/src/` (or, earlier still, `fv/docs/src/`), with `clean/core/` in place of `clean/`, `ragu/` in place of `circuits/`, and `introduction.md` in place of `index.md`. If unsure, `ls ../fv/src/fv/ 2>/dev/null || ls book/src/fv/ 2>/dev/null || ls qa/fv/docs/src/` resolves it.

## Topic → file (what each doc answers)

**Clean DSL:**
- `<docs>/clean/index.md` — what Clean is; soundness vs completeness as concepts; compositionality.
- `<docs>/clean/circuit.md` — the `Circuit` monad: `ℕ → α × List (Operation F)`, `bind` semantics, witness offset threading.
- `<docs>/clean/mul.md` — minimal worked example: a multiplication circuit walked end-to-end.
- `<docs>/clean/provable.md` — `TypeMap`, `ProvableType`, `ProvableStruct`; structured values vs symbolic forms; `field`, `Var`.
- `<docs>/clean/expression.md` — `Variable`, `Expression`, `ProverEnvironment`; how symbolic circuits are evaluated.
- `<docs>/clean/operations.md` — `FlatOperation` vs `Operation`; witness / assert / lookup; why operations are the ground truth.
- `<docs>/clean/formal.md` — the formal-circuit bundle family (`FormalCircuit`, `FormalAssertion`, `GeneralFormalCircuit`, `GeneralFormalCircuit.WithHint`); the prover/verifier precondition split (`Assumptions`, `ProverAssumptions`, `ProverSpec`, `ProverData`, `ProverHint`); structure of `main` / `Assumptions` / `Spec` / `soundness` / `completeness` fields; the formal definitions of soundness and completeness.
- `<docs>/clean/example.md` — full worked example tying circuit + provable + expression + formal together (`DivNonzero`).
- `<docs>/clean/parameters.md` — compile-time parameters as ordinary Lean function arguments; partial-application instantiation.

**Ragu FV pipeline:**
- `<docs>/circuits/index.md` — the two-approach analysis (high-level export vs. low-level trace); why Ragu chose the low-level export with a Lean reimplementation; the formal instance interface and its fields.
- `<docs>/circuits/extraction.md` — `ExtractionDriver`, `MaybeKind = Empty`, `ImplWire = Expr<F>`; how `alloc` / `mul` / `add` / `enforce_zero` / `constant` map to operations.
- `<docs>/circuits/serialization.md` — symbolic input wires, `input_var.get i`, `alloc_input_wires`, `serializeOutput` / `deserializeInput`.
- `<docs>/circuits/fingerprint.md` — the vk-style fingerprint equivalence check (the sole Rust↔Lean tie since the autogen trace files and `same_constraints` proofs were removed): canonical byte encoding + SHA-256 digest of the op trace, computed in both the Rust extractor (`lean_extraction -- fingerprint`) and Lean (`lake exe fingerprints`), compared in CI; the `2³²` input-variable index region; trust assumptions of the check.
- `<docs>/circuits/assumptions.md` — what the FV does and does not guarantee; trusted core; axiom dependencies (`propext`, `Classical.choice`, `Quot.sound`, `Lean.ofReduceBool`, `Lean.trustCompiler`, `Ragu.Core.Primes.p_prime`).
- `<docs>/circuits/ci.md` — `cargo run -p lean_extraction -- check`, `lake build --wfail` (sorry-as-failure) over every module under `qa/fv/Ragu/` via the lib glob, so an unimported file cannot escape; fingerprint comparison step.

The book TOC lives at `src/SUMMARY.md` of the `fv` repository if you want the canonical reading order.

## Term → file (use for definition lookups)

| Term | Defined in |
|---|---|
| `Circuit` (monad), `bind`, witness offset | `clean/circuit.md` |
| `Variable`, `Expression`, `ProverEnvironment` | `clean/expression.md` |
| `Operation`, `FlatOperation`, `witness`, `assert`, `lookup` | `clean/operations.md` |
| `TypeMap`, `ProvableType`, `ProvableStruct`, `field`, `Var` | `clean/provable.md` |
| `FormalCircuit`, `FormalAssertion`, `GeneralFormalCircuit`, `GeneralFormalCircuit.WithHint`, `.toWithHint`, `Assumptions`, `ProverAssumptions`, `Spec`, `ProverSpec`, `ProverData`, `ProverHint`, soundness, completeness (formal definitions) | `clean/formal.md` |
| Compile-time parameters, partial-application instantiation | `clean/parameters.md` |
| `FormalInstance`, `reimplementation` | `circuits/index.md` |
| `same_constraints`, `same_output`, `exportedOperations`, `exportedOutput` (removed; superseded by the fingerprint check) | `circuits/fingerprint.md` |
| `ExtractionDriver`, `MaybeKind`, `ImplWire`, driver-method → op-trace mapping | `circuits/extraction.md` |
| `input_var.get`, `alloc_input_wires`, `serializeOutput`, `deserializeInput` | `circuits/serialization.md` |
| Fingerprint, canonical encoding, `lean_extraction -- fingerprint`, `lake exe fingerprints`, `Ragu.Fingerprint`, `inputVarOffset` | `circuits/fingerprint.md` |
| Trust assumptions, axiom dependencies | `circuits/assumptions.md` |
| `--wfail`, `lean_extraction -- check`, what CI verifies | `circuits/ci.md` |

## Reading order (for new readers)

`<docs>/index` (scope, what is and is not verified) → `clean/index` → `clean/circuit` → `clean/provable` → `clean/expression` → `clean/operations` → `clean/formal` → `clean/mul` → `clean/example` → `clean/parameters` → `circuits/index` → `circuits/extraction` → `circuits/serialization` → `circuits/fingerprint` → `circuits/assumptions` → `circuits/ci`.

## Out of scope

- Lean syntax basics, tactic strategy, mathlib usage — not in this corpus; consult Lean / mathlib docs.
- Specific gadget proof bodies (e.g., the body of `Point.AddIncomplete.soundness`) — read source under `qa/fv/Ragu/Circuits/...`.
- Opinion on circuit-type choice, naming conventions, spec style, "did the spec lift to high-level operations" — that's `/fv-review`.

## Routing rule of thumb

1. If the question names a term from the **Term → file** table → `Read` that file from the live `<docs>` root.
2. If the question matches a topic but no specific term → consult **Topic → file** for the right doc.
3. If neither matches → the answer probably isn't in this corpus; say so rather than guess.
