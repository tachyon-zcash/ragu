# Surface Placement Policy

Rules for what belongs in the book vs. rustdoc. Both surfaces may cover the
same concepts in different registers (rustdoc: precise/terse; book:
accessible/motivational); same-register duplication drifts and must be avoided.

## Surface Ownership

- **Rustdoc owns API truth**: signatures, bounds, `cfg`/feature behavior, error
  semantics, safety contracts, and all pre/postconditions/invariants.
- Rustdoc must be **self-sufficient**: a reader relying only on rustdoc can
  correctly use every public item and implement required traits/constraints.
- **The book owns conceptual context**: motivation, mathematical foundations,
  design rationale, cross-cutting composition guidance, and high-level API
  overviews.
- The book may **informally restate** API requirements only to aid
  understanding, not as the compliance source.
- If the book states a rule **more precisely** than rustdoc, that precision
  must move to rustdoc; the book must not be the only place a constraint is
  fully specified.

## Math

- Prefer the **book for math-heavy exposition** (richer LaTeX/macros).
- Rustdoc treats math as a **black box**: state requirements and guarantees
  without re-deriving foundations.

## Notation and Terminology

- Maintain a single **Notation & Terms** home in the book; use consistent
  symbols and names across book and rustdoc.

## Stability Boundary

- **Stable, cross-cutting abstractions** (terminology, spanning invariants,
  composition model, design rationale) belong in the book.
- **Volatile, implementation-coupled facts** (optimizations, representation
  choices, algorithm variants) belong in code docs; the book stays abstract.
- **Single-purpose/internal algorithms** too narrow for the user guide belong
  in code-local docs, including any math needed to maintain them.

## Module Documentation

- Module-level `//!` docs: terse purpose + key types/traits + key invariants +
  link to the relevant book chapter.
- For every public item, rustdoc documents preconditions, postconditions, and
  invariants, using shared book notation where applicable.
- Rustdoc documents safety/soundness (`unsafe`, aliasing/lifetime/validity)
  explicitly and authoritatively at the relevant items.
- Document constraints where correctness is enforced: type-level guarantees,
  `Result`/error semantics, asserts, feature gates, `unsafe` obligations.

## Cross-Referencing

- Use **bidirectional deep links**: book links to exact rustdoc items (API
  authority); rustdoc links to exact book sections (math/notation/rationale).
- Maintain **stable book anchors** for long-lived references; prefer explicit
  anchors when available.

## Duplication Management

- For any non-trivial claim, enforce **canonical home + summary + link** (no
  parallel full descriptions across surfaces).
- Duplicate only **tiny, drift-resistant fragments** (one-line definition,
  single formula, short warning); otherwise use summary + link.

## Examples

- Book examples prefer **reused tested snippets** (doctests/examples/tests);
  use pseudocode when runnable code isn't practical; `rust,ignore` is a last
  resort.
- Rustdoc examples should compile and test (minimize `ignore`) and are the
  canonical runnable samples.
