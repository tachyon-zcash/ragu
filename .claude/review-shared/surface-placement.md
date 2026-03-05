# Surface Placement Policy

What belongs in the book vs. rustdoc.

## Math lives in the book

- The book is the primary home for math — it supports custom macros, display
  environments, and cross-referencing that rustdoc cannot.
- In rustdoc, math must survive three nested layers (Rust comment syntax,
  markdown parsing, LaTeX delimiters) that fight over escaping, line width,
  and special characters. Prefer the book for anything beyond a short inline
  formula.
- Exception: algorithms and constructions too narrow or internal for the user
  guide must be documented mathematically in the code, including whatever
  derivations are needed to maintain them.
- Code should still use math notation (shared with the book) whenever
  describing a concept or object that exists in the book. The notation home
  is the book; code references it.

## Code owns API truth

- Rustdoc is the authority for API specifics: signatures, bounds, feature
  behavior, error semantics, safety contracts, preconditions, postconditions,
  and invariants.
- A reader relying only on rustdoc should be able to correctly use every
  public item and implement every required trait.
- The book may cover the same topics at a higher level (motivation, design
  rationale, composition guidance) but defers to code documentation for
  specifics.
- If the book states a constraint more precisely than rustdoc, that precision
  must move to rustdoc.

## Don't write the same thing twice

- For any given topic, decide which components belong on which surface. The
  book typically owns the conceptual overview; the code owns the lower-level
  details. This split can be ad-hoc per topic.
- Each piece of information has one canonical home.
- When both surfaces need to reference the same content, use summary + link
  rather than parallel full descriptions.
- Tiny, drift-resistant fragments (one-line definitions, single formulas,
  short warnings) may be duplicated; anything larger should not.

## Code changes; the book should not become redundant

- Volatile, implementation-coupled facts (optimizations, representation
  choices, algorithm variants) belong in code docs.
- The book stays abstract enough that routine code changes don't invalidate
  it.
- Content that interacts with the book in limited or compartmentalized ways
  is better documented only in the code.

## Code has better examples

- Rustdoc examples compile and test — they are the canonical runnable samples
  and the least likely to bitrot.
- The book should reuse tested snippets (doctests, examples, tests) where
  possible; use pseudocode when runnable code isn't practical.
- `rust,ignore` in the book is a last resort.
