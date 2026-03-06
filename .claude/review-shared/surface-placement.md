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
- Rustdoc may fully state API requirements (preconditions, invariants,
  safety contracts, behavioral descriptions of public items) even when
  the book covers the same topic — each surface must serve its audience
  independently. This is not duplication; it is each surface doing its job.
- Pure design rationale or motivational exposition that adds no API
  insight should not be duplicated — use summary + link instead.

## Code changes; the book should not become redundant

- Volatile, implementation-coupled facts (optimizations, representation
  choices, algorithm variants) belong in code docs.
- The book stays abstract enough that routine code changes don't invalidate
  it.
- Content that interacts with the book in limited or compartmentalized ways
  is better documented only in the code.

## The book can cross-cut; rustdoc is item-scoped

- Rustdoc is structurally tied to items (modules, types, functions).
  Explanations that span multiple items or modules are awkward in rustdoc —
  you have to pick one item to attach them to.
- The book has no such constraint. Concepts that span the crate boundary,
  involve multiple traits interacting, or require narrative buildup belong
  in the book.

## Proximity keeps docs accurate

- Docs next to the code they describe are more likely to be updated when the
  code changes. The farther documentation is from its subject, the faster it
  drifts.
- This reinforces placing implementation-specific details in code docs, not
  just to avoid book redundancy, but because proximity to the code is a
  maintenance incentive.

## Discovery paths differ

- Users find book content by reading linearly or via table of contents; they
  find rustdoc by searching for a type, trait, or function.
- Place content where its audience will look. API specifics in rustdoc because
  that's where users land when they need API info; conceptual overviews in the
  book because that's where users go when learning.

## The book serves non-Rust readers

- Researchers, protocol designers, and auditors may read the book without
  looking at code. The book should be self-contained for understanding the
  system conceptually without requiring Rust literacy.

## Linking is asymmetric

- Book-to-rustdoc links are stable (item paths are crate-structural).
  Rustdoc-to-book links are fragile (anchors and structure can move).
- The fragile direction (rustdoc → book) needs more resilient summaries so
  that a broken link degrades gracefully rather than leaving the reader
  stranded.

## Code has better examples

- Rustdoc examples compile and test — they are the canonical runnable samples
  and the least likely to bitrot.
- The book should reuse tested snippets (doctests, examples, tests) where
  possible; use pseudocode when runnable code isn't practical.
- `rust,ignore` in the book is a last resort.
