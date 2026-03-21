# Documentation Review Policy

## Scope

Review documentation in Rust source files — doc comments (`///`, `//!`), code
comments (`//`), and module-level documentation. For shared prose and math
rules, see `.claude/review-shared/writing.md` and `.claude/review-shared/math.md`.
For book vs. rustdoc placement rules, see
`.claude/review-shared/surface-placement.md`.

## Prose in Doc Comments

- Write doc comments as complete sentences with proper punctuation.
- Third-person singular for functions: "Returns the sum" not "Return the sum".
  Type descriptions start with an article: "A wrapper for..." not "Wrapper
  for...".
- Prefer relative clauses: "Type that computes X" not "Type for computing X".
- Start `///` with a brief one-line summary, then a blank line, then details.
- Link related items with intra-doc links: `` [`OtherType`] `` not "see
  OtherType". Link consistently — if you use `` [`Foo`] `` once, use it
  everywhere in that block. Inconsistent linking suggests carelessness.
- Module docs should only name public API items. If you can't link to it,
  don't mention it — it's an implementation detail.

## Formatting

- Wrap doc prose at ~80 chars (after the `///` or `//!` prefix). Display math
  and code blocks may exceed this.
- Escape underscores in LaTeX subscripts as `\_{...}` to prevent markdown
  interpretation. Write `$\mathbf{u}\_{i,j}$` not `$\mathbf{u}_{i,j}$`.
- Display math (`$$ ... $$`) on separate lines, not inline with prose.
- Link reference definitions (`` [`Foo`]: path::to::Foo ``) go at the end of
  the doc block, not interspersed with prose.
- Use `#` for top-level module headings, skip to `###` for subsections. `##`
  is too visually similar to `#` to serve as a useful hierarchy level.
- Blank line between doc blocks for adjacent struct fields.
- Blank line before code comments unless at the start of a block.
- Always backtick code identifiers, including in headings:
  write `` ### The `ONE` Wire `` not `### The ONE Wire`.

## Module Documentation Structure

- Lead with motivation before implementation. Readers need context to evaluate
  design choices — explain *why* before *how*.
- Separate background from design rationale. Use distinct sections: "Background"
  for conceptual grounding, "Design" for architectural choices and trade-offs.
- Justify design decisions. Don't just say "we do X"; explain why the naive
  alternative is undesirable.
- Make implicit dependencies explicit. Use doc links (`` [`Driver`] ``) rather
  than assuming the reader knows the surrounding architecture.
- Enumerate submodules with one-line summaries when a module organizes several.
- Connect math to code: tie mathematical constructs to concrete code paths.

## Doc Comments vs Code Comments

- `///`/`//!`: API-facing — what something does, why, how to use it, invariants.
- `//`: Implementation details — algorithm steps, optimization rationale,
  non-obvious behavior. If you're explaining *how* rather than *what*, it
  belongs in a code comment.
- In non-doc `//` comments, avoid Unicode math symbols. Prefer breaking into
  smaller functions with doc comments that render KaTeX.

## Content Guidelines

- Establish documentation ownership: one authoritative location per concept.
  Other modules reference that location rather than re-explaining.
- Avoid tables that merely reformat information visible in the code.
- Don't document obvious optimizations. If the optimization isn't surprising,
  don't mention it.
- Document intended behavior, not incidental capabilities.
- For polynomial eval functions: verify fixed vs free variables match the
  signature. Convention: uppercase (X, Y) = polynomial variables; lowercase
  (x, y) = fixed evaluation points.
