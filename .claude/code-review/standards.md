# Code Review Master Standards

These standards apply to all code reviewers. Each reviewer also has a
focus-specific policy file.

## Scope

- Review Rust source files (`.rs`) in the workspace.
- Focus on changed code. Flag surrounding code ONLY if the change introduced
  an inconsistency with it.

## Severity Levels

- **must-fix**: Correctness bug, safety issue, clear violation of project
  conventions, or documentation that is actively misleading.
- **suggestion**: Improvement that would make the code clearer, more idiomatic,
  or easier to maintain, but isn't wrong as-is.

## Synced Content

Some content appears in both the README and the book, delimited by
`<!-- BEGIN SYNC -->` / `<!-- END SYNC -->` HTML comments. The canonical
pairs are:

| README section | Book page |
|---------------|-----------|
| `## Requirements` | `book/src/guide/requirements.md` |

When reviewing changes inside a synced block, verify that the
corresponding file contains identical content. Flag any drift as
`must-fix`. When editing a synced block (e.g. during fix-up), update
both files in the same change.

## Shared Policies

For content placement decisions (book vs. rustdoc), see
`.claude/review-shared/surface-placement.md`.

## General Principles

- Be specific. "This could be improved" is not actionable. Quote the code, name
  the issue, propose a fix.
- Stay within your policy's scope. If something is outside your area, leave it
  for the relevant reviewer.
- If you find no real issues, say so. Do not manufacture problems.
- Consider the project context: this is a `no_std` recursive proof system
  (proof-carrying data framework). Cryptographic code has different norms than
  application code.
