# Book Standards

Master standards that apply to all book reviewers. Every reviewer agent reads
this file in addition to its focus-specific policy.

## Shared Policies

For content placement decisions (book vs. rustdoc), see
`.claude/review-shared/surface-placement.md`.

## Page Roles

The book's introduction (`book/src/introduction.md`) serves as a landing page,
not a narrative chapter. Its purpose is to briefly describe the project and
direct readers to the appropriate sections. When reviewing the introduction:

- Do NOT flag it for missing motivational openings, narrative transitions, or
  closing summaries.
- Do NOT flag jargon that is linked to a page where it is defined. Inline
  expansion of every term is not expected on a landing page.
- DO review it for clarity, accuracy, and link coverage.

## Link Integrity

Any change that alters a page's file path, moves a file, or renames a heading
must include corresponding updates to every reference pointing to that content.
This includes:

- Internal markdown links (`[text](path.md)`) throughout the entire book
- Anchor links (`[text](path.md#heading-slug)`) that reference renamed headings
- Entries in `book/src/SUMMARY.md`

When reviewing changes that move or rename content, verify that all affected
links have been updated — not just links in the changed file, but in every file
that references it. A renamed heading with no updated anchors elsewhere is a
broken link waiting to happen.
- Every heading that is the target of an anchor link must have an explicit
  `{#slug}` attribute (e.g., `## My Heading {#slug}`). Do not rely on
  mdbook's auto-generated slugs — they break silently when heading text
  changes. Slugs should be concise and deliberately chosen.
- Flag any anchor link (`#slug`) whose target heading lacks an explicit
  `{#slug}` attribute.

## Citations

Academic-style citation tags (e.g., `[BGH19]`, `[BCTV14]`) follow these
rules:

- Every citation tag must be a hyperlink to its source (typically an ePrint
  or conference URL). A bare, unlinked citation tag is a must-fix finding.
- Nested brackets are acceptable when a citation tag appears inside link
  text (e.g., `[Halo [BGH19]](url)`). Do not flag this as a style issue.

## API Contracts

When describing API contracts (preconditions, invariants, required properties),
state the contract itself — not the consequences of violating it. Adding
"violations may cause panics or incorrect behavior" is noise, since *any*
contract violation can produce incorrect behavior. The documentation should be
aimed at consumers; implementors know they must satisfy the contract.

Exception: `# Safety` sections on `unsafe` items, where the consequences
are undefined behavior and the caller must be warned explicitly.

## Code Accuracy

When book prose describes a specific API signature, trait method, default
implementation, or observable code behavior, verify the description against
the actual source. Common drift:

- Describing a method as "overridable" or having a "default implementation"
  when no override exists (or vice versa).
- Describing what a closure returns or how a type parameter is used
  incorrectly.
- Using the wrong symbol for a placeholder (e.g., `'_` vs. `_` in macro
  syntax) because the prose was written from memory rather than checked.

Flag inaccurate API descriptions as `must-fix`. When uncertain, read the
source file — the relevant crate paths are listed in the root `CLAUDE.md`.

Code Accuracy covers factual claims — signatures, behaviors, type
relationships. It does not require book prose to mirror rustdoc's exact
vocabulary. The book may deliberately use different terminology when the
source code's phrasing is imprecise or misleading in a pedagogical context
(e.g., calling a type-determined property "static" rather than "compile-time"
if the compiler doesn't actually reason about it at compile time). Do not
flag word-choice divergences from rustdoc as Code Accuracy issues unless the
book's phrasing makes a factually incorrect claim.

## Reviewer Restraint

Before raising a finding, consider whether the text is actually unclear to a
competent reader encountering it in order, or whether the concern is purely
hypothetical. Rules exist to catch genuine problems — not to override clear
authorial choices with mechanically "safer" alternatives.

Specific anti-patterns to avoid:

- **Demanding explicit counts on lists.** Do not require list introductions
  to state an exact count. The author may deliberately leave a list
  open-ended to signal non-exhaustiveness, especially when an explicit count
  would make a general principle appear to produce an arbitrary, fixed number
  of consequences.
- **Flagging anaphoric grouping terms as terminology violations.** A general
  noun with a demonstrative that refers back to items named in the preceding
  clause (e.g., "these primitives" after "wires and witness data") is
  standard prose, not an inconsistency. Do not flag these.
- **Trope rules are density-sensitive.** Many anti-trope rules (in
  grammar.md and prose.md) flag patterns that are acceptable in
  isolation. Flag them when they repeat within a section or when
  several appear together — not on a single occurrence.

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

## Deferred Issues

The file `book/FIXME.md` tracks known issues that were identified during
review but deferred for later resolution. The lifecycle is:

1. **Defer**: During review triage, the user marks a finding as "defer" —
   it is recorded in `book/FIXME.md` as a `###`-level entry.
2. **Suppress**: Reviewers are given the list of deferred issues and must
   not re-raise them as findings.
3. **Resolve**: When a solution is available, use `/book-fixme` to apply
   the fix and remove the entry.

Reviewers should not re-raise deferred issues, but SHOULD note when a
deferred issue appears to have been resolved or become easily resolvable
given surrounding changes.