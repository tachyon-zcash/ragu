---
name: code-review
description: Review Rust changes using Ragu policies; validate findings and report coverage.
user-invocable: true
---

# Code review

Review `$ARGUMENTS` using the project's current policies.

## Scope and snapshot

- No arguments: review `git diff HEAD -- '*.rs'` and untracked Rust files from
  `git ls-files --others --exclude-standard -- '*.rs'`. Stop if both are empty.
- Staged changes: use `git diff --cached -- '*.rs'` and index contents.
- PR number or URL: capture the base tip, comparison base (normally the merge
  base), and head as full SHAs; review the diff and full affected files there.
- Files, line ranges, or a concept: locate the relevant implementation and
  inspect enough surrounding code and callers to assess it.

Record scope, local HEAD or PR SHAs, and selected contents, including untracked
files. Preserve existing edits when isolating a snapshot. Clarify scope only
when it cannot be determined. Before reporting, recheck the inputs; refresh
changed findings and checks or identify the older snapshot and unfinished work.

## Policies and checks

Discover `.claude/code-review/*.md`, read `standards.md` and every applicable
policy, and apply their shared references. For documentation, also read
`.claude/review-shared/{writing,math,surface-placement}.md`. For code that runs
in a `Driver` context (gadgets, circuits, stages, steps, routines), apply
`circuit-documentation.md` to its doc comments as well; it condenses
`book/src/implementation/circuit-code-documentation.md`, which stays the
convention's canonical text.

Prefer Read for files, Grep for searches, and Glob for discovery.
In minimal runtimes without Grep/Glob, use Bash `rg` for searches and
`rg --files --hidden` for discovery, including the review policy directory.

For Rust or build changes, run pinned-nightly formatting, workspace Clippy,
rustdoc including private items, and targeted tests, using CI toolchains,
targets, and features. Deny Clippy and rustdoc warnings. Check documentation
changes on their edited surface. Run checks once per snapshot; record commands,
configuration, results, and test counts. Confirm the intended tests actually ran.
Distinguish setup failures from test failures and explain skipped or unavailable
checks.

Do not report compiler/linter diagnostics, unsupported style preferences, or
the particular lint waived by an allow. For diff reviews, exclude unrelated
pre-existing issues. An intentional behavior change still needs review against
its new contract.

## Validate and report

Check candidates against affected code, callers, and policies. Try to disprove
behavioral defects using existing safeguards, unreachable triggers, or the
intended new contract. For diff reviews, establish how the change introduces,
worsens, or exposes the issue. Policy findings must cite the actual rule and
conflicting text.
Resolve disagreements with evidence and merge findings sharing a root cause.

Mark each discovered policy area completed, incomplete, or not applicable
(with a reason). Coverage is complete only when every applicable area is reviewed.
Report scope and snapshot, checks, and remaining gaps.
Separate must-fix findings from suggestions, ordered by file and line; include
locations, evidence, consequences, and concrete corrections. Keep unresolved
hypotheses distinct from confirmed defects. Add cross-cutting observations
only when useful. If no supported findings remain, say so for the inspected
scope; there is no finding quota.

## Requested follow-up

Deliver the review before fixing or publishing unless already authorized.
For requested fixes, reread current contents, preserve unrelated edits, and
run relevant regression checks; Rust/build fixes also require `just ci_local`.
Report deferred findings and validation limits.

Before requested PR publication, refresh findings if the head changed. Use
`gh pr comment` with a numbered synthesis, code links pinned to the full
reviewed SHA and line ranges, and coverage limits.
