---
name: doc-audit
description: Audit documentation surface placement (book vs. rustdoc) and refine the policy
user-invocable: true
---

# Doc Audit

Audit documentation for surface placement violations — content that lives in
the wrong place (book vs. rustdoc) per the project's surface placement policy.
For each violation, the user decides whether to fix the content, refine the
policy, or defer.

## Step 1: Figure Out What to Audit

The user's `$ARGUMENTS` determine scope. Interpret them:

| Arguments | What to do |
|-----------|-----------|
| *(empty)* | Run `git diff -- '*.rs' book/src/` and `git diff --cached -- '*.rs' book/src/`. Audit uncommitted documentation changes. If no changes, say so and stop. |
| A Rust file or module path | Read the rustdoc for that file/module. Find the corresponding book chapter(s) by following links or searching `book/src/`. Audit both sides. |
| A book chapter path | Read that chapter. Find the corresponding rustdoc by following links or searching for referenced types/traits. Audit both sides. |
| A concept or trait name (e.g., "Driver", "Gadget") | Search both rustdoc and book for all mentions. Audit the full documentation surface for that concept. |
| Multiple paths or concepts | Handle each, then audit for cross-cutting consistency. |
| A PR number or URL | Fetch the PR diff with `gh pr diff`. Audit documentation changes in the diff. |

If you're unsure what the user means, ask before launching agents.

## Step 2: Gather Context

1. Read `.claude/review-shared/surface-placement.md` (the policy).
2. Read the target content identified in Step 1 — both the rustdoc side and
   the book side. For each piece of documentation being audited, you need
   visibility into the other surface to detect misplacements.
3. If the target is a concept, use Grep to find all occurrences in both
   `book/src/` and Rust source files.
4. Read `book/FIXME.md` and extract the `###`-level headings under
   `## Deferred Issues`. These will be injected into agent prompts to prevent
   re-raising known issues.

## Step 3: Launch Auditors

Launch three `general-purpose` Task agents in parallel (model `sonnet`), each
with a different focus. Also run automated checks in parallel (see below).

### Agent 1: Rustdoc Audit

> You are auditing rustdoc (Rust doc comments) in the ragu project against its
> surface placement policy.
>
> Read these files:
> - `.claude/review-shared/surface-placement.md` (the placement policy)
> - `.claude/code-review/standards.md` (master code review standards — for
>   severity calibration and reviewer restraint)
>
> **What to audit:** {describe the rustdoc content — file paths, the diff,
> specific items}
>
> {If the scope is a diff or a narrow range, add: "Focus on the specified
> content. Flag issues in surrounding text ONLY if the specified content
> introduced an inconsistency with it."}
>
> {If the scope spans multiple files or a concept, add: "Pay attention to
> consistency across the files. Flag contradictions, redundancies, or
> inconsistencies as they span these locations."}
>
> Look for:
> - Content in rustdoc that belongs in the book per the policy (math-heavy
>   exposition, design rationale, cross-cutting composition guidance)
> - Missing content that the policy requires in rustdoc (preconditions,
>   postconditions, invariants, safety contracts, feature behavior)
> - Missing links to book chapters where the policy requires them
>
> **Do NOT flag:**
> - Pre-existing issues on unmodified lines (unless the change introduced
>   an inconsistency)
> - Things that linters or compilers already catch
> - Pedantic nitpicks not backed by the surface placement policy
> - Code-local algorithm docs with math — the policy explicitly allows these
>
> The following issues are already tracked and deferred. Do NOT raise
> findings that duplicate or overlap with these items:
> {bullet list of ### headings from book/FIXME.md}
>
> For each finding:
> - **Location**: file path and line number (or item name)
> - **Rule**: which policy rule is violated (quote it)
> - **Issue**: what's wrong, specifically
> - **Suggestion**: a concrete fix — what to move, add, or remove
> - **Severity**: `must-fix` or `suggestion`
>
> **Tool usage rules:**
> - Use the Grep tool for searching — do NOT run `grep` or `rg` via Bash.
> - Use the Read tool to read files — do NOT use `cat`, `head`, or `tail`.
> - Use the Glob tool to find files — do NOT use `find` or `ls`.
> - When you do use Bash, the command must be a clean shell command with NO
>   comment lines (`#`) prepended. Put your reasoning in the `description`
>   parameter, not in the command itself.
>
> If you find no violations, say so — don't manufacture problems.

### Agent 2: Book Audit

> You are auditing book content in the ragu project against its surface
> placement policy.
>
> Read these files:
> - `.claude/review-shared/surface-placement.md` (the placement policy)
> - `.claude/book-review/standards.md` (master book review standards — for
>   severity calibration and reviewer restraint)
>
> **What to audit:** {describe the book content — file paths, the diff,
> specific sections}
>
> {If the scope is a diff or a narrow range, add: "Focus on the specified
> content. Flag issues in surrounding text ONLY if the specified content
> introduced an inconsistency with it."}
>
> {If the scope spans multiple files or a concept, add: "Pay attention to
> consistency across the passages. Flag contradictions, redundancies, or
> gaps as they span these locations."}
>
> Look for:
> - Content in the book that belongs in rustdoc per the policy (precise API
>   constraints stated only in the book, safety contracts, exact
>   pre/postconditions)
> - Content that duplicates rustdoc at the same register (same-register
>   duplication, not informal restatement)
> - Missing links to rustdoc items where the policy requires them
> - Volatile, implementation-coupled details that belong in code docs
>
> **Do NOT flag:**
> - Pre-existing issues on unmodified lines (unless the change introduced
>   an inconsistency)
> - Informal restatements of API requirements that aid understanding —
>   the policy explicitly allows these
> - Pedantic nitpicks not backed by the surface placement policy
>
> The following issues are already tracked and deferred. Do NOT raise
> findings that duplicate or overlap with these items:
> {bullet list of ### headings from book/FIXME.md}
>
> For each finding:
> - **Location**: file path and line number (or quoted text)
> - **Rule**: which policy rule is violated (quote it)
> - **Issue**: what's wrong, specifically
> - **Suggestion**: a concrete fix — what to move, add, or remove
> - **Severity**: `must-fix` or `suggestion`
>
> **Tool usage rules:**
> - Use the Grep tool for searching — do NOT run `grep` or `rg` via Bash.
> - Use the Read tool to read files — do NOT use `cat`, `head`, or `tail`.
> - Use the Glob tool to find files — do NOT use `find` or `ls`.
> - When you do use Bash, the command must be a clean shell command with NO
>   comment lines (`#`) prepended. Put your reasoning in the `description`
>   parameter, not in the command itself.
>
> If you find no violations, say so — don't manufacture problems.

### Agent 3: Cross-Reference Audit

> You are auditing cross-references between the book and rustdoc in the ragu
> project against its surface placement policy.
>
> Read these files:
> - `.claude/review-shared/surface-placement.md` (the placement policy)
> - `.claude/book-review/standards.md` (for link integrity rules)
> - `.claude/code-review/standards.md` (for severity calibration)
>
> **What to audit:** {describe the scope — which files/concepts on both sides}
>
> {If the scope is a diff or a narrow range, add: "Focus on the specified
> content. Flag issues in surrounding text ONLY if the specified content
> introduced an inconsistency with it."}
>
> Look for:
> - Non-trivial claims with parallel full descriptions on both surfaces
>   instead of canonical home + summary + link
> - Duplicated fragments that are NOT tiny/drift-resistant
> - Inconsistent notation or terminology between book and rustdoc for the
>   same concept
> - Rustdoc-to-book links that lack resilient summaries (the fragile
>   direction — broken links should degrade gracefully)
>
> **Do NOT flag:**
> - Pre-existing issues on unmodified lines (unless the change introduced
>   an inconsistency)
> - Tiny, drift-resistant duplications (one-line definitions, single
>   formulas, short warnings) — the policy explicitly allows these
>
> The following issues are already tracked and deferred. Do NOT raise
> findings that duplicate or overlap with these items:
> {bullet list of ### headings from book/FIXME.md}
>
> For each finding:
> - **Location**: both sides — the book location and the rustdoc location
> - **Rule**: which policy rule is violated (quote it)
> - **Issue**: what's wrong, specifically
> - **Suggestion**: a concrete fix
> - **Severity**: `must-fix` or `suggestion`
>
> **Tool usage rules:**
> - Use the Grep tool for searching — do NOT run `grep` or `rg` via Bash.
> - Use the Read tool to read files — do NOT use `cat`, `head`, or `tail`.
> - Use the Glob tool to find files — do NOT use `find` or `ls`.
> - When you do use Bash, the command must be a clean shell command with NO
>   comment lines (`#`) prepended. Put your reasoning in the `description`
>   parameter, not in the command itself.
>
> If you find no violations, say so — don't manufacture problems.

Launch ALL three agents in parallel.

### Automated Checks

In parallel with the agents, run:

1. `python3 qa/book/broken_links.py` — catches broken cross-surface links
2. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --document-private-items`
   — catches broken intra-doc links

If either fails to run, note the failure but do not block the review. Include
any findings alongside agent results in synthesis.

## Step 4: Synthesize

Once all agents return, organize findings by location. If multiple agents
flagged overlapping concerns, merge them. Before presenting, read
`book/FIXME.md` and remove any finding that substantially overlaps with an
already-deferred issue. Present:

- **Must-fix** issues first
- **Suggestions** second
- For each finding, note which agent identified it

## Step 5: Validate Proposed Changes

After synthesizing findings, but before presenting them to the user:

1. Collect all proposed changes (the "suggestion" field from each finding) into
   a single numbered list — the **proposed plan**.
2. Launch validation agents. Fixes may touch rustdoc or book content, so
   validate against both review systems:

   - For EACH `.claude/code-review/*.md` file **except `standards.md`**, launch
     a `general-purpose` Task agent (model `sonnet`).
   - For EACH `.claude/book-review/*.md` file **except `standards.md`**, launch
     a `general-purpose` Task agent (model `sonnet`).

   Give each agent this prompt:

   > You are validating a set of proposed documentation changes against review
   > policies.
   >
   > Read these files:
   > - `.claude/{code-review or book-review}/standards.md` (master standards)
   > - `.claude/{code-review or book-review}/{focus}.md` (your policy)
   > - `.claude/review-shared/surface-placement.md` (placement policy)
   {if focus is "documentation" (code-review) or any book-review policy,
   also include:}
   > - `.claude/review-shared/writing.md` (shared writing rules)
   > - `.claude/review-shared/math.md` (shared math rules)
   >
   > Here is the proposed plan of changes:
   > {numbered list of proposed changes with locations and suggested rewrites}
   >
   > For each proposed change, check whether applying it would **introduce** a
   > violation of any rule in your policy, the master standards, or the
   > surface placement policy. Only flag real conflicts — do not restate rules
   > that are already satisfied.
   >
   > For each conflict found:
   > - **Change #**: which proposed change
   > - **Rule violated**: quote the relevant policy text
   > - **Conflict**: explain specifically how the suggestion violates the rule
   > - **Resolution**: suggest how to fix the suggestion to comply
   >
   > **Tool usage rules:**
   > - Use the Grep tool for searching file contents — do NOT run `grep` or `rg`
   >   as a Bash command.
   > - Use the Read tool to read files — do NOT use `cat`, `head`, or `tail`.
   > - Use the Glob tool to find files — do NOT use `find` or `ls`.
   > - When you do use Bash, the command must be a clean shell command with NO
   >   comment lines (`#`) prepended. Put your reasoning in the `description`
   >   parameter, not in the command itself.
   >
   > If no proposed changes conflict with your policy, say so.

   Launch ALL agents in parallel.

3. Merge validation feedback into the findings. For each conflict:
   - If the validator provides a compliant alternative, replace the original
     suggestion with the corrected version.
   - If the conflict has no clear resolution, annotate the finding with the
     conflict so the user can decide during triage.

4. If any suggestions were corrected, briefly note it in the synthesis output.

## Step 6: Triage

Two modes based on how the audit was invoked:

### Local Mode (file paths, diff, concept)

Use AskUserQuestion to let the user decide the disposition of each finding
(or group of related findings). For each, offer:

- **Fix** — move/add/remove documentation as suggested
- **Refine** — the policy rule is wrong or too strict; note this for a
  follow-up `/book-refine` or `/code-refine` pass
- **Defer** — record this finding in `book/FIXME.md` for future attention
- **Skip** — drop this finding

If there are many findings, batch them into logical groups.

### PR Mode (`#123` or PR URL)

Use AskUserQuestion to let the user decide whether to post a synthesis comment
on the PR via `gh pr comment`. Format findings as a numbered list with code
links using the full commit SHA and line ranges (`L[start]-L[end]`).

## Step 7: Apply Fixes

For each finding the user chose to **fix**:

1. Read the target file(s) to get the current content.
2. Apply the suggested change using the Edit tool. This may involve:
   - Moving content from one surface to the other
   - Replacing a full description with summary + link
   - Adding a missing link or anchor
   - Adding missing preconditions/invariants to rustdoc
3. After all fixes, run relevant checks:
   - `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --document-private-items`
     (if rustdoc was modified)
   - `python3 qa/book/broken_links.py` (if book was modified)

## Step 8: Record Deferred Issues

For each finding the user chose to **defer**:

1. Read `book/FIXME.md`.
2. Check whether a substantially similar issue is already listed. First scan
   the `###` headings for a potential match; if a heading looks similar, read
   the paragraph beneath it to confirm it describes the same issue. Only skip
   if both the heading and description match.
3. If the issue is new, append it as a new `###`-level subsection under
   `## Deferred Issues`, following the existing format: a short descriptive
   heading, then a concise paragraph explaining the issue and its location.
4. Write the updated file.

## Step 9: Handle Refine Requests

For each finding the user chose to **refine**:

Collect the findings and the user's reasoning (why the rule is wrong or too
strict). Then tell the user to run `/book-refine` or `/code-refine` with that
context — surface-placement.md lives in `review-shared/`, so either refine
skill can update it. Provide the specific findings and reasoning so the user
can paste them as arguments.

Do NOT modify `.claude/review-shared/surface-placement.md` directly. Policy
changes have wide blast radius (both review systems read the file) and require
the plan-mode, generalization, and system-wide audit steps that the dedicated
refine skills provide.

The goal is to iteratively tighten the policy: each audit round either fixes
violations or trims rules that don't hold up, converging toward a small,
enforceable set.

## Step 10: Report

Tell the user:

1. **Fixes applied** — what was moved/added/removed and where
2. **Deferred** — what was recorded in `book/FIXME.md`
3. **Refine needed** — findings marked for policy refinement, with the
   suggested `/book-refine` or `/code-refine` invocation
4. **Check results** — any issues from rustdoc build or link checks
5. **Remaining scope** — if the audit was narrow, suggest what to audit next
