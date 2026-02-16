---
name: code-refine
description: Incorporate feedback into code review policies, standards, and infrastructure
user-invocable: true
---

# Code Refine

Incorporate the user's feedback into the code review system. The feedback is in
`$ARGUMENTS` and/or in the preceding conversation context. This skill modifies
the code review infrastructure itself to make future reviews better.

**You MUST use plan mode (EnterPlanMode) for this skill.** Do all analysis and
auditing first, present a plan for the user's approval, and only then execute.

## Step 1: Read Everything

Read ALL of these files before doing anything else:

- `.claude/review-shared/writing.md` — Shared writing rules (used by book-review and code-review)
- `.claude/review-shared/math.md` — Shared math notation rules (used by book-review and code-review)
- `.claude/code-review/standards.md` — Master standards shared across all code reviewers
- All files matching `.claude/code-review/*.md` — Per-focus review policies
- `.claude/skills/code-review/SKILL.md` — Code review orchestration
- `.claude/skills/code-refine/SKILL.md` — This file

## Step 2: Understand the Feedback

The user's feedback could be anything. Common forms:

- **A specific rewrite**: "I'd write it like: ..." — the user is showing you
  their preferred style by example. Extract the implicit rule.
- **A complaint about a review**: "Stop flagging X" or "That's not actually
  wrong" — a policy is too aggressive or incorrect.
- **A gap**: "You missed that..." or "You should also check for..." — a policy
  is missing coverage.
- **A new dimension**: "I need reviews to also check for..." — need a new
  policy file entirely.
- **A process change**: "Reviews should work differently..." — the skill
  orchestration needs modification.
- **A cross-cutting concern**: something that doesn't fit neatly into one
  policy, or that requires reviewers to coordinate.

## Step 3: Generalize

Don't just record the specific instance — extract the underlying principle.
Examples:

| User says | Generalized rule |
|-----------|-----------------|
| "Don't flag this as an unwrap issue, it's inside a test" | `unwrap()` and `expect()` are acceptable in test code (`#[cfg(test)]` modules and `tests/` crates) |
| "The naming reviewer shouldn't complain about single-letter variables in closures" | Single-letter names are acceptable in short closures and iterator chains where the type provides sufficient context |
| "You missed that the doc comment says 'evaluate' but the function is called 'eval_at'" | Flag mismatches between doc comment verbs and function names — the doc summary should use the same verb as the function name |
| "Stop flagging my `as` casts in const contexts" | `as` casts are acceptable in `const` contexts where `try_into()` is not available |
| "This function is too complex to split — add an exception for synthesis functions" | Functions that orchestrate circuit synthesis may exceed the 50-line guideline when splitting would obscure the constraint structure |
| "You should also check that `// SAFETY:` comments actually justify the invariant" | (Strengthening an existing rule: don't just check presence of `// SAFETY:`, verify the comment explains soundness) |

If you're not sure how to generalize a specific correction into a principle,
ask the user. Don't guess — a wrong generalization is worse than none.

## Step 4: Audit the Entire Policy System

Before deciding where to put anything, review the full set of policies and
standards as a whole. Look for:

- **Duplication**: Does this rule (or something close to it) already exist
  somewhere? If so, strengthen or clarify the existing rule rather than adding
  a second one. If the same concept appears in multiple places, consolidate.
- **Contradictions**: Does the new rule conflict with anything already in the
  policies? If so, resolve the conflict — ask the user if it's ambiguous which
  should win.
- **Consolidation opportunities**: Has the policy system grown rules that are
  specific cases of a more general principle? If so, propose replacing them
  with the generalization.
- **Misplaced rules**: Are any existing rules in the wrong file? A rule in
  `documentation.md` that's really about correctness belongs in
  `correctness.md`. Flag and propose moves.
- **Scope creep**: Is a policy file accumulating rules outside its stated scope?
  If so, propose splitting or redistributing.
- **Staleness**: Do any existing rules seem outdated given the user's latest
  feedback? The user's new feedback might implicitly supersede an older rule.
- **Shared vs specific**: Could the new rule benefit book-review too? If so,
  it belongs in `.claude/review-shared/` rather than `.claude/code-review/`.

Include any findings from this audit in your plan, even if they go beyond the
user's immediate feedback. The goal is to keep the policy system coherent as it
grows.

## Step 5: Plan the Changes

Enter plan mode (EnterPlanMode). Your plan should include:

1. **The generalized principle(s)** extracted from the feedback.
2. **Where each change goes** and why:
   - Cross-cutting writing rule (shared with book-review) → `.claude/review-shared/writing.md`
   - Cross-cutting math rule (shared with book-review) → `.claude/review-shared/math.md`
   - General code standard (all code reviewers) → `.claude/code-review/standards.md`
   - Focus-specific rule (one reviewer) → the appropriate `.claude/code-review/*.md`
   - New review dimension → new `.claude/code-review/{name}.md`
   - Process/orchestration change → `.claude/skills/code-review/SKILL.md`
   - Learning process change → this file
3. **Audit findings** — any duplication, contradictions, consolidation
   opportunities, or misplaced rules discovered in Step 4, with proposed fixes.
4. **The specific edits** you intend to make, quoted clearly enough for the
   user to approve or reject each one.

When in doubt between general and specific placement, prefer the more specific
location. A rule can always be promoted to `.claude/code-review/standards.md`
later if it turns out to be universal.

Wait for user approval before proceeding.

## Step 6: Execute

After the user approves the plan:

- Edit the target file(s). Add new rules in the appropriate section.
- For `.claude/code-review/standards.md`, add to the appropriate existing
  section or create a new section if none fits.
- If creating a new policy file, follow the same structure as existing ones
  (Scope, then themed sections with rationale and examples).
- Execute any consolidation, deduplication, or moves identified in the audit.

## Step 7: Report

Tell the user:

1. **What principle(s) you extracted** — each generalized rule, stated clearly
2. **Where you put each one** — which file and section
3. **The exact new text** — quote what you added or changed
4. **Audit actions taken** — any deduplication, consolidation, or moves beyond
   the immediate feedback
