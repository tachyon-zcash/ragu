---
name: master-fv
description: Run Ragu formalization work through fv-docs, fv-review, spec-fidelity-audit, and fv-preflight in that order, fixing each stage's findings before advancing. Use when implementing or revising a formalization, or when asked for /master-fv or the full FV cycle.
---

# Master FV

Invoke each of the four maintained FV skills exactly once, in the order below.
At each stage, read and apply its linked `SKILL.md` in full, fix what it flags,
and validate those fixes before invoking the next skill. Use the files in the target checkout so
refinements to those skills carry into this workflow. Invoking `master-fv` invokes
all four stages, including those that normally require named invocation.

## Workflow

Run sequentially, in this exact order:

1. **[fv-docs](../fv-docs/SKILL.md).** Read the authoritative in-tree FV pages
   relevant to the task. Ground the formalization and any prose edits in those
   definitions, keeping assumptions and coverage limits explicit.
2. **[fv-review](../fv-review/SKILL.md).** Apply its reimplementation, interface,
   specification, and proof guidance while implementing or reviewing the scoped
   formalization. Investigate proof failures and newly added hypotheses as
   possible under-constraint findings.
3. **[spec-fidelity-audit](../spec-fidelity-audit/SKILL.md).** Audit design intent,
   implementation, and formalization together. Keep its finding tags and
   per-claim coverage map, including gaps in the proof-to-code connection and
   unavailable evidence.
4. **[fv-preflight](../fv-preflight/SKILL.md).** Run its merge-blocker audit and
   required final sweep on the resulting changes, including the foundational
   trust, coverage, and non-vacuity checks. Record actual command results and
   any checks that could not run.

The linked skills own their detailed procedures. Keep that guidance in its
existing files rather than duplicating it here.

## Finish

Keep one findings list across stages. Resolve each stage's actionable findings
within the authorized scope before advancing. Rerun affected validation as needed,
keeping the skills in a single ordered pass. Finish after `fv-preflight`'s findings
are addressed and its required checks pass.

If a finding needs unavailable evidence, a dependency, or a design decision,
report it as a blocker with what is needed to resolve it; complete any
independent work without counting the blocked stage as passed.

Briefly summarize fixes and validation results, and note any remaining blockers.
