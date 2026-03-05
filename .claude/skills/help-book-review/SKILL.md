---
name: help-book-review
description: Show help for the book review pipeline
user-invocable: true
---

Print the following help text exactly, then stop. Do not add commentary.

---

## Book Review Pipeline

Three skills, one feedback loop:

**`/book-review`** — review any part of the book
**`/book-refine`** — improve the review system based on your feedback
**`/doc-audit`** — audit book vs. rustdoc surface placement

### Reviewing

```
/book-review                              review uncommitted changes
/book-review book/src/guide/gadgets/      review a whole section
/book-review book/src/protocol/core/nark.md   review a specific chapter
/book-review book/src/protocol/core/nark.md:40-80   focus on specific lines
/book-review book/src/protocol/prelim/bulletproofs.md book/src/protocol/core/nark.md
                                          review multiple files + cross-file consistency
/book-review "accumulation schemes"       find and review a topic wherever it appears
/book-review "the transition from preliminaries to core construction"
                                          review a conceptual boundary across chapters
```

Launches one parallel agent per policy file in `.claude/book-review/`. Currently:
**grammar**, **prose**, **structure**, **math**, **formatting**. Results are
synthesized and presented as must-fix issues first, then suggestions.

### Refining

After a review, give feedback in natural language, then:

```
/book-refine                              use feedback from the conversation
/book-refine "stop flagging passive voice in definitions"
/book-refine "I'd write 'the prover' not 'a prover'"
/book-refine "add a reviewer for code example accuracy"
```

This enters plan mode — it reads all policies, generalizes your feedback into
a principle, audits for duplication/contradictions, and shows you the proposed
changes before executing. New policy files are auto-discovered by `/book-review`.

### Policy files

```
.claude/review-shared/writing.md              shared writing rules (grammar + prose reviewers)
.claude/review-shared/math.md                shared math notation rules (math reviewer)
.claude/review-shared/surface-placement.md   book vs. rustdoc placement policy
.claude/book-review/standards.md  master standards (all reviewers)
.claude/book-review/grammar.md    book-specific grammar rules
.claude/book-review/prose.md      transitions, terminology appendix
.claude/book-review/structure.md  organization, flow, progressive disclosure
.claude/book-review/math.md       notation, correctness, accessibility
.claude/book-review/formatting.md line width, headings, code blocks
```

Edit these directly or let `/book-refine` manage them.

---
