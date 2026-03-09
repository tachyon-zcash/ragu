# Prose Quality Review Policy

## Scope

Review text-level writing quality in book chapter markdown files
(`book/src/`). This policy covers concerns that span paragraphs or larger
units of text — transitions and coherence. For sentence-level mechanics
(voice, structure, word choice), see `grammar.md`. All rules in
`.claude/book-review/standards.md` also apply.

In addition to `.claude/review-shared/writing.md` (shared writing rules — terminology
consistency, capitalization, etc.), the following book-specific rules apply.

## Terminology

- Defined terms from `book/src/appendix/terminology.md` take precedence over
  any ad hoc term choices.

## Concept Introduction

- When introducing a mechanism, frame it from the subject's existing
  capability ("Gadgets know how to traverse their own wires") rather than
  from the feature's perspective ("Conversion supports X through Y"). The
  former grounds the reader in something already understood and leads
  naturally into the mechanism; the latter presents an abstract feature
  acting on behalf of an unnamed need.

## Transitions

- Each paragraph should connect to the preceding one. Flag abrupt topic shifts
  with no connecting logic.
- Section transitions should give the reader a reason to keep reading.

## Tone

- Do not use false-suspense transitions to manufacture drama before an
  unremarkable point. Cut "Here's the kicker", "Here's the thing",
  "Here's where it gets interesting", and "Here's what most people miss".
- Only reach for analogy when it is genuinely more illuminating than
  the direct explanation. Don't assume the reader needs a metaphor
  ("Think of it like a highway system for data").
- Do not open an argument by asking the reader to imagine an appealing
  future ("Imagine a world where..."). Make the argument directly.
- Do not perform self-awareness. Simulated candor — pretending to break
  the fourth wall or admit a bias — reads as hollow unless it is
  specific and has stakes.
- Do not cite unnamed authorities ("Experts argue...", "Industry reports
  suggest..."). If you can't name the source, don't invoke it.
- Do not coin compound labels ("supervision paradox", "acceleration
  trap") and treat them as established terms. Name things precisely, or
  make the argument without the label.
- Match the stakes of claims to what is actually being demonstrated.
  Don't inflate every argument to world-historical scale ("will define
  the next era of computing").

## Paragraph Patterns

One instance of any pattern below might be fine. Flag when a pattern
repeats or when several appear together.

- Do not use a string of very short sentences or fragments as standalone
  paragraphs to manufacture emphasis. This is an inhuman cadence — use
  it sparingly and deliberately, not as a default rhythm.
- Do not follow a claim with a stream of verbless gerund fragments as
  standalone sentences ("Fixing small bugs. Writing straightforward
  features. Implementing well-defined tickets.").
- Do not repeat the same sentence opening multiple times in quick
  succession (anaphora). One deliberate use can be effective; a string
  of "They could..." clauses is not.
- One rule-of-three (tricolon) is elegant. Do not stack multiple
  tricolons back-to-back.
- If you're writing a list, write a list. Don't disguise it as prose by
  wrapping each item in a paragraph beginning "The first...", "The
  second...", "The third...".

## Composition

- Do not summarize every section before and after writing it, and do not
  restate at the document level what was just said at the section level.
- Introduce a metaphor, use it, then move on. Don't return to the same
  metaphor throughout an entire piece.
- One well-chosen historical analogy is stronger than five weak ones. Do
  not rapid-fire a list of historical companies or tech revolutions to
  build authority.
- Do not restate a single argument in ten different ways across
  thousands of words. If the point is made, move forward or stop.
- Do not repeat entire paragraphs or sections verbatim within the same
  piece.
- Do not announce the conclusion. End the piece — don't label the
  ending. Cut "In conclusion", "To sum up", and "In summary".
- Do not follow the formula of acknowledging problems only to
  immediately dismiss them with an optimistic pivot ("Despite these
  challenges, the initiative continues to thrive"). If there are real
  challenges, engage with them.
