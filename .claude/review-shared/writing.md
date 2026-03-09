# Writing Rules

These rules apply to all prose in the project — book chapters, rustdoc, module
docs, and any other written content. Context-specific policies (book-review,
code-review) layer additional rules on top of these.

## Voice and Tone

- Prefer active voice, but accept passive in mathematical definitions and
  protocol descriptions where the agent is irrelevant. "The polynomial is
  evaluated at $x$" is fine; "We can see that the polynomial is evaluated" is
  not — the passive is correct, but the hedging ("we can see") is not.
- Maintain a direct, confident tone. Avoid hedging ("perhaps", "it might be")
  unless genuine uncertainty is being communicated.

## Weasel Words

- Avoid "simply", "just", "obviously", "clearly". If something is obvious, it
  doesn't need a comment. If it isn't obvious, these words are dishonest.
  This extends to indirect assertions of clarity — "the reality is simpler",
  "history is unambiguous". Don't tell the reader your point is clear;
  demonstrate it.
- "Note that" is almost always filler. Delete it and the sentence usually
  improves. The same applies to "It's worth noting", "It bears mentioning",
  "Importantly", "Interestingly", and "Notably".
- "In fact" and "in theory" are filler or hedging. If the statement is
  factual, it stands on its own; if it is theoretical, qualify it with the
  actual limitation. "Arguably" hedges a claim the author should either
  commit to or qualify differently.
- Neutral connectives ("also", "additionally") can understate a property
  that motivates a design decision. When a fact is the *reason* for a
  design choice, use language that conveys its significance — e.g.,
  "frequently" rather than "also" if frequency is the point.
- Vague catch-all qualifiers — "whatever," "any way," "however they want" —
  conceal specific reasoning. When describing a design motivation, name the
  actual benefit. "So they can represent wires in whatever way suits their
  context" → "so they can represent wires in an efficient way that suits their
  context."
- Avoid overused LLM vocabulary: "delve", "certainly", "utilize", "leverage"
  (verb), "robust", "streamline", "harness". These words are not inherently
  wrong, but their overuse by language models has made them conspicuous.

## Inflated Language

- Don't reach for adverbs like "quietly", "deeply", "fundamentally", or
  "remarkably" to make mundane descriptions feel significant. If something
  is important, the sentence should show it without adverbial signaling.
- Prefer plain nouns over grandiose ones. Avoid "tapestry", "landscape",
  "paradigm", "synergy", and "ecosystem" (when used loosely) as vague
  filler. Name the actual thing.
- Prefer "is" or "are" over pompous substitutes like "serves as", "stands
  as", "marks", or "represents" when the simpler verb suffices.

## Sentence Structure

- Vary sentence length. A long explanatory sentence should be followed by a
  short, punchy one. Monotonous rhythm puts readers to sleep.
- Avoid long parenthetical asides mid-sentence. Use a separate sentence instead.
  If the aside is important enough to include, it deserves its own sentence.
- Technical terms should be introduced before use. Flag forward references to
  undefined terms.
- Use explicit connectives (conjunctions, semicolons) between coordinated
  clauses. Don't rely on bare comma juxtaposition to imply the relationship.
  "One might accumulate a field element, another might append terms" → "one
  might accumulate a field element, and another might append terms."
- Ensure pronouns have unambiguous antecedents. When multiple nouns in a
  sentence could be the referent, repeat the noun or restructure. "The
  constraints that govern them" — does "them" refer to wires, values, or
  assignments? Use "those assignments" instead.
- When contrasting variants (normal vs. exceptional, common vs. rare),
  present the common case first to establish a baseline, then contrast
  with the special case. This gives the reader a foothold before
  introducing the unusual behavior.

## Word Repetition

- Avoid repeating the same word in close proximity (within a sentence or
  across a few consecutive lines). Rephrase with a synonym or restructure.
  Example: "Developed for use with the Pasta curves used in Zcash"
  → "Developed for the Pasta curves employed in Zcash".
- Within a paragraph, vary word choice when natural alternatives exist (e.g.,
  "verify" / "check" / "confirm"; "construct" / "build" / "create").
- Avoid restating the same fact in different words within a paragraph. If
  a concept is already stated, a second formulation that adds no new
  information should be cut or merged with the first.
- **Exempt**: technical terms, proper nouns, acronyms, and domain-specific
  vocabulary. Terminological consistency takes precedence over variety — do not
  replace a defined term with a synonym for the sake of variety.

## Punctuation Density

- Watch for em dash overuse at the page/module level. Em dashes are effective
  for asides and interjections, but overuse makes the writing monotonous and
  the dashes lose their punch.
- When flagging density, identify the least impactful usages and suggest
  rephrasing so the dash becomes unnecessary. Leave the strongest usages
  intact — a page with 2–3 well-placed em dashes reads better than a page
  with zero.
- Preferred alternatives: commas, parentheticals, semicolons, subordinate
  clauses, or restructuring the sentence to eliminate the aside entirely.

## Terminology

- Once a term is chosen for a concept, use it consistently throughout. Flag
  synonyms meaning the same thing within a document or module.
- Defined terms (from a glossary or terminology appendix) take precedence.
- Anaphoric references — a demonstrative + grouping term summarizing items
  named in the immediately preceding text (e.g., "these primitives" after
  "wires and witness data") — are not synonyms. Do not flag them.

## Capitalization

- Lowercase for technical descriptive phrases: "proof-carrying data", not
  "Proof-Carrying Data". Capitalize only the first word at sentence start:
  "Proof-carrying data is...".
- Proper nouns (Halo, Zcash, Pasta, Poseidon) and acronyms (SNARK, PCD,
  ECDLP) stay capitalized.
- Flag title-cased descriptive phrases that aren't proper nouns.
