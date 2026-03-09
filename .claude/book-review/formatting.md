# Formatting Review Policy

## Scope

Review formatting in book chapter markdown files (`book/src/`). All rules in
`.claude/book-review/standards.md` also apply.

## Tooling

Before reviewing manually, run the automated detection tool:

```
python3 qa/book/line_width.py
```

Use its output as your primary work list. For each violation it reports, read
the surrounding context. If the line is an inherent exception (see "Inherent
Exceptions" below), skip it — it is not a finding. Otherwise, suggest a
compliant rewrap. If all violations are inherent exceptions or the tool reports
none, you have no findings for this policy — say so and stop.

You may also narrow the scan to the files under review:

```
python3 qa/book/line_width.py path/to/file.md
```

## Line Width

All prose lines in `book/src/` markdown files must be at most **80 characters**.

The following are **exempt** from the limit:

- Lines inside fenced code blocks (`` ``` ``).
- Lines inside display math blocks (`$$...$$`).
- Lines inside mermaid diagrams (a fenced code block with `mermaid` language).
- Heading lines (`# ...` through `###### ...`).
- Link reference definitions (`[label]: URL`).
- Footnote definition lines (`[^label]: ...`) containing long URLs.
- Lines that are a single HTML tag (e.g., `<details>`, `</summary>`).
- Lines that are a single inline math expression (`$...$` with no surrounding
  prose).
- Table rows (`| ... | ... |`).

When a line exceeds the limit, the fix is to rewrap the paragraph—not to
truncate content or remove detail.

## Smart Rewrapping

See `.claude/book-review/formatting-examples.md` for concrete before/after
examples of each pattern. When suggesting rewraps, prefer the patterns shown
there. If the user corrects a suggestion, the correction should be added to
the catalog via `/book-refine`.

When suggesting line rewraps, follow these rules:

1. **Never break inline math** (`$...$`) across lines. The entire `$...$`
   expression must stay on one line.
   - **Short math wraps inline:** Treat small expressions (e.g., `$p$`,
     `$c_{n-1}$`) as regular words during fill-wrap.
   - **Long math gets its own line:** When an expression would push a line
     past the limit, demote it to a standalone line (exempt from the
     80-char limit per the exemptions above).
   - **Break between expressions:** When two math expressions appear near
     each other on an overlong line, the gap between them is a preferred
     break point.
   - **Parenthetical units:** A parenthetical containing math (e.g.,
     `(of the form $...$)`) is indivisible — tolerate an overlong line
     rather than split the parenthetical.
2. **Never break markdown links** (`[text](url)` or `[text][ref]`) across
   lines. The entire link must stay on one line.
3. **Bold and emphasis split freely.** Unlike math and links, bold (`**...**`)
   and emphasis (`*...*`) markup can be split across lines during fill-wrap.
   Treat them as ordinary words.
4. **Prefer rewording** surrounding prose over splitting a formula or link.
   If an inline math expression or link is itself longer than 80 characters,
   leave that line as-is (it falls under the single-expression exemption or
   is an inherent exception).
5. **Preserve paragraph breaks.** Do not merge separate paragraphs to fix
   line width.
6. **Preserve list structure.** Continuation lines in list items should be
   indented to align with the first content character of the item.

## Inherent Exceptions

Some lines inherently exceed 80 characters and cannot be fixed by rewrapping.
These are **not violations** — do not flag them during review. A line is an
inherent exception when:

1. **Irreducible markdown link.** A `[text](url)` (possibly with trailing
   punctuation like `,` or `.`) is already isolated on its own line, and the
   link itself exceeds 80 characters. The surrounding prose has already been
   rewrapped to give the link its own line — no further action is possible.
   List indentation counts toward the width but does not change the verdict:
   if the indented link line exceeds 80 characters, it is still inherent.
2. **Compound link reference.** Two or more links joined by punctuation
   (e.g., `[A](url)/[B](url)`) form an indivisible unit. Tolerate an
   overlong line rather than split the compound.
3. **Math-parenthetical unit.** (Already documented in Smart Rewrapping
   rule 1, sub-bullet "Parenthetical units.") A parenthetical containing
   inline math is kept as a single unit even if the line exceeds 80 chars.

## Paragraph Conventions

Fill-wrap prose to ~80 columns. Break at word boundaries — don't force breaks at
sentence or clause boundaries. Sentences flow together continuously; a line break
may land mid-sentence. In math-heavy paragraphs, short inline math tokens wrap
like ordinary words; only long expressions that would overflow need standalone
line treatment.

## Typography and Decoration

- Do not begin every bullet in a list with a bolded phrase. If you need
  bullets, let the content carry the list — not typographic decoration.
  (Bold-prefixed definition lists like `**Term:** definition` are fine;
  the anti-pattern is gratuitous bolding of the first word of each item.)
- Do not use unicode arrows (→), curly quotes, or other characters that
  require special input. Use plain text equivalents (->), straight
  quotes, and standard punctuation.