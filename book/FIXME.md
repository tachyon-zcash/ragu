# Book Review FIXMEs

Tracked issues from structural review that are deferred for later. Use
`/book-refine` to turn feedback into policy improvements when addressing these.

## Deferred Issues

### Missing motivational opening in `protocol/prelim/nested_commitment.md`

Page jumps straight into "Ragu uses a curve cycle..." without explaining what
problem nested commitments solve or why the reader should care. Add a
motivational paragraph before the technical content.

### Section ordering in `guide/getting_started.md`

"Configuration at a Glance" appears before the reader knows what they're
building. Consider moving it after "Overview: Building a Merkle Tree with
Proofs" so readers understand WHAT they're building before seeing configuration
parameters.

### Redundant Header trait explanation

`guide/getting_started.md` (Step 1) and `guide/writing_circuits.md` (Working
with Headers) cover near-identical Header trait implementations. Consider
consolidating: keep the minimal example in getting_started.md and have
writing_circuits.md reference it with deeper explanation.

### Inconsistent Rank notation in `guide/configuration.md`

Rank is written as `R\<N\>` (escaped), `R<13>` (code), and `R^{13}` (math)
interchangeably. Pick one convention and apply consistently.

### Missing `#` title heading in `introduction.md`

The introduction page has no `# Title` heading — it starts directly with an HTML
`<img>` tag. Add a proper heading (e.g. `# Introduction` or `# Ragu`) for
consistency and accessibility.

### Empty category heading for `implementation/drivers/`

SUMMARY.md line 48 `[Drivers]()` has no index.md, with only 2 child pages
(emulator.md has content, custom.md is a TODO stub). Revisit when custom.md
is written — may need a substantive index.md or flattening.

### Missing motivational opening in `guide/drivers.md`

Page opens with technical driver definition without first explaining why
drivers matter to the reader. Add a brief motivational paragraph.

