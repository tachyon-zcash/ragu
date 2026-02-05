# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All development commands use `just` (justfile). Run `just` to see available commands.

### Essential Commands

For most tasks and plans, **Please use `just ci_local` for verification.**

- `just ci_local` - Run all CI checks locally (formatting, clippy, tests, doc, book). **Use this to verify all changes.**
- `just lint` - Run clippy, fmt check, typos, and build book
- `just fix` - Auto-fix formatting, clippy issues, and typos
- `just book serve` - Build and serve the Ragu book locally

### Single Test Execution
```bash
cargo test --all-features <test_name>
```

### Benchmarks
- `just bench` - Auto-detects platform (Linux native, macOS uses Docker)
- macOS benchmarks run in Docker with valgrind for profiling

### Worktree Setup

When creating a new worktree, if `CLAUDE.md` and `.claude/` are not version controlled, create symlinks to them from the main worktree:

```bash
# From the new worktree directory
ln -s ../path/to/main/CLAUDE.md CLAUDE.md
ln -s ../path/to/main/.claude .claude
```

This ensures consistent configuration and guidance across all worktrees.

### Tool Preferences

When running terminal commands, respect the following preference, fallback to default option if unavailable:

- Use `rg` (ripgrep) instead of `grep` for all file searching and pattern matching

## Planning and Exploration Workflow

**When entering plan mode to design an implementation:**

Launch multiple parallel Explore subagents (typically 4, or however many necessary) to gather context before finalizing the plan. Each subagent should explore different aspects:
- Relevant abstractions and their current implementations
- Similar patterns or precedents in the codebase
- Dependencies and constraints
- Testing patterns and requirements

Use the Task tool with `subagent_type=Explore` and run them in parallel for efficiency. Synthesize findings from all subagents before presenting the implementation plan.

**Example pattern:**
```
EnterPlanMode -> Launch 4 parallel Explore agents -> Synthesize findings -> Present plan -> ExitPlanMode
```

This ensures comprehensive context gathering before committing to an implementation approach.

## Documentation Standards

**Strictly mimic Rust's std library documentation (Steve Klabnik style).**

### Mathematical Notation

- Use KaTeX (`$...$`) for mathematical expressions in doc comments, not backticks or Unicode. Backticks are for code identifiers; Unicode subscripts and operators render inconsistently.
- Use LaTeX conventions within KaTeX: `\cdot` for multiplication, `\sum` for summation, `^{}` for superscripts. Write `$\sum_j c_j \cdot Y^j$` not `Σⱼ cⱼ · Yʲ`.
- In code comments (non-doc `//` comments), avoid Unicode math symbols. Prefer breaking functions into smaller pieces with doc comments that render KaTeX, even for private functions.
- Apply standard spacing in mathematical notation: `$f(x, y)$` not `$f(x,y)$`.
- When documenting polynomial evaluation functions, verify fixed vs. free variables against the function signature. Convention: uppercase letters (X, Y) denote polynomial variables; lowercase (x, y) denote fixed evaluation points.
- Escape underscores in LaTeX subscripts as `\_{...}` to prevent markdown interpretation. Write `$\mathbf{u}\_{i,j}$` not `$\mathbf{u}_{i,j}$`.

### Prose Quality

- Write doc comments as complete sentences with proper punctuation.
- Use third-person singular verbs for function/method doc comments: "Returns the sum" not "Return the sum". Type descriptions should start with an article: "A wrapper for..." not "Wrapper for...".
- Prefer relative clauses over prepositional phrases: "Type that computes X" not "Type for computing X".
- Start `///` comments with a brief one-line summary, then a blank line, then details if needed.
- Avoid weasel words: "simply", "just", "obviously", "clearly". If something is obvious, it doesn't need a comment.
- Link to related items with intra-doc links: `[`OtherType`]` not "see OtherType".
- Module docs should only name items that are part of the module's public API. If you can't link to it, don't mention it—it's an implementation detail.
- Don't use unicode symbols or emoji, only plain text (e.g. No ->, only ->).

### Formatting

- Wrap doc comment prose at ~80 characters (after the `//!` or `///` prefix). Display math and code blocks may exceed this when necessary.
- Place display math (`$$ ... $$`) on separate lines, not inline with prose.
- Gather link reference definitions (`[`Foo`]: path::to::Foo`) at the end of the doc block, not interspersed with prose.
- Use `#` for top-level module headings, then skip to `###` for subsections. `##` is too visually similar to `#` to serve as a useful hierarchy level.
- Add a blank line between doc comment blocks for adjacent struct fields.
- Add a blank line before code comments unless the comment is at the start of a block (function body, match arm, loop body, etc.).
- Always backtick code identifiers, including in headings. Write `### The \`ONE\` Wire` not `### The ONE Wire`.

### Module Documentation Structure

- Lead with motivation before implementation. Explain *why* something exists before describing *how* it works.
- Separate background from design rationale. Use distinct sections: "Background" for conceptual or mathematical grounding, "Design" for architectural choices and trade-offs.
- Justify design decisions. Don't just say "we do X"; explain why the naive alternative is undesirable.
- Make implicit dependencies explicit. Reference concrete types and traits with doc links (`[`Driver`]`).
- Enumerate submodules with one-line summaries when a module organizes several related submodules.
- Connect math to code. When documenting mathematical constructs, tie them to concrete code paths.
- Distinguish doc comments from code comments by content:
  - **Doc comments** (`///`, `//!`): API-facing information—what something does, why it exists, how to use it, what invariants it maintains.
  - **Code comments** (`//`): Implementation details—algorithm steps, optimization rationale, non-obvious code behavior.
- Establish documentation ownership. Each concept should have one authoritative location. Other modules should reference that location rather than re-explaining.
- Module-level docs explain concepts and architecture.
- Item-level docs are concise and precise.
- Use `///` for public items, include examples where helpful.
- Most detailed documentation is in crate-level rustdoc or the book, not scattered comments.

### Content Guidelines

- **IMPORTANT: always document "what it does", never add superfluous comments about "what changed" during refactoring**. When desirable and if helpful, we can add links to github PR or issues for historical account.
- Avoid tables that merely reformat information visible in the code. Tables are useful for comparative data or reference material.
- Don't document obvious optimizations or compare against naive alternatives.
- Link code identifiers consistently. If you use `[`Foo`]` once in a doc block, use it everywhere in that block.
- Document intended behavior, not incidental capabilities.

## Code Style and Structure

### Memory Efficiency and Cache Friendliness
**Priority: Memory efficiency and cache-friendly access patterns over naive instruction count reduction.**

- Avoid deep clones; prefer streaming and lazy evaluation
- Use zero-sized types where possible (e.g., `Empty` MaybeKind for witness-ignoring drivers)
- Defer witness computation when possible (e.g., `Endoscalar` stores `u128` instead of 128 booleans)
- Prefer "gain pattern" over "scale pattern" in linear expressions for streaming efficiency

### Function Design

- Functions should do one thing. If a function has sections separated by blank lines with different purposes, consider splitting it.
- Avoid deep nesting. Prefer early returns, `let-else`, or extracting helpers. More than 3 levels of indentation is a code smell.
- Keep functions short enough to fit on one screen (~50 lines). Long functions hide bugs.
- Group related items together. Private helpers should be near their callers.

## Naming Conventions

- Variable names should reflect their mathematical or domain meaning. Prefer `acc` over `a` for accumulators, `coeff` over `c` for coefficients, unless the single-letter name is standard notation in the relevant paper/protocol.
- Avoid abbreviations that aren't universally understood. `poly` for polynomial is fine; `cmt` for commitment is not.
- Boolean variables and functions should read as predicates: `is_zero()`, `has_input`, not `zero()` or `input`.
- Type names should be nouns; trait names should be adjectives or capabilities (e.g., `Driver`, `Gadget`).

## Correctness and Safety

### Type-Driven Correctness
**Use Rust's type system to eliminate or expose errors at compile time.**

- Leverage zero-sized marker types for static guarantees
- Use higher-kinded types (HKT) pattern with `Maybe`/`MaybeKind` to unify witness-present and witness-absent logic
- Gadgets must be "fungible" (behavior fully determined by type, not instance state)
- Stage progression enforced at compile-time via type-level `Parent` tracking

### Rust Best Practices
- Follow std library patterns and idioms
- Leverage trait coherence and associated types
- Use `#[derive(Gadget)]` macro for automatic HKT implementations

### Error Handling and Safety

- No `unwrap()` or `expect()` in library code unless the invariant is documented and truly impossible to violate. Prefer propagating errors or using `assert!` for internal invariants.
- No `unsafe` without a `// SAFETY:` comment explaining why it's sound.
- Avoid `as` casts between numeric types; prefer `try_into()` or explicit conversion functions that handle overflow.
- Cryptographic code must be constant-time where timing side-channels matter. Document when constant-time behavior is required and verified.

### Assertions

- Use `assert!`, not `debug_assert!`. If an assertion is cheap enough to keep, keep it always. If it's too expensive for production, it's too expensive for debugging—write a test instead.
- Assertions guard invariants that correct callers cannot violate through the API. An assertion should never fire unless there's a bug in *this* code, not the caller's code.
- Design code so invariants can be checked cheaply. If protecting an invariant requires an expensive assertion, restructure the code so the invariant is inherent (e.g., use types that make invalid states unrepresentable) or move the check to a test.
- Expensive assertions are a code smell. They suggest either the invariant isn't worth checking at runtime, or the data structure doesn't make the invariant easy to verify.

## API Design

- Public APIs should be hard to misuse. Prefer newtypes over raw integers/arrays when the type carries semantic meaning.
- Generic bounds should be minimal. Don't require `Clone` if you don't clone.
- Avoid output parameters; return values instead. Rust's tuples and structs make this easy.
- Default trait implementations should be overridable for performance without changing semantics.

## Changes and Commits

- Each commit should be a single logical change that compiles and passes tests.
- Refactoring commits should be separate from behavioral changes.
- Don't mix whitespace/formatting changes with substantive code changes.
- Commit messages should explain *why*, not just *what*. The diff shows what changed.

## What Not To Do

- Don't leave commented-out code. Delete it; git remembers.
- Don't add/modify dependencies without justification. This is a `no_std` crate; dependencies are expensive.
- Don't add features "for later". Implement what's needed now.

## Architecture Overview

Ragu is a proof-carrying data (PCD) framework implementing a modified Halo-style recursive SNARK construction.

### Crate Structure
- `ragu_core` - Fundamental traits: `Driver`, `Gadget`, `Maybe`, `Routine`
- `ragu_circuits` - Circuit synthesis, polynomial evaluation, `Registry`
- `ragu_gadgets` - Circuit gadgets (Boolean, Element, Point, etc.)
- `ragu_primitives` - Cryptographic primitives (Poseidon, curves, Transcript)
- `ragu_pcd` - PCD application layer: `Step`, `Header`, `Application`, `Proof`/`Pcd`
- `ragu_arithmetic` - Field arithmetic and curve operations
- `ragu_pasta` - Pasta curve cycle implementation
- `ragu_macros` - Proc macros (`#[derive(Gadget)]`)

## IMPORTANT: Update This File

**When making major changes to architecture, abstractions, or development workflow, Claude should always first update the module or crate documentation, then update the pointer in CLAUDE.md here.**

Current CLAUDE.md file only provides general overview and succinct pointer to primary concepts, abstractions to code doc, NOT a detailed explanation of these patterns or design decisions.

This ensures future Claude Code instances have accurate context.
