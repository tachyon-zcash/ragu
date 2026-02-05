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

## Coding Principles

### Memory Efficiency and Cache Friendliness
**Priority: Memory efficiency and cache-friendly access patterns over naive instruction count reduction.**

- Avoid deep clones; prefer streaming and lazy evaluation
- Use zero-sized types where possible (e.g., `Empty` MaybeKind for witness-ignoring drivers)
- Defer witness computation when possible (e.g., `Endoscalar` stores `u128` instead of 128 booleans)
- Prefer "gain pattern" over "scale pattern" in linear expressions for streaming efficiency

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

## Documentation Style

**Strictly mimic Rust's std library documentation (Steve Klabnik style).**

- Module-level docs explain concepts and architecture
- Item-level docs are concise and precise
- Use `///` for public items, include examples where helpful
- Mathematical notation in rustdoc uses KaTeX (see `katex-header.html`)
- Most detailed documentation is in crate-level rustdoc or the book, not scattered comments

**IMPORTANT: always document "what it does", never add superfluous comments about "what changed" during refactoring**.
When desirable and if helpful, we can add links to github PR or issues for historical account.

Additional rules:
- don't use unicode symbols or emoji, only plain text (e.g. No →, only ->)

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

Current CLAUDE.md file only provides general overview and succinct pointer to primary concepts, abstractions to code doc,
NOT a detailed explanation of these patterns or design decisions.

This ensures future Claude Code instances have accurate context.
