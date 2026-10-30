# Documenting Circuit Code

This page defines the documentation convention for code that runs in a
[`Driver`](../guide/drivers/index.md) context: gadget constructors and methods,
[`Circuit`](ragu_circuits::Circuit) implementations, [`Step`](ragu_pcd::step::Step)
and [`Stage`](ragu_circuits::staging::Stage) bodies, routines, and helper APIs
that allocate wires, emit constraints, or compute assignments.

The goal is to make failure modes precise without implying that witness input
can change the constraint system.

## Core Rule

Circuit code deterministically emits **constraints**. In this convention,
constraints means the driver-observable constraint-system description: gates,
linear constraints, coefficients, wire references, and routine boundaries where
they affect the emitted system.

Plain **input** means ordinary non-witness input: Rust values, type parameters,
const generics, configuration, iterator lengths, header types, and constants.
[`DriverValue`](ragu_core::drivers::DriverValue) describes whether a value is
available in a driver context; it does not by itself determine the value's role.
Use **witness input** for values supplied to an API for witness generation, and
**witness data** for computed or stored values such as gadget assignments and
auxiliary data. Name public instance data explicitly when that distinction
matters. All of these may be carried through `DriverValue`.

Input may determine emitted constraints. Values carried through `DriverValue`
may determine witness generation and auxiliary values, but must not determine
emitted constraints.

Do not repeat this rule in every method. It is the default for all circuit code.
Document the cases where callers need to know more.

## Determinism

The core rule says circuit code emits constraints *deterministically*. That word
carries a requirement worth stating on its own, because nothing in the type
system enforces it.

A circuit is walked more than once, by different drivers: metrics counts gates
and constraints, the trace driver computes witness data, and the wiring drivers
evaluate `s(X, Y)`. Each walk runs the same circuit code and must observe the
same sequence of driver operations. When two walks disagree, the artifacts they
produce no longer describe a single constraint system.

Circuit code is therefore required to emit the same constraints on every walk,
and the rest of the system assumes it does. Beyond the `DriverValue` rule above,
a `&self` receiver does not rule out any of:

- interior mutability (`Cell`, `RefCell`, atomics) in a circuit, gadget, or
  routine
- global, thread-local, or lazily initialized state
- iteration order that varies between runs
- addresses, pointer identity, or allocation-dependent behavior
- time, randomness, I/O, or ambient environment

This is a limitation of the language, not an omission. Rust cannot express "this
closure is pure," so determinism sits with the circuit author.

Local checks catch some violations after the fact. Gate and constraint counts
that disagree between drivers surface as a structural error when a trace is
assembled against its floor plan, for instance. Treat these as a backstop for
one symptom rather than as enforcement: circuit code that emits a *different but
equally shaped* constraint system on each walk passes all of them. Do not
describe error handling or local checks as though they make nondeterministic
circuit code safe.

Do not restate this requirement on every method; like the core rule, it is the
default. State it where an API accepts caller-supplied circuit behavior — a
closure, or a `Routine`, `Circuit`, `Step`, or `Stage` implementation — and
the caller needs to know the behavior runs on each walk and must agree with
itself every time.

```rust,ignore
/// # Preconditions
///
/// This routine runs once per driver walk. It must emit the same constraints on
/// each walk; emission that depends on interior mutable or ambient state does
/// not describe a single constraint system.
```

## Gadget Contracts

Gadgets contain wires and may also carry witness data. These are different
categories. Constraints can enforce statements about wire assignments, but they
cannot enforce the truth of witness data itself.

Some gadget types carry **wire contracts**. For example, a `Boolean` represents a
wire constrained to be `0` or `1`, and a `Nonzero` represents a wire constrained
to be nonzero. `Element` is the opposite kind of example: it is a basic wire
wrapper and does not impose an additional wire contract.

A method that takes a contract-bearing gadget may use that wire contract. A
method that returns a contract-bearing gadget should enforce or derive that wire
contract, unless the API explicitly says otherwise. Do not write ordinary docs as
though wire contracts might be broken.

The witness data inside a gadget is used during witness generation. It should
track the represented wire assignment, but a gadget cannot protect that fact
directly. APIs that attach witness data to existing wires need caller-facing
wording about that responsibility, but this is not the same as bypassing a wire
contract.

Warnings belong on APIs that construct contract-bearing gadgets without
enforcing or deriving the corresponding wire contract, or that deliberately defer
or delegate that enforcement:

- `new_unchecked` constructors
- promotion or rebinding of contract-bearing gadgets when the enforcement source
  is external to the API
- staging APIs that omit `Consistent`
- `unenforced` APIs

## Verbs

Use these verbs consistently.

- **enforce**: a condition is forced by emitted constraints.
- **check**: local Rust validation or verifier-side boolean rejection.
- **require**: an API or caller requirement.
- **assume**: a cryptographic assumption, model assumption, or explicitly
  external invariant.
- **compute**: local computation, including witness generation.

Avoid using **enforce** for ordinary Rust validation, witness computation, or
requirements that are not represented by constraints.

## Sections

### Constraints

Use `# Constraints` only when input determines emitted constraints in a way the
caller needs to account for: variable-length iteration, header-dependent
serialization, uniformity requirements, stage sizes, routine identity, or other
non-obvious constraint differences.

Write complete, concise prose.

```rust,ignore
/// # Constraints
///
/// The header implementation, its output serialization, `HEADER_SIZE`, and the
/// allocator's behavior determine the emitted constraints.
```

```rust,ignore
/// # Constraints
///
/// The iterator length determines the emitted constraints. The length must not
/// be derived from witness input.
```

Do not add this section merely because a constant value becomes a coefficient
when that is obvious from the API.

### Soundness

Use `# Soundness` when the method's cryptographic or algebraic meaning is not
fully communicated by the return type.

Soundness describes what any satisfying assignment means. It should not explain
the internal constraint recipe unless the API is specifically about that recipe.

```rust,ignore
/// # Soundness
///
/// Any satisfying assignment makes the returned element represent
/// `self / divisor`.
```

For gadget constructors, the return type often carries enough meaning. Add
`# Soundness` only when an excluded case or relation deserves explicit mention.

### Completeness

Use `# Completeness` sparingly. It describes when honest witness generation
or honest proving is expected to succeed.

Do not use `# Completeness` for incomplete mathematical formulas, because that
collides with the standard "complete formula" terminology. Use
`# Exceptional Cases` instead.

```rust,ignore
/// # Completeness
///
/// Witness generation succeeds when the witness input is nonzero.
```

### Exceptional Cases

Use `# Exceptional Cases` for incomplete formulas or mathematically excluded
inputs.

```rust,ignore
/// # Exceptional Cases
///
/// This method requires `self.x != other.x`. When used inside
/// `NonzeroBank::scope`, the scope enforces this requirement.
///
/// # Soundness
///
/// Any satisfying assignment for the enclosing scope makes the returned point
/// represent `self + other`.
```

This section is about the mathematical domain of the method, not about wire
contracts being optional.

### Preconditions

Use `# Preconditions` for APIs that expose a caller responsibility before the
result may be used according to its type. This is most common when an API
constructs a contract-bearing gadget without enforcing or deriving the
corresponding wire contract in the same call.

```rust,ignore
/// Wraps `element` as `Nonzero` without enforcing nonzeroness.
///
/// # Preconditions
///
/// The caller must enforce that the represented wire assignment is nonzero
/// before using the result as an ordinary `Nonzero`.
```

Ordinary methods that take a gadget-typed argument should not restate the
gadget's wire contract as a precondition.

### Witness Consistency

Use `# Witness Consistency` only for APIs that pair caller-provided witness data
with existing wires.

```rust,ignore
/// Constructs an element from an existing wire and witness data.
///
/// # Witness Consistency
///
/// If witness data is present, the value must match the represented wire
/// assignment. If it does not, later witness generation may compute values
/// that violate the constraints.
```

This section describes a best-effort witness-generation responsibility. It is
not a soundness claim and it is not a substitute for an enforced wire contract.

### Errors

Use `# Errors` for method-specific Rust `Err` cases: failures introduced by the
method's own input domain, witness generation, encoding rules, setup
requirements, bounded construction, or local checking behavior. The section
should name the local condition that causes the error in terms of this
convention.

Do not add `# Errors` merely because the method calls driver APIs that can fail.
Routine propagation of driver errors is part of using a `&mut D`; leave it
implicit, or fold it into the main description when the wrapper behavior is
important. Avoid standalone boilerplate such as "Propagates capacity or
local-check errors from the driver."

Common categories:

- **witness-generation error**: witness input does not support the witness
  values the method needs to compute.
- **input error**: ordinary input is outside the API domain.
- **encoding error**: serialized or encoded data is malformed or has the wrong
  length.
- **capacity error**: emitted constraints exceed a configured rank, degree, gate,
  constraint, or circuit bound.
- **setup error**: registration, initialization, or configuration failed.
- **local check error**: a testing or simulator driver found an unsatisfied
  constraint during local execution.
- **structural error**: circuit or gadget behavior violates a required structural
  invariant, such as emitting a variable number of gadget wires.

Use `capacity error`, `setup error`, `local check error`, and `structural error`
for errors that are part of the method's own behavior. Do not list them only
because some delegated driver operation might return them.

```rust,ignore
/// # Errors
///
/// Returns a witness-generation error if the quotient assignment cannot be
/// computed from witness input.
```

When a witness-generation error corresponds to an exceptional value that
the constraints also exclude, document both sides: the `# Soundness` or
`# Exceptional Cases` section describes the enforced fact, and `# Errors`
describes local witness generation.

### Panics

Use `# Panics` only for internal invariants, impossible states after validation,
or ordinary Rust collection preconditions. Circuit code that receives `&mut D`
should prefer `Result` for local computation failures unless the condition is
truly internal.

## Examples

### Invertible From Witness Input

```rust,ignore
/// Allocates an `Invertible` from witness input.
///
/// # Soundness
///
/// No satisfying assignment can make the represented element zero.
///
/// # Completeness
///
/// Witness generation succeeds when the witness input is nonzero.
///
/// # Errors
///
/// Returns a witness-generation error if the witness input is zero.
```

This documents both the enforced fact about wire assignments and the local
witness-generation failure.

### Division By A Nonzero Gadget

```rust,ignore
/// Divides this element by `divisor`.
///
/// # Soundness
///
/// Any satisfying assignment makes the returned element represent
/// `self / divisor`.
///
/// # Errors
///
/// Returns a witness-generation error if the quotient assignment cannot be
/// computed from witness input.
```

The `Nonzero` parameter already carries a wire contract. Do not document zero
divisors as ordinary caller input. Zero witness data here would be a
witness-consistency problem, not a missing divisor precondition.

### Promotion From A Bare Wire

```rust,ignore
/// Constructs an element from an existing wire and witness data.
///
/// # Witness Consistency
///
/// If witness data is present, the value must match the represented wire
/// assignment. If it does not, later witness generation may compute values
/// that violate the constraints.
```

This is not a contract-bypass warning for `Element`, because `Element` does not
impose an additional wire contract.

### Constant Point

```rust,ignore
/// Embeds a constant `Point`.
///
/// # Errors
///
/// Returns an input error if `p` is the identity.
```

Here `p` is input, not witness input. The failure is deterministic for that
ordinary input.

### Incomplete Point Addition

```rust,ignore
/// Computes `self + other` using incomplete affine addition.
///
/// # Exceptional Cases
///
/// This method requires `self.x != other.x`. When used inside
/// `NonzeroBank::scope`, the scope enforces this requirement.
///
/// # Soundness
///
/// Any satisfying assignment for the enclosing scope makes the returned point
/// represent `self + other`.
///
/// # Errors
///
/// Returns a witness-generation error if witness input falls into the
/// exceptional case.
```

The `NonzeroBank` is an enforcement context. Do not describe the returned point
as temporarily untrusted.

### Stage Rebinding

```rust,ignore
/// Rebinds reserved stage wires as the stage output gadget.
///
/// # Preconditions
///
/// This method does not enforce the output wire contracts in this circuit.
/// Callers must use it only when those contracts are enforced elsewhere.
```

For `enforced`, prefer:

```rust,ignore
/// Rebinds reserved stage wires as the stage output gadget and enforces the wire
/// contracts covered by `Consistent`.
```

## Wording To Avoid

Avoid these patterns:

- "witness modes" for public API docs
- "shape" when the actual constraints may differ
- "synthesis" as a catch-all for execution, witness generation, tracing,
  wiring evaluation, or verification
- "witness execution" for witness generation
- "assignment generation" or "assignment-generation data" when "witness
  generation" or "witness data" is meant
- "supplied value" when the distinction between input and witness input matters
- "invalid witness" as a prose error category; legacy APIs may return
  `Error::InvalidWitness` for several categories, so describe the concrete
  failure instead
- "enforce" for checks that are not represented by constraints
- standalone `# Errors` sections that only say driver errors are propagated
- caveating every ordinary gadget argument with "if its contract holds"
- saying a gadget protects invariants about witness data
- describing promotion from a bare wire as a contract bypass when the promoted
  type does not carry an additional wire contract
- implying that error handling, local checks, or the type system prevent
  nondeterministic circuit code

Prefer direct wording:

- "input" for ordinary input
- "witness input" for values supplied to an API for witness generation
- "witness generation" for local witness computation
- "witness data" for computed or stored gadget and auxiliary values, including
  values carried through `DriverValue`
- "instance data" for verifier-visible circuit instance values
- "constraints" for the emitted constraint system
- "verification returns `Ok(false)`" for rejected public proof data

## Review Checklist

The code-review policy in `.claude/code-review/circuit-documentation.md`
mirrors this checklist for reviewers; keep the two aligned.

When documenting or reviewing circuit code, ask:

1. Can a value carried through `DriverValue` affect emitted constraints? If yes,
   this is a bug or needs a very explicit justification.
2. Does ordinary input affect emitted constraints in a caller-relevant way? If
   yes, add `# Constraints`.
3. Does the method establish a semantic relation not clear from the return type?
   If yes, add `# Soundness`.
4. Does honest witness generation have a meaningful domain restriction? If
   yes, add `# Completeness` or `# Exceptional Cases`.
5. Does the API construct a contract-bearing gadget without enforcing or deriving
   the corresponding wire contract? If yes, add `# Preconditions`.
6. Does the API attach witness data to existing wires? If yes, consider
   `# Witness Consistency`.
7. Does the method introduce a method-specific `Err` beyond routine driver
   propagation? If yes, document the local condition and category. If no, do not
   add a boilerplate `# Errors` section.
8. Is a condition described with "enforce"? Verify it is actually forced by
   constraints.
9. Does the API accept caller-supplied circuit behavior that every driver walk
   will run? If yes, state the determinism requirement instead of leaving it to
   be inferred.
