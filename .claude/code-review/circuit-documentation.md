# Circuit Documentation Review Policy

## Scope

Review doc comments (`///`, `//!`) and code comments on code that runs in a
`Driver` context: gadget constructors and methods, `Circuit`, `Step`, `Stage`
and `Routine` implementations, and helpers that allocate wires, emit
constraints, or compute assignments. The canonical convention is the book page
`book/src/implementation/circuit-code-documentation.md`; this policy condenses
it so the review does not depend on the reviewed tree's copy. If the two
disagree, apply this policy and report the drift. If the reviewed content
contains no such code, say so and stop.

The general documentation policy (`documentation.md`) still owns prose,
formatting and placement. This policy owns the meaning of circuit docs: which
facts are enforced, which are computed, and which are the caller's.

## Core Rule

Circuit code deterministically emits constraints. Ordinary input (Rust values,
type parameters, const generics, configuration, iterator lengths, header types,
constants) may determine the emitted constraints. Values carried through
`DriverValue` (witness input and witness data) may determine witness generation
and auxiliary values and must never determine emitted constraints. A doc that
describes `DriverValue`-dependent constraints is describing a bug; flag it as
`must-fix` and verify the code.

Do not ask for this rule to be restated on every method. Flag only the cases
where a caller needs to know more.

## Verbs

- **enforce**: forced by emitted constraints.
- **check**: local Rust validation, or verifier-side rejection.
- **require**: an API or caller requirement.
- **assume**: a cryptographic, model or explicitly external assumption.
- **compute**: local computation, including witness generation.

Flag "enforce" used for Rust validation or witness computation, and "check"
used for a relation that constraints force (`enforce_equal`, `enforce_zero`,
`Consistent`). Verify the verb against the code before flagging.

## Sections

Flag a missing section only when the code meets its trigger; flag a present
section only when it is boilerplate or wrong.

- `# Constraints`: ordinary input determines the emitted constraints in a way
  the caller must account for (variable-length iteration, header-dependent
  serialization, uniformity requirements, profile- or stage-dependent loading,
  routine identity). Not for a constant that obviously becomes a coefficient.
- `# Soundness`: the method establishes a relation not clear from the return
  type. Describes what any satisfying assignment means, not the constraint
  recipe.
- `# Completeness` (sparingly) or `# Exceptional Cases`: honest witness
  generation has a domain restriction, or a formula is incomplete. Never use
  `# Completeness` for incomplete formulas.
- `# Preconditions`: the API constructs a contract-bearing gadget (`Boolean`,
  `Nonzero`, stage outputs) without enforcing or deriving its wire contract:
  `new_unchecked`, promotion or rebinding with external enforcement,
  `unenforced` stage loads, staging that omits `Consistent`. Name the circuit
  or argument that enforces the contract instead.
- `# Witness Consistency`: the API attaches caller-provided witness data to
  existing wires. Best-effort witness-generation wording, not a soundness claim.
- `# Errors`: method-specific `Err` cases, named by category (witness-generation,
  input, encoding, capacity, setup, local check, structural). Flag standalone
  boilerplate that only says driver errors are propagated.
- `# Panics`: internal invariants and ordinary collection preconditions only.

## Gadget Contracts

A method taking a contract-bearing gadget may use its wire contract; a method
returning one enforces or derives it unless the API says otherwise. Flag docs
that caveat ordinary gadget arguments with "if its contract holds", that
describe a returned contract-bearing gadget as temporarily untrusted inside an
enforcement scope such as `NonzeroBank::scope`, or that say a gadget protects
the truth of its witness data. Promotion of a bare wire into `Element` is not a
contract bypass.

## Determinism

Every driver walk must observe the same constraints. Flag docs that present
error handling, local checks or the type system as making nondeterministic
circuit code safe. Where an API accepts caller-supplied circuit behavior (a
closure, `Routine`, `Circuit`, `Step` or `Stage`), the determinism requirement
should be stated once, as a precondition.

## Wording To Avoid

"witness modes" in public docs; "shape" when constraints may differ;
"synthesis" as a catch-all; "witness execution"; "assignment generation";
"supplied value" where input versus witness input matters; "invalid witness" as
an error category. Prefer "input", "witness input", "witness generation",
"witness data", "instance data", "constraints", and "verification returns
`Ok(false)`".

## Checklist

1. Can a `DriverValue` affect emitted constraints? Bug or explicit justification.
2. Does ordinary input change the constraints in a caller-relevant way? Needs
   `# Constraints`.
3. Is a relation established that the return type does not convey? Needs
   `# Soundness`.
4. Is honest witness generation restricted? Needs `# Completeness` or
   `# Exceptional Cases`.
5. Is a contract-bearing gadget built without its contract? Needs
   `# Preconditions` naming the enforcer.
6. Is witness data attached to existing wires? Consider `# Witness Consistency`.
7. Is there a method-specific `Err`? Document its category; otherwise no
   `# Errors` section.
8. Is "enforce" or "check" used? Verify against the emitted constraints.
9. Does the API run caller-supplied circuit behavior on every walk? State the
   determinism requirement.
