# Concrete Drivers

[Gadgets](../gadgets/index.md), [routines](../routines.md), and most other user
code are written generic over `D: Driver<'dr>` and passed to framework APIs that
supply their own drivers internally, and so concrete implementations tend to be
obscured from the user. Users only ever interact directly with a small set of
drivers provided by the framework—primarily for testing and native evaluation.

## The [`Emulator`] {#emulator}

The simplest useful implementation of [`Driver`] is the [`Emulator`], which
natively executes circuit code without enforcing constraints. It is useful in
contexts where only the computed result matters—not its validity proof—such as
computing expected outputs or extracting information about the computational
structure.

The [`Driver`] abstraction is designed to accommodate this. Each driver controls
how allocations and constraints are handled, so the emulator can skip constraint
machinery entirely and run generic circuit code natively with little overhead
and without reimplementation. This is especially valuable for recursive proofs,
where verifier logic must run both inside a circuit and outside it.

### Modes

The [`Emulator`] operates in two modes:

* **[`Wireless`]**: The `Wire` type is `()`, so nothing about wire assignments
  is preserved. This mode is parameterized by a [`MaybeKind`] to indicate
  witness availability.

* **[`Wired`]**: The `Wire` type is `F` itself, which tracks the assignments
  that the circuit code's witness generation logic produces. Wired mode always
  has witness availability.

### Constructors

| Constructor | Mode | Wire | Use Case |
|---|---|---|---|
| [`Emulator::execute()`] | `Wireless<Always<()>, F>` | `()` | Native witness execution |
| [`Emulator::counter()`] | `Wireless<Empty, F>` | `()` | Wire counting, static analysis |
| [`Emulator::extractor()`] | `Wired<F>` | `F` | Wire extraction |
| [`Emulator::wireless()`] | `Wireless<M, F>` | `()` | Generic (parameterized [`MaybeKind`]) |

[`Emulator::wireless()`] is useful when witness availability depends on another
driver's behavior, such as when invoking an [`Emulator`] within generic circuit
code.

### Convenience Helpers

Two associated functions construct an emulator, run a closure, and return the
result in a single step:

* [`Emulator::emulate_wireless`] takes a witness value and a closure, creates a
  wireless emulator with that witness available as `Always<W>`, and runs the
  closure.
* [`Emulator::emulate_wired`] takes a witness value and a closure, creates a
  wired emulator with the witness available as `Always<W>`, runs the closure,
  and retains wire values for extraction.

### Routines

Because emulators are not involved in enforcing constraints, they short-circuit
[routine](../routines.md) execution: if a routine can
[predict](ragu_core::routines::Routine::predict) its output, the emulator skips
[`execute`](ragu_core::routines::Routine::execute) entirely and returns the
prediction. This contrasts with the [`Simulator`], which always executes even
for known predictions so it can verify consistency between the prediction and
the actual result.

### Wire Extraction {#wire-extraction}

[`Gadget`]s can have their wires extracted from an [`Emulator`] in [`Wired`]
mode using [`Emulator::wires`], which returns a `Vec<F>` of field element
assignments. This is useful for computing expected wire assignments after
running a [routine](../routines.md) or other circuit code—typically during
testing or when feeding assignments into a downstream synthesis driver.

## The [`Simulator`] {#simulator}

The [`Simulator`] (provided by `ragu_primitives`) also executes circuit code
natively, but unlike the emulator it **does enforce constraints**. Every
gate and constraint is checked for correctness as it is
created, and the simulator collects realistic metrics (allocation count,
gate count, constraint count) in the process.

## `PhantomData<F>` {#phantom-driver}

[`PhantomData<F>`] implements [`Driver<'static>`][`Driver`] for any field `F`.
It behaves like a wireless emulator with `Empty` witnesses—it does nothing at
all. This exists so that gadget types can be named at the type level without a
real driver, which is exactly what [`GadgetKind`][gadgetkind-page] needs: the
[`Kind!`][kind-page] macro uses `PhantomData<F>` as the stand-in driver when
extracting a gadget's [`GadgetKind`] from its [`Gadget`] implementation.

[`Emulator`]: ragu_core::drivers::emulator::Emulator
[`Wireless`]: ragu_core::drivers::emulator::Wireless
[`Wired`]: ragu_core::drivers::emulator::Wired
[`MaybeKind`]: ragu_core::maybe::MaybeKind
[`Emulator::execute()`]: ragu_core::drivers::emulator::Emulator::execute
[`Emulator::counter()`]: ragu_core::drivers::emulator::Emulator::counter
[`Emulator::extractor()`]: ragu_core::drivers::emulator::Emulator::extractor
[`Emulator::wireless()`]: ragu_core::drivers::emulator::Emulator::wireless
[`Emulator::emulate_wireless`]: ragu_core::drivers::emulator::Emulator::emulate_wireless
[`Emulator::emulate_wired`]: ragu_core::drivers::emulator::Emulator::emulate_wired
[`Emulator::wires`]: ragu_core::drivers::emulator::Emulator::wires
[`Simulator`]: ragu_primitives::Simulator
[`PhantomData<F>`]: core::marker::PhantomData
[`Driver`]: ragu_core::drivers::Driver
[`GadgetKind`]: ragu_core::gadgets::GadgetKind
[`Gadget`]: ragu_core::gadgets::Gadget
[`Kind!`]: ragu_core::gadgets::Kind
[gadgetkind-page]: ../gadgets/gadgetkind.md
[kind-page]: ../gadgets/kind.md
