# Emulator

The simplest implementation of [`Driver`][driver-trait] is the
[`Emulator`][emulator-type], which natively executes circuit code without
enforcing constraints. This driver is useful when the correctness of circuit
code execution does not need to be directly checked, because in that case
circuit code is just native code with pointless steps. Instead of reimplementing
algorithms to anticipate the results or structure of in-circuit computations—to
avoid the overhead of constraint enforcement or wire assignment tracking done in
circuit code— the [`Emulator`][emulator-type] driver can be used to avoid as
much of this overhead as possible.

One of the purposes of the design of the `Driver` abstraction in Ragu is to
enable circuit code to be written so that it can be efficiently natively
executed, reducing code. This especially helps with developing recursive proofs
since almost everything performed by the verifier must be also be written to be
executed within a circuit as well.

## `Wired` and `Wireless` modes

The [`Emulator`][emulator-type] can be instantiated in
[`Wireless`][wireless-marker] mode (where the `Wire` type of the driver is `()`,
and so nothing about the wire assignments or their relationships are preserved)
or in [`Wired`][wired-marker] mode (where, when a witness is available, the
`Wire` type contains the assignments that the circuit code's witness generation
logic produces). The purpose of the two modes is to allow the user to avoid as
much unnecessary computation as possible during emulation depending on their
needs.

| Emulator | Wire | Witness availability ([`MaybeKind`][maybekind-trait]) |
|---|---|---|
| `Emulator<Wireless<M, F>>` [**(`Emulator::wireless`)**](Emulator::wireless) | `()` | [`Always<()>`][always-marker] or [`Empty`][empty-marker] |
| `Emulator<Wired<M, F>>` [**(`Emulator::wired`)**][Emulator::wired] | [`Maybe<F>`](maybe-trait) | [`Always<()>`][always-marker] or [`Empty`][empty-marker] |
| `Emulator<Wireless<Always<()>, F>>` [**(`Emulator::execute`)**][Emulator::execute] | `()` | [`Always<()>`][always-marker] |
| `Emulator<Wired<Always<()>, F>>` [**(`Emulator::extractor`)**][Emulator::extractor] | [`Always<F>`][always-marker] | [`Always<()>`][always-marker] |

## Wire Extraction

[`Gadget`][gadget-trait]s can have their wires extracted from an `Emulator` in
`Wired` mode; a provided helper utility ([`Emulator::wires`][Emulator::wires])
returns a vector of wires for a given gadget.
[`Emulator::always_wires`][Emulator::always_wires] can be used instead when a
witness is always present (`MaybeKind = Always<()>`).

[gadget-trait]: ragu_core::gadgets::Gadget
[maybe-trait]: ragu_core::maybe::Maybe
[always-marker]: ragu_core::maybe::Always
[empty-marker]: ragu_core::maybe::Empty
[maybekind-trait]: ragu_core::maybe::MaybeKind
[emulator-type]: ragu_core::drivers::emulator::Emulator
[driver-trait]: ragu_core::drivers::Driver
[wireless-marker]: ragu_core::drivers::emulator::Wireless
[wired-marker]: ragu_core::drivers::emulator::Wired
[Emulator::wireless]: ragu_core::drivers::emulator::Emulator::wireless
[Emulator::wired]: ragu_core::drivers::emulator::Emulator::wired
[Emulator::wires]: ragu_core::drivers::emulator::Emulator::wires
[Emulator::always_wires]: ragu_core::drivers::emulator::Emulator::always_wires
[Emulator::execute]: ragu_core::drivers::emulator::Emulator::execute
[Emulator::extractor]: ragu_core::drivers::emulator::Emulator::extractor
