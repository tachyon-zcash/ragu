# Emulator Driver

The simplest implementation of `Driver` is the `Emulator`, which natively
executes circuit code without enforcing constraints. This driver is useful when
the correctness of circuit code does not need to be guaranteed—for example, in
witness generation logic performed by a prover—because in that case the circuit
code is just native code with pointless steps. Instead of reimplementing
algorithms to anticipate the structure or results of their computations, simply
to avoid the overhead of constraint enforcement or wire assignment tracking done
in typical circuit synthesis code, the `Emulator` driver can be used to avoid as
much of this overhead as possible.

One of the purposes of the design of the `Driver` abstraction in Ragu is to
enable circuit code to be written so that it can be efficiently natively
executed, reducing code. This especially helps with developing recursive proofs
since almost everything performed by the verifier must be also be written to be
executed within a circuit as well.

## `Wired` and `Wireless` modes

The `Emulator` can be instantiated in `Wireless` mode (where the `Wire` type of
the driver is `()`, and nothing about the wire assignments or relationships are
preserved) or in `Wired` mode (where, if a witness is available, the `Wire` type
contains the assignments that the circuit code's witness generation logic
produces). The purpose of the two modes is to allow the user to avoid as much
unnecessary computation as possible during emulation depending on their needs.

| Emulator | Wire | Witness availability (`MaybeKind`) |
|---|---|---|
| `Emulator<Wireless<M, F>>` **(`Emulator::wireless`)** | `()` | `Always<()>` or `Empty` |
| `Emulator<Wired<M, F>>` **(`Emulator::wired`)** | `Maybe<F>` | `Always<()>` or `Empty` |
| `Emulator<Wireless<Always<()>, F>>` **(`Emulator::execute`)** | `()` | `Always<()>` |
| `Emulator<Wired<Always<()>, F>>` **(`Emulator::extractor`)** | `Always<F>` | `Always<()>` |

## Wire Extraction

`Gadget`s can have their wires extracted from an `Emulator` in `Wired` mode; a
provided helper utility (`Emulator::wires`) returns a vector of wires for a
given gadget. Commonly, `Emulator::always_wires` is used instead when a witness
is expected to be present (`MaybeKind = Always<()>`).
