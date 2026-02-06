# Driver Architecture

This section covers the internal implementation of Ragu's driver system. For a user-focused conceptual overview, see [Drivers](../../guide/drivers.md) in the User Guide.

## Design Rationale

Circuits are generic over the `Driver` trait. Each synthesis invocation is a deterministic pass over the circuit definition with a different backend "interpreter" that computes and extracts different information.

## Lifetime Parameters `'dr` and `'source`

Driver-generic code uses two lifetime parameters, `'dr` and `'source`.

Circuits (and thus gadgets, steps, headers, etc) are parameterized by driver lifetime `'dr` as in `Element<'dr, D>`, meaning circuits cannot outlive their driver.

Associated types `Witness` and `Instance` are parameterized by `'source`, which is further bound at execution to `'dr`' by method signatures.

These constraints enable the compiler to provide zero-copy access to witness values held by the driver.

## Performance Considerations

Most zkSNARK toolkits always perform both witness generation and constraint synthesis, even when not necessary.

Ragu's driver model provides separation of concerns through the `MaybeKind` abstraction:

- During **constraint synthesis** (`MaybeKind = Empty`): Witness closures are never called; the compiler optimizes them away entirely
- During **witness generation** (`MaybeKind = Always<T>`): Witness closures are always called; field element values are computed

This compile-time type parameterization can elide witness computation and will even eliminate the runtime overhead of conditional availability checks.

This design is intended to allow Ragu circuit synthesis to be frequently invoked on performance-critical hot paths.

## Implemented Drivers

Drivers specify associated types that determine behavior according to purpose.

| Driver | Purpose | MaybeKind | Wire |
| ------ | ------- | --------- | ---- |
| SXY | Circuit synthesis (internal) | `Empty` | `Wire<F>` |
| RX | Witness generation (internal) | `Always<()>` | `()` |
| Simulator | Validation | `Always<()>` | `Wire<F>` |
| Emulator | Testing | varies | varies |

### SXY Driver

Synthesizes the mesh polynomial *S(X, Y)*:

- `MaybeKind = Empty`: Witness closures passed to `driver.alloc()` and `driver.mul()` are never called.
- `Wire = Wire<F>`: Tracks assignments as powers of X and constraints as powers of Y.

The driver collects the assignments and constraints for each wire and constructs the resulting mesh polynomial.

### RX Driver

Generates the witness polynomial *R(X)*:

- `MaybeKind = Always<T>`: Witness closures passed to `driver.alloc()` and `driver.mul()` are called to compute field elements.
- `Wire = ()`: Tracks no assignments or constraints.

The driver collects the field elements for each witness and constructs the resulting witness polynomial.

### Emulator

See [Emulator](./emulator.md)

### Simulator

See [Simulator](./simulator.md)

## See Also

- [Writing Custom Drivers](custom.md) — Implementing new drivers
- [Emulator](emulator.md) — The built-in testing driver
- [Routines](routines.md) — Tools for driver-level optimization of gadgets
