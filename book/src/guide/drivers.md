# Drivers

The **driver** abstraction provides a unified interface that enables the same circuit code to work across different execution contexts. A driver is a compile-time specialized backend that determines how a circuit is handled at runtime.

Circuits are written generically over the `Driver` trait. They invoke generic driver operations like `driver.mul()` and `driver.enforce_zero()` that each driver interprets differently. Each synthesis invocation is a deterministic pass over the circuit definition with a different backend "interpreter" that computes and extracts different information. For example, the `SXY` driver builds wiring polynomials *S(X, Y)* during registry construction (canonically referred to as circuit synthesis), and the `RX` driver generates witness polynomials *R(X)*.

The driver exposes operations (for instance `driver.mul()` for encoding multiplication gates and `driver.enforce_zero()` for enforcing linear constraints) while hiding implementation details. Since [R1CS][r1cs-concept] supports *virtual wires* (unlimited fan-in addition gates are free via `driver.add()`), the driver can handle both "in-circuit" operations that contribute to the constraint counts and "out-of-circuit" computations like witness generation.

## Execution Contexts

There are different kinds of execution we're particularly interested in distinguishing between:

### In-circuit versus out-of-circuit

Recursive proofs require algorithms to execute both as circuit constraints (in-circuit) and as direct computations (out-of-circuit). Writing these algorithms generically over the `Driver` trait ensures the same implementation works in both contexts, maintaining consistency for completeness with little runtime overhead.

### Witness generation versus constraint synthesis

**Constraint synthesis** builds the circuit's structure—determining what wires exist, what multiplication gates connect them, and what linear constraints they must satisfy. It answers: "What truths must hold?"

**Witness generation** computes the actual field element values that satisfy those constraints. It answers: "Do these truths hold?"

These are logically separate operations. Some drivers build circuit structure without computing witness values—witness closures are never called and the compiler optimizes them away. Other drivers generate witness values without tracking circuit structure—witness closures are always called to compute field element values.

## The `Maybe` Monad

The same circuit code works whether witness values are present or not. Drivers specify a `MaybeKind` associated type which determines whether witness values are available. This allows the compiler to statically reason about witness availability, according to the purpose of the driver.

`DriverValue<D, T>` is a type alias for the concrete `Maybe<T>` type for a given driver.

## Available Drivers

- **Emulator** - Direct execution without enforcing constraints
- **Simulator** - Full synthesis simulation with constraint validation

The `Emulator` driver is parameterized on a *mode* that determines whether it tracks wire assignments:

- `Emulator::wireless()` - No wire tracking, maybe witness available
- `Emulator::execute()` - Always has witness, no wire extraction
- `Emulator::extractor()` - Full tracking, enables wire value extraction

Internally, Ragu uses additional drivers for circuit synthesis and witness generation—see [Driver Architecture](../implementation/drivers/index.md) for details.

[r1cs-concept]: ../concepts/r1cs.md
