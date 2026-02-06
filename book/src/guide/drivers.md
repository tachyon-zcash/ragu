# Drivers

The **driver** abstraction provides a unified interface that enables the same circuit code to work across different execution contexts. A driver is a compile-time specialized backend interpreter that determines how circuit operations are executed at runtime.

Circuits are written generically over the `Driver` trait. They invoke generic driver operations like `driver.mul()` and `driver.enforce_zero()` that each driver interprets differently. Each synthesis invocation is a deterministic pass over the circuit definition with a different backend "interpreter" that computes and extracts different information. For example, the `SXY` driver builds wiring polynomials *S(X, Y)* during registry construction (canonically referred to as circuit synthesis), and the `RX` driver generates witness polynomials *R(X)*.

The driver exposes operations (for instance `driver.mul()` for encoding multiplication gates and `driver.enforce_zero()` for enforcing linear constraints) while hiding implementation details. Since R1CS supports *virtual wires* (unlimited fan-in addition gates are free via `driver.add()`), the driver can handle both "in-circuit" operations that contribute to the constraint counts and "out-of-circuit" computations like witness generation.

## Execution Contexts

There are different kinds of execution we're particularly interested in distinguishing between:

### 1. In-circuit versus out-of-circuit

Recursive proofs require algorithms to execute both as circuit constraints (in-circuit) and as direct computations (out-of-circuit). Writing these algorithms generically over the `Driver` trait ensures the same implementation works in both contexts, maintaining consistency for completeness with little runtime overhead.

### 2. Witness generation versus constraint synthesis

Drivers specify a `MaybeKind` associated type in the `DriverTypes` trait, which determines how witness information is represented. The `DriverValue<D, T>` is a type alias for the concrete `Maybe<T>` type for driver `D`, where `T` is the type of the witness data being wrapped. The alias resolves to different concrete types based on the driver's `MaybeKind`:

**SXY Driver**: Builds the circuit structure without computing witness values. Sets `MaybeKind = Empty` (witness closures passed to `driver.alloc()` and `driver.mul()` are never called, compiler optimizes them away) and `Wire = Wire<F>` (tracks wire assignments as powers of X and constraints on those wires as powers of Y). Together these construct the polynomial *S(X,Y)* encoding.

**RX Driver**: Generates witness values without tracking circuit structure. Sets `MaybeKind = Always<T>` (witness closures are always called to compute field element values), and `Wire = ()` (no wire tracking needed). Each operation invokes its witness closure and stores the resulting field elements in arrays, constructing the witness polynomial *R(X)*.

This type-level parameterization ensures that witness computation is only executed when the driver's `MaybeKind` requires it.

### 3. Different synthesis contexts

Beyond `SXY` and `RX` drivers, the `Emulator` driver executes circuit code directly without enforcing constraints, and the `Simulator` driver fully simulates synthesis and validates constraints for testing purposes.

The `Emulator` driver is particularly flexible because it's parameterized on a *mode* that determines whether it tracks wire assignments:

- `Emulator::wireless()` - No wire tracking, maybe witness available
- `Emulator::execute()` - Always has witness, no wire extraction
- `Emulator::extractor()` - Full tracking, enables wire value extraction

## The `Maybe` Monad

The `Maybe<T>` monad allows the compiler to statically reason about the existence of witness data for a concrete driver, allowing the same code to be interpreted whether witness values are present or not.

Traditionally, most zkSNARK toolkits bundle witness generation and constraint synthesis. This means every time you synthesize constraints, witness computation code executes even when witness values aren't needed, or vice versa. Ragu maintains separation of concerns through the `Maybe<T>` abstraction. In some frameworks, circuit synthesis alone accounts for 25-30% of the proof generation time (specifically constraint synthesis and inlining linear combinations; the R1CS to QAP reduction is an additional smaller cost).

Ragu supports non-uniform circuits without a traditional pre-processing step, so circuit synthesis is frequently invoked and becomes a performance-critical hot path. We need to optimize polynomial reductions, but without storing gigantic polynomials with all coefficients and indeterminates in memory.

When writing gadgets with the `GadgetKind` trait, you'll work with `Maybe<T>` values - see [Gadget Implementation](../implementation/gadgets.md) for details on how gadgets interact with drivers.

## Available Drivers

- **SXY** - Circuit synthesis (builds S(X,Y) polynomial)
- **RX** - Witness generation (builds R(X) polynomial)
- **Emulator** - Direct execution without constraints
- **Simulator** - Full synthesis simulation with validation

For implementation details, see [Driver Architecture](../implementation/drivers/index.md).
