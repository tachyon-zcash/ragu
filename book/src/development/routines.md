# Routines

A *routine* is a transformation that takes gadgets (circuit variables) as inputs and produces gadgets as outputs. Unlike ordinary circuit functions, routines are reusable components that expose a structured interface which enables [driver-level](./drivers/index.md) optimizations like memoization and parallelization. [^1]

## `Predict` and `Execute` Capabilities 

The `Routine` trait exposes two methods:

1. `predict()`: Attempts to predict the routine's output given its input. Drivers can then leverage these predictions to skip execution or run it in a background thread. The prediction process produces routine-specific auxiliary (`Aux`) data that `execute()` uses during actual synthesis to avoid redundant computation.

    The prediction returns either:

    - `Prediction::Known(output, aux)` - Output successfully predicted; driver can skip/parallelize execution, and possibly use the auxiliary data to aid witness generation.
    - `Prediction::Unknown(aux)` - Cannot predict output; returns auxiliary data to optimize execution

    ```rust
    let result = match routine.predict(&mut dummy, &dummy_input)? {
        Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
            routine.execute(self, input, aux)?
        }
    };
    ```

    Functionally, this affords a *potential* optimization pattern that enables `predict()` to spawn background threads computing intermediate `Aux` while circuit execution continues, with `execute()` later joining the thread to retrieve those precomputed hints. This would enable the circuit to continue execution without blocking on expensive interstitial witness computations, allowing witness generation to overlap with synthesis. However, witness generation is currently fully sequential.

2. `execute()`: Performs the actual circuit synthesis for the routine using the provided driver. It receives the input gadget and auxiliary data from `predict()` and returns the output gadget. 

## Driver Optimizations

Routines enable driver-level optimizations like memoization and parallelization. 

**Memoization**: `SXY` driver can cache routine synthesis if the same routine is invoked multiple times, such as a Poseidon implementation that uses routines for its permutation rounds to avoid recomputing it each time. The Routine trait marks locations in circuit code where drivers can identify structurally identical invocations. This allows drivers to memoize the polynomial construction, making subsequent circuit synthesis significantly faster when the same routine is called multiple times.

The memoization opportunity is extensible to multiple routines in the same circuit, or cross-circuit memoization for routines across circuits. 

**Parallelization**: `RX` driver can parallelize witness generation by leveraging `predict()` to obtain output witness values and auxiliary data early, spawning background threads to compute witnesses for multiple routines without blocking circuit execution.

## In-Circuit versus Out-of-Circuit

Routines enable the same code to work in both contexts:

**Out-of-circuit (unconstrained) execution**: Using the [Emulator](./drivers/emulator.md) driver, routines call `predict()` to short-circuit execution, performing fast and unconstrained witness computation without enforcing constraints.

**In-circuit execution**: Using the `SXY` driver, routines call `execute()` to synthesize constraints. The verifier checks the constraints built by `SXY`.

## Future optimizations

A higher-level optimization could perform PCD graph restructuring by analyzing routine patterns across the graph and modifying its topology. Any kind of techniques that leverage routines to analyze the PCD graph structure aren't implemented. 

Additionally, identifying and eliminating redundant R1CS constraints is another optimization layer. However, that should be the prerogative of the application developer when optimizing their R1CS circuits.

[^1]: In [halo2](https://github.com/zcash/halo2) for instance, the synthesize function runs twice to identify these optimization patterns.