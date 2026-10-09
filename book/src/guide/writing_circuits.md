# Writing Circuits

This guide explains how PCD applications are structured through Steps - the
fundamental building blocks that combine proofs in Ragu's architecture.

> **Note:** For a complete working example with full code, see
> [Getting Started](getting_started.md). This guide focuses on explaining
> the concepts and design patterns.

## Understanding PCD Steps

A PCD application is built from **Steps** - computations that take proof
inputs and produce new proofs. Unlike traditional circuits that just verify
computation, PCD Steps can:

- Take proofs from previous steps as inputs
- Combine multiple proofs together
- Produce new proofs that attest to the combined computation

### The Step Trait

Every Step must implement this core structure:

```rust
pub trait Step<C: Cycle> {
    const INDEX: Index;
    type Shared: Shared<C::CircuitField>;
    type Witness<'source>;
    type Aux<'source>;
    type Left: Header<C::CircuitField>;
    type Right: Header<C::CircuitField>;
    type Output: Header<C::CircuitField>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        right: DriverValue<D, <Self::Right as Header<C::CircuitField>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>;
}
```

Let's break down what each part means.

## Anatomy of a Step

### 1. Step Index

```rust
const INDEX: Index = Index::new(0);
```

A unique identifier for this step in your application. Each step must have a
distinct index starting from 0.

### 2. Type Parameters

**Witness**: Data provided by the prover (private input)
```rust
type Witness<'source> = FieldElement;  // What the prover knows
```

**Shared**: The typed connection between steps in a bundle. A standalone step
declares `type Shared = ();` and returns `()` in the shared-gadget position.
Bundle steps use the same named shared gadget type, described below.

**Aux**: Auxiliary data returned alongside the output header value (e.g., for pipelining to future steps)
```rust
type Aux<'source> = FieldElement;  // What to return
```

**Left/Right**: Types of proofs this step accepts
```rust
type Left = LeafNode;   // Left proof type
type Right = LeafNode;  // Right proof type
```

**Output**: Type of proof this step produces
```rust
type Output = InternalNode;  // What this step creates
```

### 3. The witness Function

This is where the circuit logic is implemented. The function:
1. Receives witness data from the prover
2. Receives left/right header data as `DriverValue`s
3. Performs computation (constraints)
4. Returns encoded headers, the shared gadget, output data, and auxiliary output

## Two Types of Steps

### Seed Steps (Create Initial Proofs)

Seed steps create the first application proofs in a tree. The caller supplies
no proof inputs; `seed` provides the application's bootstrap proof:

```rust
type Left = ();     // Bootstrap child
type Right = ();    // Bootstrap child
type Output = LeafNode;
```

The key operations in a seed step:
1. **Allocate witness** - Convert prover data to circuit elements
2. **Compute** - Perform operations like hashing (288 constraints for Poseidon)
3. **Encode output** - Package result as a proof

These proofs are created using `app.seed()`.

### Fuse Steps (Combine Proofs)

Fuse steps take existing proofs and combine them:

```rust
type Left = LeafNode;   // Takes a LeafNode proof
type Right = LeafNode;  // Takes another LeafNode
type Output = InternalNode;  // Produces InternalNode
```

The key operations in a fuse step:
1. **Encode inputs** - Convert input proof headers to circuit gadgets via
   `Encoded::new(dr, &mut (), left)?`
2. **Extract data** - Get header values with `.as_gadget()`
3. **Combine** - Hash or process the data together
4. **Encode output** - Package combined result as a new proof

These proofs are created using `app.fuse()`.

## Understanding Encoded::new()

When working with input proofs in a fuse step:

```rust
let left = Encoded::new(dr, &mut (), left)?;
let right = Encoded::new(dr, &mut (), right)?;
```

The `Encoded::new()` call:
- Takes an allocator (here `&mut ()`, the stateless unit allocator)
  that controls wire allocation — see
  [Allocation](primitives/allocation.md)
- Converts the header data into circuit gadgets
- Makes the proof's header data available for use in circuit logic
- Returns an `Encoded` proof that can be passed to the next step

After encoding, extract the actual data with `.as_gadget()`:
```rust
let left_data = left.as_gadget();
let right_data = right.as_gadget();
```

## Working with Headers

Headers define what data flows through the proof tree. Each header
implementation specifies a `SUFFIX` (unique identifier), a `Data` type
(the native Rust value), an `Output` type (the circuit gadget
representation), and an `encode` function that converts `Data` into
`Output` by allocating circuit elements.

For a complete example with multiple header types, see
[Getting Started — Define Header Types](getting_started.md#step-1-define-header-types).
The `allocator` parameter controls how field elements are allocated;
see [Allocation](primitives/allocation.md) for details on choosing an
allocator.

## Common Patterns

### Pattern 1: Seed Steps (Create Initial Proofs)

```rust
type Left = ();     // Bootstrap child
type Right = ();    // Bootstrap child
type Output = YourHeader;
```

Usage:
```rust
let (pcd, aux) = app.seed(&mut rng, CreateLeaf { ... }, witness)?;
```

### Pattern 2: Fuse Steps (Combine Proofs)

```rust
type Left = HeaderA;
type Right = HeaderB;
type Output = HeaderC;
```

Usage:
```rust
let (pcd, aux) = app.fuse(&mut rng, CombineNodes { ... }, (), left_pcd, right_pcd)?;
```

Every proof carries two application circuit slots. A step
registered with `register(A)` is registered as the repeated bundle `(A, A)`:
`seed` and `fuse` take it alone, trace it once, and fill every slot with that
one claim. An application computation that needs more gates than one circuit
holds can use two steps, registered together with `register_bundle` and proved with
`seed_bundle` or `fuse_bundle`:

```rust
let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
    .with_registry_tags(tags)
    .register_bundle((StepA, StepB))?
    .finalize(params)?;
```

The registry tags and parameters come from the application's setup, as for
standalone steps. No staging configuration is needed.

```rust
let (pcd, aux) = app.fuse_bundle(
    &mut rng,
    (StepA { ... }, StepB { ... }),
    (witness_a, witness_b),
    left_pcd,
    right_pcd,
)?;
```

The steps use the same header types and consecutive indices. They cannot
be proved separately, substituted, or reordered: `fuse` requires a step
registered on its own, bundle entry points require both steps in the registered order,
and both verifiers refuse a proof whose slots do not hold the registered bundle.

Both steps implement `Step` and declare
the **same shared gadget type**: one named collection of circuit values that
must agree between them. Derive `Gadget` and `Shared` on that struct:

```rust
use ragu_core::{drivers::Driver, gadgets::{Gadget, Kind}};
use ragu_primitives::{Element, shared::Shared};

#[derive(Gadget, Shared)]
struct Connection<'dr, D: Driver<'dr>> {
    input: Element<'dr, D>,
    intermediate_state: Element<'dr, D>,
}

impl Step<Pasta> for StepA {
    type Shared = Kind![Fp; Connection<'_, _>];
    // INDEX, Witness, Left, Right, Output, Aux as for a Step.

    fn witness<'dr, 'source: 'dr, D, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, LeftData>,
        right: DriverValue<D, RightData>,
    ) -> Result<...> {
        // Allocate or compute these values in this circuit's normal logic.
        let input = ...;
        let intermediate_state = ...;
        let shared = Connection { input, intermediate_state };
        Ok(((left_header, right_header, output_header), shared, output_data, aux))
    }
}

impl Step<Pasta> for StepB {
    type Shared = Kind![Fp; Connection<'_, _>];
    // Return the same struct, containing the actual values B uses or computes.
    ...
}
```

Ragu binds every corresponding wire automatically: A's `input` equals B's
`input`, and A's `intermediate_state` equals B's `intermediate_state`. No
shared size, positional shared array, or manual connecting equality is
supplied. The derive includes every gadget field, supports fixed vectors and
nested shared structs, and refuses skipped, raw-wire, or witness-only fields.
Using different connection types in one bundle is a compile-time error, even
if their fields have identical shapes.

Each step must still constrain its own computation and return the actual
values it uses. The shared type describes which values agree; it does not
derive application mathematics or determine whether a connection is needed.
The steps can prepare their witnesses sequentially, in either order, or
independently in parallel when their data dependencies allow it. This does
not change their registered slot order or the prover's current scheduling.

Ragu derives its internal capacity from the largest shared gadget among the
registered bundles and constructs the circuits during `finalize`. It pads
smaller bundles internally. Each bundle step reserves `ceil(n / 2)`
gates for the application-wide capacity `n`, and adds one connecting equality
constraint per shared wire. Registration checks size arithmetic and capacity;
finalization checks each complete circuit's gate and constraint budgets.
Standalone steps, bootstrap, and rerandomization reserve no shared block.

Recursive and terminal verification enforce the common stage, including
proofs built outside the Rust API. The [protocol chapter](../protocol/recursion/public_inputs.md)
explains the internal staging and binding checks.

### Pattern 3: Stateful Steps

State can be passed through the witness:
```rust
type Witness<'source> = (Counter, Data);

fn witness(..., witness: DriverValue<D, Self::Witness<'source>>, ...) {
    let (counter, data) = witness.cast();
    // Counter is used in circuit logic
}
```

### Pattern 4: Multiple Header Types

Different steps can produce different headers:
```rust
// Step 1 produces LeafNode
type Output = LeafNode;

// Step 2 consumes LeafNode, produces InternalNode
type Left = LeafNode;
type Right = LeafNode;
type Output = InternalNode;
```

The type system ensures you can't accidentally combine incompatible proofs.

## Building an Application

With Steps and Headers defined, an application is constructed as follows:

```rust
let pasta = ragu_pcd::pasta::baked();
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(CreateLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .register(CombineNodes { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .finalize(pasta)?;
```

For details on parameter selection (`Pasta`, `R<13>`, `4`), see
[Configuration](configuration.md).

## Related Topics

- [Getting Started](getting_started.md) provides a complete walkthrough with
  a working Merkle tree example
- [Configuration](configuration.md) explains the ApplicationBuilder
  parameter choices
- [Gadgets](gadgets/index.md) documents the available building block operations
