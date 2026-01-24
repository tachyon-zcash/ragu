# Writing Circuits

This guide explains how PCD applications are structured through Steps - the fundamental building blocks that combine proofs in Ragu's architecture.

> **Note:** For a complete working example with full code, see [Getting Started](getting_started.md). This guide focuses on explaining the concepts and design patterns.

## Understanding PCD Steps

A PCD application is built from **Steps** - computations that take proof inputs and produce new proofs. Unlike traditional circuits that just verify computation, PCD Steps can:

- Take proofs from previous steps as inputs
- Combine multiple proofs together
- Produce new proofs that attest to the combined computation

### The Step Trait

Every Step must implement this core structure:

```rust
pub trait Step<C: Cycle> {
    const INDEX: Index;
    type Witness<'source>;
    type Aux<'source>;
    type Left: Header<C::CircuitField>;
    type Right: Header<C::CircuitField>;
    type Output: Header<C::CircuitField>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
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

A unique identifier for this step in your application. Each step must have a distinct index starting from 0.

### 2. Type Parameters

**Witness**: Data provided by the prover (private input)
```rust
type Witness<'source> = FieldElement;  // What the prover knows
```

**Aux**: Data returned to the caller (output values)
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
2. Receives encoders for left/right input proofs
3. Performs computation (constraints)
4. Returns encoded proofs and auxiliary output

## Two Types of Steps

### Seed Steps (Create Initial Proofs)

Seed steps create the first proofs in a tree - they have no proof inputs:

```rust
type Left = ();   // No left input
type Right = ();  // No right input
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
1. **Encode inputs** - Convert input proof headers to circuit gadgets via `.encode(dr)?`
2. **Extract data** - Get header values with `.as_gadget()`
3. **Combine** - Hash or process the data together
4. **Encode output** - Package combined result as a new proof

These proofs are created using `app.fuse()`.

## Understanding .encode()

When working with input proofs in a fuse step:

```rust
let left = left.encode(dr)?;
let right = right.encode(dr)?;
```

The `.encode()` call:
- Converts the header data into circuit gadgets (allocates field elements)
- Makes the proof's header data available for use in circuit logic
- Returns an `Encoded` proof that can be passed to the next step

After encoding, extract the actual data with `.as_gadget()`:
```rust
let left_data = left.as_gadget();
let right_data = right.as_gadget();
```

## Working with Headers

Headers define what data flows through the proof tree:

```rust
struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const SUFFIX: Suffix = Suffix::new(0);  // Unique ID
    type Data<'source> = F;                 // Data type
    type Output = Kind![F; Element<'_, _>]; // Gadget output

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)  // How to convert data to gadget
    }
}
```

**SUFFIX**: Unique identifier for this header type (used for type safety)
**Data**: The native Rust type for this header's data
**Output**: The gadget representation (circuit elements)
**encode**: How to convert `Data` into `Output`

## Common Patterns

### Pattern 1: Seed Steps (Create Initial Proofs)

```rust
type Left = ();   // No left input
type Right = ();  // No right input
type Output = YourHeader;
```

Usage:
```rust
let (proof, aux) = app.seed(&mut rng, CreateLeaf { ... }, witness)?;
```

### Pattern 2: Fuse Steps (Combine Proofs)

```rust
type Left = HeaderA;
type Right = HeaderB;
type Output = HeaderC;
```

Usage:
```rust
let (proof, aux) = app.fuse(&mut rng, CombineNodes { ... }, (), left_pcd, right_pcd)?;
```

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
let pasta = Pasta::baked();
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(CreateLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .register(CombineNodes { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .finalize(pasta)?;
```

For details on parameter selection (`Pasta`, `R<13>`, `4`), see [Configuration](configuration.md).

## Related Topics

- [Getting Started](getting_started.md) provides a complete walkthrough with a working Merkle tree example
- [Configuration](configuration.md) explains the ApplicationBuilder parameter choices
- [Gadgets](gadgets/index.md) documents the available building block operations
