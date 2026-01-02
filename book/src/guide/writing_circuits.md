# Writing Circuits

This guide explains how PCD applications are structured through Steps - a fundamental building blocks that combine proofs in Ragu's architecture.

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

## Example 1: Creating a Leaf (Seed Step)

The following example demonstrates how a leaf proof is created from witness data:

```rust
struct CreateLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CreateLeaf<'params, C> {
    const INDEX: Index = Index::new(0);

    // Prover provides a field element
    type Witness<'source> = C::CircuitField;

    // Return the hash result to caller
    type Aux<'source> = C::CircuitField;

    // No input proofs (this creates the first proof)
    type Left = ();
    type Right = ();

    // Produces a LeafNode proof
    type Output = LeafNode;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        _right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // 1. Allocate the witness as a circuit element
        let leaf = Element::alloc(dr, witness)?;

        // 2. Hash the leaf using Poseidon
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let leaf = sponge.squeeze(dr)?;

        // 3. Extract the value to return as Aux
        let leaf_value = leaf.value().map(|v| *v);

        // 4. Encode the output proof
        let leaf_encoded = Encoded::from_gadget(leaf);

        // 5. Return (left, right, output) proofs + aux data
        Ok((
            (
                Encoded::from_gadget(()),  // No left input
                Encoded::from_gadget(()),  // No right input
                leaf_encoded,               // Our output
            ),
            leaf_value,  // Return hash to caller
        ))
    }
}
```

### Breaking It Down

**Step 1: Allocate Witness**
```rust
let leaf = Element::alloc(dr, witness)?;
```
Converts the prover's data into a circuit element (creates a constraint).

**Step 2: Perform Computation**
```rust
let mut sponge = Sponge::new(dr, self.poseidon_params);
sponge.absorb(dr, &leaf)?;
let leaf = sponge.squeeze(dr)?;
```
Hashes the input using Poseidon (adds ~140 constraints).

**Step 3: Extract Auxiliary Output**
```rust
let leaf_value = leaf.value().map(|v| *v);
```
Gets the computed hash value to return to the application.

**Step 4: Encode the Proof**
```rust
let leaf_encoded = Encoded::from_gadget(leaf);
```
Wraps the circuit element as an encoded proof.

**Step 5: Return All Proofs**
```rust
Ok(((
    Encoded::from_gadget(()),  // Left (unused)
    Encoded::from_gadget(()),  // Right (unused)
    leaf_encoded,              // Output proof
), leaf_value))
```

## Example 2: Combining Proofs (Fuse Step)

Now let's combine two leaf proofs into an internal node:

```rust
struct CombineNodes<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CombineNodes<'params, C> {
    const INDEX: Index = Index::new(1);

    // No additional witness needed
    type Witness<'source> = ();
    type Aux<'source> = C::CircuitField;

    // Takes two LeafNode proofs
    type Left = LeafNode;
    type Right = LeafNode;

    // Produces InternalNode proof
    type Output = InternalNode;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // 1. Encode the input proofs (verifies them in-circuit)
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;

        // 2. Extract the header data from proofs
        let left_data = left.as_gadget();
        let right_data = right.as_gadget();

        // 3. Hash the two headers together
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left_data)?;
        sponge.absorb(dr, right_data)?;
        let output = sponge.squeeze(dr)?;

        // 4. Extract value and encode output
        let output_value = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        // 5. Return encoded proofs
        Ok(((left, right, output_encoded), output_value))
    }
}
```

### Key Differences from CreateLeaf

**Working with Encoders**
```rust
let left = left.encode(dr)?;
let right = right.encode(dr)?;
```
The `.encode()` call:
- Verifies the input proof's correctness in-circuit
- Makes the proof's header data available as gadgets
- Returns an `Encoded` proof that can be passed to the next step

**Extracting Header Data**
```rust
let left_data = left.as_gadget();
let right_data = right.as_gadget();
```
Gets the actual header values (field elements) from the verified proofs.

**Combining Data**
```rust
sponge.absorb(dr, left_data)?;
sponge.absorb(dr, right_data)?;
```
Hashes both headers together to create a Merkle-like structure.

## Working with Headers

Headers define what data flows through the proof tree. A header is defined as follows:

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

These proofs are created using `app.seed()`:
```rust
let (proof, aux) = app.seed(&mut rng, CreateLeaf { ... }, witness)?;
```

### Pattern 2: Fuse Steps (Combine Proofs)

```rust
type Left = HeaderA;
type Right = HeaderB;
type Output = HeaderC;
```

Proofs are combined using `app.fuse()`:
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

Proofs are then created and verified through the application API:

```rust
// Create leaf proofs
let (proof1, aux1) = app.seed(&mut rng, CreateLeaf { ... }, Fp::from(100))?;
let leaf1 = proof1.carry(aux1);

let (proof2, aux2) = app.seed(&mut rng, CreateLeaf { ... }, Fp::from(200))?;
let leaf2 = proof2.carry(aux2);

// Combine them
let (proof3, aux3) = app.fuse(&mut rng, CombineNodes { ... }, (), leaf1, leaf2)?;
let node = proof3.carry::<InternalNode>(aux3);

// Verify
assert!(app.verify(&node, &mut rng)?);
```

## Related Topics

- [Getting Started](getting_started.md) provides a complete walkthrough of the hello_pcd example
- [Configuration](configuration.md) explains the ApplicationBuilder parameter choices
- [Gadgets](gadgets/index.md) documents the available building block operations

## Reference Implementation

Complete, runnable examples can be found in:
- `crates/ragu_pcd/examples/hello_pcd.rs` - Merkle tree construction
- `crates/ragu_pcd/tests/nontrivial.rs` - Real-world usage patterns
