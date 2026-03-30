# Getting Started

This guide demonstrates a complete proof-carrying data (PCD) application
built with Ragu. The example constructs a simple Merkle tree where each node
carries a proof of correctness.

## What This Example Demonstrates

This working PCD application shows how to:
- Create leaf proofs from raw data
- Combine leaf proofs into internal nodes
- Verify the entire proof tree

The example illustrates the core idea of PCD: **data that carries its
own proof of correctness**.

## Prerequisites

Add Ragu to your `Cargo.toml`:

```toml
[dependencies]
ragu_arithmetic = "0.1"
ragu_circuits = "0.1"
ragu_core = "0.1"
ragu_pasta = { version = "0.1", features = ["baked"] }
ragu_pcd = "0.1"
ragu_primitives = "0.1"
ff = "0.13"
rand = "0.8"
```

The `baked` feature on `ragu_pasta` includes precomputed curve parameters.

## Configuration at a Glance

This guide uses `ApplicationBuilder::<Pasta, R<13>, 4>`:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| **Cycle** | `Pasta` | Elliptic curve cycle for proof recursion (standard choice) |
| **Rank** | `R<13>` | Up to 2,048 multiplication gates (8,192 polynomial coefficients) |
| **Header Size** | `4` | Each proof carries 4 field elements of data |

These defaults work for most applications. See
[Configuration](configuration.md) for guidance on choosing different values.

## Overview: Building a Merkle Tree with Proofs

This application implements two core operations:

1. **WitnessLeaf**: Takes a value, hashes it, and produces a leaf proof
2. **Hash2**: Takes two leaf proofs and combines them into an internal
   node proof

The result is a proof tree where each node proves it was correctly computed
from its children.

## Step 1: Define Header Types

Headers define what data flows through the proof tree. This example uses two
types:

```rust
use ff::Field;
use ragu_core::{Result, drivers::{Driver, DriverValue}, gadgets::{Bound, Kind}, maybe::Maybe};
use ragu_pcd::header::{Header, Suffix};
use ragu_primitives::Element;

// LeafNode: carries a hash of raw data
struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const SUFFIX: Suffix = Suffix::new(0);  // Unique ID
    type Data = F;                           // Field element
    type Output = Kind![F; Element<'_, _>];  // Circuit representation

    fn encode<'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)  // Convert to circuit element
    }
}

// InternalNode: carries hash of two children
struct InternalNode;

impl<F: Field> Header<F> for InternalNode {
    const SUFFIX: Suffix = Suffix::new(1);  // Different ID
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, witness)
    }
}
```

**Key Points:**
- `SUFFIX`: Unique identifier for each header type
- `Data`: The Rust type for this header's data (a field element)
- `Output`: The circuit representation (Element gadget)
- `encode`: How to convert Data into circuit form

## Step 2: Implement WitnessLeaf Step

This step creates leaf proofs from raw values:

```rust
use ragu_arithmetic::Cycle;
use ragu_pcd::step::{Encoded, Index, Step};
use ragu_primitives::poseidon::Sponge;

struct WitnessLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for WitnessLeaf<'_, C> {
    const INDEX: Index = Index::new(0);  // Step ID

    type Witness<'source> = C::CircuitField;  // Input: field element
    type Aux<'source> = ();                   // No auxiliary output
    type Left = ();                           // No left input
    type Right = ();                          // No right input
    type Output = LeafNode;                   // Produces LeafNode

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        _: DriverValue<D, <Self::Right as Header<C::CircuitField>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // 1. Allocate the witness value in the circuit
        let leaf = Element::alloc(dr, witness)?;

        // 2. Hash it using Poseidon
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, &leaf)?;
        let leaf = sponge.squeeze(dr)?;

        // 3. Extract the hash value for the output header
        let leaf_data = leaf.value().map(|v| *v);

        // 4. Encode as output proof
        let leaf_encoded = Encoded::from_gadget(leaf);

        // 5. Return (left, right, output) proofs + output data + aux
        Ok((
            (
                Encoded::from_gadget(()),  // No left
                Encoded::from_gadget(()),  // No right
                leaf_encoded,              // Our output
            ),
            leaf_data,  // Hash result
            D::unit(),
        ))
    }
}
```

**What's happening:**
1. Allocate witness value in the circuit (one wire allocation)
2. Hash using Poseidon (288 constraints)
3. Extract hash value for the output header data
4. Package as encoded proof
5. Return proof tuple + header data + auxiliary output

## Step 3: Implement Hash2 Step

This step combines two leaf proofs:

```rust
struct Hash2<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for Hash2<'_, C> {
    const INDEX: Index = Index::new(1);  // Different step ID

    type Witness<'source> = ();           // No extra witness
    type Aux<'source> = ();               // No auxiliary output
    type Left = LeafNode;                 // Takes LeafNode
    type Right = LeafNode;                // Takes LeafNode
    type Output = InternalNode;           // Produces InternalNode

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        right: DriverValue<D, <Self::Right as Header<C::CircuitField>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // 1. Encode input proofs
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;

        // 2. Hash both headers together
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;

        // 3. Extract and encode result
        let output_data = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        // 4. Return encoded proofs + output data + aux
        Ok(((left, right, output), output_data, D::unit()))
    }
}
```

**What `Encoded::new(dr, data)?` does:** Converts the header data into a
circuit gadget by calling `Header::encode`. This makes the input proof's
header data available for use in the circuit logic (e.g., hashing the two
headers together).

## Step 4: Build the Application

The application is configured and built as follows:

```rust
use ragu_circuits::polynomials::R;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<()> {
    // 1. Initialize Pasta curve parameters
    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(12345);

    // 2. Build application with our steps
    let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
        .register(WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(Hash2 {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .finalize(pasta)?;

    println!("Application built successfully!");

    // Continue to Step 5...
    Ok(())
}
```

## Step 5: Create and Verify Proofs

The application can now be used to create and verify proofs:

```rust
// Create first leaf
let (leaf1, _) = app.seed(
    &mut rng,
    WitnessLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) },
    Fp::from(100u64),  // Hash the value 100
)?;
assert!(app.verify(&leaf1, &mut rng)?);
println!("Leaf 1 verified (value: 100)");

// Create second leaf
let (leaf2, _) = app.seed(
    &mut rng,
    WitnessLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) },
    Fp::from(200u64),  // Hash the value 200
)?;
assert!(app.verify(&leaf2, &mut rng)?);
println!("Leaf 2 verified (value: 200)");

// Combine leaves into internal node
let (node1, _) = app.fuse(
    &mut rng,
    Hash2 { poseidon_params: Pasta::circuit_poseidon(pasta) },
    (),  // No extra witness
    leaf1,
    leaf2,
)?;
assert!(app.verify(&node1, &mut rng)?);
println!("Internal node verified!");

println!("\nTree structure:");
println!("       node1");
println!("      /     \\");
println!("  leaf1   leaf2");
println!("   (100)    (200)");
```

## Understanding the Flow

The three core operations work as follows:

**seed()** calls the Step's `witness()` function with trivial inputs,
executes the circuit logic, and generates a SNARK proof. The result is
a `Pcd` bundling the computation result (header data) with a
cryptographic proof of correctness.

**fuse()** takes two existing `Pcd` values and combines them through a
Step, producing a new `Pcd` with proof of the combined computation.

**verify()** checks that the SNARK proof is valid, all accumulated
claims from prior steps are sound, and header data matches the claimed
computation.

Each node carries a proof of correct computation from its children,
all the way down to the leaves.

## Related Topics

For deeper exploration of PCD applications in Ragu:

- **[Writing Circuits](writing_circuits.md)**: Detailed explanation of
  Steps, Headers, and circuit logic implementation
- **[Configuration](configuration.md)**: Understanding the Pasta/R<13>/4
  parameters and selection criteria
- **[Gadgets](gadgets/index.md)**: Documentation of Element, Sponge, and
  other building blocks
- **[Drivers](drivers/index.md)**: The Driver trait abstraction, witness
  data, and linear expressions


## Summary

This example covered the foundational concepts of PCD in Ragu:
- Header types that define proof data structure
- Steps that implement computation and proof combination
- Application configuration and building
- Proof creation and verification workflows

These are the building blocks of all Ragu PCD applications.
