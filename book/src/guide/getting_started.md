# Getting Started with Ragu

This guide demonstrates a complete Proof-Carrying Data (PCD) application built with Ragu. The example constructs a simple Merkle tree where each node carries a proof of correctness.

## What This Example Demonstrates

This working PCD application shows how to:
- Create leaf proofs from raw data
- Combine leaf proofs into internal nodes
- Verify the entire proof tree

The example illustrates the core functions of PCD: **data that carries its own proof of correctness**.

## Prerequisites

Add Ragu to your `Cargo.toml`:

```toml
[dependencies]
ragu_circuits = "0.1"
ragu_core = "0.1"
ragu_pasta = "0.1"
ragu_pcd = "0.1"
ragu_primitives = "0.1"
arithmetic = "0.1"
ff = "0.13"
rand = "0.8"
```

## Configuration at a Glance

This guide uses `ApplicationBuilder::<Pasta, R<13>, 4>`:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| **Cycle** | `Pasta` | Elliptic curve cycle for proof recursion (standard choice) |
| **Rank** | `R<13>` | Circuit capacity: 2^13 = 8,192 constraints |
| **Header Size** | `4` | Each proof carries 4 field elements of data |

These defaults work for most applications. See [Configuration](configuration.md) for guidance on choosing different values.

## Overview: Building a Merkle Tree with Proofs

This application implements two core operations:

1. **CreateLeaf**: Takes a value, hashes it, and produces a leaf proof
2. **CombineNodes**: Takes two leaf proofs and combines them into an internal node proof

The result is a proof tree where each node proves it was correctly computed from its children.

## Step 1: Define Header Types

Headers define what data flows through the proof tree. This example uses two types:

```rust
use ff::Field;
use ragu_core::{Result, drivers::{Driver, DriverValue}, gadgets::{GadgetKind, Kind}, maybe::Maybe};
use ragu_pcd::header::{Header, Suffix};
use ragu_primitives::Element;
use ragu_primitives::poseidon::Sponge;

// LeafNode: carries a hash of raw data
struct LeafNode;

impl<F: Field> Header<F> for LeafNode {
    const SUFFIX: Suffix = Suffix::new(0);  // Unique ID
    type Data<'source> = F;                  // Field element
    type Output = Kind![F; Element<'_, _>];  // Circuit representation

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)  // Convert to circuit element
    }
}

// InternalNode: carries hash of two children
struct InternalNode;

impl<F: Field> Header<F> for InternalNode {
    const SUFFIX: Suffix = Suffix::new(1);  // Different ID
    type Data<'source> = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Element::alloc(dr, witness)
    }
}
```

**Key Points:**
- `SUFFIX`: Unique identifier for each header type
- `Data`: The Rust type for this header's data (field elements)
- `Output`: The circuit representation (Element gadget)
- `encode`: How to convert Data into circuit form

## Step 2: Implement CreateLeaf Step

This step creates leaf proofs from raw values:

```rust
use arithmetic::Cycle;
use ragu_pcd::step::{Encoded, Encoder, Index, Step};
use ragu_primitives::poseidon::Sponge;

struct CreateLeaf<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CreateLeaf<'params, C> {
    const INDEX: Index = Index::new(0);  // Step ID

    type Witness<'source> = C::CircuitField;  // Input: field element
    type Aux<'source> = C::CircuitField;      // Output: hash result
    type Left = ();                            // No left input
    type Right = ();                           // No right input
    type Output = LeafNode;                    // Produces LeafNode

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        _: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
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

        // 3. Extract the hash value to return
        let leaf_value = leaf.value().map(|v| *v);

        // 4. Encode as a proof
        let leaf_encoded = Encoded::from_gadget(leaf);

        // 5. Return (left, right, output) proofs + aux data
        Ok((
            (
                Encoded::from_gadget(()),  // No left
                Encoded::from_gadget(()),  // No right
                leaf_encoded,               // Our output
            ),
            leaf_value,  // Hash result
        ))
    }
}
```

**What's happening:**
1. Convert witness to circuit element (creates constraint)
2. Hash using Poseidon (288 constraints)
3. Extract hash value to return to caller
4. Package as encoded proof
5. Return proof tuple + auxiliary output

## Step 3: Implement CombineNodes Step

This step combines two leaf proofs:

```rust
struct CombineNodes<'params, C: Cycle> {
    poseidon_params: &'params C::CircuitPoseidon,
}

impl<'params, C: Cycle> Step<C> for CombineNodes<'params, C> {
    const INDEX: Index = Index::new(1);  // Different step ID

    type Witness<'source> = ();           // No extra witness
    type Aux<'source> = C::CircuitField;  // Return combined hash
    type Left = LeafNode;                 // Takes LeafNode
    type Right = LeafNode;                // Takes LeafNode
    type Output = InternalNode;           // Produces InternalNode

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // 1. Encode input proofs (verifies them!)
        let left = left.encode(dr)?;
        let right = right.encode(dr)?;

        // 2. Hash both headers together
        let mut sponge = Sponge::new(dr, self.poseidon_params);
        sponge.absorb(dr, left.as_gadget())?;
        sponge.absorb(dr, right.as_gadget())?;
        let output = sponge.squeeze(dr)?;

        // 3. Extract and encode result
        let output_value = output.value().map(|v| *v);
        let output = Encoded::from_gadget(output);

        // 4. Return verified proofs + combined hash
        Ok(((left, right, output), output_value))
    }
}
```

**What `.encode(dr)?` does:** The `Header::encode` call converts the header data into a circuit gadget by allocating field elements. This makes the input proof's header data available for use in the circuit logic (e.g., hashing the two headers together).

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
        .register(CreateLeaf {
            poseidon_params: Pasta::circuit_poseidon(pasta),
        })?
        .register(CombineNodes {
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
// Create first leaf using seed
let leaf1 = app.seed(
    &mut rng,
    CreateLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) },
    Fp::from(100u64),  // Hash the value 100
)?;
let leaf1 = leaf1.0.carry(leaf1.1);
assert!(app.verify(&leaf1, &mut rng)?);
println!("Leaf 1 verified (value: 100)");

// Create second leaf
let leaf2 = app.seed(
    &mut rng,
    CreateLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) },
    Fp::from(200u64),  // Hash the value 200
)?;
let leaf2 = leaf2.0.carry(leaf2.1);
assert!(app.verify(&leaf2, &mut rng)?);
println!("Leaf 2 verified (value: 200)");

// Combine leaves into internal node using fuse
let node1 = app.fuse(
    &mut rng,
    CombineNodes { poseidon_params: Pasta::circuit_poseidon(pasta) },
    (),  // No extra witness
    leaf1,
    leaf2,
)?;
let node1 = node1.0.carry::<InternalNode>(node1.1);
assert!(app.verify(&node1, &mut rng)?);
println!("Internal node verified!");

println!("\nTree structure:");
println!("       node1");
println!("      /     \\");
println!("  leaf1   leaf2");
println!("   (100)    (200)");
```

## Understanding the Flow

The proof creation and verification process follows these steps:

1. **seed()/fuse()** calls the Step's `witness()` function
2. The circuit logic executes (hashing, combining, etc.)
3. A SNARK proof is generated for that computation
4. The proof bundles:
   - The computation result (header data)
   - Cryptographic proof of correctness
   - References to input proofs (if any)

5. **verify()** checks:
   - The SNARK proof is valid
   - Input proofs are valid (recursively)
   - Header data matches claimed computation

This is **Proof-Carrying Data**: each node carries a proof that it was correctly computed from its children, all the way down to the leaves.

## Related Topics

For deeper exploration of PCD applications in Ragu:

- **[Writing Circuits](writing_circuits.md)**: Detailed explanation of Steps, Headers, and circuit logic implementation
- **[Configuration](configuration.md)**: Understanding the Pasta/R<13>/4 parameters and selection criteria
- **[Gadgets](gadgets/index.md)**: Documentation of Element, Sponge, and other building blocks
- **[Drivers](drivers.md)**: Explanation of execution contexts (Emulator, SXY, RX)


## Summary

This example covered the foundational concepts of PCD in Ragu:
- Header types that define proof data structure
- Steps that implement computation and proof combination
- Application configuration and building
- Proof creation and verification workflows

These concepts form the base upon which all Ragu PCD applications are built.
