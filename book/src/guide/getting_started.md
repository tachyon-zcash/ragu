# Getting Started with Ragu

This guide walks you through your first Ragu circuit, from definition to execution.

## Installation

Add Ragu to your `Cargo.toml`:

```toml
[dependencies]
ragu_pcd = "0.0.0"
ragu_pasta = { version = "0.0.0", features = ["baked"] }
ragu_circuits = "0.0.0"
```

## Using PCD (Proof-Carrying Data)

Ragu provides a PCD framework for composing proofs. The main workflow:

1. Define **Headers** - data types that flow through your proof tree
2. Define **Steps** - computations that transform and combine proofs
3. Build an **Application** - register steps and create/verify proofs

**See working examples:**
- `crates/ragu_pcd/tests/nontrivial.rs` - Merkle-like tree example
- `crates/ragu_pcd/tests/rerandomization.rs` - Proof rerandomization example

### Basic API

```rust
use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;
use ragu_pcd::ApplicationBuilder;

// Build application with concrete parameters
let pasta = Pasta::baked();
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(step1)?
    .register(step2)?
    .finalize(pasta)?;

// Create initial proof (leaf node)
let (proof, aux) = app.seed(&mut rng, step, witness)?;
let pcd = proof.carry(aux);

// Verify proof
assert!(app.verify(&pcd, &mut rng)?);

// Combine proofs (internal node)
let (proof, aux) = app.fuse(&mut rng, step, witness, left_pcd, right_pcd)?;
let pcd = proof.carry::<HeaderType>(aux);

// Verify combined proof
assert!(app.verify(&pcd, &mut rng)?);
```
