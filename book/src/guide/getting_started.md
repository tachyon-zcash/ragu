# Getting Started with Ragu

This guide walks you through your first Ragu circuit, from definition to execution.

## Installation

Add Ragu to your `Cargo.toml`:

```toml
[dependencies]
ragu_pcd = "0.0.0"
ragu_pasta = { version = "0.0.0", features = ["baked"] }
```

## Using PCD (Proof-Carrying Data)

Ragu provides a PCD framework for composing proofs. The main workflow:

1. Define **Headers** - data types that flow through your proof tree
2. Define **Steps** - computations that merge proofs
3. Build an **Application** - register steps and create/verify proofs

**See working examples:**
- `crates/ragu_pcd/tests/nontrivial.rs` - Complete Merkle-like tree example
- Tests in `crates/ragu_pcd/tests/` - Various usage patterns

### Basic API

```rust
// Build application
let app = ApplicationBuilder::new()
    .register(step1)?
    .register(step2)?
    .finalize(params)?;

// Create proofs
let proof = app.merge(rng, step, witness, left, right)?;

// Verify proofs
app.verify(&proof, rng)?;
```
