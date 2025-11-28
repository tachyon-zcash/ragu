# PCD Examples

Ragu exposes a small, high-level API for building PCD (Proof-Carrying Data) applications.
Two runnable examples demonstrate the typical usage pattern:

## 1. hello_pcd.rs

A minimal example showing:

- Defining header types (LeafNode, InternalNode)
- Implementing PCD steps (CreateLeaf, CombineNodes)
- Creating leaf proofs from witness values
- Merging proofs to build a simple Merkle-like structure
- Verifying intermediate and final proofs

You can run it with:

```bash
cargo run -p ragu_pcd --example hello_pcd
```

## 2. rerandomize_pcd.rs

Shows how to use the built-in rerandomization step:

- Build an initial PCD proof (e.g., from hello_pcd)
- Call `app.rerandomize()` to refresh the proof's randomness
- Verify that the rerandomized proof still validates
- Observe that the header data remains unchanged 

Run it with:

```bash
cargo run -p ragu_pcd --example rerandomize_pcd
```

---

These examples demonstrate the public API surface of `ragu_pcd` and how the building blocks (headers, steps, application builder) fit together.
More detailed documentation will be added as the API stabilizes.
