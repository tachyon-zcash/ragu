# Configuration

When building a PCD application with Ragu, you configure three key parameters
that determine the system's capacity and behavior.

## Application Parameters

The `ApplicationBuilder` requires three type parameters:

```rust
ApplicationBuilder::<Pasta, R<14>, 4>::new()
//                  ^^^^^  ^^^^   ^
//                  Cycle  Rank   Header Size
```

Let's understand each one.

## 1. Cycle: Pasta

The **Cycle** parameter specifies the elliptic curve cycle used for recursive
proof composition.

```rust
ApplicationBuilder::<Pasta, ...>::new()
//                  ^^^^^ curve cycle
```

### What is Pasta?

Pasta is a 2-cycle of elliptic curves (Pallas and Vesta) specifically
designed for efficient recursion:
- **Pallas**: base field (`Fp`) used in the circuit layer
- **Vesta**: base field (`Fq`) used in the proof layer

These curves have matching field/group orders, enabling efficient proof
recursion without expensive non-native field arithmetic.

### Setup

Load the Pasta parameters:

```rust
use ragu_core::pasta::Pasta;

let pasta = ragu_pcd::pasta::baked();  // Requires the `baked` crate feature
```

The `ragu_pcd/baked` feature supports both `std` and `no_std` applications
and enables `alloc`.

The `baked()` function returns precomputed generator points for Pallas and
Vesta, loaded from data embedded in the binary. Poseidon parameters are
compile-time constants and do not require initialization.

### Why Pasta?

- **Efficient recursion**: Designed specifically for recursive proof systems
- **No trusted setup**: Transparent parameters
- **Battle-tested**: Used in production by Zcash
- **Standard**: Compatible with Halo 2 and other Pasta-based systems

## 2. Rank: `R<N>`

The **Rank** parameter controls circuit capacity - how many constraints each
circuit can handle.

```rust
ApplicationBuilder::<Pasta, R<14>, ...>::new()
//                           ^^^^ rank = 2^14
```

### Understanding Rank

`R<N>` sets the polynomial size to 2^N coefficients, which determines two
constraint limits:

- **Gates**: up to 2^(N−2)
- **Constraints**: up to 2^N

Currently only `R<7>` (testing) and `R<14>` (production) are implemented.
See the `Rank` trait documentation for how to add new values.

| Rank | Gate Limit | Constraint Limit | Use Case |
|------|---------------------|-------------|----------|
| `R<7>` | 32 | 128 | Unit tests |
| `R<14>` | 4,096 | 16,384 | Production |

### Choosing the Right Rank

**For testing**: Use `R<7>`
- Fast proving, quick iteration
- Suitable for small test circuits

**For production**: Use `R<14>`
- 4,096 gates, 16,384 constraints
- Standard capacity for most applications

### What Happens if You Exceed Rank?

```rust
Error: exceeded the maximum number of gates (4096)
```

**Solutions**:
1. Add a larger rank (see the `Rank` trait documentation) and switch to it
2. Optimize circuit: Reduce unnecessary operations
3. Split into multiple steps: Break large computation into smaller pieces

[Step Capacity and Proving Cost](capacity.md) measures what each of these costs,
including how much a step holds and what splitting one is worth.

## 3. HEADER_SIZE

The **HEADER_SIZE** parameter specifies how many field elements flow through
each proof's header.

```rust
ApplicationBuilder::<Pasta, R<14>, 4>::new()
//                                  ^ header size
```

### What are Headers?

Headers are the data that flows through your proof tree. Each proof carries:
- **Left child's header** (HEADER_SIZE elements)
- **Right child's header** (HEADER_SIZE elements)
- **Own output header** (HEADER_SIZE elements)

### Sizing Your Headers

The size depends on what data you need to track:

**Simple hash (1 element)**:
```rust
ApplicationBuilder::<Pasta, R<14>, 1>::new()

struct MyHeader;
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>];  // Single field element
}
```

**Merkle root + metadata (4 elements)**:
```rust
ApplicationBuilder::<Pasta, R<14>, 4>::new()

struct MyHeader;
impl Header<F> for MyHeader {
    type Output = Kind![F; (
        Element<'_, _>,  // Merkle root
        Element<'_, _>,  // Block height
        Element<'_, _>,  // Timestamp
        Element<'_, _>,  // State hash
    )];
}
```

**Complex state (8+ elements)**:
```rust
ApplicationBuilder::<Pasta, R<14>, 8>::new()

// Multiple values, counters, flags, etc.
```

### Header Size Trade-offs

**Smaller headers (1-2 elements)**:
- ✓ Faster proving
- ✓ Less memory usage
- ✗ Limited data per proof

**Larger headers (4-8 elements)**:
- ✓ More data per proof
- ✓ Rich application state
- ✗ Slower proving
- ✗ More memory

**Rule of thumb**: Use the minimum size that fits your data. Don't
over-allocate.

### Changing Header Size

If you need to change HEADER_SIZE:

1. Update `ApplicationBuilder` parameter
2. Update all `Header::Output` types to match
3. Rebuild application:
   ```rust
   let app = ApplicationBuilder::<Pasta, R<14>, NEW_SIZE>::new()
   ```

The type system will catch mismatches at compile time.

## Complete Configuration Example

Here's a production-ready configuration:

```rust
use ragu_circuits::{polynomials::R, registry::Tag};
use ragu_core::pasta::Pasta;
use ragu_pcd::{ApplicationBuilder, RegistryTags};

// Initialize Pasta curves
let pasta = ragu_pcd::pasta::baked();

// Pin the final field elements supplied by your setup procedure.
let tags = RegistryTags::<Pasta> {
    native: Tag::new(native_kappa), // Fp
    nested: Tag::new(nested_kappa), // Fq
};

// Build application with production parameters
let app = ApplicationBuilder::<Pasta, R<14>, 4>::new()
    .register(step1)?
    .register(step2)?
    .with_registry_tags(tags)
    .finalize(pasta)?;
```

**Why these parameters?**
- `Pasta`: Standard curve cycle for PCD
- `R<14>`: 4,096 gates — enough for most steps
- `4`: Four field elements per header - balance between flexibility and
  performance

## Registry Tags

**Temporary stopgap:** caller-supplied registry tags replace the evaluation-based
derivation for the registry-collision issue
[#78](https://github.com/tachyon-zcash/ragu/issues/78). This setup parameter is
intended to be removed once the workaround is no longer needed. Consumers
choose the procedure that supplies the $\kappa$ values, subject to the sampling
requirement below. The Bitcoin/OpenTimestamps example in `qa/ceremony`
exercises this temporary mechanism; it does not define a production ceremony
protocol for Ragu.

`with_registry_tags` supplies the application's registry tags: one field element
per registry, injected into every circuit's wiring polynomial. They exist so
that whoever controls the circuit definitions cannot adapt them to
Fiat-Shamir challenges that have already been derived.

Production callers can supply the final $\kappa$ values directly, as above.
The native and nested tags use distinct registry labels and fields, so both
values are needed, passed together as one `RegistryTags` argument. The builder
stores them and `finalize` installs them without hashing them again.

`finalize` requires these tags and returns an initialization error if they
are missing.

For tests, benchmarks, and fuzzing, `ragu_circuits` provides the explicitly
named `insecure-test-registry-tag` feature. It uses a fixed test key when
no tag is supplied. `ragu_testing` enables this feature for the repository's
test fixtures, so existing test callers can keep using `finalize` directly.
**Production consumers must supply their own tags and must not enable this
feature or depend on `ragu_testing`.** Cargo features are additive, including
features enabled by dependencies and `--all-features`.

The registry tag ($\kappa$) must be sampled independently and without bias
after the complete pre-keyed system description has been fixed and publicly
committed, then permanently bound to that description.

Sampling is over the whole field, so zero is intentionally accepted. Under
independent uniform sampling, the probability that either Pasta registry tag
is zero is at most $1/|\mathbb{F}_p| + 1/|\mathbb{F}_q|$. Soundness arguments
that require nonzero tags must include this setup error.

The description covers the complete setup of both native and nested registries:
the code and dependencies, ordered circuit manifests (including internal
circuits), fields and domains, ranks and capacities, transcript rules and
domain-separation tags, features and configuration, and all public parameters.
Values fixed unambiguously by the committed code need not be repeated; every
remaining setup choice must be committed explicitly. Changing the description
requires a new set of tags.

`RegistryTags::from_beacon` is an optional helper that derives both tags from
caller-supplied beacon bytes and `manifest_digest`. It hashes each registry's
label, the manifest digest, and the beacon output together with length prefixes.
Consumers can instead supply the final field elements directly through
`with_registry_tags`. When using the helper, a canonical, versioned manifest
records the complete description. Hash the manifest and the actual contents of
referenced artifacts with SHA-256 or an equivalent collision-resistant hash;
a Git commit ID alone does not provide that content binding.

The consumer is responsible for the sampling requirement and for checking
that the committed description matches the setup. Ragu does not perform
ceremony verification. The `Tag::from_beacon` documentation states the
helper's input contract in full.

### Ceremony

`qa/ceremony/README.md` contains the QA example, its manifest format, and the
Bitcoin/[OpenTimestamps](https://opentimestamps.org) steps used to exercise it.
Its provider and block-selection choices belong to that example. A future
Bitcoin block provides unpredictability after commitment, not unbiasability;
this assumes miners do not selectively withhold blocks or reorganize the
chain to bias the tags.

## Parameter Selection Guide

### Starting a New Project

1. **Testing**: `ApplicationBuilder::<Pasta, R<7>, 1>`
   - Quick iterations
   - Minimal overhead
   - Test your logic

2. **Production**: `ApplicationBuilder::<Pasta, R<14>, 4>`
   - Standard capacity
   - Proven parameters
   - Well-tested

### Measuring Your Needs

Use `Simulator` to measure constraint usage:

```rust
use ragu_primitives::Simulator;

let sim = Simulator::simulate(witness, |dr, w| {
    my_step_logic(dr, w)?;
    Ok(())
})?;

println!("Gates: {}", sim.num_gates());
```

For `R<7>`, the gate limit is 32.
For `R<14>`, the gate limit is 4,096.
If your circuit exceeds these, add a larger rank (see the `Rank` trait
documentation).

## Advanced: Multiple Configurations

You can build different applications with different parameters:

```rust
// Small, fast application for testing
let test_app = ApplicationBuilder::<Pasta, TestRank, 1>::new()
    .register(small_step)?
    .finalize(pasta)?;

// Production application, with tags drawn for exactly this set of steps
let prod_app = ApplicationBuilder::<Pasta, ProductionRank, 8>::new()
    .register(complex_step)?
    .with_registry_tags(prod_tags)
    .finalize(pasta)?;
```

Proofs from different configurations are **not compatible** - they're
entirely separate proof systems.

### ✗ Header Size Mismatch

```rust
// Application configured for 4 elements
ApplicationBuilder::<Pasta, R<14>, 4>::new()

// But Header only provides 1!
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>];  // Only 1 element
}
```

**Error**: Type mismatch at compile time.

**Fix**: Match HEADER_SIZE to your header's actual size.

### ✗ Rank Too Small

```rust
ApplicationBuilder::<Pasta, R<7>, 4>::new()  // Only 32 gates

// Step uses 2 Poseidon hashes = ~280 constraints
// Plus proof verification overhead = ~1500 total
// Exceeds 32!
```

**Error**: `GateBoundExceeded(32)` at runtime.

**Fix**: Switch to `R<14>` or add a larger rank.

### ✗ Missing the `baked` Feature

```toml
[dependencies]
ragu_pcd = "0.1"  # Missing features = ["baked"]
```

**Error**: Compile error — `ragu_pcd::pasta::baked()` does not exist without the feature.

**Fix**: Add `features = ["baked"]` to the `ragu_pcd` dependency. The feature
also enables `alloc`.

## Next Steps

- See [Writing Circuits](writing_circuits.md) to build Steps with these
  parameters
- Read [Getting Started](getting_started.md) for a complete example using
  these configurations
- Explore [Gadgets](gadgets/index.md) to understand constraint costs

## Summary

| Parameter | Purpose | Typical Value | When to Change |
|-----------|---------|---------------|----------------|
| **Cycle** | Curve cycle | `Pasta` | Almost never |
| **Rank** | Circuit capacity | `R<14>` | Circuit too large/small |
| **HEADER_SIZE** | Header elements | `4` | Data needs change |

Start with `ApplicationBuilder::<Pasta, R<14>, 4>` and adjust based on your
measurements!
