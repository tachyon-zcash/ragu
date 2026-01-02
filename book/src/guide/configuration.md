# Configuration and Setup

When building a PCD application with Ragu, you configure three key parameters that determine the system's capacity and behavior.

## Application Parameters

The `ApplicationBuilder` requires three type parameters:

```rust
ApplicationBuilder::<Pasta, R<13>, 4>::new()
//                  ^^^^^  ^^^^   ^
//                  Cycle  Rank   Header Size
```

Let's understand each one.

## 1. Cycle: Pasta

The **Cycle** parameter specifies the elliptic curve cycle used for recursive proof composition.

```rust
ApplicationBuilder::<Pasta, ...>::new()
//                  ^^^^^ curve cycle
```

### What is Pasta?

Pasta is a 2-cycle of elliptic curves (Pallas and Vesta) specifically designed for efficient recursion:
- **Pallas**: Field elements for the circuit layer
- **Vesta**: Field elements for the proof layer

These curves have matching field/group orders, enabling efficient proof recursion without expensive non-native field arithmetic.

### Setup

Load the Pasta parameters:

```rust
use ragu_pasta::Pasta;

let pasta = Pasta::baked();  // Loads precomputed parameters
```

The `baked()` feature includes:
- Generator points for commitments
- Poseidon hash parameters
- Precomputed constants for efficiency

### Why Pasta?

- **Efficient recursion**: Designed specifically for recursive proof systems
- **No trusted setup**: Transparent parameters
- **Battle-tested**: Used in production by Zcash
- **Standard**: Compatible with Halo 2 and other Pasta-based systems

## 2. Rank: R\<N\>

The **Rank** parameter controls circuit capacity - how many constraints each circuit can handle.

```rust
ApplicationBuilder::<Pasta, R<13>, ...>::new()
//                           ^^^^ rank = 2^13
```

### Understanding Rank

`R<N>` means your circuits can handle up to **2^N constraints**:

| Rank | Constraints | Typical Use Case |
|------|-------------|------------------|
| `R<11>` | 2,048 | Testing, small circuits |
| `R<12>` | 4,096 | Medium circuits |
| `R<13>` | 8,192 | Production (default) |
| `R<14>` | 16,384 | Large circuits |
| `R<15>` | 32,768 | Very large circuits |

### Constraint Types

Circuits have two types of constraints:
- **Multiplication constraints**: Cost ~1 each (finite, limited by rank)
- **Linear constraints**: Nearly free (additions, subtractions)

Common operations and their costs:
```rust
let a = Element::alloc(dr, value)?;        // 0 multiplications
let b = a.add(dr, &c);                     // 0 multiplications
let d = a.mul(dr, &b)?;                    // 1 multiplication
let e = a.invert(dr)?;                     // ~1 multiplication
sponge.absorb(dr, &a)?;                    // ~140 multiplications (Poseidon)
```

### Choosing the Right Rank

**For development/testing**: Start with `R<11>` or `R<12>`
- Faster proving times
- Quicker iteration
- Good for small test cases

**For production**: Use `R<13>` or `R<14>`
- Standard capacity for most applications
- Balances performance and flexibility
- Used in `nontrivial.rs` tests

**For complex circuits**: Use `R<15>` or higher
- Large proof trees
- Complex Step computations
- Multiple Poseidon hashes per step

### What Happens if You Exceed Rank?

```rust
Error: exceeded the maximum number of multiplication constraints (8192)
```

**Solutions**:
1. Increase rank: `R<13>` → `R<14>` (doubles capacity)
2. Optimize circuit: Reduce unnecessary operations
3. Split into multiple steps: Break large computation into smaller pieces

## 3. HEADER_SIZE

The **HEADER_SIZE** parameter specifies how many field elements flow through each proof's header.

```rust
ApplicationBuilder::<Pasta, R<13>, 4>::new()
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
ApplicationBuilder::<Pasta, R<13>, 1>::new()

struct MyHeader;
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>];  // Single field element
}
```

**Merkle root + metadata (4 elements)**:
```rust
ApplicationBuilder::<Pasta, R<13>, 4>::new()

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
ApplicationBuilder::<Pasta, R<13>, 8>::new()

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

**Rule of thumb**: Use the minimum size that fits your data. Don't over-allocate.

### Changing Header Size

If you need to change HEADER_SIZE:

1. Update `ApplicationBuilder` parameter
2. Update all `Header::Output` types to match
3. Rebuild application:
   ```rust
   let app = ApplicationBuilder::<Pasta, R<13>, NEW_SIZE>::new()
   ```

The type system will catch mismatches at compile time.

## Complete Configuration Example

Here's a production-ready configuration:

```rust
use ragu_circuits::polynomials::R;
use ragu_pasta::Pasta;
use ragu_pcd::ApplicationBuilder;

// Initialize Pasta curves
let pasta = Pasta::baked();

// Build application with production parameters
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(step1)?
    .register(step2)?
    .finalize(pasta)?;
```

**Why these parameters?**
- `Pasta`: Standard curve cycle for PCD
- `R<13>`: 8,192 constraints - enough for most steps
- `4`: Four field elements per header - balance between flexibility and performance

## Parameter Selection Guide

### Starting a New Project

1. **Prototype**: `ApplicationBuilder::<Pasta, R<11>, 1>`
   - Quick iterations
   - Minimal overhead
   - Test your logic

2. **Development**: `ApplicationBuilder::<Pasta, R<12>, 2>`
   - Realistic constraints
   - Room to grow
   - Still fast

3. **Production**: `ApplicationBuilder::<Pasta, R<13>, 4>`
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

println!("Multiplications: {}", sim.num_multiplications());
println!("Allocations: {}", sim.num_allocations());
```

If multiplications < 2,048: `R<11>` is enough
If multiplications < 4,096: Use `R<12>`
If multiplications < 8,192: Use `R<13>`
And so on...

## Advanced: Multiple Configurations

You can build different applications with different parameters:

```rust
// Small, fast application for testing
let test_app = ApplicationBuilder::<Pasta, R<10>, 1>::new()
    .register(small_step)?
    .finalize(pasta)?;

// Large, production application
let prod_app = ApplicationBuilder::<Pasta, R<14>, 8>::new()
    .register(complex_step)?
    .finalize(pasta)?;
```

Proofs from different configurations are **not compatible** - they're entirely separate proof systems.

### ✗ Header Size Mismatch

```rust
// Application configured for 4 elements
ApplicationBuilder::<Pasta, R<13>, 4>::new()

// But Header only provides 1!
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>];  // Only 1 element
}
```

**Error**: Type mismatch at compile time.

**Fix**: Match HEADER_SIZE to your header's actual size.

### ✗ Rank Too Small

```rust
ApplicationBuilder::<Pasta, R<10>, 4>::new()  // Only 1024 constraints

// Step uses 2 Poseidon hashes = ~280 constraints
// Plus proof verification overhead = ~1500 total
// Exceeds 1024!
```

**Error**: `MultiplicationBoundExceeded(1024)` at runtime.

**Fix**: Increase rank to `R<11>` or higher.

### ✗ Forgetting to Bake Pasta

```rust
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .finalize(pasta)?;  // But pasta was never initialized!
```

**Error**: Panic or undefined behavior.

**Fix**: Always `let pasta = Pasta::baked();` first.

## Next Steps

- See [Writing Circuits](writing_circuits.md) to build Steps with these parameters
- Read [Getting Started](getting_started.md) for a complete example using these configurations
- Explore [Gadgets](gadgets/index.md) to understand constraint costs

## Summary

| Parameter | Purpose | Typical Value | When to Change |
|-----------|---------|---------------|----------------|
| **Cycle** | Curve cycle | `Pasta` | Almost never |
| **Rank** | Circuit capacity | `R<13>` | Circuit too large/small |
| **HEADER_SIZE** | Header elements | `4` | Data needs change |

Start with `ApplicationBuilder::<Pasta, R<13>, 4>` and adjust based on your measurements!
