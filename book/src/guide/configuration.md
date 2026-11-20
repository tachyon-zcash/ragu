# Configuration

When building a PCD application with Ragu, you configure three key parameters
that determine the system's capacity and behavior.

## Application Parameters

The `ApplicationBuilder` requires a cycle, a rank, and a header size. An
optional fourth parameter selects the backend and defaults to
`ragu_backend::ReferenceBackend`:

```rust
ApplicationBuilder::<Pasta, R<13>, 4>::new()
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

Standard uses the original tables of $2^{13}$ vector generators per curve.
For the Aggregator profile, which the `unstable-aggregator` feature exposes,
`baked-aggregator` adds separate $2^{15}$ tables through
`ragu_pcd::pasta::baked_aggregator()`, sized for the aggregator rank.
The regular `baked()` tables remain the same size even when that feature is
enabled; the larger tables are initialized only when their loader is called.

### Why Pasta?

- **Efficient recursion**: Designed specifically for recursive proof systems
- **No trusted setup**: Transparent parameters
- **Battle-tested**: Used in production by Zcash
- **Standard**: Compatible with Halo 2 and other Pasta-based systems

## 2. Rank: `R<N>`

The **Rank** parameter controls circuit capacity - how many constraints each
circuit can handle.

```rust
ApplicationBuilder::<Pasta, R<13>, ...>::new()
//                           ^^^^ rank = 2^13
```

### Understanding Rank

`R<N>` sets the polynomial size to 2^N coefficients, which determines two
constraint limits:

- **Gates**: up to 2^(N−2)
- **Constraints**: up to 2^N

Currently `R<7>`, `R<13>`, `R<14>` and `R<15>` are implemented. Three of them
have aliases: `TestRank`, `WalletRank` and `AggregatorRank`. See the `Rank`
trait documentation for how to add new values.

| Rank | Gate Limit | Constraint Limit | Use Case |
|------|---------------------|-------------|----------|
| `R<7>` (`TestRank`) | 32 | 128 | Unit tests |
| `R<13>` (`WalletRank`) | 2,048 | 8,192 | Production |
| `R<14>` | 4,096 | 16,384 | Tests of circuits that exceed `R<13>` |
| `R<15>` (`AggregatorRank`) | 8,192 | 32,768 | The Aggregator profile |

### Choosing the Right Rank

**For testing**: Use `R<7>`
- Fast proving, quick iteration
- Suitable for small test circuits

**For production**: Use `R<13>`
- 2,048 gates, 8,192 constraints
- Standard capacity for most applications

### What Happens if You Exceed Rank?

```rust
Error: exceeded the maximum number of gates (2048)
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
ApplicationBuilder::<Pasta, R<13>, 4>::new()
//                                  ^ header size
```

### What are Headers?

Headers are the data that flows through your proof tree. Each proof carries:
- **Left child's header** (HEADER_SIZE elements)
- **Right child's header** (HEADER_SIZE elements)
- **Own output header** (HEADER_SIZE elements)

### Sizing Your Headers

The last of the HEADER_SIZE elements is the header type's suffix, so the
encoding that a header's `Output` writes can hold at most HEADER_SIZE − 1
elements. A shorter encoding is padded with zeros up to the suffix. A longer
one is rejected when the header is encoded, with
`Error::MalformedEncoding`.

The size depends on what data you need to track:

**Simple hash (1 element, plus the suffix)**:
```rust
ApplicationBuilder::<Pasta, R<13>, 2>::new()

struct MyHeader;
impl Header<F> for MyHeader {
    type Output = Kind![F; Element<'_, _>];  // Single field element
}
```

**Merkle root + metadata (4 elements, plus the suffix)**:
```rust
ApplicationBuilder::<Pasta, R<13>, 5>::new()

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

**Complex state (8+ elements, plus the suffix)**:
```rust
ApplicationBuilder::<Pasta, R<13>, 9>::new()

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

**Upper bound**: for the Standard profile at the wallet rank `R<13>`,
the largest header size is 201 elements. Ragu's challenge binder circuits
load the headers of both children and the step's own beside the online
openings, and at 201 the largest binder uses all 2048 gates. A larger header fails `finalize` with
`Error: exceeded the maximum number of gates (2048)`.
Profiles with extensions can have a lower limit because their additional
claims and commitments also consume gates. Check capacity with `finalize`
for the selected profile and registered application.

### Changing Header Size

If you need to change HEADER_SIZE:

1. Update `ApplicationBuilder` parameter
2. Check that every `Header::Output` type still writes at most
   `NEW_SIZE - 1` elements
3. Rebuild application:
   ```rust
   let app = ApplicationBuilder::<Pasta, R<13>, NEW_SIZE>::new()
   ```

The compiler does not check a header's size against HEADER_SIZE. An encoding
that is too long fails at runtime, when the header is encoded.

## Complete Configuration Example

Here's a production-ready configuration:

```rust
use ragu_circuits::polynomials::R;
use ragu_core::pasta::Pasta;
use ragu_pcd::ApplicationBuilder;

// Initialize Pasta curves
let pasta = ragu_pcd::pasta::baked();

// Build application with production parameters
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(step1)?
    .register(step2)?
    .finalize(pasta)?;
```

**Why these parameters?**
- `Pasta`: Standard curve cycle for PCD
- `R<13>`: 2,048 gates — enough for most steps
- `4`: Four field elements per header, three of data and the suffix - balance
  between flexibility and performance

## Registry Tags

Each of the application's two registries carries a registry tag $\kappa$: one
field element, injected into every circuit's wiring polynomial at a reserved
position. The tag exists so that whoever controls the circuit definitions
cannot adapt them to Fiat-Shamir challenges that have already been derived; the
[wiring chapter](../protocol/construction/wiring.md#system-gate) shows where it
sits, and the `Tag` documentation in `ragu_circuits::registry` gives the
argument.

`finalize` derives both tags from the registered circuits. Each wiring
polynomial $s_i(X, Y)$ is written down as the list of its nonzero monomials
$c \cdot X^e Y^q$ in canonical order, and the lists are hashed, in registration
order, with the field's modulus, the rank and the number of circuits, into a
BLAKE2b digest that is reduced to a field element. Two registries with the
same tag hashed the same polynomials, unless their reduced digests collide.
Any application built from the same steps, in the same order, with the same
profile, rank, header size and parameters, derives the same tags, and any
change to a circuit's wiring polynomial changes them. Tests that need two
applications with identical circuits but different tags, or different circuits
with identical ones, override the derived tags through a `test-utils` seam.

The tag guards against circuits that read as honest but were chosen after
challenges were derived. It does not make circuit code untrusted: the steps an
application registers define what its verifier accepts. In particular, the tag
hashes the wiring polynomial produced by one driver walk of each circuit, while
the prover and verifier evaluate that polynomial through separate walks with
their own drivers. The tag therefore relies on circuit code emitting the same
constraints on every walk, as the
[determinism rule](../implementation/circuit-code-documentation.md#determinism)
requires.

## Parameter Selection Guide

### Starting a New Project

1. **Testing**: `ApplicationBuilder::<Pasta, R<7>, 1>`
   - Quick iterations
   - Minimal overhead
   - Test your logic

2. **Production**: `ApplicationBuilder::<Pasta, R<13>, 4>`
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
For `R<13>`, the gate limit is 2,048.
If your circuit exceeds these, add a larger rank (see the `Rank` trait
documentation).

## Advanced: Multiple Configurations

You can build different applications with different parameters:

```rust
// Small, fast application for testing
let test_app = ApplicationBuilder::<Pasta, TestRank, 1>::new()
    .register(small_step)?
    .finalize(pasta)?;

// Production application
let prod_app = ApplicationBuilder::<Pasta, WalletRank, 8>::new()
    .register(complex_step)?
    .finalize(pasta)?;
```

Proofs from different configurations are **not compatible** - they're
entirely separate proof systems.

### ✗ Header Too Large

```rust
// Application configured for 4 elements: 3 of data and the suffix
ApplicationBuilder::<Pasta, R<13>, 4>::new()

// But the header writes 4!
impl Header<F> for MyHeader {
    type Output = Kind![F; (
        Element<'_, _>,
        Element<'_, _>,
        Element<'_, _>,
        Element<'_, _>,
    )];
}
```

**Error**: `MalformedEncoding` at runtime, when the header is encoded.

**Fix**: Raise HEADER_SIZE to at least one more than the number of elements
that your largest header writes. A header that writes fewer is padded with
zeros.

### ✗ Rank Too Small

```rust
ApplicationBuilder::<Pasta, R<7>, 4>::new()  // Only 32 gates

// Step uses 2 Poseidon hashes = ~280 constraints
// Plus proof verification overhead = ~1500 total
// Exceeds 32!
```

**Error**: `GateBoundExceeded { limit: 32 }` at runtime.

**Fix**: Switch to `R<13>` or add a larger rank.

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
| **Rank** | Circuit capacity | `R<13>` | Circuit too large/small |
| **HEADER_SIZE** | Header elements | `4` | Data needs change |

Start with `ApplicationBuilder::<Pasta, R<13>, 4>` and adjust based on your
measurements!
