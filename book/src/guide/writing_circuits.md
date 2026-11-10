# Writing Circuits

This guide explains how PCD applications are structured through Steps - the
fundamental building blocks that combine proofs in Ragu's architecture.

> **Note:** For a complete working example with full code, see
> [Getting Started](getting_started.md). This guide focuses on explaining
> the concepts and design patterns.

## Understanding PCD Steps

A PCD application is built from **Steps** - computations that take proof
inputs and produce new proofs. Unlike traditional circuits that just verify
computation, PCD Steps can:

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

    // Optional: how many values the step stages. Defaults to none.
    const NUM_STAGED: usize = 0;

    // Optional: the output proof's polynomials, committed before
    // the step's challenge is drawn. Defaults to the constant one in every
    // slot.
    fn polynomials<'source>(
        &self,
        witness: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, Self::Left>,
        right: HeaderInput<'_, C::CircuitField, Self::Right>,
    ) -> Result<[Vec<C::CircuitField>; NUM_ONLINE_POLYNOMIALS]>;

    // Optional: the `NUM_STAGED` staged values, committed before the step's
    // challenge is drawn. Defaults to none.
    fn staged<'source>(
        &self,
        witness: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, Self::Left>,
        right: HeaderInput<'_, C::CircuitField, Self::Right>,
    ) -> Result<Vec<C::CircuitField>>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
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
    )>;
}
```

Let's break down what each part means.

## Anatomy of a Step

### 1. Step Index

```rust
const INDEX: Index = Index::new(0);
```

A unique identifier for this step in your application. Each step must have a
distinct index starting from 0.

### 2. Type Parameters

**Witness**: Data provided by the prover (private input)
```rust
type Witness<'source> = FieldElement;  // What the prover knows
```

**Aux**: Auxiliary data returned alongside the output header value (e.g., for pipelining to future steps)
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

### 3. The `witness` Function

This is where the circuit logic is implemented. The function:
1. Receives witness data from the prover
2. Receives left/right header data as `DriverValue`s
3. Receives the step's polynomial oracles (see
   [Polynomial Oracles](#polynomial-oracles)); a step of an application that
   uses no online polynomials ignores them, and any other step pins the
   output slots it leaves as padding (see
   [Padding Slots](#padding-slots))
4. Performs computation (constraints)
5. Returns encoded proofs and auxiliary output

### 4. The `polynomials` and `staged` Functions

Every proof stores `NUM_ONLINE_POLYNOMIALS` (two) online polynomials and their
commitments, associated with its output header. The header's field encoding
is separate; the polynomial count is a parameter of the protocol, not of
the header type. A step that uses these slots implements `polynomials`,
which runs before the step's challenge is drawn and returns the output polynomials'
coefficients, one vector per slot, computed from the witness and from the
inputs' data and polynomials. Ragu commits them, and they travel with the
proof. The default puts the constant one in every slot, which is right for
steps that use no online polynomials; a step that uses one slot returns the
constant one for the other. `polynomials` is prover code, not a constraint:
the circuit must still hold each output slot to what it should contain (see
[Padding Slots](#padding-slots)).

These polynomial commitments are unblinded and deterministic for the
returned coefficients. Their opening points and values are public. Use
`staged` for witness values that should stay out of the public instance;
its stage commitment is blinded, but public openings or header fields can
still reveal the staged values.

`staged` runs beside `polynomials` and returns the `NUM_STAGED` values the
step's checks at $\zeta$ read but no header carries, such as the roots it
multiplies into an accumulator polynomial (see
[Polynomial Oracles](#polynomial-oracles)).

## Two Types of Steps

### Seed Steps (Create Initial Proofs)

Seed steps create the first application proofs in a tree. The caller supplies
no proof inputs; `seed` provides the application's bootstrap proof:

```rust
type Left = ();     // Bootstrap child
type Right = ();    // Bootstrap child
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
1. **Encode inputs** - Convert input proof headers to circuit gadgets via
   `Encoded::new(dr, &mut (), left)?`
2. **Extract data** - Get header values with `.as_gadget()`
3. **Combine** - Hash or process the data together
4. **Encode output** - Package combined result as a new proof

These proofs are created using `app.fuse()`.

## Understanding Encoded::new()

When working with input proofs in a fuse step:

```rust
let left = Encoded::new(dr, &mut (), left)?;
let right = Encoded::new(dr, &mut (), right)?;
```

The `Encoded::new()` call:
- Takes an allocator (here `&mut ()`, the stateless unit allocator)
  that controls wire allocation — see
  [Allocation](primitives/allocation.md)
- Converts the header data into circuit gadgets
- Makes the proof's header data available for use in circuit logic
- Returns an `Encoded` proof that can be passed to the next step

After encoding, extract the actual data with `.as_gadget()`:
```rust
let left_data = left.as_gadget();
let right_data = right.as_gadget();
```

## Polynomial Oracles

A step can relate its input and output proofs' polynomials without putting
their coefficients in the circuit. Each proof has two polynomial slots,
accessed as `Slot::left(i)`, `Slot::right(i)` and `Slot::output(i)`, holding
whatever the producing step committed. What a slot means is
your convention for that header, as the meaning of its fields is: the
circuits of the steps that produce the header constrain it, and Ragu proves
that every opening is of the committed polynomial. The `Oracles` argument
of `witness` lets the circuit open each slot once:

```rust
// A random point squeezed after every slot's polynomial and the staged
// values were committed.
let zeta = oracles.zeta().clone();
// The value of the left input proof's first polynomial at zeta, as a wire.
let l0 = oracles.query(dr, Slot::left(0), &zeta)?;
// The output polynomial at the same point.
let o0 = oracles.query(dr, Slot::output(0), &zeta)?;
// The root this step multiplies in, staged before zeta (see below).
let t = oracles.staged()[0].clone();
// Enforce O0(zeta) = L0(zeta) * (zeta - t), the relation the step proves.
let factor = zeta.sub(dr, &t);
let expected = l0.mul(dr, &factor)?;
o0.enforce_equal(dr, &expected)?;
// A slot may also be opened at any wire, such as a witnessed nullifier.
let membership = oracles.query(dr, Slot::left(1), &nullifier)?;
```

A check at `zeta` is sound when it evaluates a residual polynomial whose
coefficients were fixed before `zeta`, whose degree is bounded, and which is
nonzero whenever the intended identity is false. The challenge and openings at
it may be used to evaluate that residual, but values derived from them are not
fixed coefficients or roots: computing `t = zeta - O0(zeta) / L0(zeta)` in the
circuit is no safer than witnessing it. Input header fields, staged values and
constants are fixed before `zeta`; hash outputs and choices from a small set
each need their own argument. So a step stages such values: it
declares `const NUM_STAGED: usize = 1;` and returns them from `staged`, which
runs beside `polynomials`, before `zeta`:

```rust
fn staged<'source>(
    &self,
    root: &Self::Witness<'source>,
    _: HeaderInput<'_, Fp, Self::Left>,
    _: HeaderInput<'_, Fp, Self::Right>,
) -> Result<Vec<Fp>> {
    Ok(vec![*root])
}
```

Ragu commits the staged values in the proof's application stage before
`zeta` is drawn and hands them to `witness` as wires through
`oracles.staged()`, each bound to the committed value. Every step circuit
of the application reserves room for the largest `NUM_STAGED` any of its
steps declares, `ceil(n / 2)` gates.

The returned wire is a witness: nothing in the circuit checks that it is the
polynomial's value at the point. Ragu's polynomial commitment scheme proves
every opening, in the same batch as the rest of the step's claims, and the
parent step holds the circuit's instance to the openings that were proved. A
slot the circuit does not query is opened at `zeta` to the polynomial's value
there, so every step pays for all six openings whether it uses them or not.

### Padding Slots

Ragu proves that an opening is of the committed polynomial, not which
polynomial was committed. An output slot is held to a polynomial only by the
constraints `witness` places on its openings: a slot the circuit does not
query, or queries without constraining the value, holds whatever the prover
committed, whatever `polynomials` returns. If a header's convention makes a
slot padding, every step that outputs that header must pin it, by opening it
at `zeta` and holding the value to one:

```rust
let zeta = oracles.zeta().clone();
let padding = oracles.query(dr, Slot::output(1), &zeta)?;
padding.enforce_equal(dr, &Element::one())?;
```

Otherwise a prover can commit any polynomial there, and a later step that
opens the slot expecting the constant one, or computes a product with it,
checks a polynomial of the prover's choosing. A step may leave an output
slot unconstrained on purpose, as a hint for the steps that consume it; those
steps must then constrain it themselves. Ragu's own bootstrap and
decompression steps pin both of their output slots, and rerandomization
holds its output slots equal to its input's.

A compressed proof's statement carries a header's fields but not its
polynomials. In a profile that decompresses statements back into proofs, the
decompressed proof has the original header fields and padding in both slots,
and a step consuming it cannot tell it from one a registered step produced.
Under such a profile, a header that can be compressed and decompressed must
treat its slots as padding: no step may open them expecting the polynomials
its fields describe.

## Working with Headers

Headers define what data flows through the proof tree. Each header
implementation specifies a `SUFFIX` (unique identifier), a `Data` type
(the native Rust value), an `Output` type (the circuit gadget
representation), an `encode` function that converts `Data` into
`Output` by allocating circuit elements. The accompanying proof stores
`NUM_ONLINE_POLYNOMIALS` online polynomials and their commitments, exposed by
`UncompressedPcd::polynomials()` and `UncompressedPcd::commitments()` (see
[Polynomial Oracles](#polynomial-oracles)).

For a complete example with multiple header types, see
[Getting Started — Define Header Types](getting_started.md#step-1-define-header-types).
The `allocator` parameter controls how field elements are allocated;
see [Allocation](primitives/allocation.md) for details on choosing an
allocator.

## Common Patterns

### Pattern 1: Seed Steps (Create Initial Proofs)

```rust
type Left = ();     // Bootstrap child
type Right = ();    // Bootstrap child
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
let pasta = ragu_pcd::pasta::baked();
let app = ApplicationBuilder::<Pasta, R<13>, 4>::new()
    .register(CreateLeaf { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .register(CombineNodes { poseidon_params: Pasta::circuit_poseidon(pasta) })?
    .finalize(pasta)?;
```

For details on parameter selection (`Pasta`, `R<13>`, `4`), see
[Configuration](configuration.md).

## Related Topics

- [Getting Started](getting_started.md) provides a complete walkthrough with
  a working Merkle tree example
- [Configuration](configuration.md) explains the ApplicationBuilder
  parameter choices
- [Gadgets](gadgets/index.md) documents the available building block operations
