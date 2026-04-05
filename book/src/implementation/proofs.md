# PCD Step and Proofs

> API reference: see the [`ragu_pcd`](https://tachyon.z.cash/ragu/internal/ragu_pcd/) crate documentation
> for `Application`, `Step`, `Header`, `Proof`, and `Pcd`.

The proof structure in Ragu represents the cryptographic evidence that a
computation was performed correctly. Proofs are _recursive_ and each proof can
verify previous proofs while simultaneously attesting to a new computation.
This enables construction of arbitrarily deep proof trees where each node
carries evidence of its entire computational history.

## Arity-2 PCD

Ragu treats all recursion steps as arity-2 PCD, even when only IVC semantics
are required for a given step (using a dummy second input). This avoids
separate proof structures for IVC and PCD, and the performance cost is
believed to be negligible. IVC emerges as the degenerate case with a dummy
accumulator input, forming a lopsided binary tree.

## The `Pcd` Type

The primary type that applications interact with is `Pcd` (proof-carrying data):

```rust
pub struct Pcd<C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    proof: Proof<C, R>,
    data: H::Data,
}
```

A `Pcd` bundles two components:

* **`proof`**: The cryptographic proof object containing all data necessary
  for verification.
* **`data`**: Application-defined public inputs, with a succinct
  encoded representation as a `Header` representing the current
  state of the computation.

The type parameters configure the proof system:

* **`C: Cycle`**: The elliptic curve cycle used for recursion (e.g., Pasta).
* **`R: Rank`**: The circuit capacity as a power of two (e.g., `R<13>` for
  2^13 constraints).
* **`H: Header`**: The header type providing a succinct encoded representation
  of the proof's public inputs.

## The `Step` Trait

A `Step` defines a single computation in the PCD graph. Every step
takes two child proofs as input (which may be trivial) and produces
a new proof:

```rust
pub trait Step<C: Cycle> {
    const INDEX: Index;

    type Witness<'source>;
    type Aux<'source>;
    type Left: Header;
    type Right: Header;
    type Output: Header;

    // Simplified signature - actual API includes driver and encoder abstractions
    fn witness(&self, dr, left, right) -> Result<(HeaderGadget<Left>, HeaderGadget<Right>, HeaderGadget<Output>), Aux>;
}
```

The associated types define the step's interface:

* **`INDEX`**: Unique identifier for this step within the application.
* **`Witness`**: Private data provided by the prover (not visible to verifiers).
* **`Aux`**: Auxiliary data produced during synthesis, returned alongside the
  output header data. Used for pipelining values to future steps.
* **`Left`, `Right`**: The header types of the two child proofs.
* **`Output`**: The header type of the resulting proof.

### Example: Two-Step Application

Consider a simple application that aggregates values:

```rust
// Step 1: Leaf step - introduces a single value
struct LeafStep { value: u64 }
impl Step<C> for LeafStep {
    type Left = ();           // No left child (trivial)
    type Right = ();          // No right child (trivial)
    type Output = ValueHeader; // Outputs a value commitment
}

// Step 2: DoubleAndAdd step - computes 2*left + right
struct DoubleAndAddStep;
impl Step<C> for DoubleAndAddStep {
    type Left = ValueHeader;   // Left child carries a value
    type Right = ValueHeader;  // Right child carries a value
    type Output = ValueHeader; // Output is 2*left + right
}
```

Leaf steps are used with `seed()` to create base proofs. Combine
steps are used with `fuse()` to merge child proofs, building up the
PCD tree from leaves to root.

## Creating Proofs

The `Application` provides two methods for creating proofs:

### `seed`

Creates a new proof from witness data alone, without requiring child proofs.
This is the entry point for leaf nodes in a PCD tree:

```rust
let (proof, aux) = app.seed(&mut rng, MyLeafStep { ... }, witness)?;
let pcd = proof.carry(aux);
```

Internally, `seed` fuses the step with trivial proofs. Steps used with `seed`
must have `Left = ()` and `Right = ()`.

#### Trivial Proofs

A _trivial proof_ is a dummy proof used to seed the base case of
recursion. It does not encode any real computation; instead, it
provides a well-formed starting proof that allows the recursive
machinery to bootstrap. Internally, trivial proofs use non-degenerate
polynomials and deterministic challenges.

Trivial proofs are not meant to verify independently—they exist
solely to provide valid input structure for `seed()` when no real
child proofs are available.

### `fuse`

Combines two child proofs using a step's logic:

```rust
let (proof, aux) = app.fuse(&mut rng, DoubleAndAddStep, step_witness, left_pcd, right_pcd)?;
let pcd = proof.carry::<OutputHeader>(aux);
```

The `step_witness` parameter provides any additional private data
the step needs (in our `DoubleAndAddStep` example above, this is
just `()` since the step doesn't require extra witness data beyond
the child proofs).

Within the step's `witness` function, calling `.encode()` on the
child encoders commits the child proof data to the witness
polynomials. Verification of these claims is deferred and occurs
when this proof is itself folded into a subsequent step.

## The `carry` Method

The `carry` method converts a raw `Proof` into a `Pcd` by
attaching header data:

```rust
let pcd: Pcd<'_, _, _, MyHeader> = proof.carry(header_data);
```

This separation allows the proving methods to return auxiliary data that
applications use to construct the final header.

## Verification

Proofs are verified using `verify`:

```rust
let valid: bool = app.verify(&pcd, &mut rng)?;
```

Verification confirms the entire recursive proof structure is sound, including
all accumulated claims from previous steps.

## Rerandomization

The `rerandomize` method produces a new proof that
verifies identically but reveals nothing about the original proof's randomness:

```rust
let fresh_pcd = app.rerandomize(pcd, &mut rng)?;
```

This is useful for privacy-preserving applications where proof linkability
must be prevented.

Internally, rerandomization folds the input proof with a _seeded
trivial proof_ using a dedicated rerandomization step. The fresh
randomness from `rng` ensures the output proof is unlinkable to the
original.

## Unified Accumulator Structure

Ragu uses an
_[accumulation scheme](../protocol/core/accumulation/index.md)_
(similar to [Halo]) to achieve efficient recursion. Rather than fully
verifying each child proof inside the circuit,
proofs are _folded_ together deferring expensive verification work while
accumulating claims that will eventually be checked.

The `Proof` type serves as a **unified accumulator** that
carries both:

* The current computation's witness and commitments
* Accumulated claims from all previous proofs in the tree

This design means a single proof structure handles the entire recursive
history, regardless of tree depth. 

[Halo]: https://eprint.iacr.org/2019/1021

## Compressed vs. Uncompressed Proofs

Ragu exposes a single proof structure capable of operating in two modes:

* **Uncompressed mode**: BCLMS21-style split-accumulation form
  that is non-succinct (not sublinear in the circuit size), with a
  large witness but inexpensive to generate.
* **Compressed mode**: A succinct form (logarithmic in the circuit
  size) using an IPA polynomial commitment scheme, with a more
  expensive verifier (outer decision procedure) that's dominated by
  a linear-time MSM.

The recursion operates in uncompressed mode, and then a compression
step is performed at certain boundary conditions for bandwidth
reasons. For instance, in shielded transaction aggregation,
broadcasting transaction data in compressed mode optimizes for
bandwidth. Compressed proofs can be decompressed back to
accumulation form if further folding is needed.

### Uncompressed (Split-Accumulation Form)

* **Size**: Scales with circuit size (non-succinct)
* **Generation**: Fast—just polynomial arithmetic and commitments
* **Use case**: Intermediate computation during recursion
* **Folding**: Efficiently combined using accumulation

This is the natural operating mode during recursive proving. When calling
`seed()` or `fuse()`, the resulting proof is in uncompressed form.

### Compressed (IPA-Based Succinct Form)

* **Size**: Logarithmic in circuit size (succinct)
* **Generation**: Expensive—requires inner product argument (IPA)
* **Use case**: Final proof for transmission/storage
* **Verification**: Dominated by multi-scalar multiplication

Compression is applied at _boundary points_ for example, before broadcasting
a proof onchain where bandwidth matters.

```admonish tip title="When to Compress"
Keep proofs uncompressed during intermediate recursion steps. Only compress
when you need to transmit or store the final result. Compressed proofs can
be decompressed back to accumulation form if further folding is needed.
```

For deeper background, see
[proof-carrying data](../concepts/pcd.md).

## Internal Proof Structure

The `Proof` type contains the cryptographic data required for
verification, organized into components that mirror the protocol's
[staging system](../protocol/extensions/staging.md). Each proof
component captures polynomials and commitments on both the host and
nested curves.
