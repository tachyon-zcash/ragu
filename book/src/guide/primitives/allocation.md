# Allocation

All wires are created in groups whenever new gates are created via
[`mul()`] (or, more generally, with [`gate()`]). In some rare cases,
gadgets need _standalone_ wires that cannot be represented as linear
combinations of wires they have access to. The [`Allocator`] trait
generalizes over (possibly stateful) strategies for assigning
arbitrary data to free wires.

## The [`Allocator`] Trait {#allocator-trait}

```rust
pub trait Allocator<'dr, D: Driver<'dr>> {
    fn alloc(
        &mut self,
        dr: &mut D,
        value: impl Fn() -> Result<Coeff<D::F>>,
    ) -> Result<D::Wire>;
}
```

`Allocator::alloc` takes a mutable reference to the driver and a
witness-producing closure, and returns a single wire. The closure
follows the same purity contract as [`Driver::mul`]: it may be
called zero or more times and must be side-effect-free.
`Driver::mul` produces three wires from a multiplication
relationship; `alloc` produces one wire carrying an arbitrary value.

Gadgets that need standalone wires should prefer to accept a generic
`&mut A` where `A: Allocator`, though it is not always necessary
when threading an allocator through the call site is difficult. For
example, [`Element::alloc`] delegates to whichever allocator the
caller provides:

```rust
let x = Element::alloc(dr, &mut allocator, witness)?;
```

This allows the caller to determine the optimal allocation strategy
for gadgets that do not otherwise care or lack the context to make
the best decision themselves.

## The Unit Allocator {#unit-allocator}

The simplest allocator is `()`. Each call invokes [`mul()`] with
$B = C = 0$ and returns the $A$ wire:

```rust
impl<'dr, D: Driver<'dr>> Allocator<'dr, D> for () {
    fn alloc(
        &mut self,
        dr: &mut D,
        value: impl Fn() -> Result<Coeff<D::F>>,
    ) -> Result<D::Wire> {
        let (a, _, _) = dr.mul(
            || Ok((value()?, Coeff::Zero, Coeff::Zero)),
        )?;
        Ok(a)
    }
}
```

In exchange for being stateless, this allocator creates a gate for
every free wire, which is not optimal.

## [`Standard`] {#standard}

Theoretically, an allocator could offer two wires per gate by
distributing the $A$ and $B$ wires of each [`mul()`], allowing $C$
to be a meaningless product that is discarded. This is slightly
suboptimal because the trace contains the useless discarded product
and is more expensive to manipulate. Instead, the more general
[`gate()`] (which creates four wires) can be used, where the $A$
and $D$ wires are distributed and the $B$ and $C$ wires are
assigned to zero.

[`Standard`] exploits this by creating gates, assigning the $A$
wire, and then stashing the $D$ wire's token for future allocation
with the [driver's assistance][assign-extra]. In exchange for being
stateful, it is less wasteful.

```rust
let allocator = &mut Standard::new();
let a = Element::alloc(dr, allocator, witness_a)?;
let b = Element::alloc(dr, allocator, witness_b)?;
// Both a and b share one gate.
```

### Donated Tokens {#donated-tokens}

Some gadgets allocate a gate whose $D$ wire is unconstrained because
$C$ is constrained to be zero. Rather than waste that wire, they
can _donate_ the `Extra` token to the allocator. [`Standard`]
collects these donated tokens and hands them out on future `alloc`
calls before falling back to new gates.

As an example, [`Boolean::alloc`] constrains $a \cdot (1 - a) = 0$
which produces a gate where $C$ is constrained to zero, leaving $D$
unconstrained. `Boolean::alloc` donates that spare `Extra` token
back to the allocator:

```rust
let (a, b, c, extra) = dr.gate(|| /* ... */)?;
dr.enforce_zero(|lc| lc.add(&c)); // c = 0

// The gate's spare D wire is donated to the allocator.
allocator.donate(extra);
```

Subsequent allocations redeem these donated tokens at zero gate
cost:

```rust
let allocator = &mut Standard::new();
let flag = Boolean::alloc(dr, allocator, bit)?;   // 1 gate
let x = Element::alloc(dr, allocator, witness)?;  // 0 gates
```

## Choosing an Allocator {#choosing}

The choice of allocator is both a decision a gadget makes (if it
asks to receive one from the caller) and one the circuit developer
makes (if asked to provide one). The trade-offs depend on context,
but a rough guide:

| Situation | Allocator |
|-----------|-----------|
| Two or more allocations, or donating gadgets | [`Standard`] |
| Single isolated allocation | `()` |

### Allocators and Routines {#routines}

An allocator does not cross a [routine](../routines.md) boundary. The
constraints of a routine depend only on its type and the type of its input
gadget. A caller's allocator would make them depend on the allocator's pool
too, and tokens donated inside the routine would let the caller assign wires
of the routine's gates. A routine therefore creates its own allocator, and
the tokens donated inside the routine stay there.

For example, [`EndoscalarChallenge::from_element`] decomposes its element
in a routine and takes no allocator. The routine allocates the bits with
`()`, because nothing in it redeems their donated tokens.

## Cost Accounting {#cost-accounting}

The [`Simulator`] makes allocation costs visible. Compare two unit
allocations against one paired allocation:

```rust
// Two unit allocations: 2 gates
let sim = Simulator::simulate((a, b), |dr, witness| {
    let (a, b) = witness.cast();
    let _ = Element::alloc(dr, &mut (), a)?;
    let _ = Element::alloc(dr, &mut (), b)?;
    Ok(())
})?;
assert_eq!(sim.num_gates(), 2);

// Two paired allocations: 1 gate
let sim = Simulator::simulate((a, b), |dr, witness| {
    let (a, b) = witness.cast();
    let alloc = &mut Standard::new();
    let _ = Element::alloc(dr, alloc, a)?;
    let _ = Element::alloc(dr, alloc, b)?;
    Ok(())
})?;
assert_eq!(sim.num_gates(), 1);
```

In larger circuits, allocation costs compound quickly. Running the
[`Simulator`] before committing to a rank is the easiest way to
catch unnecessary gate overhead early.

[`gate()`]: ragu_core::drivers::DriverTypes::gate
[`mul()`]: ragu_core::drivers::Driver::mul
[`Allocator`]: ragu_primitives::allocator::Allocator
[`Element::alloc`]: ragu_primitives::Element::alloc
[`Driver::mul`]: ragu_core::drivers::Driver::mul
[`Standard`]: ragu_primitives::allocator::Standard
[assign-extra]: ragu_core::drivers::DriverTypes::assign_extra
[`Boolean::alloc`]: ragu_primitives::Boolean::alloc
[`EndoscalarChallenge::from_element`]: ragu_primitives::EndoscalarChallenge::from_element
[`Simulator`]: ragu_primitives::Simulator
