# Simple Gadgets

## [`Element`][element-gadget]

Arguably the simplest gadget is [`Element`][element-gadget], which internally represents a wire along with its known assignment (an arbitrary field element). In fact, it is implemented as follows:

```rust
#[derive(Gadget)]
pub struct Element<'dr, D: Driver<'dr>> {
    #[ragu(wire)]
    wire: D::Wire,

    #[ragu(value)]
    value: DriverValue<D, D::F>,
}
```

`Element`s do not guarantee that any particular constraint has been imposed on the underlying wire. Because wires are the fundamental type of all arithmetic circuit code, `Element`s are the primitive unit type used for serialization using the [`Write`][write-trait] trait.

### Allocated Elements

[`Element::alloc`](ragu_primitives::Element::alloc) can be used to create an `Element` which has an assignment based on witness data. This is a thin wrapper around the underlying [`Driver::alloc`](ragu_core::drivers::Driver::alloc) action.

### Constant Elements

The [`Element::one`](ragu_primitives::Element::one) and [`Element::zero`](ragu_primitives::Element::zero) methods (and [`Element::constant`](ragu_primitives::Element::constant) more generally) can be used to construct `Element`s that represent _constant_ values that cannot vary in their value depending on witness data.

## [`Boolean`][boolean-gadget]

The [`Boolean`][boolean-gadget] gadget provides a way to interact with wires that are constrained to be $0$ or $1$ in the field. The logical `AND` of two booleans can be computed by multiplying two booleans, and given a boolean wire `a` its logical `NOT` can be obtained with the virtual wire `1 - a`. The `Boolean` gadget guards the underlying wire (guaranteeing that it is boolean constrained) and allows it to be manipulated in these ways to produce new `Boolean` values.

`Boolean`s, like `Element`s, can be allocated or constants. However, they do not carry with them any state that would indicate if they are a constant or not. This means that `Boolean` itself cannot be used to optimize away boolean logic between constants, and so a non-[`Gadget`][gadget-trait] abstraction must be built to enable these kinds of optimizations.

## [`FixedVec`][fixedvec-gadget]

The [`Gadget`][gadget-trait] trait does not allow gadgets to represent a dynamic number of wires. The [`FixedVec`][fixedvec-gadget] gadget wraps `Vec<G>` (where `G` is a [`Gadget`][gadget-trait]) using a statically guaranteed length for the underlying vector so that [`Gadget`][gadget-trait] can be implemented.

[gadget-trait]: ragu_core::gadgets::Gadget
[boolean-gadget]: ragu_primitives::Boolean
[element-gadget]: ragu_primitives::Element
[write-trait]: ragu_primitives::io::Write
[fixedvec-gadget]: ragu_primitives::vec::FixedVec