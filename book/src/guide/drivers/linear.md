# Linear Expressions

[`enforce_zero()`] and [`add()`] both work with linear combinations of wires.
Drivers define their own [`Wire`] types so they can represent wires efficiently
to suit their execution context. For the same reason, evaluating a linear
combination $c_1 w_1 + c_2 w_2 + \cdots$ can look very different depending on
the driver: one might accumulate a field element, and another might fold each
term's contribution into polynomial coefficients. Circuit code shouldn't have to
build a `Vec<(Coeff, Wire)>` and hand it off, which would force an intermediate
allocation that drivers don't usually need.

The [`LinearExpression`] trait solves this with a builder-pattern API: the
driver supplies an empty expression of its own concrete type, circuit code
chains terms onto it incrementally, and it processes each term on the spot, with
no intermediate collection required.

## The Closure Pattern {#the-closure-pattern}

[`add()`] and [`enforce_zero()`] accept closures so that drivers which don't
track constraints can skip the expression entirely. When a driver does invoke
the closure, it supplies an empty expression of its own concrete type; circuit
code builds on that expression using only the [`LinearExpression`] trait
methods.[^hidden-types]

The central implementation method is [`add_term`], which appends a wire with an
explicit [`Coeff<F>`] coefficient. [`Coeff<F>`] is an enum whose variants let
drivers select cheaper code paths for common coefficient patterns instead of
always performing a full field multiplication. The convenience methods [`add`],
[`sub`], and [`extend`] delegate to [`add_term`] by default.

Here, an `enforce_zero` call constrains the elliptic curve equation $x^3 + b -
y^2 = 0$, where `x3` holds $x^3$ and `y2` holds $y^2$:

```rust,ignore
dr.enforce_zero(|lc| {
    lc.add(x3.wire())
        .add_term(&D::ONE, Coeff::Arbitrary(C::b()))
        .sub(y2.wire())
})?;
```

## Virtual Wires {#virtual-wires}

Unlike [`enforce_zero()`], the [`add()`] method does not create a constraint. It
returns a **virtual wire** representing the linear combination described by the
closure. Because the combination is substituted inline wherever the wire appears
in later constraints, virtual wires are free: they do not add gates to the
circuit.

This matters for gadgets like [`Point`]. During point addition, the result
coordinates are linear combinations involving the input coordinates alongside
intermediate values, and each arithmetic step adds more terms. Without virtual
wires, [`Point`] would have to carry those growing expressions explicitly; a
scalar multiplication would make this unmanageable.

Virtual wires solve this by offloading the bookkeeping to the driver. Each call
to [`add()`] offers the driver a linear combination and receives an opaque wire
in return. A constraint-tracking driver records the combination and resolves it
when the wire appears in later constraints; other drivers can return a wire
backed by the evaluated field element alone.

## Gain

Many algorithms that build a linear expression need to scale terms by a running
factor. The traditional approach stores terms in a sum and distributes the
factor by scaling the accumulated result in each step. For some drivers, scaling
the result means revisiting every previous term, so not all can do this
efficiently.

The **gain** mechanism factors this scaling out, applying it to each *new* term
rather than the accumulated sum. Every linear expression carries a gain scalar,
initialized to $1$. Each [`add_term`] call scales the new term by the current
gain, so a term worth $v$ contributes $g \cdot v$ instead. Earlier terms are
unaffected. The [`gain`] method scales the current gain by a given [`Coeff<F>`].

Gain reverses the usual processing direction: accumulator-style algorithms like
Horner's method work from high to low, but gain-based algorithms work from low
to high. Every algorithm of the first kind has an efficient counterpart of the
second, though the gain direction can feel unfamiliar at first.

One example is binary decomposition. The [`multipack`] routine packs a slice of
[`Boolean`] wires into field elements by adding each bit and doubling the gain
after every step. Starting from gain $1$, the first bit contributes $b_0$, the
second $2 b_1$, the third $4 b_2$, and so on, producing
$b_0 + 2 b_1 + 4 b_2 + \cdots$ naturally.

[^hidden-types]: Because closures carry concrete parameter types, the driver
    cannot hide its expression type: Rust requires it to appear in the trait
    hierarchy (as the [`LCadd`] and [`LCenforce`] associated types), even though
    circuit code never refers to them by name.

[`LinearExpression`]: ragu_core::drivers::linexp::LinearExpression
[`add`]: ragu_core::drivers::linexp::LinearExpression::add
[`sub`]: ragu_core::drivers::linexp::LinearExpression::sub
[`add_term`]: ragu_core::drivers::linexp::LinearExpression::add_term
[`extend`]: ragu_core::drivers::linexp::LinearExpression::extend
[`gain`]: ragu_core::drivers::linexp::LinearExpression::gain
[`Coeff<F>`]: ragu_arithmetic::Coeff
[`LCadd`]: ragu_core::drivers::DriverTypes::LCadd
[`LCenforce`]: ragu_core::drivers::DriverTypes::LCenforce
[`Wire`]: ragu_core::drivers::Driver::Wire
[`add()`]: ragu_core::drivers::Driver::add
[`enforce_zero()`]: ragu_core::drivers::Driver::enforce_zero
[`multipack`]: ragu_primitives::boolean::multipack
[`Boolean`]: ragu_primitives::boolean::Boolean
[`Point`]: ragu_primitives::point::Point
