# Drivers

Ragu requires the same algorithms to execute both natively—where only the
computation’s result matters—and as arithmetic circuits describing the same
computation. The protocol’s non-uniform design amplifies this: there is no
one-time preprocessing step, so circuit code is frequently evaluated in
additional settings for algebraic or structural manipulation, where only a
subset of the usual synthesis machinery is needed. Maintaining separate
implementations across these contexts would quickly become untenable.

The **[`Driver`]** trait eliminates this duplication: we write circuit code
once, generic over a driver, and concrete drivers specialize their
interpretation for each context. In particular, drivers can choose wire
representations and gate expensive work (such as witness assignment) so contexts
don’t pay for unneeded capabilities, often through compile-time specialization.

## The [`Driver`] Trait {#driver-trait}

Circuit code is written generically over a type `D: Driver<'dr>`, receiving the
driver as a mutable reference `dr: &mut D`. The driver is stateful: as circuit
code calls its methods, it accumulates wires, constraints, and internal
bookkeeping. The mutable reference is the sole interface between circuit code
and the synthesis context it runs in.

The driver exposes three core operations:

* [`mul()`]: returns wires $(a, b, c)$ with the initial constraint $a \cdot b =
      c$, simultaneously assigning their values. The caller provides a closure
      that returns the three assignments; it is evaluated only in contexts where
      [witness data](witness.md) is needed.
* [`enforce_zero()`]: enforces that a linear combination of previously created
      wires equals zero. This operation takes a closure that is only executed
      when the driver needs to know about the constraint system. The closure is
      used to [build the linear combination](linear.md#the-closure-pattern) in a
      way that suits the driver's needs and optimization opportunities.
* [`add()`]: returns a new _virtual_ wire representing a linear combination of
      previously created wires. See [Virtual Wires](linear.md#virtual-wires) for
      more on how this works and why it matters.

There are also some helpful utilities made available by all drivers. The
associated [`ONE`] constant is a wire that is fixed to the value $1$, and is
available everywhere. The [`constant()`] method is a simple helper that returns
a virtual wire assigned to a constant, which is free because it is a virtual
wire that scales [`ONE`].

### Allocation

Sometimes only a single wire is needed, but [`mul()`] always allocates three. To
support single-wire allocation, drivers provide an additional [`alloc()`] method
that allocates and assigns one wire.

By default, `alloc` calls `mul`, returns the $a$ wire, and sets the
corresponding $b$ and $c$ wires to zero to satisfy the multiplication
constraint—wasting $b$ and $c$. Drivers may override `alloc` to avoid this
overhead. For example, synthesis drivers return the $a$ wire from a `mul`
operation, stash the associated $b$ wire for the next `alloc` call, and fill in
$c$ later to satisfy the constraint.

### The `'dr` Lifetime

Drivers are parameterized by a special `'dr` lifetime that enables efficient
borrowing throughout circuit code. Without it, the trait's associated types
would carry an implicit `'static` bound, and every reference would have to be
replaced with reference counting.

The lifetime lets a driver's `Wire` type hold a plain reference into the
driver's backing storage. It also propagates into witness and instance methods,
so circuits (and [gadgets](../gadgets/index.md)) can borrow their input data
rather than requiring callers to clone or wrap it in `Arc`.

```admonish info
`'dr` also enables zero-cost scoped parallelism for [`Routine`]s. The trait's
predict/execute split and `Aux<'dr>` associated type are scaffolding for a
driver that dispatches routine execution to worker threads: binding `'dr` to the
thread scope's lifetime lets routines hold borrowed references and send auxiliary
data to workers without `Arc`.
```

### `DriverTypes` {#drivertypes}

`Driver<'dr>` has a supertrait, [`DriverTypes`], that collects associated types
which can be named without binding the `'dr` lifetime. The field type
`ImplField` and wire type `ImplWire` are re-exported on `Driver` as
[`F`][driver-f] and [`Wire`], but the remaining associated types (`MaybeKind`,
`LCadd`, and `LCenforce`) live only on `DriverTypes` because circuit code rarely
needs to refer to them by name.

The lifetime-free aspect lets conversion infrastructure (see the
[`convert`][convert-mod] module) and the [`DriverValue`] type alias work without
a driver lifetime in scope. Circuit code should always use `Driver<'dr>` as its
bound directly; `DriverTypes` only matters when writing lifetime-polymorphic
abstractions over drivers.

### Purity {#purity}

All four closure-accepting `Driver` methods—[`mul()`], [`alloc()`], [`add()`],
and [`enforce_zero()`]—require their closures to be [`Fn`], not `FnOnce` or
`FnMut`. This is a deliberate signal that closures should be side-effect-free:
synthesis must produce identical constraints regardless of whether a given
driver invokes the closure. `Fn` prevents accidental `&mut` captures, although
it does not prevent interior mutability.

The two closure families differ in whether they have additional protection
beyond `Fn`. For the witness-providing closures on [`mul()`] and [`alloc()`],
the [`Maybe`]/[`DriverValue`] system provides a harder compile-time guarantee:
drivers with `MaybeKind = Empty` never call those closures at all, and the
closure bodies are dead-code-eliminated. The expression-building closures on
[`add()`] and [`enforce_zero()`] have no such backstop; drivers with `MaybeKind
= Empty` still call these closures when building constraint structure.

### Equality

The [`enforce_equal()`] method is a convenience helper that constrains two wires
to have the same value by calling [`enforce_zero()`] on their difference.

[`mul()`]: ragu_core::drivers::Driver::mul
[`enforce_zero()`]: ragu_core::drivers::Driver::enforce_zero
[`add()`]: ragu_core::drivers::Driver::add
[`ONE`]: ragu_core::drivers::Driver::ONE
[`constant()`]: ragu_core::drivers::Driver::constant
[`alloc()`]: ragu_core::drivers::Driver::alloc
[`Driver`]: ragu_core::drivers::Driver
[`Routine`]: ragu_core::routines::Routine
[`enforce_equal()`]: ragu_core::drivers::Driver::enforce_equal
[`Wire`]: ragu_core::drivers::Driver::Wire
[`DriverTypes`]: ragu_core::drivers::DriverTypes
[driver-f]: ragu_core::drivers::Driver::F
[convert-mod]: ragu_core::convert
[`DriverValue`]: ragu_core::drivers::DriverValue
[`Maybe`]: ragu_core::maybe::Maybe
[`Fn`]: https://doc.rust-lang.org/std/ops/trait.Fn.html
