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

* [`mul()`]: returns wires $(a, b, c)$ with the constraint $a \cdot b = c$,
      simultaneously assigning their values. The caller provides a closure that
      returns the three assignments; it is evaluated only in contexts where
      [witness data](witness.md) is needed. See [`DriverTypes`](#drivertypes)
      for the lower-level [`gate()`] method that [`mul()`] delegates to by
      default.
* [`enforce_zero()`]: enforces that a linear combination of previously created
      wires equals zero. This operation takes a closure that is only executed
      when the driver needs to know about constraints. The closure is
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
corresponding $b$ and $c$ wires to zero to satisfy the gate—wasting $b$ and $c$. Drivers may override `alloc` to avoid this
overhead. For example, synthesis drivers return the $a$ wire from a `mul`
operation, stash the associated $b$ wire for the next `alloc` call, and fill in
$c$ later to satisfy the gate.

### The `'dr` Lifetime {#the-dr-lifetime}

Drivers are parameterized by a lifetime `'dr` that ties [routines] to the
driver's scope. The [`routine()`] method bounds routines by `'dr`, ensuring
that any data a routine borrows outlives the driver. This enables a
parallel-dispatch driver to bind `'dr` to a thread scope's lifetime so that
routines holding borrowed references can be safely sent to worker threads.

### `DriverTypes` {#drivertypes}

`Driver<'dr>` has a supertrait, [`DriverTypes`], that collects implementation
details which are agnostic to the `'dr` lifetime. These include associated types
(`ImplField`, `ImplWire`, `MaybeKind`, `LCadd`, `LCenforce`) and the low-level
[`gate()`] method.

The most important item on `DriverTypes` is [`gate()`]. It allocates four wires
$(a, b, c, d)$ subject to the constraints $a \cdot b = c$ and $c \cdot d = 0$.
The second constraint makes $d$ useless in the typical case: whenever $c$ is
nonzero, $d$ is forced to zero. For this reason [`mul()`] delegates to `gate`
by default and discards $d$, and circuit code should always prefer `mul`. But
when $c$ is guaranteed to be zero, $d$ becomes unconstrained—code can call
`gate` directly and use the returned $d$.

`Driver<'dr>` re-exports the field and wire types as [`F`][driver-f] and
[`Wire`]; the remaining associated types live only on `DriverTypes` because
circuit code rarely needs to name them. The lifetime-free aspect lets conversion
infrastructure (see the [`convert`][convert-mod] module) and the
[`DriverValue`] type alias work without a driver lifetime in scope. Circuit code
should always bound on `Driver<'dr>`, not `DriverTypes`.

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
[`gate()`]: ragu_core::drivers::DriverTypes::gate
[`enforce_zero()`]: ragu_core::drivers::Driver::enforce_zero
[`add()`]: ragu_core::drivers::Driver::add
[`ONE`]: ragu_core::drivers::Driver::ONE
[`constant()`]: ragu_core::drivers::Driver::constant
[`alloc()`]: ragu_core::drivers::Driver::alloc
[`Driver`]: ragu_core::drivers::Driver
[`Routine`]: ragu_core::routines::Routine
[`routine()`]: ragu_core::drivers::Driver::routine
[`enforce_equal()`]: ragu_core::drivers::Driver::enforce_equal
[`Wire`]: ragu_core::drivers::Driver::Wire
[`DriverTypes`]: ragu_core::drivers::DriverTypes
[driver-f]: ragu_core::drivers::Driver::F
[convert-mod]: ragu_core::convert
[`DriverValue`]: ragu_core::drivers::DriverValue
[`Maybe`]: ragu_core::maybe::Maybe
[`Fn`]: https://doc.rust-lang.org/std/ops/trait.Fn.html
[routines]: ../routines.md
