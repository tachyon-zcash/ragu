# Writing Custom Drivers

The [guide](../../guide/drivers/index.md) explains how circuit code interacts
with drivers through the [`Driver`] trait. This section explains how to
*implement* that trait—what each associated type controls, what the gate
constraint means, and how design choices propagate through monomorphized
circuit code.

A custom driver is useful when the built-in
[emulator, simulator, and `PhantomData`](../../guide/drivers/concrete.md)
do not cover your use case. Examples include collecting constraint metadata,
logging gate allocations, or running custom verification logic during
synthesis.

## The Two Traits

A driver implementation consists of two traits:

* [`DriverTypes`] carries the associated types and the low-level [`gate()`]
  method. It is lifetime-free, which lets conversion infrastructure and the
  [`DriverValue`] type alias reference driver types without a `'dr` in scope.

* [`Driver<'dr>`][`Driver`] provides the user-facing API: [`mul()`],
  [`add()`], [`enforce_zero()`], and [`routine()`]. It has a supertrait bound
  on `DriverTypes` and re-exports the field and wire types as `F` and `Wire`.

Circuit code bounds on `Driver<'dr>`; infrastructure that needs to name
types without a driver lifetime bounds on `DriverTypes` instead.

## A Minimal Driver: `PhantomData<F>`

The simplest driver is [`PhantomData<F>`], which does nothing at all. Walking
through its implementation introduces every associated type and method.

### Associated Types

```rust
impl<F: Field> DriverTypes for PhantomData<F> {
    type ImplField = F;
    type ImplWire = ();
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type Extra = ();
    // ...
}
```

Each type controls a specific axis of behavior:

* **`ImplField`**: the field the driver operates over. Must match
  `Driver::F`.

* **`ImplWire`**: the wire representation. `PhantomData` uses `()` because
  it tracks no assignments. Drivers that need wire values (like the
  [`Simulator`]) use `F` itself. The [`Emulator`] in wired mode also uses `F`,
  while wireless mode uses `()`.

* **`MaybeKind`**: determines whether witness values exist, and with them
  whether witness-producing closures (on `gate()`/`mul()`) can execute.
  `Empty` means those closures are never called and their bodies are
  dead-code-eliminated after monomorphization. `Always<()>` means the values
  are available, and the driver calls the closures when it needs their
  assignments: the [`Simulator`] calls every one, and the wireless
  [`Emulator`], which tracks no wires, calls none. Expression-building
  closures on `add()` and `enforce_zero()` are not gated by `MaybeKind` —
  drivers always call them when they need constraint structure.

* **`LCadd`** and **`LCenforce`**: the [`LinearExpression`] types used by
  `add()` and `enforce_zero()`. The trivial `()` implementation ignores
  all terms. [`DirectSum`] accumulates terms and computes their sum.

* **`Extra`**: the token type returned by `gate()` for the auxiliary $D$
  wire. It carries metadata from `gate()` to `assign_extra()`, not
  whether overriding $D$ is possible. `()` carries no metadata (the
  wired [`Emulator`] uses `()` and still accepts arbitrary $D$ values).
  `bool` (as the [`Simulator`] uses) tracks whether $C$ is zero,
  letting `assign_extra` reject a nonzero $D$ when the constraint
  $C \cdot D = 0$ would be violated.

### `gate()` and `assign_extra()`

```rust
fn gate(
    &mut self,
    _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
) -> Result<((), (), (), ())> {
    Ok(((), (), (), ()))
}

fn assign_extra(
    &mut self,
    _: Self::Extra,
    _: impl Fn() -> Result<Coeff<F>>,
) -> Result<()> {
    Ok(())
}
```

`PhantomData` ignores both closures. The witness closure on `gate` is gated
by `MaybeKind = Empty`, so the compiler eliminates it entirely.

### `Driver<'dr>`

```rust
impl<F: Field> Driver<'_> for PhantomData<F> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}
    fn enforce_zero(
        &mut self,
        _: impl Fn(Self::LCenforce) -> Self::LCenforce,
    ) -> Result<()> {
        Ok(())
    }
}
```

The `mul()` method has a default implementation that delegates to `gate()`,
and `constant()` delegates to `add()`. A driver only needs to override them
if the default behavior is insufficient.

## A Constraint-Enforcing Driver: `Simulator`

The [`Simulator`] shows how a driver can do real work. It assigns field
values to wires, checks constraints, and counts gates. Udon's `Field` lets
`DirectSum` accumulate products before reducing them when `value()` consumes
the linear expression.

### Associated Types

```rust
impl<F: udon::field::Field> DriverTypes for Simulator<F> {
    type ImplField = F;
    type ImplWire = F;
    type MaybeKind = Always<()>;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;
    type Extra = bool;
    // ...
}
```

The key differences from `PhantomData`:

1. **`ImplWire = F`**: wires carry their assigned field values.
2. **`MaybeKind = Always<()>`**: witness values are available, and the
   simulator calls every witness closure.
3. **`LCadd` and `LCenforce` = `DirectSum<F>`** — linear expressions
   accumulate terms and evaluate their sum, rather than ignoring them.
4. **`Extra = bool`**: tracks whether $C$ is zero so that `assign_extra`
   can enforce the $C \cdot D = 0$ constraint.

### Gate Implementation

```rust
fn gate(
    &mut self,
    values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
) -> Result<(F, F, F, bool)> {
    let (a, b, c) = values()?;
    let a = a.value();
    let b = b.value();
    let c = c.value();

    if a * b != c {
        return Err(Error::InvalidWitness("gate check failed".into()));
    }

    self.num_gates += 1;
    Ok((a, b, c, c.is_zero().into()))
}
```

The simulator calls the closure, which `MaybeKind = Always<()>` permits. The
returned `bool`
records whether $C$ is zero—if it is, the $D$ wire is unconstrained and
`assign_extra` can place an arbitrary value there.

### `assign_extra`

```rust
fn assign_extra(
    &mut self,
    c_is_zero: bool,
    value: impl Fn() -> Result<Coeff<F>>,
) -> Result<F> {
    let d = value()?.value();
    if !c_is_zero && !bool::from(d.is_zero()) {
        return Err(Error::InvalidWitness("auxiliary constraint failed".into()));
    }
    Ok(d)
}
```

This enforces the second gate constraint: $C \cdot D = 0$. If $C$ is
nonzero, $D$ must be zero. The `Extra = bool` token carries this information
from `gate()` to `assign_extra()` without re-examining the wire values.

### Constraint Enforcement

```rust
fn enforce_zero(
    &mut self,
    lc: impl Fn(DirectSum<F>) -> DirectSum<F>,
) -> Result<()> {
    let lc = lc(DirectSum::default());
    if lc.value() != F::ZERO {
        return Err(Error::InvalidWitness("constraint failed".into()));
    }
    self.num_constraints += 1;
    Ok(())
}
```

The [`DirectSum`] linear expression accumulates terms from the closure and
computes their sum. The simulator checks that the sum is zero and increments
its constraint counter.

## Design Decisions

### `MaybeKind`: `Empty` vs `Always`

`MaybeKind` controls whether witness-producing closures (on
`gate()`/`mul()`) can run. It does not govern expression-building closures
on `add()` and `enforce_zero()`; drivers always call those when they
need constraint structure.

| `MaybeKind` | Witness closures | `DriverValue<D, T>` | Use Case |
|---|---|---|---|
| `Empty` | Dead-code-eliminated | `Empty` (zero-size) | Type-level work, counting |
| `Always<()>` | Invoked when the driver needs assignments | `Always<T>` (holds value) | Testing, simulation, proving |

A driver that only needs constraint structure (gate counts, wire
topology, linear combination shape) should use `Empty`, because witness
closures are dead-code-eliminated and `DriverValue` collapses to a
zero-size type. A driver that evaluates circuits and checks constraint
satisfaction should use `Always<()>`, which lets it invoke witness closures
and carries real values through `DriverValue`.

### `LinearExpression`: `()` vs `DirectSum`

* **`()`**: ignores all terms. Appropriate when the driver does not need to
  know about linear combinations (e.g., `PhantomData`).
* **[`DirectSum`]**: accumulates wire-coefficient pairs and evaluates their
  sum. Appropriate when the driver evaluates or checks constraints.

A driver's `LCadd` and `LCenforce` types can differ if `add()` and
`enforce_zero()` need different representations, but in practice they
are usually the same.

### `Extra` Token

The `Extra` type connects `gate()` to `assign_extra()`. It carries whatever
information `assign_extra` needs to decide whether the $D$ wire override is
valid:

* **`()`**: no metadata carried; `assign_extra` receives no
  information about the gate's $C$ wire.
* **`bool`**: carries the "is $C$ zero?" flag, as the [`Simulator`] does.
* A richer type could carry additional metadata if needed.

Dropping the `Extra` token without calling `assign_extra` keeps the default
$D = 0$ assignment.

## Implementing `routine()`

The default [`routine()`] implementation predicts the routine's output using
an [`Emulator`], then executes the routine with the predicted auxiliary data:

```rust
fn routine<R: Routine<Self::F> + 'dr>(
    &mut self,
    routine: R,
    input: Bound<'dr, Self, R::Input>,
) -> Result<Bound<'dr, Self, R::Output>> {
    let aux = Emulator::predict(&routine, &input)?.into_aux();
    routine.execute(self, input, aux)
}
```

Most custom drivers can use this default. Override it only if your driver
needs to intercept routine execution. The wireless [`Emulator`], for
example, short-circuits when the routine returns `Prediction::Known`
but still calls `execute()` on `Prediction::Unknown`.

With `DriverTypes` and `Driver<'dr>` implemented, a custom driver can be
passed to any circuit code bounded on `Driver`. The associated types
control which parts of synthesis are active: `MaybeKind` gates witness
computation, the `LinearExpression` types determine how linear combinations
are handled, and `Extra` connects gate allocation to the auxiliary wire.
For the concrete drivers provided by the framework, see the
[guide](../../guide/drivers/concrete.md).

[`Driver`]: ragu_core::drivers::Driver
[`DriverTypes`]: ragu_core::drivers::DriverTypes
[`DriverValue`]: ragu_core::drivers::DriverValue
[`mul()`]: ragu_core::drivers::Driver::mul
[`add()`]: ragu_core::drivers::Driver::add
[`enforce_zero()`]: ragu_core::drivers::Driver::enforce_zero
[`routine()`]: ragu_core::drivers::Driver::routine
[`gate()`]: ragu_core::drivers::DriverTypes::gate
[`LinearExpression`]: ragu_core::drivers::LinearExpression
[`DirectSum`]: ragu_core::drivers::DirectSum
[`PhantomData<F>`]: core::marker::PhantomData
[`Simulator`]: ragu_primitives::Simulator
[`Emulator`]: ragu_core::drivers::emulator::Emulator
