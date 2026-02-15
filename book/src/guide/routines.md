# Routines

Circuit code asks the [`Driver`] to allocate wires and enforce constraints,
turning a computation into a verifiable trace. The driver typically sees only a
flat stream of constraints, with no structural insight into the operations they
compose.

**Routines** mark self-contained sections of circuit logic, giving the driver
visibility into these boundaries and the freedom to handle them however it
likes: reusing the underlying polynomial reductions across repeated invocations,
reordering their placement in the trace, predicting outputs to enable
concurrency, or even skipping execution when full synthesis isn't required.

## Execution

The simplest form of a [`Routine`] declares an [`Input`] gadget kind, an
[`Output`] gadget kind, and an **[`execute`]** method that performs the actual
circuit synthesis. Consider a routine `Txz` that evaluates a polynomial $t(X,
Z)$ at a given point. It takes the pair $(x, z)$ as [`Element`]s and returns the
result:

```rust,ignore
impl<F: Field> Routine<F> for Txz {
    // (x, z)
    type Input = Kind![F; (Element<'_, _>, Element<'_, _>)];

    // t(x, z)
    type Output = Kind![F; Element<'_, _>];

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        let (x, z) = input;

        // ... perform the arithmetic for the evaluation ...

        Ok(txz)
    }
}
```

Routines are intended to be invoked through the driver rather than called
directly. [`Driver`]s provide a [`routine`] method that accepts a [`Routine`]
and its input gadget:

```rust,ignore
let txz = dr.routine(Txz::default(), (x, z))?;
```

The result is semantically identical to calling `execute` directly, but only
[`routine`] hands scheduling to the driver. Both the input and output are single
[gadgets](gadgets/index.md) with type-determined semantics; the driver's only
obligation is to return a correct result.

### Memoization

`Routine` has a narrow interface—one input gadget, one output gadget—and so
different invocations of the same routine differ only by their input wires. The
[fungibility](gadgets/index.md) guarantee of gadgets reinforces this: synthesis
behavior is fully determined by the type, so the driver can analyze equivalence
between routine invocations without inspecting the internal constraint logic.

This fungibility is what makes memoization possible. When the driver sees a
second invocation of the same routine, it already knows the internal constraint
structure is identical. The only thing that has changed is which wires flow in
and out, and the driver can account for that without re-executing the body.

### Parameterization

Although gadgets must be fungible, routines are not parameterized by a driver
and so they are free to carry non-trivial state. This allows them to hold
configuration, references, or precomputed data that outlive any particular
driver, provided their execution remains deterministic.

```rust,ignore
struct ScaledTxz {
    /// A precomputed scaling factor that adjusts the polynomial evaluation.
    scale: u64,
}
```

Two instances of `ScaledTxz` with different `scale` values are distinct
routines—the driver treats them independently.

## Prediction

Beyond memoization, routines demarcate sections of circuit code that align with
another optimization opportunity: functions whose outputs can be efficiently
predicted from their inputs. When a driver knows the output ahead of time, it
has options. It might allow synthesis to proceed on the predicted result while
collecting the actual trace concurrently. Or, during [emulation] (where the
driver evaluates logic without enforcing constraints), it might skip execution
entirely.

What a driver actually does with this information is not the routine author's
concern. The abstraction simply provides the boundary and, optionally, a
prediction; the driver decides how to use them.

The full [`Routine`] trait adds three items to support this: an associated type
**[`Aux`]** that the routine defines to carry whatever intermediate state (if
any) is worth preserving between prediction and execution, a **[`predict`]**
method, and an `aux` parameter on [`execute`] that feeds prediction results back
in.

```rust,ignore
impl<F: Field> Routine<F> for Txz {
    type Input = Kind![F; (Element<'_, _>, Element<'_, _>)];
    type Output = Kind![F; Element<'_, _>];
    type Aux<'dr> = ();

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<Prediction<
        <Self::Output as GadgetKind<F>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'dr>>,
    >> {
        // ...
    }

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        // ...
    }
}
```

[`predict`] examines the input and returns a [`Prediction`]:

- **[`Known`]`(output, aux)`** — the routine can predict the output gadget, and
  provides auxiliary data alongside it.
- **[`Unknown`]`(aux)`** — the routine cannot efficiently predict the output (a
  hash function, for instance), but can still provide auxiliary data.

Either way, the auxiliary data is threaded back into [`execute`] via the `aux`
parameter, allowing it to reuse work that [`predict`] already performed rather
than recomputing it.

The trait also requires `Send + Clone` so that routines can cross thread
boundaries, which makes concurrent strategies available to the driver.

```admonish info
**When to use a routine.** Wrap a section of circuit code in a `Routine` when
you expect it to be invoked more than once (enabling memoization), when its
output is efficiently predictable (enabling concurrency), or both. The two
optimizations are independent—a routine need not be amenable to both. A hash
function, for example, is a natural memoization target but cannot predict its
output; it would return [`Unknown`] from [`predict`] while optionally providing
auxiliary data for [`execute`].
```

[emulation]: ../implementation/drivers/emulator.md
[`Aux`]: ragu_core::routines::Routine::Aux
[`Element`]: ragu_primitives::Element
[`Prediction`]: ragu_core::routines::Prediction
[`predict`]: ragu_core::routines::Routine::predict
[`execute`]: ragu_core::routines::Routine::execute
[`Input`]: ragu_core::routines::Routine::Input
[`Output`]: ragu_core::routines::Routine::Output
[`routine`]: ragu_core::drivers::Driver::routine
[`Known`]: ragu_core::routines::Prediction::Known
[`Unknown`]: ragu_core::routines::Prediction::Unknown
[`Driver`]: ragu_core::drivers::Driver
[`Gadget`]: ragu_core::gadgets::Gadget
[`Routine`]: ragu_core::routines::Routine
[gadget]: gadgets/index.md
