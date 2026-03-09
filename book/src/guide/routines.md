# Routines

Circuit code asks the [driver](drivers/index.md) to allocate wires and enforce
constraints, turning a computation into a verifiable trace. The driver typically
sees only a flat stream of constraints, with no structural insight into the
operations they compose.

**Routines** mark self-contained sections of circuit logic, giving the driver
visibility into these boundaries and the freedom to handle them however it
likes: reusing the underlying [polynomial reductions][poly-synthesis] across
repeated invocations, reordering their placement in the trace, predicting
outputs to enable concurrency, or even skipping execution when full synthesis
isn't required.

This visibility depends on the [`Gadget`] trait. Routine inputs and outputs are
[gadgets][gadget], and the [fungibility](gadgets/index.md#fungibility)
guarantee—that a gadget's synthesis behavior is determined entirely by its
type—is what gives the driver an identity system for routines in the first
place. The dependence is mutual: the properties `Gadget` imposes find their
practical application at routine boundaries, and would serve little purpose
without them.

## Execution

The simplest form of a [`Routine`] declares an [`Input`] gadget, an [`Output`]
gadget, and an [`execute`] method that performs circuit synthesis. Consider a
routine `Txz` that evaluates a polynomial $t(X, Z)$ at a given point. It takes
the pair $(x, z)$ as [`Element`]s and returns the result:

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
[gadgets](gadgets/index.md), and the driver's only obligation is to return an
equivalent result.

### Memoization

`Routine` has a narrow interface—one input gadget, one output gadget—and so
different invocations of the same routine differ only by their input wires.
Fungibility handles the rest: the driver can recognize equivalent invocations
without inspecting the constraint logic.

The constraint system ultimately reduces to [polynomial
expressions][poly-synthesis], and equivalent routines contribute structurally
identical terms at different positions. The driver can derive one invocation's
contribution from another without re-executing the body.

### Parameterization

Unlike gadgets, routines are not parameterized by a driver and are free to carry
non-trivial state. This allows them to hold configuration, references, or
precomputed data that outlive any particular driver, provided their execution
remains deterministic.

```rust,ignore
struct ScaledTxz {
    /// A precomputed scaling factor that adjusts the polynomial evaluation.
    scale: u64,
}
```

Two instances of `ScaledTxz` with different `scale` values are distinct
routines—the driver treats them independently.

## Prediction

Routines also demarcate sections of circuit code whose outputs can be
efficiently predicted from their inputs. The [`Routine`] trait includes a
[`predict`] method that examines the input and returns a [`Prediction`]:

* **[`Known`]**: predicted output plus auxiliary data.
* **[`Unknown`]**: auxiliary data only.
* **`Err`**: an unrecoverable failure (e.g. missing witness data); drivers must
  propagate the error, not fall back to [`execute`]. "Cannot efficiently
  predict" is represented by [`Unknown`], not `Err`.

Prediction often performs intermediate computation that [`execute`] would
otherwise redo, so both variants carry an [`Aux`] value—an associated type
defined by the routine—which the driver threads back into [`execute`].

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

Although the `predict` method takes a `&mut D` driver, it is witness-oriented by
design: the driver passed in is always a lightweight stand-in (such as an
[`Emulator`]) that does not collect or enforce constraints.

Ultimately, the driver decides what to do with the prediction. Drivers that know
the output ahead of time might skip execution entirely during [emulation], or
synthesize on the predicted result while collecting the actual trace
concurrently. Concurrency relies on the fact that `Routine`s implement `Send +
Clone`.

[`Emulator`]: ragu_core::drivers::emulator::Emulator

```admonish info
**When to use a routine.** Wrap a section of circuit code in a `Routine` when
you expect it to be invoked more than once (enabling memoization), when its
output is efficiently predictable (enabling concurrency), or both. The two
optimizations are independent—a routine need not be amenable to both. A hash
function, for example, is a natural memoization target but cannot predict its
output; it would return [`Unknown`] from [`predict`] while optionally providing
auxiliary data for [`execute`].
```

[emulation]: drivers/concrete.md#emulator
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
[poly-synthesis]: ../implementation/polynomials.md#synthesis
