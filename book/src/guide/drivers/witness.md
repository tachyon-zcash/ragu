# Witness Data

Circuits describe computations parameterized by witness data, yet circuit code
frequently executes in contexts where witness values are irrelevant. Wire
assignments matter when constructing execution traces, but polynomial evaluators
are indifferent to them.

The straightforward approach is to model witness data as `Option<T>`, but this
collapses two distinct notions of optionality. In witness-independent logic,
`Option<T>` represents a computation-defined absence or presence that is
meaningful regardless of whether witnesses are available. In contrast, a
“witness option” is purely contextual: it is `Some` when the driver is
collecting assignments, and `None` otherwise. Combinators such as `and_then`
make these uses *look* composable, but mixing them can make constraint
generation depend on witness availability, leading to correctness bugs.

The performance picture reinforces this. In practice, drivers operate in a
uniform mode: they either require witnesses everywhere or omit them everywhere,
so `Option<T>`’s discriminant and branching are pure overhead. When witnesses
are always absent, `Option<T>` still has to represent `Some(T)`, which can force
allocations in code paths that build or store witness values even when those
values are never used; a zero-sized representation would eliminate them
entirely. `Option<T>` also introduces “missing witness” errors—and the cost of
propagating them—at every point where witness data is manipulated. A correct
design rules out these failure modes statically.

## [`DriverValue<D, T>`] {#driver-value}

For witness data, Ragu replaces `Option<T>` with a type-level mechanism. Each
driver `D` requires circuit code to interact with witness data through
[`DriverValue<D, T>`]. This type alias resolves differently depending on the
driver:

* If the witness must be available, [`DriverValue<D, T>`] resolves to
  `Always<T>`, a `#[repr(transparent)]` wrapper with the same layout as `T`.
* If the witness is not expected, [`DriverValue<D, T>`] resolves to `Empty`, a
  zero-sized type that carries no data, like `()`. Operations on these values
  are no-ops.

## [`Maybe<T>`] {#maybe-trait}

Both `Always<T>` and `Empty` implement the [`Maybe<T>`] trait, which provides a
shared interface analogous to `Option<T>`. Circuit code manipulates witness
values through this trait without knowing which concrete representation it
holds. Its methods cover extraction, transformation, and construction of witness
values.

### [`take`], [`as_ref`], [`as_mut`], and [`snag`] {#take-as_ref-snag}

[`take`] extracts the enclosed value, analogous to [`Option::unwrap()`], except
that it is infallible, without branching, overhead or panics. `Always::take()`
returns the inner value directly, while `Empty::take()` is a compile-time trap:
it contains a `const { panic!(...) }` that the compiler evaluates before code
generation. In practice this is unreachable: when `MaybeKind = Empty`, drivers
never invoke witness closures, so after monomorphization the dead-code
elimination pass removes those call sites entirely.

[`as_ref`] and [`as_mut`] are the equivalents of [`Option::as_ref()`] and
[`Option::as_mut()`]. [`snag`] is shorthand for `.as_ref().take()`. Because
[`take`] consumes the `Maybe<T>` by value, [`snag`] covers the common case of
obtaining a `&T` without consuming the original value.

### [`map`] and [`and_then`] {#map-and-then}

[`map`] and [`and_then`] behave like their [`Option`] counterparts. Both
preserve the `Always`/`Empty` distinction: [`map`] applies a function to the
underlying value and returns a new `Maybe`, while [`and_then`] chains a closure
that itself returns a `Maybe` of the same kind. Under `Empty`, neither closure
is invoked.

### [`just`] and [`try_just`] {#just-and-try-just}

[`just`] constructs a `Maybe<T>` from a closure; under `Empty`, the closure is
never called. [`try_just`] is the same, but it accepts a fallible closure and
propagates its error. For example, this [`Point`] reconstructs its full witness
value from the two coordinate elements it stores:

```rust,ignore
D::just(|| {
    let x = *self.x.value().take();
    let y = *self.y.value().take();
    C::from_xy(x, y).expect("must be valid affine point on curve")
})
```

Each [`take`] extracts a coordinate’s witness value, and the outer [`just`]
wraps the composed result back into a [`DriverValue<D, T>`]. Under `Empty`, the
entire expression collapses to a no-op.

### [`cast`] {#cast}

[`cast`] consumes a `Maybe<T>` and converts it into a structurally decomposed
form, as defined by the [`MaybeCast`] trait. For example, a `Maybe<(A, B)>` can
be cast into `(Maybe<A>, Maybe<B>)`, splitting a tuple witness into its
components. Any type can implement [`MaybeCast`] to define its own
decomposition; the built-in implementations cover tuples and arrays.

### [`clone`] {#clone}

[`Maybe<T>`] provides its own [`clone`] method rather than implementing
[`Clone`] as a supertrait. Rust does not allow a supertrait bound that is
conditional on `T: Clone`, so a dedicated trait method fills the gap. It behaves
identically to [`Clone::clone`] when the value is present; under `Empty`, it
returns `Empty`.

## [`MaybeKind`] and the [`Perhaps`] Alias {#generic-code}

Most code that works with [`Maybe<T>`] only needs the trait methods described
above. Users who need to build abstractions that are themselves generic over
[`Maybe<T>`] will additionally need the [`MaybeKind`] trait and the [`Perhaps`]
type alias. These are documented in the [`maybe`] module.

[`just`]: ragu_core::maybe::Maybe::just
[`try_just`]: ragu_core::maybe::Maybe::try_just
[`map`]: ragu_core::maybe::Maybe::map
[`and_then`]: ragu_core::maybe::Maybe::and_then
[`cast`]: ragu_core::maybe::Maybe::cast
[`MaybeCast`]: ragu_core::maybe::MaybeCast
[`MaybeKind`]: ragu_core::maybe::MaybeKind
[`DriverValue<D, T>`]: ragu_core::drivers::DriverValue
[`Maybe<T>`]: ragu_core::maybe::Maybe
[`take`]: ragu_core::maybe::Maybe::take
[`snag`]: ragu_core::maybe::Maybe::snag
[`as_ref`]: ragu_core::maybe::Maybe::as_ref
[`as_mut`]: ragu_core::maybe::Maybe::as_mut
[`Option<T>`]: core::option::Option
[`Option`]: core::option::Option
[`Option::unwrap()`]: core::option::Option::unwrap
[`Option::as_ref()`]: core::option::Option::as_ref
[`Option::as_mut()`]: core::option::Option::as_mut
[`clone`]: ragu_core::maybe::Maybe::clone
[`Clone`]: core::clone::Clone
[`Clone::clone`]: core::clone::Clone::clone
[`Perhaps`]: ragu_core::maybe::Perhaps
[`maybe`]: ragu_core::maybe
[`Point`]: ragu_primitives::point::Point
