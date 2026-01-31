//! Stateful abstractions for algorithms and protocols that are synthesized into
//! arithmetic circuits.
//!
//! ## Design
//!
//! Gadgets are abstract data types that contain wires and witness data. By
//! definition, all gadgets are polymorphic over [drivers](crate::drivers).
//! Gadgets use the type system to encode information about wire assignments and
//! the constraints that have previously been placed on them. Gadgets that
//! satisfy the requisite API contracts can implement the [`Gadget`] trait so
//! that drivers can manipulate them and their wires for optimization purposes
//! without affecting their semantics.
//!
//! There are two main traits that gadgets implement: the [`Gadget`] trait is
//! implemented for gadgets instantiated over a driver, and the [`GadgetKind`]
//! trait is implemented to help relate gadgets instantiated over different
//! drivers. The requirements for implementing these traits are strict, but the
//! traits can be [automatically derived](derive@Gadget) in most cases. Further,
//! not all gadgets need to implement these traits if they are not intended to
//! be used with [routines](crate::routines).
//!
//! #### Basic Properties
//!
//! * All gadgets are [`Clone`].
//! * All gadgets are parameterized by a [`Driver`] type that outlives the
//!   special lifetime `'dr`.
//! * Gadgets can contain wires ([`D::Wire`](Driver::Wire)), witness data
//!   ([`DriverValue<D, T>`](crate::drivers::DriverValue)), other gadgets, and
//!   otherwise can contain any other [`Send`] contents that are `'static`.
//!
//! #### Fungibility
//!
//! Gadgets must be _fungible_: a gadget's behavior during circuit synthesis
//! must be fully determined by its type, not by any particular instance's
//! state. This ensures deterministic synthesis and allows drivers to substitute
//! or transform gadgets without affecting circuit behavior.
//!
//! From this principle, three consequences follow:
//!
//! 1. **No dynamic-length collections.** The number of wires must be
//!    type-determined. Use `FixedVec` with a compile-time `Len` bound instead
//!    of `Vec`.
//!
//! 2. **No enum discriminants.** Which variant is active constitutes instance
//!    state that affects synthesis.
//!
//! 3. **No non-witness runtime state.** Any runtime data must be _stable_
//!    (identical across all instances of that type).
//!
//! Wires are fungible by definition, and witness data cannot affect synthesis,
//! so gadgets containing only these (plus `PhantomData` and nested gadgets)
//! automatically satisfy fungibility. The derive macro enforces this.
//!
//! #### Transformations between Drivers
//!
//! Gadgets must define a canonical mapping between their instantiations over
//! different [`Driver`] types. This mapping is described using an associated
//! [`GadgetKind`] implementation and uses the [`FromDriver`] trait to
//! facilitate the transformation of wires and witness data from one driver to
//! another.
//!
//! It is required that the transformation of wires for a gadget does not depend
//! on the gadget's state. This naturally follows from fungibility, and is
//! imposed on gadgets that are automatically derived.
//!
//! #### Multithreading
//!
//! Gadgets are required to be [`Send`] if their driver has `Send` wires. This
//! allows gadgets to cross thread boundaries.
//!
//! Due to limitations of the Rust language this bound cannot be expressed
//! easily without unnecessary API complexity. Instead, the [`GadgetKind`] trait
//! is an `unsafe` trait to implement and the implementor must ensure that this
//! property holds. This requirement is automatically imposed on gadgets that
//! are automatically derived.
//!
//! #### Compositional Gadgets
//!
//! Gadgets can be composed of other gadgets by definition. Gadgets can even be
//! polymorphic over gadgets, and some gadgets are even composed of gadgets that
//! are instantiated with different drivers.

mod foreign;

use ff::Field;

use super::{
    Result,
    drivers::{Driver, FromDriver},
};

/// An abstract data type (parameterized by a [`Driver`] type) which
/// encapsulates wires allocated by the driver along with any corresponding
/// witness information.
///
/// ## Fungibility
///
/// Gadgets must be _fungible_: a gadget's behavior during circuit synthesis
/// must be fully determined by its type, not by any particular instance's
/// state. Wires are fungible by definition, and witness data cannot affect
/// synthesis, so gadgets containing only these automatically satisfy this
/// requirement. This precludes enum discriminants, dynamic-length collections,
/// and non-stable runtime state.
///
/// ## Implementations
///
/// In order to make it easy to satisfy the API contract, this trait can be
/// [automatically derived](derive@Gadget) for almost all gadgets.
pub trait Gadget<'dr, D: Driver<'dr>>: Clone {
    /// The kind of this gadget.
    type Kind: GadgetKind<D::F, Rebind<'dr, D> = Self>;

    /// Proxy for the `GadgetKind::map_gadget` method.
    fn map<'new_dr, ND: FromDriver<'dr, 'new_dr, D>>(
        &self,
        ndr: &mut ND,
    ) -> Result<<Self::Kind as GadgetKind<D::F>>::Rebind<'new_dr, ND::NewDriver>> {
        Self::Kind::map_gadget(self, ndr)
    }

    /// Proxy for the `GadgetKind::enforce_equal_gadget` method.
    fn enforce_equal<D2: Driver<'dr, F = D::F, Wire = D::Wire>>(
        &self,
        dr: &mut D2,
        other: &Self,
    ) -> Result<()> {
        Self::Kind::enforce_equal_gadget::<D2, D>(dr, self, other)
    }

    /// Returns how many wires are in this gadget.
    ///
    /// Gadgets do not vary in the number of wires they contain, so this should
    /// return the same quantity regardless of the specific instance of this
    /// [`Gadget`] implementation.
    fn num_wires(&self) -> usize {
        struct WireCounter {
            count: usize,
        }

        impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for WireCounter {
            type NewDriver = core::marker::PhantomData<D::F>;

            fn convert_wire(&mut self, _: &D::Wire) -> Result<()> {
                self.count += 1;
                Ok(())
            }
        }

        let mut dr = WireCounter { count: 0 };
        self.map(&mut dr).expect("wire counting should never fail");
        dr.count
    }
}

/// A driver-agnostic kindness of a gadget.
///
/// The [`Gadget::Kind`] associated type is used to specify the driver-agnostic
/// _kind_ of a gadget, using this trait to specify how gadgets can have their
/// driver-specific components mapped to a rebound gadget type. This type must
/// be `'static` so that drivers can use dynamic typing to differentiate between
/// (otherwise opaque) gadgets.
///
/// Implementations of this trait define a generic associated type
/// [`Rebind`](GadgetKind::Rebind) which dictates the type of the gadget when
/// bound to a specific driver. The `map` method defines how a gadget
/// `Rebind<'dr, D1>` of one driver `D1` can be translated into a gadget
/// `Rebind<'dr, D2>` for another driver `D2`. The mapping can leverage the
/// [`FromDriver`] trait to convert wires.
///
/// # Safety
///
/// This trait is unsafe to implement because the following property must hold:
///
/// * `D::Wire: Send` implies `Rebind<'dr, D>: Send`.
///
/// It is difficult to express this bound for all gadgets in Rust's type system,
/// though it can be done with enormous API complexity. Instead, this trait is
/// `unsafe` to implement and the implementor must ensure that this property
/// holds. The [`Gadget`](derive@Gadget) derive macro ensures that this is the
/// case.
pub unsafe trait GadgetKind<F: Field>: core::any::Any {
    /// The rebinding type for this gadget.
    type Rebind<'dr, D: Driver<'dr, F = F>>: Gadget<'dr, D, Kind = Self>;

    /// Maps a gadget of this kind to a new driver type.
    fn map_gadget<'dr, 'new_dr, D: Driver<'dr, F = F>, ND: FromDriver<'dr, 'new_dr, D>>(
        this: &Self::Rebind<'dr, D>,
        ndr: &mut ND,
    ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>>;

    /// Enforces that two gadgets' wires are equal.
    ///
    /// The provided driver is used to create linear constraints between the
    /// gadgets' wires through recursive descent through the gadget structure.
    /// The provided gadgets can be for another driver, since it's only
    /// important that the wire type be the same.
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Self::Rebind<'dr, D2>,
        b: &Self::Rebind<'dr, D2>,
    ) -> Result<()>;
}

/// Automatically derives the [`Gadget`], [`GadgetKind`] and [`Clone`] traits
/// for common gadget types.
///
/// This only works for structs with named fields. Enums are disallowed because
/// their discriminants constitute instance state that would violate the
/// fungibility requirement.
///
/// ## Example
///
/// ```rust
/// # use ragu_core::{drivers::{Driver, DriverValue}, gadgets::Gadget};
/// #[derive(Gadget)]
/// struct Boolean<'dr, D: Driver<'dr>> {
///     #[ragu(wire)]
///     wire: D::Wire,
///     #[ragu(value)]
///     value: DriverValue<D, bool>,
/// }
/// ```
///
/// This automatically derives [`Gadget`], [`GadgetKind`] and [`Clone`]
/// implementations for your struct. Fields can be annotated to specify their
/// type:
/// * Fields without any annotation default to gadget fields, which are
///   converted using [`GadgetKind::map_gadget`].
/// * `#[ragu(wire)]` for fields that represent wires in the driver, which are
///   converted using [`FromDriver::convert_wire`].
/// * `#[ragu(value)]` for fields that represent driver-specific values, which
///   are converted or cloned using
///   [`DriverValue::just`](crate::maybe::Maybe::just).
/// * `#[ragu(gadget)]` can be used to explicitly mark gadget fields, but is
///   optional since this is the default behavior.
/// * `#[ragu(phantom)]` for `PhantomData` fields.
///
/// The macro assumes by default that the driver type is `D` and determines the
/// lifetime by analyzing the bounds. It is possible to override the default
/// type parameter used as the driver for the gadget by annotating it with
/// `#[ragu(driver)]` like so:
///
/// ```rust
/// # use ragu_core::{drivers::{Driver, DriverValue}, gadgets::Gadget};
/// #[derive(Gadget)]
/// struct Boolean<'my_dr, #[ragu(driver)] MyD: Driver<'my_dr>> {
///     #[ragu(wire)]
///     wire: MyD::Wire,
///     #[ragu(value)]
///     value: DriverValue<MyD, MyD::F>,
/// }
/// ```
pub use ragu_macros::Gadget;

/// Obtains the concrete [`GadgetKind<F>`] of a [`Gadget`] type given only the
/// gadget's type and a field type `F`. This is particularly useful in contexts
/// where a specific concrete driver does not exist or the type is annoying to
/// write by hand.
///
/// ## Usage
///
/// The macro is provided the field type `F` and the gadget type `G`, separated
/// by a semicolon. Anywhere in the gadget type where a driver is expected, you
/// can instead use a bare `_`, and anywhere the driver's lifetime `'dr` is
/// expected you can use `'_` instead.
///
/// ```rust
/// # use ff::Field;
/// # use ragu_core::{drivers::{Driver, DriverValue}, gadgets::Kind};
/// # #[derive(ragu_core::gadgets::Gadget)]
/// # struct Boolean<'my_dr, #[ragu(driver)] MyD: Driver<'my_dr>> {
/// #     #[ragu(wire)]
/// #     wire: MyD::Wire,
/// #     #[ragu(value)]
/// #     value: DriverValue<MyD, MyD::F>,
/// # }
/// # trait MyTrait<F: Field> {
/// #     type Kind: ragu_core::gadgets::GadgetKind<F>;
/// # }
/// # struct Foo;
/// impl<F: Field> MyTrait<F> for Foo {
///     type Kind = Kind![F; Boolean<'_, _>];
/// }
/// ```
///
/// In this example, the `Kind!` macro expands to the type
///
/// ```rust
/// # use ff::Field;
/// # use ragu_core::{drivers::{Driver, DriverValue}, gadgets::{Kind, Gadget}};
/// # use core::marker::PhantomData;
/// # #[derive(ragu_core::gadgets::Gadget)]
/// # struct Boolean<'my_dr, #[ragu(driver)] MyD: Driver<'my_dr>> {
/// #     #[ragu(wire)]
/// #     wire: MyD::Wire,
/// #     #[ragu(value)]
/// #     value: DriverValue<MyD, MyD::F>,
/// # }
/// # type MyKind<F: Field> =
/// <Boolean<'static, PhantomData<F>> as Gadget<'static, PhantomData<F>>>::Kind
/// # ;
/// ```
///
/// This works because [`PhantomData<F>`](core::marker::PhantomData) implements
/// [`Driver<'static>`](Driver) for all fields `F`, and the circular constraint
/// between [`Gadget::Kind`] and the rebind type [`GadgetKind::Rebind`] requires
/// the resulting [`GadgetKind`] type to be the (only) correct one. This macro
/// only works in contexts where the (possibly generic) [`Field`] type `F` is
/// known, and any other constraints on the [`Gadget`] implementation are
/// satisfied.
///
/// In some contexts (like the `Self` type of an impl) the fully qualified
/// expansion runs afoul of strict portions of Rust's coherence and type
/// parameter constraint rules even though the type does not violate them. In
/// these cases, it's usually sufficient to put an `@` symbol at the start of
/// your type, like `Kind![F; @Boolean<'_, _>]`, which signals to the procedural
/// macro that it should perform the substitution without qualifications, which
/// works fine in most cases.
pub use ragu_macros::gadget_kind as Kind;

/// Enforces a gadget's internal constraints on existing wires.
///
/// Some gadgets require internal invariants for correctness; a `Point` must
/// satisfy its curve equation, a `Boolean` must be 0 or 1. This trait enforces
/// those constraints on wires allocated elsewhere, separating allocation from
/// constraint enforcement.
///
/// Gadgets without internal constraints (like `Element`) implement this as a
/// no-op. Composite gadgets delegate to their fields.
pub trait Consistent<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    /// Enforce internal consistency constraints on this gadget's wires.
    fn enforce_consistent(&self, dr: &mut D) -> Result<()>;
}

/// Derives [`Consistent`] by calling `enforce_consistent` on `#[ragu(gadget)]` fields.
pub use ragu_macros::Consistent;
