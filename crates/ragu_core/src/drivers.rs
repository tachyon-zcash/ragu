//! Unified interface for writing cryptographic protocols and arithmetic
//! circuits in Ragu.
//!
//! ## Design
//!
//! The fundamental interface of Ragu is [`Driver`], a trait that describes an
//! interpreter or synthesis context for cryptographic protocols. Nearly all
//! protocols in Ragu are implemented in terms of drivers—even those not
//! ultimately evaluated inside circuits—enabling most of the codebase to share
//! a common execution model.
//!
//! Drivers allow users to create wires, assign values to them, constrain them
//! in different ways and write code that manipulates their corresponding
//! witness data. The unified design of drivers confers several benefits for
//! implementations of cryptographic algorithms that are synthesized into
//! circuits:
//!
//! * **Integration of witness evaluation**: Constraints can be written
//!   alongside witness computation logic, even though drivers tend to reason
//!   about one or the other. To reduce overhead, drivers specify a [`Maybe<T>`]
//!   type (via the type alias [`DriverValue`]) which enables static analysis and
//!   optimization of witness computation for a specific driver context. This
//!   coupling with witness evaluation logic is a zero-cost abstraction.
//! * **Integration of in-circuit and out-of-circuit code**: Recursive proofs
//!   require many algorithms to be executed both within and outside of
//!   circuits, and these implementations must remain consistent for
//!   completeness. The driver abstraction allows these algorithms to be written
//!   once and reused in both contexts with minimal overhead.
//! * **Specialization of wire types**: Drivers define their own (opaque) wire
//!   type [`Driver::Wire`], which users can only clone. Driver-specific wire
//!   types allow simpler implementations of drivers for a wider variety of
//!   contexts. The optimal representation of wires can vary widely: they might
//!   be smart pointers, partial polynomial evaluations, assignment values, or
//!   even just the unit type `()`. Monomorphized circuit synthesis code
//!   inherits memory and performance optimizations from these specializations.
//!
//! ### Routines
//!
//! Drivers can execute circuit synthesis within well-defined abstraction
//! boundaries called [routines](crate::routines). In exchange for a slightly
//! stricter API, users can give drivers flexibility in how circuit synthesis is
//! performed---permitting aggressive parallelization, memoization and other
//! optimizations. In order to achieve this, drivers implement the
//! [`FromDriver`] trait to specify how wires can be translated from one driver
//! to another.

use arithmetic::Coeff;
use ff::Field;

use crate::{
    Result,
    gadgets::GadgetKind,
    maybe::{Maybe, MaybeKind},
    routines::{Prediction, Routine},
};

mod emulator;
mod linexp;
mod phantom;
mod simulator;

pub use emulator::Emulator;
pub use linexp::{DirectSum, LinearExpression};
pub use simulator::Simulator;

/// Alias for the concrete [`Maybe<T>`] type for a driver `D`, used to represent input data
/// that may or may not be available. This provides a uniform interface for both public
/// and private data.
pub type DriverValue<D, T> = <<D as DriverTypes>::MaybeKind as MaybeKind>::Rebind<T>;

/// Defines implementation types for a concrete driver. Users of drivers do not
/// need to directly interact with this trait.
pub trait DriverTypes {
    /// The field that this driver operates over.
    type ImplField: Field;

    /// The type of wire that this driver provides.
    type ImplWire: Clone;

    /// The kind of [`Maybe<T>`] types for witness values that this driver
    /// expects.
    type MaybeKind: MaybeKind;

    /// The concrete linear expression type that this driver uses for obtaining
    /// sum for addition gates.
    type LCadd: LinearExpression<Self::ImplWire, Self::ImplField>;

    /// The concrete linear expression type that this driver uses for obtaining
    /// sums for linear constraints.
    type LCenforce: LinearExpression<Self::ImplWire, Self::ImplField>;
}

/// A context for executing cryptographic algorithms and synthesizing their
/// corresponding arithmetic circuits.
///
/// Drivers are used to write code that is intended to be synthesized into
/// arithmetic circuits over a field determined by the [`Driver::F`] associated
/// type. Arithmetic circuits are represented in Ragu (equivalently) as a set of
/// wires for multiplication gates and a set of linear constraints placed on
/// their assigned field values to encode addition gates.
///
/// ## Usage
///
/// * Wires can be created with the [`alloc`](Driver::alloc) and
///   [`mul`](Driver::mul) methods. The [`add`](Driver::add) method can also
///   create a virtual wire that is defined as a linear combination of some
///   existing wires. The [`constant`](Driver::constant) method is a helper for
///   creating a wire with a constant value.
/// * Wires are assigned values upon their creation; the driver may or may not
///   need to obtain these values depending on whether or not a witness for them
///   is expected.
/// * Users keep track of wire assignments or related witness data using a
///   driver-specific [`DriverValue`] type. This type implements an
///   `Option`-like abstraction called [`Maybe`] which allows for compile-time
///   optimization and static analysis of witness data computation and memory.
/// * Finally, and most importantly, wires can be constrained in two ways:
///     * The [`mul`](Driver::mul) method enforces a multiplicative constraint
///       on the created wires; the wires are the inputs and output of a
///       multiplication gate of an arithmetic circuit.
///     * The [`enforce_zero`](Driver::enforce_zero) method can be used to
///       require that a linear combination of wires equals zero.
///
/// ## `'dr` lifetime
///
/// Drivers are parameterized by a lifetime `'dr`. Routines are constrained to
/// outlive this lifetime so that references to non-`'static` parameters or
/// witness data can be placed inside of them while still allowing drivers to
/// use multithreaded execution.
pub trait Driver<'dr>: DriverTypes<ImplWire = Self::Wire, ImplField = Self::F> + Sized {
    /// The field that this driver operates over.
    type F: Field;

    /// The type of wire that this driver provides. These values are
    /// deliberately opaque to users: they can be cloned, but they cannot be
    /// compared or manipulated in any other way.
    type Wire: Clone;

    /// Drivers guarantee that a fixed wire is assigned the value $1$.
    const ONE: Self::Wire;

    /// Asks the driver to allocate a new wire.
    ///
    /// The provided closure may be called by the driver if an assignment is
    /// needed. If it is called, any errors are propagated from it, and the
    /// closure can rely on [`Witness<Self, T>::take`](Maybe::take) succeeding
    /// unconditionally.
    fn alloc(&mut self, value: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire>;

    /// Returns a virtual wire that has a fixed constant value.
    fn constant(&mut self, value: Coeff<Self::F>) -> Self::Wire {
        self.add(|lc| lc.add_term(&Self::ONE, value))
    }

    /// Asks the driver to allocate the wires $(A, B, C)$ with the constraint $A
    /// \cdot B = C$.
    ///
    /// The provided closure may be called by the driver if an assignment is
    /// needed. If it is called, any errors are propagated from it, and the
    /// closure can rely on [`Witness<Self, T>::take`](Maybe::take) succeeding
    /// unconditionally.
    fn mul(
        &mut self,
        values: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)>;

    /// Asks the driver to create a virtual wire that is the linear combination
    /// of some existing wires. This may impose some runtime cost for circuit
    /// synthesis depending on the driver. However, it is relatively "free" to
    /// perform this operation as it does not require an actual constraint to be
    /// created, since unlimited fan-in addition gates do not have a cost in
    /// `ragu`'s circuit model.
    ///
    /// The provided closure _may_ be called to obtain the linear combination.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire;

    /// Asks the driver to create a constraint that a linear combination of
    /// wires equals zero.
    ///
    /// The provided closure _may_ be called to obtain the linear combination.
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()>;

    /// Enforces that two wires are equal.
    fn enforce_equal(&mut self, a: &Self::Wire, b: &Self::Wire) -> Result<()> {
        self.enforce_zero(|lc| lc.add(a).sub(b))
    }

    /// Proxy for the `Input::just` method for this driver.
    fn just<R: Send>(f: impl FnOnce() -> R) -> DriverValue<Self, R> {
        <DriverValue<Self, R> as Maybe<R>>::just(f)
    }

    /// Proxy for the `Witness::with` method for this driver.
    fn with<R: Send>(f: impl FnOnce() -> Result<R>) -> Result<DriverValue<Self, R>> {
        <DriverValue<Self, R> as Maybe<R>>::with(f)
    }

    /// Executes a routine with this driver.
    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        let mut dummy = Emulator::<Self::MaybeKind, Self::F>::default();
        let dummy_input = R::Input::map_gadget(&input, &mut dummy)?;
        match routine.predict(&mut dummy, &dummy_input)? {
            Prediction::Known(_, aux) | Prediction::Unknown(aux) => {
                routine.execute(self, input, aux)
            }
        }
    }
}

/// Conversion context that is capable of transforming wires from one driver to
/// another.
pub trait FromDriver<'dr, 'new_dr, D: Driver<'dr>> {
    /// The new driver type that uses the same field.
    type NewDriver: Driver<'new_dr, F = D::F>;

    /// Proxy for the `Witness::just` method for the new driver.
    fn just<R: Send>(f: impl FnOnce() -> R) -> DriverValue<Self::NewDriver, R> {
        <DriverValue<Self::NewDriver, R> as Maybe<R>>::just(f)
    }

    /// Converts a wire from `D` to the new driver's wire type, based on
    /// contextual information.
    fn convert_wire(
        &mut self,
        wire: &D::Wire,
    ) -> Result<<Self::NewDriver as Driver<'new_dr>>::Wire>;
}
