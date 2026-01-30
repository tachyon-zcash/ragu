//! Driver for executing circuit code natively with minimal overhead.
//!
//! ## Overview
//!
//! Circuit code is written with the [`Driver`] abstraction, which is used to
//! express operations such as allocating wires and enforcing constraints
//! alongside the corresponding witness generation logic. The simplest driver
//! would be one that simply executes circuit code directly _without_ enforcing
//! constraints; that is the purpose of this module's [`Emulator`].
//!
//! The [`Emulator`] driver never checks multiplication or linear constraints,
//! but it _can_ be used to collect and compute wire assignments.
//! When instantiated in [`Wireless`] mode, the emulator simply executes the
//! circuit code natively without wires (i.e., `Wire=()`), saving memory.
//! Whereas in [`Wired`] mode, the emulator tracks wire assignments which can
//! be extracted afterwards.
//!
//! The [`Wireless`] mode is parameterized by a [`MaybeKind`] to indicate
//! witness availability:
//!
//! * `Wireless<Empty, F>`: used for counting operations and other static
//!   structure analyses without requiring witness values. Constructed via
//!   [`Emulator::counter`]. Operation counts are available via
//!   [`Emulator::num_multiplications`] and [`Emulator::num_constraints`].
//! * `Wireless<Always<()>, F>`: used for native witness execution/generation,
//!   constructed via [`Emulator::execute`] or directly execute the logic with
//!   [`Emulator::emulate_wireless`].
//!
//! The [`Wired`] mode always has witness availability (i.e., `Always<()>`):
//!
//! * `Wired<F>`: used for native execution with wire extraction. Constructed
//!   via [`Emulator::extractor`] or directly execute the logic with
//!   [`Emulator::emulate_wired`].
//!
//! Sometimes, witness availability depends on other drivers' behavior, such as
//! when invoking an [`Emulator`] within generic circuit code itself. In such
//! cases, [`Emulator::wireless`] can be used to create wireless emulators
//! parameterized by [`MaybeKind`].
//!
//! ### Wire Extraction
//!
//! One of the common uses of an [`Emulator`] instantiated in [`Wired`] mode is
//! for computing the expected wire assignments for a [`Gadget`] after executing
//! a [`Routine`] or some other circuit code.
//!
//! ### Routines
//!
//! [`Emulator`]s are used for _natively_ executing code, not enforcing
//! correctness. As such, they short-circuit execution of [`Routine`]s using
//! [routine prediction](Routine::predict) when possible.
//!
//! ## Usage
//!
//! The [`Emulator`] can be instantiated in [`Wired`] mode using
//! [`Emulator::extractor`], and in [`Wireless`] mode using
//! [`Emulator::wireless`], [`Emulator::counter`], or [`Emulator::execute`].
//!
//! Common constructor methods:
//! * [`Emulator::extractor`] creates a wired [`Emulator`] for extracting wire
//!   assignments from a gadget.
//! * [`Emulator::execute`] creates a wireless [`Emulator`] for native witness
//!   execution/generation. This is the common case of executing circuit code
//!   natively.
//! * [`Emulator::counter`] creates a wireless [`Emulator`] for counting
//!   operations (multiplications and constraints) without witness data.
//!
//! In [`Wired`] mode, wire assignments can be extracted from a gadget using
//! [`Emulator::wires`], which returns a `Vec<F>` of field elements.

use ff::Field;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{
    Result,
    drivers::{Coeff, DirectSum, Driver, DriverTypes, FromDriver, LinearExpression},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Empty, MaybeKind},
    routines::{Prediction, Routine, RoutineShape},
};

/// Mode that an [`Emulator`] may be running in; usually either [`Wired`] or
/// [`Wireless`].
pub trait Mode {
    /// Equal to the resulting [`Emulator`]'s [`DriverTypes::MaybeKind`].
    type MaybeKind: MaybeKind;

    /// Equal to the resulting [`Emulator`]'s [`DriverTypes::ImplField`].
    type F: Field;

    /// Equal to the resulting [`Emulator`]'s [`DriverTypes::ImplWire`].
    type Wire: Clone;

    /// Equal to the resulting [`Emulator`]'s [`DriverTypes::LCadd`].
    type LCadd: LinearExpression<Self::Wire, Self::F>;

    /// Equal to the resulting [`Emulator`]'s [`DriverTypes::LCenforce`].
    type LCenforce: LinearExpression<Self::Wire, Self::F>;
}

/// Mode for an [`Emulator`] that tracks wire assignments.
///
/// Wired mode always has witness availability (i.e., `MaybeKind = Always<()>`).
pub struct Wired<F: Field>(PhantomData<F>);

/// Container for a [`Field`] element representing a wire assignment.
///
/// Wire values are exposed through [`Emulator::wires`].
pub enum WiredValue<F: Field> {
    /// The special wire representing the constant $1$.
    One,

    /// A wire with an assigned value.
    Assigned(F),
}

impl<F: Field> WiredValue<F> {
    /// Retrieves the underlying wire assignment value.
    pub fn value(self) -> F {
        match self {
            WiredValue::One => F::ONE,
            WiredValue::Assigned(value) => value,
        }
    }

    /// Retrieves a reference to the underlying wire value.
    fn snag<'a>(&'a self, one: &'a F) -> &'a F {
        match self {
            WiredValue::One => one,
            WiredValue::Assigned(value) => value,
        }
    }
}

impl<F: Field> Clone for WiredValue<F> {
    fn clone(&self) -> Self {
        match self {
            WiredValue::One => WiredValue::One,
            WiredValue::Assigned(value) => WiredValue::Assigned(*value),
        }
    }
}

/// Implementation of [`LinearExpression`] for wired mode's [`DirectSum`].
pub struct WiredDirectSum<F: Field>(DirectSum<F>);

impl<F: Field> LinearExpression<WiredValue<F>, F> for WiredDirectSum<F> {
    fn add_term(self, wire: &WiredValue<F>, coeff: Coeff<F>) -> Self {
        WiredDirectSum(self.0.add_term(wire.snag(&F::ONE), coeff))
    }

    fn gain(self, coeff: Coeff<F>) -> Self {
        WiredDirectSum(self.0.gain(coeff))
    }

    fn extend(self, with: impl IntoIterator<Item = (WiredValue<F>, Coeff<F>)>) -> Self {
        WiredDirectSum(
            self.0
                .extend(with.into_iter().map(|(wire, coeff)| (wire.value(), coeff))),
        )
    }

    fn add(self, wire: &WiredValue<F>) -> Self {
        WiredDirectSum(self.0.add(wire.snag(&F::ONE)))
    }

    fn sub(self, wire: &WiredValue<F>) -> Self {
        WiredDirectSum(self.0.sub(wire.snag(&F::ONE)))
    }
}

impl<F: Field> Mode for Wired<F> {
    type MaybeKind = Always<()>;
    type F = F;
    type Wire = WiredValue<F>;
    type LCadd = WiredDirectSum<F>;
    type LCenforce = WiredDirectSum<F>;
}

/// Mode for an [`Emulator`] that does not track wire assignments.
pub struct Wireless<M: MaybeKind, F: Field>(PhantomData<(M, F)>);

impl<M: MaybeKind, F: Field> Mode for Wireless<M, F> {
    type MaybeKind = M;
    type F = F;
    type Wire = ();
    type LCadd = ();
    type LCenforce = ();
}

/// A driver used to natively execute circuit code without enforcing
/// constraints. This driver also short-circuit [`Routine`] execution using
/// their provided [`Routine::predict`] method when possible.
///
/// See the [module level documentation](self) for more information.
///
/// ## [`Mode`]
///
/// The [`Emulator`] driver is parameterized on a [`Mode`], which determines
/// whether wire assignments are tracked or not ([`Wired`] vs. [`Wireless`]).
///
/// ## Operation Counting
///
/// The [`Emulator`] tracks the number of multiplication gates and linear
/// constraints encountered during execution. This is useful for determining
/// the shape of routines without requiring witness values. Access these counts
/// via [`num_multiplications`](Emulator::num_multiplications) and
/// [`num_constraints`](Emulator::num_constraints).
pub struct Emulator<M: Mode> {
    num_multiplications: usize,
    num_constraints: usize,
    _marker: PhantomData<M>,
}

impl<M: Mode> Emulator<M> {
    /// Returns the number of multiplication gates encountered.
    pub fn num_multiplications(&self) -> usize {
        self.num_multiplications
    }

    /// Returns the number of linear constraints encountered.
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    /// Returns the current operation counts as a [`RoutineShape`].
    ///
    /// This is useful for verifying that a routine's reported shape matches
    /// its actual execution.
    pub fn shape(&self) -> RoutineShape {
        RoutineShape::new(self.num_multiplications, self.num_constraints)
    }

    /// Resets the operation counters to zero.
    pub fn reset_counters(&mut self) {
        self.num_multiplications = 0;
        self.num_constraints = 0;
    }
}

impl<F: Field> Emulator<Wired<F>> {
    /// Extract the wires from a gadget produced using a wired [`Emulator`].
    /// This method returns the actual wire assignments if successful.
    pub fn wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<F>> {
        /// A conversion utility for extracting wire values.
        struct WireExtractor<F: Field> {
            wires: Vec<WiredValue<F>>,
        }

        impl<F: Field> FromDriver<'_, '_, Emulator<Wired<F>>> for WireExtractor<F> {
            type NewDriver = PhantomData<F>;

            fn convert_wire(
                &mut self,
                wire: &WiredValue<F>,
            ) -> Result<<Self::NewDriver as Driver<'_>>::Wire> {
                self.wires.push(wire.clone());
                Ok(())
            }
        }

        let mut collector = WireExtractor { wires: Vec::new() };
        <G::Kind as GadgetKind<F>>::map_gadget(gadget, &mut collector)?;
        Ok(collector.wires.into_iter().map(|w| w.value()).collect())
    }

    /// Creates a new [`Emulator`] driver in [`Wired`] mode for executing with
    /// a known witness.
    ///
    /// This is useful for extracting wire assignments from a [`Gadget`] using
    /// [`Emulator::wires`].
    pub fn extractor() -> Self {
        Emulator {
            num_multiplications: 0,
            num_constraints: 0,
            _marker: PhantomData,
        }
    }

    /// Helper utility for executing a closure with a freshly created wired
    /// [`Emulator`] when a witness is expected to exist.
    pub fn emulate_wired<R, W: Send>(
        witness: W,
        f: impl FnOnce(&mut Self, Always<W>) -> Result<R>,
    ) -> Result<R> {
        let mut dr = Self::extractor();
        dr.with(witness, f)
    }
}

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, parameterized on
    /// the existence of a witness.
    pub fn wireless() -> Self {
        Emulator {
            num_multiplications: 0,
            num_constraints: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Emulator<Wireless<Empty, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode for counting
    /// operations and static analysis on the circuit structure.
    ///
    /// This mode does not require witness values, making it suitable for
    /// determining routine shapes. Access operation counts via
    /// [`num_multiplications`](Emulator::num_multiplications) and
    /// [`num_constraints`](Emulator::num_constraints).
    pub fn counter() -> Self {
        Self::wireless()
    }

    /// Derives a [`RoutineShape`] by running a closure through a counter
    /// [`Emulator`].
    ///
    /// This is useful for implementing [`Routine::shape`] without manually
    /// calculating the number of multiplications and constraints.
    pub fn derive_shape(f: impl FnOnce(&mut Self)) -> RoutineShape {
        let mut dr = Self::counter();
        f(&mut dr);
        dr.shape()
    }
}

impl<F: Field> Emulator<Wireless<Always<()>, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, specifically for
    /// executing with a known witness.
    pub fn execute() -> Self {
        Self::wireless()
    }

    /// Helper utility for executing a closure with a freshly created wireless
    /// [`Emulator`] when a witness is expected to exist.
    pub fn emulate_wireless<R, W: Send>(
        witness: W,
        f: impl FnOnce(&mut Self, Always<W>) -> Result<R>,
    ) -> Result<R> {
        let mut dr = Self::execute();
        dr.with(witness, f)
    }
}

impl<M: Mode<F = F>, F: Field> Emulator<M> {
    /// Helper utility for executing a closure with this [`Emulator`].
    fn with<R, W: Send>(
        &mut self,
        witness: W,
        f: impl FnOnce(&mut Self, <M::MaybeKind as MaybeKind>::Rebind<W>) -> Result<R>,
    ) -> Result<R> {
        f(self, M::MaybeKind::maybe_just(|| witness))
    }
}

impl<M: Mode> DriverTypes for Emulator<M> {
    type ImplField = M::F;
    type ImplWire = M::Wire;
    type MaybeKind = M::MaybeKind;
    type LCadd = M::LCadd;
    type LCenforce = M::LCenforce;
}

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<Wireless<M, F>> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        Ok(())
    }

    fn constant(&mut self, _: Coeff<Self::F>) -> Self::Wire {}

    fn mul(
        &mut self,
        _: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        self.num_multiplications += 1;
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        self.num_constraints += 1;
        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        short_circuit_routine(self, routine, input)
    }
}

impl<'dr, F: Field> Driver<'dr> for Emulator<Wired<F>> {
    type F = F;
    type Wire = WiredValue<F>;
    const ONE: Self::Wire = WiredValue::One;

    fn alloc(&mut self, f: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        f().map(|coeff| WiredValue::Assigned(coeff.value()))
    }

    fn constant(&mut self, coeff: Coeff<Self::F>) -> Self::Wire {
        WiredValue::Assigned(coeff.value())
    }

    fn mul(
        &mut self,
        f: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = f()?;

        // Despite wires existing, the emulator does not enforce multiplication
        // constraints.

        self.num_multiplications += 1;
        Ok((
            WiredValue::Assigned(a.value()),
            WiredValue::Assigned(b.value()),
            WiredValue::Assigned(c.value()),
        ))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(WiredDirectSum(DirectSum::default()));
        WiredValue::Assigned(lc.0.value)
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        // Despite wires existing, the emulator does not enforce linear
        // constraints.

        self.num_constraints += 1;
        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: <R::Input as GadgetKind<Self::F>>::Rebind<'dr, Self>,
    ) -> Result<<R::Output as GadgetKind<Self::F>>::Rebind<'dr, Self>> {
        short_circuit_routine(self, routine, input)
    }
}

/// The [`Emulator`] will short-circuit execution if the [`Routine`] can predict
/// its output, as the [`Emulator`] is not involved in enforcing any
/// constraints.
fn short_circuit_routine<'dr, D: Driver<'dr>, R: Routine<D::F> + 'dr>(
    dr: &mut D,
    routine: R,
    input: <R::Input as GadgetKind<D::F>>::Rebind<'dr, D>,
) -> Result<<R::Output as GadgetKind<D::F>>::Rebind<'dr, D>> {
    match routine.predict(dr, &input)? {
        Prediction::Known(output, _) => Ok(output),
        Prediction::Unknown(aux) => routine.execute(dr, input, aux),
    }
}

/// Conversion utility useful for passing wireless gadgets into
/// [`Routine::predict`] to fulfill type system obligations.
impl<'dr, D: Driver<'dr>> FromDriver<'dr, '_, D> for Emulator<Wireless<D::MaybeKind, D::F>> {
    type NewDriver = Self;

    fn convert_wire(&mut self, _: &D::Wire) -> Result<()> {
        Ok(())
    }
}
