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
//! but it _can_ be used to collect and compute wire assignments. In the latter
//! case, it should be instantiated in the [`Wired`] mode. Otherwise, the
//! [`Wireless`] mode is appropriate.
//!
//! ### Wire Extraction
//!
//! One of the common uses of an [`Emulator`] instantiated in [`Wired`] mode is
//! for computing the expected wire assignments for a [`Gadget`] after executing
//! a [`Routine`] or some other circuit code. Of course, wire assignments never
//! exist when a witness does not exist. Still, [`Wired`] mode is parameterized
//! by a [`MaybeKind`] so that a wired [`Emulator`] can be invoked in contexts
//! where witness availability depends on another driver's behavior, such as
//! invoking an [`Emulator`] within circuit code itself.
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
//! [`Emulator::wired`], and in [`Wireless`] mode using [`Emulator::wireless`].
//!
//! There are two shorthand methods for constructing an [`Emulator`]:
//! * [`Emulator::extractor`] can be used to create a wired [`Emulator`] when a
//!   witness is expected to exist ([`MaybeKind`] = [`Always`]).
//! * [`Emulator::execute`] can similarly be used to create a wireless
//!   [`Emulator`] when a witness is expected to exist. This is the common case
//!   of executing circuit code natively.
//!
//! In [`Wired`] mode, wire assignments can be extracted from a gadget using
//! [`Emulator::wires`]; the returned wires are [`MaybeWired`] values that may
//! or may not have known values depending on the parameterized [`MaybeKind`].
//! In the case that a witness always exists, [`Emulator::always_wires`] can be
//! used instead to fetch the values directly.

use core::marker::PhantomData;
use ff::Field;

use alloc::vec::Vec;

use crate::{
    Result,
    drivers::{Coeff, DirectSum, Driver, DriverTypes, FromDriver, LinearExpression},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
    routines::{Prediction, Routine},
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
pub struct Wired<M: MaybeKind, F: Field>(PhantomData<(M, F)>);

/// Container for a [`Field`] element representing a wire assignment that may or
/// may not be known depending on the parameterized [`MaybeKind`].
pub enum MaybeWired<M: MaybeKind, F: Field> {
    /// The special wire representing the constant $1$.
    One,

    /// A wire with an assigned value.
    Assigned(M::Rebind<F>),
}

impl<M: MaybeKind, F: Field> MaybeWired<M, F> {
    /// Retrieves the underlying wire assignment value.
    pub fn value(self) -> M::Rebind<F> {
        match self {
            MaybeWired::One => M::maybe_just(|| F::ONE),
            MaybeWired::Assigned(value) => value,
        }
    }

    /// Retrieves a reference to the underlying wire value.
    fn snag<'a>(&'a self, one: &'a F) -> &'a F {
        match self {
            MaybeWired::One => one,
            MaybeWired::Assigned(value) => value.snag(),
        }
    }
}

impl<M: MaybeKind, F: Field> Clone for MaybeWired<M, F> {
    fn clone(&self) -> Self {
        match self {
            MaybeWired::One => MaybeWired::One,
            MaybeWired::Assigned(value) => MaybeWired::Assigned(value.clone()),
        }
    }
}

/// Implementation of [`LinearExpression`] for a [`DirectSum`] that may or may
/// not have a known value depending on the parameterized [`MaybeKind`].
pub struct MaybeDirectSum<M: MaybeKind, F: Field>(M::Rebind<DirectSum<F>>);

impl<M: MaybeKind, F: Field> LinearExpression<MaybeWired<M, F>, F> for MaybeDirectSum<M, F> {
    fn add_term(self, wire: &MaybeWired<M, F>, coeff: Coeff<F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.add_term(wire.snag(&F::ONE), coeff)))
    }

    fn gain(self, coeff: Coeff<F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.gain(coeff)))
    }

    fn extend(self, with: impl IntoIterator<Item = (MaybeWired<M, F>, Coeff<F>)>) -> Self {
        MaybeDirectSum(self.0.map(|sum| {
            sum.extend(
                with.into_iter()
                    .map(|(wire, coeff)| (wire.value().take(), coeff)),
            )
        }))
    }

    fn add(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.add(wire.snag(&F::ONE))))
    }

    fn sub(self, wire: &MaybeWired<M, F>) -> Self {
        MaybeDirectSum(self.0.map(|sum| sum.sub(wire.snag(&F::ONE))))
    }
}

impl<M: MaybeKind, F: Field> Mode for Wired<M, F> {
    type MaybeKind = M;
    type F = F;
    type Wire = MaybeWired<M, F>;
    type LCadd = MaybeDirectSum<M, F>;
    type LCenforce = MaybeDirectSum<M, F>;
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
pub struct Emulator<M: Mode>(PhantomData<M>);

impl<M: MaybeKind, F: Field> Emulator<Wired<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wired`] mode, parameterized on
    /// the existence of a witness.
    pub fn wired() -> Self {
        Emulator(PhantomData)
    }

    /// Extract the wires from a gadget produced using a wired [`Emulator`].
    ///
    /// Wire assignments are not directly returned by this method because wired
    /// [`Emulator`]s are parameterized by a [`MaybeKind`]. Instead,
    /// [`MaybeWired`] wires are returned. If a witness [`Always`] exists then
    /// the caller should prefer to use [`Emulator::always_wires`].
    pub fn wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<MaybeWired<M, F>>> {
        /// A conversion utility for extracting wire values.
        struct WireExtractor<M: MaybeKind, F: Field> {
            wires: Vec<MaybeWired<M, F>>,
        }

        impl<M: MaybeKind, F: Field> FromDriver<'_, '_, Emulator<Wired<M, F>>> for WireExtractor<M, F> {
            type NewDriver = PhantomData<F>;

            fn convert_wire(
                &mut self,
                wire: &MaybeWired<M, F>,
            ) -> Result<<Self::NewDriver as Driver<'_>>::Wire> {
                self.wires.push(wire.clone());
                Ok(())
            }
        }

        let mut collector = WireExtractor { wires: Vec::new() };
        <G::Kind as GadgetKind<F>>::map_gadget(gadget, &mut collector)?;
        Ok(collector.wires)
    }
}

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, parameterized on
    /// the existence of a witness.
    pub fn wireless() -> Self {
        Emulator(PhantomData)
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

impl<F: Field> Emulator<Wired<Always<()>, F>> {
    /// Extract the wires from a gadget produced using a wired [`Emulator`] that
    /// expects a witness to exist. This method returns the actual wire
    /// assignments if it is successful.
    pub fn always_wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<F>> {
        Ok(self
            .wires(gadget)?
            .into_iter()
            .map(|w| w.value().take())
            .collect())
    }

    /// Creates a new [`Emulator`] driver in [`Wired`] mode, specifically for
    /// executing with a known witness.
    ///
    /// This is useful for extracting wire assignments from a [`Gadget`] using
    /// [`Emulator::always_wires`].
    pub fn extractor() -> Self {
        Emulator(PhantomData)
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
        Ok(((), (), ()))
    }

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
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

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<Wired<M, F>> {
    type F = F;
    type Wire = MaybeWired<M, F>;
    const ONE: Self::Wire = MaybeWired::One;

    fn alloc(&mut self, f: impl Fn() -> Result<Coeff<Self::F>>) -> Result<Self::Wire> {
        f().map(|coeff| MaybeWired::Assigned(M::maybe_just(|| coeff.value())))
    }

    fn constant(&mut self, coeff: Coeff<Self::F>) -> Self::Wire {
        MaybeWired::Assigned(M::maybe_just(|| coeff.value()))
    }

    fn mul(
        &mut self,
        f: impl Fn() -> Result<(Coeff<Self::F>, Coeff<Self::F>, Coeff<Self::F>)>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire)> {
        let (a, b, c) = f()?;

        // Despite wires existing, the emulator does not enforce multiplication
        // constraints.

        Ok((
            MaybeWired::Assigned(M::maybe_just(|| a.value())),
            MaybeWired::Assigned(M::maybe_just(|| b.value())),
            MaybeWired::Assigned(M::maybe_just(|| c.value())),
        ))
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(MaybeDirectSum(M::maybe_just(DirectSum::default)));
        MaybeWired::Assigned(lc.0.map(|sum| sum.value))
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        // Despite wires existing, the emulator does not enforce linear
        // constraints.

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
