//! Driver for executing circuit code natively with minimal overhead.
//!
//! The [`Emulator`] driver never checks gate or constraint satisfaction,
//! but it _can_ be used to collect and compute wire assignments.
//! When instantiated in [`Wireless`] mode, the emulator simply executes the
//! circuit code natively without wires (i.e., `Wire=()`), saving memory.
//! Whereas in [`Wired`] mode, the emulator tracks wire assignments which can
//! be extracted afterwards.
//!
//! The [`Wireless`] mode is parameterized by a [`MaybeKind`] to indicate
//! witness availability:
//!
//! * `Wireless<Empty, F>`: used mostly for wire counting and other static
//!   structure analyses. Driver still executes natively, but with `Empty`
//!   witness. Constructed via [`Emulator::counter`].
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
//! * [`Emulator::counter`] creates a wireless [`Emulator`] for wire counting
//!   and static analysis without witness data.
//!
//! In [`Wired`] mode, wire assignments can be extracted from a gadget using
//! [`Emulator::wires`], which returns a `Vec<F>` of field elements.
//!
//! See also the [book] for a user-oriented introduction to the emulator.
//!
//! [book]: https://tachyon.z.cash/ragu/guide/drivers/concrete.html#emulator

use ff::Field;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{
    Result,
    convert::{StripWires, WireMap},
    drivers::{Coeff, DirectSum, Driver, DriverTypes, DriverValue, LinearExpression},
    gadgets::{Bound, Gadget, GadgetKind},
    maybe::{Always, Empty, MaybeKind, Perhaps},
    routines::{Prediction, Routine},
};

mod sealed {
    pub trait Sealed {}
}

/// Mode that an [`Emulator`] may be running in; usually either [`Wired`] or
/// [`Wireless`].
pub trait Mode: sealed::Sealed {
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

    /// Mode-specific gate allocation. Delegated to by
    /// [`DriverTypes::gate`] for [`Emulator<M>`].
    fn gate(
        values: impl Fn() -> Result<(
            Coeff<Self::F>,
            Coeff<Self::F>,
            Coeff<Self::F>,
            Coeff<Self::F>,
        )>,
    ) -> Result<(Self::Wire, Self::Wire, Self::Wire, Self::Wire)>;
}

/// Mode for an [`Emulator`] that tracks wire assignments.
///
/// Wired mode always has witness availability (i.e., `MaybeKind = Always<()>`).
pub struct Wired<F: Field>(PhantomData<F>);

impl<F: Field> sealed::Sealed for Wired<F> {}

impl<F: Field> Mode for Wired<F> {
    type MaybeKind = Always<()>;
    type F = F;
    type Wire = F;
    type LCadd = DirectSum<F>;
    type LCenforce = DirectSum<F>;

    fn gate(
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(F, F, F, F)> {
        let (a, b, c, d) = values()?;

        // Despite wires existing, the emulator does not enforce gate
        // equations.

        Ok((a.value(), b.value(), c.value(), d.value()))
    }
}

/// Mode for an [`Emulator`] that does not track wire assignments.
pub struct Wireless<M: MaybeKind, F: Field>(PhantomData<(M, F)>);

impl<M: MaybeKind, F: Field> sealed::Sealed for Wireless<M, F> {}

impl<M: MaybeKind, F: Field> Mode for Wireless<M, F> {
    type MaybeKind = M;
    type F = F;
    type Wire = ();
    type LCadd = ();
    type LCenforce = ();

    fn gate(
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<((), (), (), ())> {
        Ok(((), (), (), ()))
    }
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

impl<F: Field> Emulator<Wired<F>> {
    /// Extract the wires from a gadget produced using a wired [`Emulator`].
    /// This method returns the actual wire assignments if successful.
    pub fn wires<'dr, G: Gadget<'dr, Self>>(&self, gadget: &G) -> Result<Vec<F>> {
        /// A conversion utility for extracting wire values.
        struct WireExtractor<F: Field> {
            wires: Vec<F>,
        }

        impl<F: Field> WireMap<F> for WireExtractor<F> {
            type Src = Emulator<Wired<F>>;
            type Dst = PhantomData<F>;

            fn convert_wire(&mut self, wire: &F) -> Result<()> {
                self.wires.push(*wire);
                Ok(())
            }
        }

        let mut collector = WireExtractor { wires: Vec::new() };
        <G::Kind as GadgetKind<F>>::map_gadget(gadget, &mut collector)?;
        Ok(collector.wires)
    }

    /// Creates a new [`Emulator`] driver in [`Wired`] mode for executing with
    /// a known witness.
    ///
    /// This is useful for extracting wire assignments from a [`Gadget`] using
    /// [`Emulator::wires`].
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
        dr.try_just(witness, f)
    }
}

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, parameterized on
    /// the existence of a witness.
    pub fn wireless() -> Self {
        Emulator(PhantomData)
    }

    /// Runs [`Routine::predict`] on a fresh wireless emulator, converting the
    /// input gadget from the source driver automatically via [`StripWires`].
    ///
    /// The source driver `D` must share the same [`MaybeKind`] as this emulator
    /// so that witness availability is preserved across the conversion. Unlike
    /// calling [`Routine::predict`] directly, this associated function handles
    /// emulator construction and wire remapping in a single step.
    pub fn predict<'src, 'dst, D, Ro>(
        routine: &Ro,
        input: &Bound<'src, D, Ro::Input>,
    ) -> Result<Prediction<Bound<'dst, Self, Ro::Output>, DriverValue<Self, Ro::Aux<'dst>>>>
    where
        D: Driver<'src, F = F, MaybeKind = M>,
        Ro: Routine<F>,
    {
        let input = StripWires::remap(input)?;
        routine.predict(&mut Self::wireless(), &input)
    }
}

impl<F: Field> Emulator<Wireless<Empty, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, usually for
    /// counting wires or other static analysis on the circuit structure.
    pub fn counter() -> Self {
        Self::wireless()
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
        dr.try_just(witness, f)
    }
}

impl<M: Mode<F = F>, F: Field> Emulator<M> {
    /// Helper utility for executing a closure with this [`Emulator`].
    fn try_just<R, W: Send>(
        &mut self,
        witness: W,
        f: impl FnOnce(&mut Self, Perhaps<M::MaybeKind, W>) -> Result<R>,
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

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<M::F>, Coeff<M::F>, Coeff<M::F>, Coeff<M::F>)>,
    ) -> Result<(M::Wire, M::Wire, M::Wire, M::Wire)> {
        M::gate(values)
    }
}

impl<'dr, M: MaybeKind, F: Field> Driver<'dr> for Emulator<Wireless<M, F>> {
    type F = F;
    type Wire = ();
    const ONE: Self::Wire = ();

    fn constant(&mut self, _: Coeff<Self::F>) -> Self::Wire {}

    fn add(&mut self, _: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {}

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        Ok(())
    }

    fn routine<R: Routine<Self::F> + 'dr>(
        &mut self,
        routine: R,
        input: Bound<'dr, Self, R::Input>,
    ) -> Result<Bound<'dr, Self, R::Output>> {
        short_circuit_routine(self, routine, input)
    }
}

impl<'dr, F: Field> Driver<'dr> for Emulator<Wired<F>> {
    type F = F;
    type Wire = F;
    const ONE: Self::Wire = F::ONE;

    fn constant(&mut self, coeff: Coeff<Self::F>) -> Self::Wire {
        coeff.value()
    }

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let lc = lc(DirectSum::default());
        lc.value()
    }

    fn enforce_zero(&mut self, _: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        // Despite wires existing, the emulator does not enforce linear
        // constraints.

        Ok(())
    }
}

/// The [`Emulator`] will short-circuit execution if the [`Routine`] can predict
/// its output, as the [`Emulator`] is not involved in enforcing any
/// constraints.
fn short_circuit_routine<'dr, D: Driver<'dr, Wire = ()>, R: Routine<D::F> + 'dr>(
    dr: &mut D,
    routine: R,
    input: Bound<'dr, D, R::Input>,
) -> Result<Bound<'dr, D, R::Output>> {
    match routine.predict(dr, &input)? {
        Prediction::Known(output, _) => Ok(output),
        Prediction::Unknown(aux) => routine.execute(dr, input, aux),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use crate::drivers::{Coeff, Driver, DriverValue};
    use crate::maybe::{Always, Maybe};
    use crate::routines::{Prediction, Routine};
    use ff::Field;
    use ragu_pasta::Fp;

    type F = Fp;

    // Manual Gadget impl because the derive macro cannot resolve `ragu_core` from within the crate.
    struct TwoWires<'dr, D: Driver<'dr>> {
        a: D::Wire,
        b: D::Wire,
        _marker: core::marker::PhantomData<&'dr ()>,
    }

    impl<'dr, D: Driver<'dr>> Clone for TwoWires<'dr, D> {
        fn clone(&self) -> Self {
            TwoWires {
                a: self.a.clone(),
                b: self.b.clone(),
                _marker: core::marker::PhantomData,
            }
        }
    }

    struct TwoWiresKind;

    /// # Safety
    /// `D::Wire: Send` implies `TwoWires<'dr, D>: Send` since the struct
    /// only contains wires and `PhantomData`.
    unsafe impl<FieldType: Field> crate::gadgets::GadgetKind<FieldType> for TwoWiresKind {
        type Rebind<'dr, D: Driver<'dr, F = FieldType>> = TwoWires<'dr, D>;

        fn map_gadget<
            'src,
            'dst,
            WM: crate::convert::WireMap<
                    FieldType,
                    Src: Driver<'src, F = FieldType>,
                    Dst: Driver<'dst, F = FieldType>,
                >,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(TwoWires {
                a: wm.convert_wire(&this.a)?,
                b: wm.convert_wire(&this.b)?,
                _marker: core::marker::PhantomData,
            })
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = FieldType>,
            D2: Driver<'dr, F = FieldType, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Bound<'dr, D2, Self>,
            b: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            dr.enforce_equal(&a.a, &b.a)?;
            dr.enforce_equal(&a.b, &b.b)?;
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>> crate::gadgets::Gadget<'dr, D> for TwoWires<'dr, D> {
        type Kind = TwoWiresKind;
    }

    // Alloc returns wires holding the assigned field values.
    #[test]
    fn wired_alloc_assigns_values() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w_one = dr.alloc(|| Ok(Coeff::One))?;
        let w_zero = dr.alloc(|| Ok(Coeff::Zero))?;
        let w_arb = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(42))))?;

        assert_eq!(w_one, F::ONE);
        assert_eq!(w_zero, F::ZERO);
        assert_eq!(w_arb, F::from(42));
        Ok(())
    }

    // Constant wires hold the expected field element for each Coeff variant.
    #[test]
    fn wired_constant_returns_correct_wire() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let c_one = dr.constant(Coeff::One);
        let c_zero = dr.constant(Coeff::Zero);
        let c_neg = dr.constant(Coeff::NegativeOne);
        let c_arb = dr.constant(Coeff::Arbitrary(F::from(7)));
        let c_two = dr.constant(Coeff::Two);
        let c_neg_arb = dr.constant(Coeff::NegativeArbitrary(F::from(13)));

        assert_eq!(c_one, F::ONE);
        assert_eq!(c_zero, F::ZERO);
        assert_eq!(c_neg, -F::ONE);
        assert_eq!(c_arb, F::from(7));
        assert_eq!(c_two, F::ONE.double());
        assert_eq!(c_neg_arb, -F::from(13));
        Ok(())
    }

    // The emulator accepts a*b != c without error since it does not enforce constraints.
    #[test]
    fn wired_mul_does_not_enforce_constraints() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let (a, b, c) = dr.mul(|| {
            Ok((
                Coeff::Arbitrary(F::from(3)),
                Coeff::Arbitrary(F::from(5)),
                Coeff::Arbitrary(F::from(99)),
            ))
        })?;

        assert_eq!(a, F::from(3));
        assert_eq!(b, F::from(5));
        assert_eq!(c, F::from(99)); // emulator does not enforce a*b==c
        Ok(())
    }

    // Linear combination via add produces the correct accumulated value.
    #[test]
    fn wired_add_computes_linear_combination() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w1 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(10))))?;
        let w2 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(20))))?;

        // 1*w1 + 3*w2 = 10 + 60 = 70
        let sum = dr.add(|lc| lc.add(&w1).add_term(&w2, Coeff::Arbitrary(F::from(3))));

        assert_eq!(sum, F::from(70));
        Ok(())
    }

    // enforce_zero succeeds even for non-zero expressions since the emulator skips constraint checks.
    #[test]
    fn wired_enforce_zero_is_noop() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(42))))?;

        let result = dr.enforce_zero(|lc| lc.add(&w));
        assert!(result.is_ok());
        Ok(())
    }

    // enforce_equal succeeds for unequal wires since the emulator skips constraint checks.
    #[test]
    fn wired_enforce_equal_is_noop() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w1 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(1))))?;
        let w2 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(999))))?;

        let result = dr.enforce_equal(&w1, &w2);
        assert!(result.is_ok());
        Ok(())
    }

    // emulate_wired runs circuit code and extracts the resulting wire field values.
    #[test]
    fn wired_emulate_wired_extracts_wires() -> Result<()> {
        let wires = Emulator::<Wired<F>>::emulate_wired((), |dr, _witness| {
            let a = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(5))))?;
            let b = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(10))))?;
            let sum = dr.add(|lc| lc.add(&a).add(&b));

            let gadget = TwoWires {
                a,
                b: sum,
                _marker: core::marker::PhantomData,
            };
            let extracted = dr.wires(&gadget)?;
            Ok(extracted)
        })?;

        assert_eq!(wires.len(), 2);
        assert_eq!(wires[0], F::from(5));
        assert_eq!(wires[1], F::from(15));
        Ok(())
    }

    // In wireless mode, Driver method closures are discarded (never called).
    #[test]
    fn wireless_driver_ops_discard_closures() -> Result<()> {
        use core::cell::Cell;

        let mut dr = Emulator::<Wireless<Always<()>, F>>::execute();
        let called = Cell::new(0);

        let () = dr.alloc(|| {
            called.set(called.get() + 1);
            Ok(Coeff::Arbitrary(F::from(42)))
        })?;

        let () = dr.constant(Coeff::One);

        let ((), (), ()) = dr.mul(|| {
            called.set(called.get() + 1);
            Ok((
                Coeff::Arbitrary(F::from(3)),
                Coeff::Arbitrary(F::from(5)),
                Coeff::Arbitrary(F::from(15)),
            ))
        })?;

        let () = dr.add(|lc| {
            called.set(called.get() + 1);
            lc
        });

        let r = dr.enforce_zero(|lc| {
            called.set(called.get() + 1);
            lc
        });
        assert!(r.is_ok());
        assert_eq!(called.get(), 0);
        Ok(())
    }

    // Counter mode runs without witnesses, enabling static constraint counting.
    #[test]
    fn wireless_counter_static_analysis() -> Result<()> {
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();

        let () = dr.alloc(|| Ok(Coeff::One))?;

        let ((), (), ()) = dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;

        let () = dr.add(|lc| lc);
        Ok(())
    }

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    // Routine whose predict returns Known; execute sets a flag so we can
    // verify it was NOT called.
    #[derive(Clone)]
    struct AlwaysKnownRoutine {
        executed: Arc<AtomicBool>,
    }

    impl Routine<F> for AlwaysKnownRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            self.executed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn predict<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Known((), D::just(|| ())))
        }
    }

    // Routine whose predict returns Unknown with aux data; execute sets a
    // flag and verifies the aux value arrived.
    #[derive(Clone)]
    struct AlwaysUnknownRoutine {
        aux_value: u64,
        executed: Arc<AtomicBool>,
    }

    impl Routine<F> for AlwaysUnknownRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = u64;

        fn execute<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            assert_eq!(aux.take(), self.aux_value);
            self.executed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn predict<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Unknown(D::just(|| self.aux_value)))
        }
    }

    // Routine whose predict returns Err.
    #[derive(Clone)]
    struct FailingPredictRoutine;

    impl Routine<F> for FailingPredictRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }

        fn predict<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Err(crate::Error::InvalidWitness("predict failed".into()))
        }
    }

    // Routine whose predict returns Unknown but execute returns Err.
    #[derive(Clone)]
    struct FailingExecuteRoutine;

    impl Routine<F> for FailingExecuteRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Err(crate::Error::InvalidWitness("execute failed".into()))
        }

        fn predict<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Unknown(D::just(|| ())))
        }
    }

    // The wired emulator always executes routines because `predict` requires
    // `Wire = ()` and cannot produce wired output.
    #[test]
    fn wired_routine_always_executes() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wired<F>>::extractor();
        let routine = AlwaysKnownRoutine {
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            executed.load(Ordering::Relaxed),
            "wired emulator must always execute"
        );
        Ok(())
    }

    // When predict returns Unknown, the emulator falls through to execute,
    // which receives the correct aux data.
    #[test]
    fn wired_routine_executes_on_unknown_prediction() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wired<F>>::extractor();
        let routine = AlwaysUnknownRoutine {
            aux_value: 123,
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            executed.load(Ordering::Relaxed),
            "execute should be called on Unknown prediction"
        );
        Ok(())
    }

    #[test]
    fn wired_routine_predict_error_propagates() {
        let mut dr = Emulator::<Wired<F>>::extractor();
        let result = dr.routine(FailingPredictRoutine, ());
        assert!(result.is_err());
    }

    #[test]
    fn wired_routine_execute_error_propagates() {
        let mut dr = Emulator::<Wired<F>>::extractor();
        let result = dr.routine(FailingExecuteRoutine, ());
        assert!(result.is_err());
    }

    #[test]
    fn wireless_always_routine_short_circuits_on_known() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wireless<Always<()>, F>>::execute();
        let routine = AlwaysKnownRoutine {
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            !executed.load(Ordering::Relaxed),
            "execute should not be called on Known prediction"
        );
        Ok(())
    }

    #[test]
    fn wireless_always_routine_executes_on_unknown() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wireless<Always<()>, F>>::execute();
        let routine = AlwaysUnknownRoutine {
            aux_value: 456,
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            executed.load(Ordering::Relaxed),
            "execute should be called on Unknown prediction"
        );
        Ok(())
    }

    #[test]
    fn wireless_always_routine_predict_error_propagates() {
        let mut dr = Emulator::<Wireless<Always<()>, F>>::execute();
        let result = dr.routine(FailingPredictRoutine, ());
        assert!(result.is_err());
    }

    #[test]
    fn wireless_always_routine_execute_error_propagates() {
        let mut dr = Emulator::<Wireless<Always<()>, F>>::execute();
        let result = dr.routine(FailingExecuteRoutine, ());
        assert!(result.is_err());
    }

    // A routine compatible with Empty MaybeKind: Aux = () and execute does
    // not call .take() on aux.
    #[derive(Clone)]
    struct NoAuxUnknownRoutine {
        executed: Arc<AtomicBool>,
    }

    impl Routine<F> for NoAuxUnknownRoutine {
        type Input = ();
        type Output = ();
        type Aux<'dr> = ();

        fn execute<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: Bound<'dr, D, Self::Input>,
            _aux: DriverValue<D, Self::Aux<'dr>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            self.executed.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn predict<'dr, D: Driver<'dr, F = F>>(
            &self,
            _dr: &mut D,
            _input: &Bound<'dr, D, Self::Input>,
        ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
        {
            Ok(Prediction::Unknown(D::just(|| ())))
        }
    }

    #[test]
    fn wireless_counter_routine_short_circuits_on_known() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();
        let routine = AlwaysKnownRoutine {
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            !executed.load(Ordering::Relaxed),
            "execute should not be called on Known prediction"
        );
        Ok(())
    }

    #[test]
    fn wireless_counter_routine_executes_on_unknown() -> Result<()> {
        let executed = Arc::new(AtomicBool::new(false));
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();
        let routine = NoAuxUnknownRoutine {
            executed: executed.clone(),
        };
        dr.routine(routine, ())?;
        assert!(
            executed.load(Ordering::Relaxed),
            "execute should be called on Unknown prediction"
        );
        Ok(())
    }

    #[test]
    fn wireless_counter_routine_predict_error_propagates() {
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();
        let result = dr.routine(FailingPredictRoutine, ());
        assert!(result.is_err());
    }

    #[test]
    fn wireless_counter_routine_execute_error_propagates() {
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();
        let result = dr.routine(FailingExecuteRoutine, ());
        assert!(result.is_err());
    }

    #[test]
    fn predict_known_returns_output() -> Result<()> {
        let input: Bound<'_, Emulator<Wired<F>>, ()> = ();
        let prediction = Emulator::<Wireless<Always<()>, F>>::predict::<Emulator<Wired<F>>, _>(
            &AlwaysKnownRoutine {
                executed: Arc::new(AtomicBool::new(false)),
            },
            &input,
        )?;
        assert!(matches!(prediction, Prediction::Known((), _)));
        Ok(())
    }

    #[test]
    fn predict_unknown_returns_aux() -> Result<()> {
        let input: Bound<'_, Emulator<Wired<F>>, ()> = ();
        let prediction = Emulator::<Wireless<Always<()>, F>>::predict::<Emulator<Wired<F>>, _>(
            &AlwaysUnknownRoutine {
                aux_value: 789,
                executed: Arc::new(AtomicBool::new(false)),
            },
            &input,
        )?;
        match prediction {
            Prediction::Unknown(aux) => assert_eq!(aux.take(), 789),
            Prediction::Known(..) => panic!("expected Unknown"),
        }
        Ok(())
    }

    #[test]
    fn predict_error_propagates() {
        let input: Bound<'_, Emulator<Wired<F>>, ()> = ();
        let result = Emulator::<Wireless<Always<()>, F>>::predict::<Emulator<Wired<F>>, _>(
            &FailingPredictRoutine,
            &input,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wired_just_calls_closure_and_returns_value() {
        let val = <Emulator<Wired<F>> as Driver>::just(|| 42u64);
        assert_eq!(val.take(), 42);
    }

    #[test]
    fn wired_try_just_ok_returns_value() -> Result<()> {
        let val = <Emulator<Wired<F>> as Driver>::try_just(|| Ok(42u64))?;
        assert_eq!(val.take(), 42);
        Ok(())
    }

    #[test]
    fn wired_try_just_err_propagates() {
        let result = <Emulator<Wired<F>> as Driver>::try_just(|| -> Result<u64> {
            Err(crate::Error::InvalidWitness("test".into()))
        });
        assert!(result.is_err());
    }

    #[test]
    fn wireless_always_just_calls_closure() {
        let val = <Emulator<Wireless<Always<()>, F>> as Driver>::just(|| 42u64);
        assert_eq!(val.take(), 42);
    }

    #[test]
    fn wireless_counter_just_skips_closure() {
        let _: crate::maybe::Empty =
            <Emulator<Wireless<crate::maybe::Empty, F>> as Driver>::just(|| {
                panic!("must not be called")
            });
    }

    #[test]
    fn wireless_counter_try_just_err_swallowed() -> Result<()> {
        let _: crate::maybe::Empty =
            <Emulator<Wireless<crate::maybe::Empty, F>> as Driver>::try_just(|| -> Result<()> {
                Err(crate::Error::InvalidWitness("swallowed".into()))
            })?;
        Ok(())
    }

    #[test]
    fn wired_mul_propagates_closure_error() {
        let mut dr = Emulator::<Wired<F>>::extractor();
        let result = dr.mul(|| Err(crate::Error::InvalidWitness("mul error".into())));
        assert!(result.is_err());
    }

    #[test]
    fn wired_alloc_propagates_closure_error() {
        let mut dr = Emulator::<Wired<F>>::extractor();
        let result = dr.alloc(|| Err(crate::Error::InvalidWitness("alloc error".into())));
        assert!(result.is_err());
    }

    #[test]
    fn wired_emulate_wired_witness_flows_through() -> Result<()> {
        let result = Emulator::<Wired<F>>::emulate_wired(F::from(77), |dr, witness| {
            let val = witness.take();
            let w = dr.alloc(|| Ok(Coeff::Arbitrary(val)))?;
            assert_eq!(w, F::from(77));
            Ok(w)
        })?;
        assert_eq!(result, F::from(77));
        Ok(())
    }

    #[test]
    fn wireless_emulate_wireless_passes_witness() -> Result<()> {
        let result =
            Emulator::<Wireless<Always<()>, F>>::emulate_wireless(42u64, |_dr, witness| {
                let val = witness.take();
                Ok(val * 2)
            })?;
        assert_eq!(result, 84);
        Ok(())
    }

    #[test]
    fn wired_wires_empty_gadget() -> Result<()> {
        let dr = Emulator::<Wired<F>>::extractor();
        let wires = dr.wires(&())?;
        assert_eq!(wires, alloc::vec![]);
        Ok(())
    }
}
