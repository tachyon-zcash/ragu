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

use ff::Field;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{
    Result,
    drivers::{Coeff, DirectSum, Driver, DriverTypes, FromDriver, LinearExpression},
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Empty, MaybeKind},
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
pub struct Emulator<M: Mode>(PhantomData<M>);

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

impl<M: MaybeKind, F: Field> Emulator<Wireless<M, F>> {
    /// Creates a new [`Emulator`] driver in [`Wireless`] mode, parameterized on
    /// the existence of a witness.
    pub fn wireless() -> Self {
        Emulator(PhantomData)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use crate::drivers::{Coeff, Driver, LinearExpression};
    use crate::maybe::Always;
    use ff::Field;
    use ragu_pasta::Fp;

    type F = Fp;

    // A minimal gadget for wire extraction tests, manually implemented
    // because the derive macro cannot resolve `ragu_core` from within the
    // crate itself.
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
            'dr,
            'new_dr,
            D: Driver<'dr, F = FieldType>,
            ND: crate::drivers::FromDriver<'dr, 'new_dr, D>,
        >(
            this: &Self::Rebind<'dr, D>,
            ndr: &mut ND,
        ) -> Result<Self::Rebind<'new_dr, ND::NewDriver>> {
            Ok(TwoWires {
                a: ndr.convert_wire(&this.a)?,
                b: ndr.convert_wire(&this.b)?,
                _marker: core::marker::PhantomData,
            })
        }

        fn enforce_equal_gadget<
            'dr,
            D1: Driver<'dr, F = FieldType>,
            D2: Driver<'dr, F = FieldType, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            dr: &mut D1,
            a: &Self::Rebind<'dr, D2>,
            b: &Self::Rebind<'dr, D2>,
        ) -> Result<()> {
            dr.enforce_equal(&a.a, &b.a)?;
            dr.enforce_equal(&a.b, &b.b)?;
            Ok(())
        }
    }

    impl<'dr, D: Driver<'dr>> crate::gadgets::Gadget<'dr, D> for TwoWires<'dr, D> {
        type Kind = TwoWiresKind;
    }

    // ── Wired mode ──────────────────────────────────────────────────

    #[test]
    fn wired_alloc_assigns_values() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w_one = dr.alloc(|| Ok(Coeff::One))?;
        let w_zero = dr.alloc(|| Ok(Coeff::Zero))?;
        let w_arb = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(42))))?;

        assert_eq!(w_one.value(), F::ONE);
        assert_eq!(w_zero.value(), F::ZERO);
        assert_eq!(w_arb.value(), F::from(42));
        Ok(())
    }

    #[test]
    fn wired_constant_returns_correct_wire() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let c_one = dr.constant(Coeff::One);
        let c_zero = dr.constant(Coeff::Zero);
        let c_neg = dr.constant(Coeff::NegativeOne);
        let c_arb = dr.constant(Coeff::Arbitrary(F::from(7)));

        assert_eq!(c_one.value(), F::ONE);
        assert_eq!(c_zero.value(), F::ZERO);
        assert_eq!(c_neg.value(), -F::ONE);
        assert_eq!(c_arb.value(), F::from(7));
        Ok(())
    }

    #[test]
    fn wired_mul_does_not_enforce_constraints() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        // Deliberately assign a * b != c: 3 * 5 != 99
        let (a, b, c) = dr.mul(|| {
            Ok((
                Coeff::Arbitrary(F::from(3)),
                Coeff::Arbitrary(F::from(5)),
                Coeff::Arbitrary(F::from(99)),
            ))
        })?;

        assert_eq!(a.value(), F::from(3));
        assert_eq!(b.value(), F::from(5));
        assert_eq!(c.value(), F::from(99)); // emulator does not enforce a*b==c
        Ok(())
    }

    #[test]
    fn wired_add_computes_linear_combination() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w1 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(10))))?;
        let w2 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(20))))?;

        // sum = 1 * w1 + 3 * w2 = 10 + 60 = 70
        let sum = dr.add(|lc| lc.add(&w1).add_term(&w2, Coeff::Arbitrary(F::from(3))));

        assert_eq!(sum.value(), F::from(70));
        Ok(())
    }

    #[test]
    fn wired_enforce_zero_is_noop() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(42))))?;

        // This linear combination is non-zero, but the emulator doesn't enforce.
        let result = dr.enforce_zero(|lc| lc.add(&w));
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn wired_enforce_equal_is_noop() -> Result<()> {
        let mut dr = Emulator::<Wired<F>>::extractor();

        let w1 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(1))))?;
        let w2 = dr.alloc(|| Ok(Coeff::Arbitrary(F::from(999))))?;

        // Different values, but emulator doesn't enforce.
        let result = dr.enforce_equal(&w1, &w2);
        assert!(result.is_ok());
        Ok(())
    }

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

    // ── Wireless mode (with witness) ────────────────────────────────

    #[test]
    fn wireless_execute_all_ops_return_unit() -> Result<()> {
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

    // ── Wireless mode (counter, no witness) ─────────────────────────

    #[test]
    fn wireless_counter_static_analysis() -> Result<()> {
        let mut dr = Emulator::<Wireless<crate::maybe::Empty, F>>::counter();

        let () = dr.alloc(|| Ok(Coeff::One))?;

        let ((), (), ()) = dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::One)))?;

        let () = dr.add(|lc| lc);
        Ok(())
    }

    // ── WiredValue ──────────────────────────────────────────────────

    #[test]
    fn wired_value_one_holds_f_one() {
        assert_eq!(WiredValue::<F>::One.value(), F::ONE);
    }

    #[test]
    fn wired_value_assigned_holds_value() {
        let v = F::from(123);
        assert_eq!(WiredValue::Assigned(v).value(), v);
    }

    // ── WiredDirectSum ──────────────────────────────────────────────

    #[test]
    fn wired_direct_sum_linear_combination() {
        let one = WiredValue::<F>::One;
        let x = WiredValue::Assigned(F::from(7));

        // sum = 1 * ONE + 3 * x = 1 + 21 = 22
        let lc = WiredDirectSum(DirectSum::default())
            .add(&one)
            .add_term(&x, Coeff::Arbitrary(F::from(3)));

        assert_eq!(lc.0.value, F::from(22));
    }

    // ── DirectSum gain factor ───────────────────────────────────────

    #[test]
    fn direct_sum_gain_factor() {
        // gain multiplies cumulatively: gain(a).gain(b) => effective gain = a*b
        //
        // Start: value=0, gain=1
        // add(5): coeff=1*1=1 => value = 0 + 5 = 5
        // gain(2): gain = 1*2 = 2
        // add(3): coeff=1*2=2 => value = 5 + 3*2 = 11
        // gain(-1): gain = 2*(-1) = -2
        // add(4): coeff=1*(-2)=-2 => value = 11 - 4*2 = 3
        let acc = DirectSum::<F>::default()
            .add(&F::from(5))
            .gain(Coeff::Arbitrary(F::from(2)))
            .add(&F::from(3))
            .gain(Coeff::NegativeOne)
            .add(&F::from(4));

        assert_eq!(acc.value, F::from(3));
    }
}
