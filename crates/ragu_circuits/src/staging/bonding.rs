//! Bonding polynomials for multi-stage circuits.
//!
//! This module produces a [`BondingObject`] from any [`MultiStageCircuit`]
//! whose witness is gate-free after finalization: before
//! [`StageBuilder::finish`], [`gate`](ragu_core::drivers::DriverTypes::gate)
//! is used to reserve stage wires; after finalization, [`Driver::mul`],
//! [`Driver::constant`], and `ONE`-wire references are rejected, and only
//! [`Driver::add`] and [`Driver::enforce_zero`] with normal wires are
//! permitted. Because the circuit has no gates of its own, it needs no
//! final trace and exists purely to enforce wiring between stages.
//!
//! The `ONE`-wire contribution is stripped so that the constant term in $Y$ is
//! zero, as required of a bonding polynomial. [`StageMask`] is a hand-optimized
//! bonding polynomial for stage well-formedness masks.
//!
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::constant`]: ragu_core::drivers::Driver::constant
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`StageMask`]: super::mask::StageMask

use alloc::boxed::Box;

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Empty,
};
use udon::field::Field;

use super::{MultiStage, MultiStageCircuit, StageBuilder};
use crate::{
    BondingObject, SegmentRecord, WiringObject,
    floor_planner::ConstraintSegment,
    into_wiring_object,
    polynomials::{Rank, sparse},
};

impl<F, R, S> MultiStage<F, R, S>
where
    F: Field,
    R: Rank,
    S: MultiStageCircuit<F, R>,
{
    /// Builds a [`BondingObject`] from this [`MultiStage`] circuit.
    ///
    /// After the [`StageBuilder`] is finalized, only [`Driver::add`] and
    /// [`Driver::enforce_zero`] are permitted (without referencing the
    /// [`Driver::ONE`] wire). [`Driver::gate`] (and by extension
    /// [`Driver::mul`]) and [`Driver::constant`] are rejected after
    /// finalization.
    ///
    /// The circuit must declare `Output = ()`. Non-empty output would
    /// be serialized into output-binding constraints by the standard
    /// constraint-emission path, contributing to $k(Y)$ and violating the
    /// bonding requirement that $k(Y) \equiv 0$. The `Output = ()` bound makes
    /// this a type-level requirement.
    ///
    /// The `ONE`-wire contribution is stripped so that the constant term in $Y$
    /// is zero, as required of a bonding polynomial.
    ///
    /// # Errors
    ///
    /// Returns an input error if the supplied circuit violates the structural
    /// restrictions above by using the `ONE` wire, emitting a gate, or allocating
    /// a constant after the stage builder is finalized.
    ///
    /// [`Driver::gate`]: ragu_core::drivers::DriverTypes::gate
    /// [`Driver::mul`]: ragu_core::drivers::Driver::mul
    /// [`Driver::add`]: ragu_core::drivers::Driver::add
    /// [`Driver::constant`]: ragu_core::drivers::Driver::constant
    /// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    /// [`Driver::ONE`]: ragu_core::drivers::Driver::ONE
    ///
    /// # Errors
    ///
    /// Returns [`ragu_core::Error::InvalidWitness`] if the circuit violates
    /// the bonding restrictions, or propagates any error from the standard
    /// wiring-object construction pipeline.
    pub fn into_bonding_object<'a>(self) -> Result<BondingObject<'a, F, R>>
    where
        Self: 'a,
        S: MultiStageCircuit<F, R, Output = ()>,
    {
        // Validate: run constraint emission with a driver that rejects ONE usage
        // and — after the stage builder finalizes — mul/gate.
        let mut validator = BondingValidator::<F>::new();
        self.circuit.witness(
            StageBuilder::new(&mut validator, BondingValidator::freeze),
            Empty,
        )?;
        if let Some(msg) = validator.error {
            return Err(ragu_core::Error::InvalidWitness(msg.into()));
        }

        // Defensive cross-check on the type-level invariant: `Output = ()` and
        // `Write<F> for ()` together guarantee no output-binding constraints
        // are emitted, so the instance polynomial $k(Y)$ has degree zero.
        let metrics = crate::metrics::eval(&self)?;
        assert_eq!(
            metrics.degree_ky, 0,
            "bonding circuit must have empty instance polynomial",
        );

        // Build the WiringObject via the standard pipeline.
        let inner = into_wiring_object::<_, _, R>(self)?;

        Ok(BondingObject::new(Box::new(Stripped::<F, R>::new(inner))))
    }
}

/// Wire type for [`BondingValidator`] that distinguishes the ONE wire from
/// normal allocated wires.
#[derive(Clone, PartialEq)]
enum BondingWire {
    One,
    Normal,
}

/// A [`LinearExpression`] that detects references to [`BondingWire::One`].
struct RejectOne(bool);

impl<F: Field> LinearExpression<BondingWire, F> for RejectOne {
    fn add_term(mut self, wire: &BondingWire, _coeff: Coeff<F>) -> Self {
        if *wire == BondingWire::One {
            self.0 = true;
        }
        self
    }

    fn gain(self, _: Coeff<F>) -> Self {
        self
    }
}

/// A [`Driver`] that validates bonding-circuit constraints.
///
/// Before the [`StageBuilder`] is finalized, [`gate`](DriverTypes::gate),
/// [`add`](Driver::add), and [`enforce_zero`](Driver::enforce_zero) with
/// normal wires are permitted. After [`freeze`](Self::freeze) is called
/// (via the builder's `on_finish` hook), [`gate`](DriverTypes::gate) is
/// rejected. [`constant`](Driver::constant) and
/// [`ONE`](Driver::ONE)-wire references are always rejected.
///
/// All methods succeed; violations are accumulated in the `error` field and
/// checked by the caller after the witness completes.
struct BondingValidator<F> {
    error: Option<&'static str>,
    frozen: bool,
    _marker: core::marker::PhantomData<F>,
}

impl<F> BondingValidator<F> {
    fn new() -> Self {
        BondingValidator {
            error: None,
            frozen: false,
            _marker: core::marker::PhantomData,
        }
    }

    fn record(&mut self, msg: &'static str) {
        self.error.get_or_insert(msg);
    }

    /// Called by the [`StageBuilder`] `on_finish` hook to lock out further
    /// allocations after all stages have been reserved.
    fn freeze(&mut self) {
        self.frozen = true;
    }
}

impl<F: Field> DriverTypes for BondingValidator<F> {
    type ImplField = F;
    type ImplWire = BondingWire;
    type MaybeKind = Empty;
    type LCadd = RejectOne;
    type LCenforce = RejectOne;
    type Extra = BondingWire;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(BondingWire, BondingWire, BondingWire, BondingWire)> {
        if self.frozen {
            self.record("bonding circuits must not allocate after stage finalization");
        }
        Ok((
            BondingWire::Normal,
            BondingWire::Normal,
            BondingWire::Normal,
            BondingWire::Normal,
        ))
    }

    fn assign_extra(
        &mut self,
        extra: Self::Extra,
        _: impl Fn() -> Result<Coeff<F>>,
    ) -> Result<BondingWire> {
        Ok(extra)
    }
}

impl<'dr, F: Field> Driver<'dr> for BondingValidator<F> {
    type F = F;
    type Wire = BondingWire;
    const ONE: Self::Wire = BondingWire::One;

    fn constant(&mut self, _: Coeff<F>) -> BondingWire {
        self.record("bonding circuits must not create constants");
        BondingWire::Normal
    }

    fn add(&mut self, lc: impl Fn(RejectOne) -> RejectOne) -> BondingWire {
        if lc(RejectOne(false)).0 {
            self.record("bonding circuits must not reference the ONE wire");
        }
        BondingWire::Normal
    }

    fn enforce_zero(&mut self, lc: impl Fn(RejectOne) -> RejectOne) -> Result<()> {
        if lc(RejectOne(false)).0 {
            self.record("bonding circuits must not reference the ONE wire");
        }
        Ok(())
    }
}

/// Wraps a [`WiringObject`] and strips the `enforce_one` contribution,
/// giving a zero constant term in $Y$.
pub(crate) struct Stripped<'a, F: Field, R: Rank>(Box<dyn WiringObject<F, R> + 'a>);

impl<'a, F: Field, R: Rank> Stripped<'a, F, R> {
    pub(crate) fn new(inner: Box<dyn WiringObject<F, R> + 'a>) -> Self {
        Self(inner)
    }
}

impl<F: Field, R: Rank> Stripped<'_, F, R> {
    /// Removes the `enforce_one` contribution, which Horner places at
    /// $y^0$ (`coeffs[0]`).
    // TODO: sparse::Polynomial should support subtracting a field element
    // from the constant term directly.
    fn strip_constant_term(mut poly: sparse::Polynomial<F, R>) -> sparse::Polynomial<F, R> {
        let coeff_0 = poly.iter_coeffs().next().unwrap();
        let correction = sparse::Polynomial::from_coeffs(alloc::vec![coeff_0]);
        poly.sub_assign(&correction);
        poly
    }

    /// Removes the ONE wire's $y^0$ contribution: the SYSTEM gate's $d$ wire,
    /// which maps to degree 0 in the wiring perspective.
    fn strip_one_wire(mut poly: sparse::Polynomial<F, R>) -> sparse::Polynomial<F, R> {
        let mut correction = sparse::View::<_, R, _>::wiring();
        correction.d.push(F::ONE);
        poly.sub_assign(&correction.build());
        poly
    }
}

impl<F: Field, R: Rank> WiringObject<F, R> for Stripped<'_, F, R> {
    fn sxy(&self, x: F, y: F, floor_plan: &[ConstraintSegment]) -> F {
        // Remove the ONE wire contribution: 1 at y^0 (d[0] maps to degree 0).
        self.0.sxy(x, y, floor_plan) - F::ONE
    }

    fn sxy_with_cache(
        &self,
        x: F,
        y: F,
        floor_plan: &[ConstraintSegment],
        cache: &mut crate::wiring::MemoCache<F>,
    ) -> F {
        // Remove the ONE wire contribution, as in `sxy`.
        self.0.sxy_with_cache(x, y, floor_plan, cache) - F::ONE
    }

    fn sx(&self, x: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        Self::strip_constant_term(self.0.sx(x, floor_plan))
    }

    fn sx_with_cache(
        &self,
        x: F,
        floor_plan: &[ConstraintSegment],
        cache: &mut crate::wiring::MemoCache<F>,
    ) -> sparse::Polynomial<F, R> {
        Self::strip_constant_term(self.0.sx_with_cache(x, floor_plan, cache))
    }

    fn sy(&self, y: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        Self::strip_one_wire(self.0.sy(y, floor_plan))
    }

    fn sy_with_cache(
        &self,
        y: F,
        floor_plan: &[ConstraintSegment],
        cache: &mut crate::wiring::MemoCache<F>,
    ) -> sparse::Polynomial<F, R> {
        Self::strip_one_wire(self.0.sy_with_cache(y, floor_plan, cache))
    }

    fn segment_records(&self) -> &[SegmentRecord] {
        self.0.segment_records()
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use ragu_core::{
        drivers::DriverValue,
        gadgets::{Bound, Gadget},
        pasta::Fp,
    };
    use ragu_primitives::{
        Element,
        allocator::{Allocator, Standard},
        io::Write,
    };
    use rand::Rng;

    use super::*;
    use crate::{
        WithAux, floor_planner,
        polynomials::TestRank,
        staging::{MultiStageCircuit, Stage, StageBuilder},
    };

    type R = TestRank;

    /// A trivial stage that provides two allocated wires.
    #[derive(Default)]
    struct TwoWireStage;

    #[derive(Gadget, Write)]
    struct TwoWires<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        w0: Element<'dr, D>,
        #[ragu(gadget)]
        w1: Element<'dr, D>,
    }

    impl Stage<Fp, R> for TwoWireStage {
        type Parent = ();
        type Witness<'source> = ();
        type OutputKind =
            <TwoWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let w0 = Element::alloc(dr, &mut (), D::just(|| Fp::ZERO))?;
            let w1 = Element::alloc(dr, &mut (), D::just(|| Fp::ZERO))?;
            Ok(TwoWires { w0, w1 })
        }
    }

    /// Minimal bonding circuit: provides two wires via a stage and enforces
    /// equality between them.
    struct EqualWires;

    impl MultiStageCircuit<Fp, R> for EqualWires {
        type Last = TwoWireStage;
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), TwoWireStage>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let (guard, builder) = builder.add_stage::<TwoWireStage>()?;
            let dr = builder.finish();
            let TwoWires { w0, w1 } = guard.unenforced(dr, D::unit())?;
            dr.enforce_zero(|lc| lc.add(w0.wire()).sub(w1.wire()))?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Circuit that calls `mul`/`gate` — should be rejected.
    struct UsesMul;

    impl MultiStageCircuit<Fp, R> for UsesMul {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let dr = builder.finish();
            dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Circuit that calls `constant` — should be rejected.
    struct UsesConstant;

    impl MultiStageCircuit<Fp, R> for UsesConstant {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let dr = builder.finish();
            let _ = dr.constant(Coeff::One);
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Circuit that uses `D::ONE` in `enforce_zero` — should be rejected.
    struct UsesOneInEnforceZero;

    impl MultiStageCircuit<Fp, R> for UsesOneInEnforceZero {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let dr = builder.finish();
            dr.enforce_zero(|lc| lc.add(&D::ONE))?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Circuit that uses `D::ONE` in `add` — should be rejected.
    struct UsesOneInAdd;

    impl MultiStageCircuit<Fp, R> for UsesOneInAdd {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let dr = builder.finish();
            let _ = dr.add(|lc| lc.add(&D::ONE));
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Empty bonding circuit: no allocations, no constraints.
    struct EmptyCircuit;

    impl MultiStageCircuit<Fp, R> for EmptyCircuit {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let _ = builder.finish();
            Ok(WithAux::new((), D::unit()))
        }
    }

    fn bonding_obj() -> Box<dyn WiringObject<Fp, R>> {
        MultiStage::<Fp, R, _>::new(EqualWires)
            .into_bonding_object()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn rejects_mul() {
        assert!(
            MultiStage::<Fp, R, _>::new(UsesMul)
                .into_bonding_object()
                .is_err()
        );
    }

    #[test]
    fn rejects_constant() {
        assert!(
            MultiStage::<Fp, R, _>::new(UsesConstant)
                .into_bonding_object()
                .is_err()
        );
    }

    #[test]
    fn rejects_one_in_enforce_zero() {
        assert!(
            MultiStage::<Fp, R, _>::new(UsesOneInEnforceZero)
                .into_bonding_object()
                .is_err()
        );
    }

    #[test]
    fn rejects_one_in_add() {
        assert!(
            MultiStage::<Fp, R, _>::new(UsesOneInAdd)
                .into_bonding_object()
                .is_err()
        );
    }

    /// Circuit that allocates after `finish()` — should be rejected.
    struct AllocsAfterFinish;

    impl MultiStageCircuit<Fp, R> for AllocsAfterFinish {
        type Last = ();
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, ()>,
        ) -> Result<Bound<'dr, D, ()>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            builder: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>> {
            let dr = builder.finish();
            let allocator = &mut Standard::new();
            allocator.alloc(dr, || Ok(Coeff::Zero))?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    #[test]
    fn rejects_alloc_after_finish() {
        assert!(
            MultiStage::<Fp, R, _>::new(AllocsAfterFinish)
                .into_bonding_object()
                .is_err()
        );
    }

    /// Bonding polynomials must have zero constant term in $Y$.
    #[test]
    fn zero_constant_term() {
        let obj = bonding_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());

        let x = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
        let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

        // s(0, y) = 0: no constraint on d_0 wires.
        assert_eq!(obj.sxy(Fp::ZERO, y, &floor_plan), Fp::ZERO);
        // s(x, 0) = 0: forces k(Y) = 0.
        assert_eq!(obj.sxy(x, Fp::ZERO, &floor_plan), Fp::ZERO);
    }

    /// sxy(x,y) = sx(x).eval(y) = sy(y).eval(x).
    #[test]
    fn evaluation_consistency() {
        let obj = bonding_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());

        let x = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
        let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

        let sxy = obj.sxy(x, y, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &floor_plan).eval(x));
    }

    /// Build a trace with the SYSTEM gate zeroed and gates 1..n from (a, d)
    /// pairs.
    fn build_trace(gate_values: &[(Fp, Fp)]) -> sparse::Polynomial<Fp, R> {
        let mut view = sparse::View::<_, R, _>::trace();
        // SYSTEM gate placeholder.
        view.a.push(Fp::ZERO);
        view.b.push(Fp::ZERO);
        view.c.push(Fp::ZERO);
        view.d.push(Fp::ZERO);
        // Mirrors `Standard::alloc`'s layout — update in lockstep.
        for &(a, d) in gate_values {
            view.a.push(a);
            view.b.push(Fp::ZERO);
            view.c.push(Fp::ZERO);
            view.d.push(d);
        }
        view.build()
    }

    /// Revdot is zero when bonding constraint is satisfied, nonzero otherwise.
    #[test]
    fn revdot_bonding_constraint() {
        let obj = bonding_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());

        let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
        let sy = obj.sy(y, &floor_plan);

        let v = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
        let w = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

        let rx_equal = build_trace(&[(v, v)]);
        assert_eq!(rx_equal.revdot(&sy), Fp::ZERO);

        let rx_unequal = build_trace(&[(v, w)]);
        assert_ne!(rx_unequal.revdot(&sy), Fp::ZERO);
    }

    /// An empty bonding circuit (no alloc, no enforce_zero) should succeed
    /// and produce a polynomial that imposes no constraint on any trace.
    #[test]
    fn empty_circuit() {
        let obj = MultiStage::<Fp, R, _>::new(EmptyCircuit)
            .into_bonding_object()
            .unwrap()
            .into_inner();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());
        let x = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
        let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

        assert_eq!(obj.sxy(Fp::ZERO, y, &floor_plan), Fp::ZERO);
        assert_eq!(obj.sxy(x, Fp::ZERO, &floor_plan), Fp::ZERO);

        let sxy = obj.sxy(x, y, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &floor_plan).eval(x));

        let rx = build_trace(&[(
            Fp::random(|bytes| rand::rng().fill_bytes(bytes)),
            Fp::random(|bytes| rand::rng().fill_bytes(bytes)),
        )]);
        assert_eq!(rx.revdot(&obj.sy(y, &floor_plan)), Fp::ZERO);
    }
}
