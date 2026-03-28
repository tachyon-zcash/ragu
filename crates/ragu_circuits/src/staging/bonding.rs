//! Bonding polynomials for multi-stage circuits.
//!
//! This module produces a [`BondingObject`] from any [`MultiStageCircuit`]
//! whose witness uses no gates: [`Driver::alloc`],
//! [`Driver::add`], and [`Driver::enforce_zero`] with normal wires are
//! permitted (no [`Driver::mul`], [`Driver::constant`], or `ONE`-wire
//! references). Because the circuit has no gates, it needs no final trace
//! and exists purely to enforce wiring between stages.
//!
//! The `ONE`-wire contribution is stripped so that the constant term in $Y$ is
//! zero, as required of a bonding polynomial. [`StageMask`] is a hand-optimized
//! bonding polynomial for stage well-formedness masks.
//!
//! [`Driver::mul`]: ragu_core::drivers::Driver::mul
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
//! [`Driver::constant`]: ragu_core::drivers::Driver::constant
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`StageMask`]: super::mask::StageMask

use ff::{Field, FromUniformBytes};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::Empty,
};

use alloc::boxed::Box;

use crate::{
    BondingObject, Circuit, CircuitObject, SegmentRecord,
    floor_planner::ConstraintSegment,
    into_circuit_object,
    polynomials::{Rank, sparse},
};

use super::{MultiStage, MultiStageCircuit};

impl<F, R, S> MultiStage<F, R, S>
where
    F: FromUniformBytes<64>,
    R: Rank,
    S: MultiStageCircuit<F, R>,
{
    /// Builds a [`BondingObject`] from this [`MultiStage`] circuit.
    ///
    /// The witness must use no gates: [`Driver::alloc`],
    /// [`Driver::add`], and [`Driver::enforce_zero`] are permitted (without
    /// referencing the [`Driver::ONE`] wire), but [`Driver::mul`] and
    /// [`Driver::constant`] are rejected.
    ///
    /// The `ONE`-wire contribution is stripped so that the constant term in $Y$
    /// is zero, as required of a bonding polynomial.
    ///
    /// [`Driver::mul`]: ragu_core::drivers::Driver::mul
    /// [`Driver::add`]: ragu_core::drivers::Driver::add
    /// [`Driver::alloc`]: ragu_core::drivers::Driver::alloc
    /// [`Driver::constant`]: ragu_core::drivers::Driver::constant
    /// [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
    /// [`Driver::ONE`]: ragu_core::drivers::Driver::ONE
    pub fn into_bonding_object<'a>(self) -> Result<BondingObject<'a, F, R>>
    where
        Self: 'a,
    {
        // Validate: run synthesis with a driver that rejects mul/gate and ONE usage.
        let mut validator = BondingValidator::<F>::new();
        self.witness(&mut validator, Empty)?;
        if let Some(msg) = validator.error {
            return Err(ragu_core::Error::InvalidWitness(msg.into()));
        }

        // Build the CircuitObject via the standard pipeline.
        let inner = into_circuit_object::<_, _, R>(self)?;

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
/// Bonding circuits may only use [`alloc`](Driver::alloc),
/// [`add`](Driver::add), and [`enforce_zero`](Driver::enforce_zero) with
/// normal wires. Calling [`mul`](Driver::mul)/[`gate`](DriverTypes::gate),
/// [`constant`](Driver::constant), or referencing the [`ONE`](Driver::ONE)
/// wire in any constraint records a violation.
///
/// All methods succeed; violations are accumulated in the `error` field and
/// checked by the caller after the witness completes.
struct BondingValidator<F> {
    error: Option<&'static str>,
    _marker: core::marker::PhantomData<F>,
}

impl<F> BondingValidator<F> {
    fn new() -> Self {
        BondingValidator {
            error: None,
            _marker: core::marker::PhantomData,
        }
    }

    fn record(&mut self, msg: &'static str) {
        self.error.get_or_insert(msg);
    }
}

impl<F: Field> DriverTypes for BondingValidator<F> {
    type ImplField = F;
    type ImplWire = BondingWire;
    type MaybeKind = Empty;
    type LCadd = RejectOne;
    type LCenforce = RejectOne;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(BondingWire, BondingWire, BondingWire, BondingWire)> {
        self.record("bonding circuits must not call mul/gate");
        Ok((
            BondingWire::Normal,
            BondingWire::Normal,
            BondingWire::Normal,
            BondingWire::Normal,
        ))
    }
}

impl<'dr, F: Field> Driver<'dr> for BondingValidator<F> {
    type F = F;
    type Wire = BondingWire;
    const ONE: Self::Wire = BondingWire::One;

    fn alloc(&mut self, _: impl Fn() -> Result<Coeff<F>>) -> Result<BondingWire> {
        Ok(BondingWire::Normal)
    }

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

/// Wraps a [`CircuitObject`] and strips the `enforce_one` contribution,
/// giving a zero constant term in $Y$.
pub(crate) struct Stripped<'a, F: Field, R: Rank>(Box<dyn CircuitObject<F, R> + 'a>);

impl<'a, F: Field, R: Rank> Stripped<'a, F, R> {
    pub(crate) fn new(inner: Box<dyn CircuitObject<F, R> + 'a>) -> Self {
        Self(inner)
    }
}

impl<F: Field, R: Rank> CircuitObject<F, R> for Stripped<'_, F, R> {
    fn sxy(&self, x: F, y: F, floor_plan: &[ConstraintSegment]) -> F {
        // Remove the ONE wire contribution: x^(2n) at y^0.
        self.0.sxy(x, y, floor_plan) - x.pow_vartime([(2 * R::n()) as u64])
    }

    fn sx(&self, x: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        let mut poly = self.0.sx(x, floor_plan);
        // Horner places the last constraint (enforce_one) at y^0 = coeffs[0].
        // TODO: sparse::Polynomial should support subtracting a field element
        // from the constant term directly.
        let coeff_0 = poly.iter_coeffs().next().unwrap();
        let correction = sparse::Polynomial::from_coeffs(alloc::vec![coeff_0]);
        poly.sub_assign(&correction);
        poly
    }

    fn sy(&self, y: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        let mut poly = self.0.sy(y, floor_plan);
        // Gate 0's b-wire holds the ONE wire; remove its y^0 contribution.
        // In the backward perspective, b[0] maps to degree 2n.
        let mut correction = sparse::View::<_, R, _>::backward();
        correction.b.push(F::ONE);
        poly.sub_assign(&correction.build());
        poly
    }

    // TODO(#614): revisit constraint_counts semantics — ambiguous with
    // system constraints (enforce_one, registry key, ONE gate).
    fn constraint_counts(&self) -> (usize, usize) {
        let (mul, lin) = self.0.constraint_counts();
        // The inner object includes the `enforce_one` constraint that we strip.
        (mul, lin - 1)
    }

    fn segment_records(&self) -> &[SegmentRecord] {
        self.0.segment_records()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        WithAux, floor_planner,
        polynomials::TestRank,
        staging::{MultiStageCircuit, StageBuilder},
    };
    use ff::Field;
    use ragu_core::drivers::DriverValue;
    use ragu_core::gadgets::Bound;
    use ragu_pasta::Fp;

    type R = TestRank;

    /// Minimal bonding circuit: allocates two wires and enforces equality.
    struct EqualWires;

    impl MultiStageCircuit<Fp, R> for EqualWires {
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
            let w0 = dr.alloc(|| Ok(Coeff::Zero))?;
            let w1 = dr.alloc(|| Ok(Coeff::Zero))?;
            dr.enforce_zero(|lc| lc.add(&w0).sub(&w1))?;
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
            let w = dr.alloc(|| Ok(Coeff::Zero))?;
            dr.enforce_zero(|lc| lc.add(&D::ONE).sub(&w))?;
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

    fn bonding_obj() -> Box<dyn CircuitObject<Fp, R>> {
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

    /// Bonding polynomials must have zero constant term in $Y$.
    #[test]
    fn zero_constant_term() {
        let obj = bonding_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

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

        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = obj.sxy(x, y, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &floor_plan).eval(x));
    }

    /// Build a trace with gate 0 as ONE (zeros) and gates 1..n from (b, d)
    /// pairs.
    fn build_trace(gate_values: &[(Fp, Fp)]) -> sparse::Polynomial<Fp, R> {
        let mut view = sparse::View::<_, R, _>::forward();
        // ONE gate placeholder.
        view.a.push(Fp::ZERO);
        view.b.push(Fp::ZERO);
        view.c.push(Fp::ZERO);
        view.d.push(Fp::ZERO);
        // Layout: (0, b, 0, d) per gate.
        for &(b, d) in gate_values {
            view.a.push(Fp::ZERO);
            view.b.push(b);
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

        let y = Fp::random(&mut rand::rng());
        let sy = obj.sy(y, &floor_plan);

        let v = Fp::random(&mut rand::rng());
        let w = Fp::random(&mut rand::rng());

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
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        assert_eq!(obj.sxy(Fp::ZERO, y, &floor_plan), Fp::ZERO);
        assert_eq!(obj.sxy(x, Fp::ZERO, &floor_plan), Fp::ZERO);

        let sxy = obj.sxy(x, y, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &floor_plan).eval(x));

        let rx = build_trace(&[(Fp::random(&mut rand::rng()), Fp::random(&mut rand::rng()))]);
        assert_eq!(rx.revdot(&obj.sy(y, &floor_plan)), Fp::ZERO);
    }
}
