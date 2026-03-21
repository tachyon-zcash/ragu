//! Bonding polynomial construction from routing constraints.
//!
//! A bonding polynomial is a wiring polynomial that only encodes linear
//! constraints. It has no witness and no trace polynomial — it is checked
//! via revdot against traces produced by other circuits or stages.
//!
//! [`StageMask`](super::mask::StageMask) is one factory (hand-optimized for
//! stage well-formedness). This module provides the machinery to build bonding
//! polynomials from [`MultiStageCircuit::routing`](super::MultiStageCircuit::routing)
//! declarations — suitable for routing polynomials and other cross-stage
//! linear constraints.
//!
//! These are kept as separate factories rather than generalizing `StageMask`
//! because `StageMask` pushes coefficients sequentially per gate, while
//! routing constraints span multiple gates in a single `enforce_zero` call,
//! requiring random access to coefficient positions.

use ff::{Field, FromUniformBytes};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};

use alloc::{boxed::Box, vec::Vec};

use crate::{
    BondingObject, Circuit, CircuitObject, SegmentRecord,
    floor_planner::ConstraintSegment,
    metrics,
    polynomials::{Rank, structured, unstructured},
    registry, s,
};

/// Build a [`BondingObject`] from a
/// [`MultiStageCircuit`](super::MultiStageCircuit)'s routing constraints.
///
/// Returns `None` if `S::num_routing_gates()` is zero (no routing).
pub(crate) fn routing_object<'a, F, R, S>() -> Result<Option<BondingObject<'a, F, R>>>
where
    F: FromUniformBytes<64>,
    R: Rank,
    S: super::MultiStageCircuit<F, R> + 'a,
{
    if S::num_routing_gates() == 0 {
        return Ok(None);
    }

    let adapter = Adapter::<S, F, R>(core::marker::PhantomData);
    let metrics = metrics::eval(&adapter)?;

    if metrics.num_linear_constraints > R::num_coeffs() {
        return Err(ragu_core::Error::LinearBoundExceeded {
            limit: R::num_coeffs(),
        });
    }
    if metrics.num_multiplication_constraints > R::n() {
        return Err(ragu_core::Error::MultiplicationBoundExceeded { limit: R::n() });
    }

    Ok(Some(BondingObject::new(Box::new(Processed {
        adapter,
        metrics,
    }))))
}

/// Bridges [`MultiStageCircuit::routing`](super::MultiStageCircuit::routing)
/// to [`Circuit`] so we can reuse the standard synthesis drivers.
/// Pre-allocates gate wire handles with the real driver, then hands a
/// [`RoutingDriver`] decorator to the routing method.
struct Adapter<S, F, R>(core::marker::PhantomData<(S, F, R)>);

impl<F: Field, R: Rank, S: super::MultiStageCircuit<F, R>> Circuit<F> for Adapter<S, F, R> {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<(Bound<'dr, D, ()>, DriverValue<D, ()>)> {
        let num_gates = S::num_routing_gates();
        let mut gates = Vec::with_capacity(num_gates);
        for _ in 0..num_gates {
            gates.push(dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?);
        }

        S::routing(dr, &gates)?;

        Ok(((), D::unit()))
    }
}

/// The produced [`CircuitObject`].
///
/// The standard synthesis includes an `enforce_one` constraint that anchors
/// the ONE wire. Bonding polynomials must not have this (zero constant term),
/// so each evaluation method runs the full synthesis then strips it out.
struct Processed<S, F, R> {
    adapter: Adapter<S, F, R>,
    metrics: metrics::CircuitMetrics,
}

impl<F: Field + FromUniformBytes<64>, R: Rank, S: super::MultiStageCircuit<F, R>>
    CircuitObject<F, R> for Processed<S, F, R>
{
    fn sxy(&self, x: F, y: F, key: &registry::Key<F>, floor_plan: &[ConstraintSegment]) -> F {
        if x == F::ZERO || y == F::ZERO {
            return F::ZERO;
        }

        // Remove the ONE wire contribution: x^(4n-1) at y^0.
        s::sxy::eval::<_, _, R>(&self.adapter, x, y, key, floor_plan)
            .expect("should succeed if metrics succeeded")
            - x.pow_vartime([(4 * R::n() - 1) as u64])
    }

    fn sx(
        &self,
        x: F,
        key: &registry::Key<F>,
        floor_plan: &[ConstraintSegment],
    ) -> unstructured::Polynomial<F, R> {
        if x == F::ZERO {
            return unstructured::Polynomial::new();
        }
        let mut poly = s::sx::eval(&self.adapter, x, key, floor_plan)
            .expect("should succeed if metrics succeeded");

        // Horner places the last constraint (enforce_one) at y^0 = coeffs[0].
        poly.as_mut()[0] = F::ZERO;
        poly
    }

    fn sy(
        &self,
        y: F,
        key: &registry::Key<F>,
        floor_plan: &[ConstraintSegment],
    ) -> structured::Polynomial<F, R> {
        if y == F::ZERO {
            return structured::Polynomial::new();
        }
        let mut poly = s::sy::eval(&self.adapter, y, key, floor_plan)
            .expect("should succeed if metrics succeeded");

        // Gate 0's c-wire holds the ONE wire; remove its y^0 contribution.
        poly.backward().c[0] -= F::ONE;
        poly
    }

    /// Returns constraint counts matching the synthesis shape.
    ///
    /// These counts include the `enforce_one` constraint that the synthesis
    /// drivers emit, even though the polynomial has that contribution stripped.
    /// This is correct: the counts describe the synthesis structure that the
    /// floor plan and eval functions expect, not the final polynomial.
    fn constraint_counts(&self) -> (usize, usize) {
        (
            self.metrics.num_multiplication_constraints,
            self.metrics.num_linear_constraints,
        )
    }

    fn segment_records(&self) -> &[SegmentRecord] {
        &self.metrics.segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        floor_planner,
        polynomials::TestRank,
        staging::{MultiStageCircuit, StageBuilder},
    };
    use ff::Field;
    use ragu_core::drivers::LinearExpression;
    use ragu_pasta::Fp;

    type R = TestRank;

    /// Minimal [`MultiStageCircuit`] with routing that enforces gate 0's
    /// a-wire equals gate 1's a-wire.
    struct RouteEqual;

    impl MultiStageCircuit<Fp, R> for RouteEqual {
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
            _: StageBuilder<'a, 'dr, D, R, (), ()>,
            _: DriverValue<D, ()>,
        ) -> Result<(Bound<'dr, D, ()>, DriverValue<D, ()>)> {
            Ok(((), D::unit()))
        }

        fn num_routing_gates() -> usize {
            2
        }

        fn routing<'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            gates: &[(D::Wire, D::Wire, D::Wire)],
        ) -> Result<()> {
            let (a0, _, _) = &gates[0];
            let (a1, _, _) = &gates[1];
            dr.enforce_zero(|lc| lc.add(a0).sub(a1))
        }
    }

    fn routing_obj() -> Box<dyn CircuitObject<Fp, R>> {
        routing_object::<Fp, R, RouteEqual>()
            .unwrap()
            .unwrap()
            .into_inner()
    }

    /// Bonding polynomials must have zero constant term (no ONE wire).
    #[test]
    fn zero_constant_term() {
        let obj = routing_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());
        let key = registry::Key::new(Fp::random(&mut rand::rng()));
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        assert_eq!(obj.sxy(Fp::ZERO, y, &key, &floor_plan), Fp::ZERO);
        assert_eq!(obj.sxy(x, Fp::ZERO, &key, &floor_plan), Fp::ZERO);
    }

    /// sxy(x,y) = sx(x).eval(y) = sy(y).eval(x).
    #[test]
    fn evaluation_consistency() {
        let obj = routing_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());
        let key = registry::Key::new(Fp::random(&mut rand::rng()));
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = obj.sxy(x, y, &key, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &key, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &key, &floor_plan).eval(x));
    }

    /// Build a trace with gate 0 as ONE (zeros) and gates 1..n from (a, b) pairs.
    fn build_trace(gate_values: &[(Fp, Fp)]) -> structured::Polynomial<Fp, R> {
        let mut rx = structured::Polynomial::new();
        {
            let rx = rx.forward();
            // Gate 0: ONE (all zeros in stage polynomials)
            rx.a.push(Fp::ZERO);
            rx.b.push(Fp::ZERO);
            rx.c.push(Fp::ZERO);
            for &(a, b) in gate_values {
                rx.a.push(a);
                rx.b.push(b);
                rx.c.push(a * b);
            }
        }
        rx
    }

    /// Revdot is zero when routed wires are equal, nonzero otherwise.
    #[test]
    fn revdot_routing_constraint() {
        let obj = routing_obj();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());
        let key = registry::Key::new(Fp::random(&mut rand::rng()));
        let y = Fp::random(&mut rand::rng());
        let sy = obj.sy(y, &key, &floor_plan);

        let v = Fp::random(&mut rand::rng());
        let w = Fp::random(&mut rand::rng());

        let rx_equal = build_trace(&[(v, Fp::ONE), (v, Fp::ONE)]);
        assert_eq!(rx_equal.revdot(&sy), Fp::ZERO);

        let rx_unequal = build_trace(&[(v, Fp::ONE), (w, Fp::ONE)]);
        assert_ne!(rx_unequal.revdot(&sy), Fp::ZERO);
    }

}
