//! General-purpose factory for bonding polynomials.
//!
//! A bonding polynomial is a wiring polynomial that only encodes linear
//! constraints. It has no witness and no trace polynomial — it is checked
//! via revdot against traces produced by other circuits or stages.
//!
//! [`StageMask`](super::mask::StageMask) is one factory (hand-optimized for
//! stage well-formedness). This module provides [`BondingCircuit`], a
//! general factory that builds bonding polynomials from arbitrary
//! `enforce_zero` declarations — suitable for routing polynomials and
//! other cross-stage linear constraints.

use ff::{Field, FromUniformBytes};
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};

use alloc::{boxed::Box, vec::Vec};

use crate::{
    Circuit, CircuitObject, SegmentRecord,
    floor_planner::ConstraintSegment,
    metrics,
    polynomials::{Rank, structured, unstructured},
    registry, s,
};

/// A restricted driver that only allows linear constraints.
///
/// Wraps a real driver but hides `alloc`, `mul`, and `routine`, ensuring
/// bonding circuit implementations can only declare linear constraints
/// between existing wire positions.
pub struct BondingDriver<'a, 'dr, D: Driver<'dr>>(&'a mut D, core::marker::PhantomData<&'dr ()>);

impl<'a, 'dr, D: Driver<'dr>> BondingDriver<'a, 'dr, D> {
    /// Constrain a linear combination of wires to equal zero.
    pub fn enforce_zero(&mut self, lc: impl Fn(D::LCenforce) -> D::LCenforce) -> Result<()> {
        self.0.enforce_zero(lc)
    }

    /// Build a virtual wire from a linear combination of existing wires.
    pub fn add(&mut self, lc: impl Fn(D::LCadd) -> D::LCadd) -> D::Wire {
        self.0.add(lc)
    }
}

/// Trait for building bonding polynomials from linear constraint declarations.
///
/// Implementors describe constraints between wire positions using
/// [`BondingDriver::enforce_zero`]. Wire handles come from the `gates` slice
/// passed to [`synthesize`](Self::synthesize), where `gates[i]` holds
/// `(a, b, c)` handles for multiplication gate `i + 1` in the polynomial
/// (gate 0 is reserved for the registry key).
///
/// To reference a specific stage's wires, index into `gates` using the
/// stage's [`skip_multiplications`](super::Stage::skip_multiplications) offset.
pub trait BondingCircuit<F: Field>: Sized + Send + Sync {
    /// How many gates to pre-allocate wire handles for.
    fn num_gates(&self) -> usize;

    /// Declare linear constraints between gate wires.
    fn synthesize<'dr, D: Driver<'dr, F = F>>(
        &self,
        bd: &mut BondingDriver<'_, 'dr, D>,
        gates: &[(D::Wire, D::Wire, D::Wire)],
    ) -> Result<()>;

    /// Produce a [`CircuitObject`] for registry registration via
    /// [`register_internal_bonding`](registry::RegistryBuilder::register_internal_bonding).
    fn into_bonding_object<'a, R: Rank>(self) -> Result<Box<dyn CircuitObject<F, R> + 'a>>
    where
        Self: 'a,
        F: FromUniformBytes<64>,
    {
        let adapter = Adapter(self);
        let metrics = metrics::eval(&adapter)?;

        if metrics.num_linear_constraints > R::num_coeffs() {
            return Err(ragu_core::Error::LinearBoundExceeded {
                limit: R::num_coeffs(),
            });
        }
        if metrics.num_multiplication_constraints > R::n() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded { limit: R::n() });
        }

        Ok(Box::new(Processed { adapter, metrics }))
    }
}

/// Bridges [`BondingCircuit`] to [`Circuit`] so we can reuse the standard
/// synthesis drivers. Pre-allocates gate wire handles, then hands the
/// restricted [`BondingDriver`] to the bonding circuit's `synthesize`.
struct Adapter<B>(B);

impl<F: Field, B: BondingCircuit<F>> Circuit<F> for Adapter<B> {
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
        let mut gates = Vec::with_capacity(self.0.num_gates());
        for _ in 0..self.0.num_gates() {
            gates.push(dr.mul(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?);
        }
        let mut bd = BondingDriver(dr, core::marker::PhantomData);
        self.0.synthesize(&mut bd, &gates)?;

        Ok(((), D::unit()))
    }
}

/// The produced [`CircuitObject`].
///
/// The standard synthesis includes an `enforce_one` constraint that anchors
/// the ONE wire. Bonding polynomials must not have this (zero constant term),
/// so each evaluation method runs the full synthesis then strips it out.
struct Processed<B> {
    adapter: Adapter<B>,
    metrics: metrics::CircuitMetrics,
}

impl<F: Field + FromUniformBytes<64>, B: BondingCircuit<F>, R: Rank> CircuitObject<F, R>
    for Processed<B>
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
    use crate::{floor_planner, polynomials::TestRank};
    use ff::Field;
    use ragu_core::drivers::LinearExpression;
    use ragu_pasta::Fp;

    type R = TestRank;

    /// Enforces gate 0's a-wire equals gate 1's a-wire.
    struct RouteEqual;

    impl BondingCircuit<Fp> for RouteEqual {
        fn num_gates(&self) -> usize {
            2
        }

        fn synthesize<'dr, D: Driver<'dr, F = Fp>>(
            &self,
            bd: &mut BondingDriver<'_, 'dr, D>,
            gates: &[(D::Wire, D::Wire, D::Wire)],
        ) -> Result<()> {
            let (a0, _, _) = &gates[0];
            let (a1, _, _) = &gates[1];
            bd.enforce_zero(|lc| lc.add(a0).sub(a1))
        }
    }

    /// Bonding polynomials must have zero constant term (no ONE wire).
    #[test]
    fn zero_constant_term() {
        let obj = RouteEqual.into_bonding_object::<R>().unwrap();
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
        let obj = RouteEqual.into_bonding_object::<R>().unwrap();
        let floor_plan = floor_planner::floor_plan(obj.segment_records());
        let key = registry::Key::new(Fp::random(&mut rand::rng()));
        let x = Fp::random(&mut rand::rng());
        let y = Fp::random(&mut rand::rng());

        let sxy = obj.sxy(x, y, &key, &floor_plan);
        assert_eq!(sxy, obj.sx(x, &key, &floor_plan).eval(y));
        assert_eq!(sxy, obj.sy(y, &key, &floor_plan).eval(x));
    }
}
