//! Application-supplied closed-form wiring evaluators.
//!
//! Ragu evaluates a circuit's wiring polynomial $s(X, Y)$ by re-synthesizing
//! the circuit through a specialized driver, once per evaluation point. That is
//! correct for any circuit but blind to structure: a circuit whose constraints
//! follow a regular pattern has an $s(X, Y)$ with a closed form, and evaluating
//! that form directly can be asymptotically cheaper than walking the circuit.
//!
//! Ragu already relies on this internally — [`StageMask`] computes its
//! contribution from a geometric-series identity rather than by synthesis. This
//! module makes the same move available to applications, which are the only
//! party that knows their own circuit's algebra.
//!
//! # What an implementation may and may not do
//!
//! An implementation replaces *evaluation only*. The circuit remains the source
//! of truth for witness generation and trace assembly, Ragu still derives the
//! segment records and floor plan from the circuit itself, and Ragu still
//! enforces the gate and constraint bounds. A closed form that disagrees with
//! the circuit does not widen what a proof can claim; it produces a wiring
//! polynomial that does not match the circuit, which breaks proving rather than
//! soundness.
//!
//! That said, a disagreement is not self-announcing, because the registry
//! digest that binds the polynomial is itself computed through these
//! evaluators. Implementations must therefore be checked against synthesis.
//! Debug builds do so automatically: the wrapper Ragu puts in front of a
//! closed form evaluates both paths and asserts they agree.
//!
//! [`StageMask`]: crate::staging

use alloc::boxed::Box;

use ragu_arithmetic::ff::Field;

use crate::{
    SegmentRecord, WiringObject,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
};

/// A closed-form evaluator for a circuit's wiring polynomial $s(X, Y)$.
///
/// Supplied by an application through
/// [`Circuit::analytic_wiring`](crate::Circuit::analytic_wiring). Implementors
/// own their state, so any precomputed tables belong on the implementing type.
///
/// # Correctness
///
/// Every method must return exactly what synthesizing the circuit would return
/// for the same input. Three obligations are easy to miss:
///
/// - The three methods must agree with each other for **all** $x$ and $y$,
///   including zero: `sxy(x, y) == sx(x).eval(y) == sy(y).eval(x)`. The registry
///   mixes all three as restrictions of one bivariate polynomial, so a
///   disagreement between them is invisible to the type system.
/// - The zero corners are included: $s(x, 0)$ and $s(0, y)$ must both be what
///   synthesis produces there, which is rarely what a factored form yields
///   without a guard.
/// - Results must depend only on the arguments and immutable `self`; the
///   registry calls this through a shared reference and caches nothing.
///
/// Only $s(x, y)$ is overridable. The polynomial restrictions $s(x, Y)$ and
/// $s(X, y)$ stay synthesized, so an implementation never has to reproduce
/// Ragu's coefficient layout — and the scalar evaluation is what the registry
/// digest spends its time on.
pub trait AnalyticWiring<F: Field, R: Rank>: Send + Sync {
    /// Evaluates $s(x, y)$.
    ///
    /// The rank is a parameter of the trait rather than of this method, so an
    /// implementation can read `R::n()` to place wires.
    fn sxy(&self, x: F, y: F) -> F;
}

/// A synthesized wiring object with an application-supplied closed form
/// standing in front of it.
///
/// Evaluation is answered from the closed form. The synthesized object is
/// retained because Ragu, not the application, owns everything derived from the
/// circuit's structure — the segment records, and hence the floor plan the
/// registry hands back — and because debug builds cross-check every evaluation
/// against it.
pub(crate) struct Analytic<'a, F: Field, R: Rank> {
    analytic: Box<dyn AnalyticWiring<F, R>>,
    reference: Box<dyn WiringObject<F, R> + 'a>,
}

impl<'a, F: Field, R: Rank> Analytic<'a, F, R> {
    pub(crate) fn new(
        analytic: Box<dyn AnalyticWiring<F, R>>,
        reference: Box<dyn WiringObject<F, R> + 'a>,
    ) -> Self {
        Self {
            analytic,
            reference,
        }
    }
}

impl<F: Field, R: Rank> WiringObject<F, R> for Analytic<'_, F, R> {
    fn sxy(&self, x: F, y: F, floor_plan: &[ConstraintSegment]) -> F {
        let value = self.analytic.sxy(x, y);
        debug_assert_eq!(
            value,
            self.reference.sxy(x, y, floor_plan),
            "analytic sxy disagrees with synthesizing the circuit"
        );
        value
    }

    fn sx(&self, x: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        self.reference.sx(x, floor_plan)
    }

    fn sy(&self, y: F, floor_plan: &[ConstraintSegment]) -> sparse::Polynomial<F, R> {
        self.reference.sy(y, floor_plan)
    }

    fn segment_records(&self) -> &[SegmentRecord] {
        self.reference.segment_records()
    }

    fn is_mask(&self) -> bool {
        self.reference.is_mask()
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::{ff::Field, geosum};
    use ragu_pasta::Fp;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        floor_planner,
        polynomials::{Rank, TestRank},
        tests::SquareCircuit,
    };

    /// A closed form for [`SquareCircuit`]'s wiring polynomial.
    ///
    /// `SquareCircuit { times: t }` emits one gate and two `enforce_equal`
    /// constraints per squaring, chained so that gate $j$'s two inputs are both
    /// the previous gate's output. Wire positions therefore advance in
    /// arithmetic progression, and $s(X, Y)$ collapses to a handful of
    /// geometric sums:
    ///
    /// $$s(x,y) = 1 + y\,x^{4n-2-t} + \Sigma_1 + \Sigma_2
    ///            - (1+y)\left(y^{2t}x^{2n+1} + \Sigma_3\right)$$
    ///
    /// with $\Sigma_1 = x^{2n-2-t}y^2\,\mathrm{geosum}(xy^2, t)$,
    /// $\Sigma_3 = x^{4n-1-t}y^2\,\mathrm{geosum}(xy^2, t-1)$, and
    /// $\Sigma_2 = \sum_{k<t} x^{2n+2+k}y^{2t+1-2k}$, which is evaluated as
    /// $x^{2n+2}y^3\cdot\frac{x^t - (y^2)^t}{x - y^2}$.
    struct SquareWiring {
        times: usize,
    }

    impl<R: Rank> AnalyticWiring<Fp, R> for SquareWiring {
        fn sxy(&self, x: Fp, y: Fp) -> Fp {
            // Only the ONE constraint survives at either origin: every other
            // term carries a positive power of both variables.
            if x.is_zero().into() || y.is_zero().into() {
                return Fp::ONE;
            }

            let n = R::n() as u64;
            let t = self.times as u64;
            let pow = |b: Fp, e: u64| b.pow_vartime([e]);

            // A single allocation and its output binding, with no squarings.
            if t == 0 {
                return Fp::ONE + y * pow(x, 2 * n + 1);
            }

            let y2 = y.square();
            let xy2 = x * y2;

            // The two constraints of squaring k, read from the last squaring
            // backwards, sit at Y-powers 2(t-k) and 2(t-k)+1.
            let sigma1 = pow(x, 2 * n - 2 - t) * y2 * geosum(xy2, t as usize);
            let sigma3 = pow(x, 4 * n - 1 - t) * y2 * geosum(xy2, (t - 1) as usize);

            // Sum_{k<t} x^{2n+2+k} y^{2t+1-2k}: x rises as y falls, so this one
            // is a homogeneous sum rather than a geometric one.
            let homogeneous = if x == y2 {
                Fp::from(t) * pow(x, t - 1)
            } else {
                (pow(x, t) - pow(y2, t)) * (x - y2).invert().unwrap()
            };
            let sigma2 = pow(x, 2 * n + 2) * y * y2 * homogeneous;

            Fp::ONE + y * pow(x, 4 * n - 2 - t) + sigma1 + sigma2
                - (Fp::ONE + y) * (pow(y, 2 * t) * pow(x, 2 * n + 1) + sigma3)
        }
    }

    /// `SquareCircuit` plus its closed form, standing in for an application
    /// that knows its own circuit's algebra and hands Ragu a shortcut.
    struct AcceleratedSquare {
        inner: SquareCircuit,
    }

    impl crate::Circuit<Fp> for AcceleratedSquare {
        type Instance<'i> = <SquareCircuit as crate::Circuit<Fp>>::Instance<'i>;
        type Output = <SquareCircuit as crate::Circuit<Fp>>::Output;
        type Witness<'w> = <SquareCircuit as crate::Circuit<Fp>>::Witness<'w>;
        type Aux<'w> = <SquareCircuit as crate::Circuit<Fp>>::Aux<'w>;

        fn instance<'dr, 'i: 'dr, D: ragu_core::drivers::Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: ragu_core::drivers::DriverValue<D, Self::Instance<'i>>,
        ) -> ragu_core::Result<ragu_core::gadgets::Bound<'dr, D, Self::Output>> {
            self.inner.instance(dr, instance)
        }

        fn witness<'dr, 'w: 'dr, D: ragu_core::drivers::Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: ragu_core::drivers::DriverValue<D, Self::Witness<'w>>,
        ) -> ragu_core::Result<
            crate::WithAux<
                ragu_core::gadgets::Bound<'dr, D, Self::Output>,
                ragu_core::drivers::DriverValue<D, Self::Aux<'w>>,
            >,
        > {
            self.inner.witness(dr, witness)
        }

        fn analytic_wiring<R: Rank>(&self) -> Option<Box<dyn AnalyticWiring<Fp, R>>> {
            Some(Box::new(SquareWiring {
                times: self.inner.times,
            }))
        }
    }

    /// Registering with and without the closed form must produce the same
    /// registry digest.
    ///
    /// The digest chains six evaluations at pseudorandom multi-point challenges
    /// over every circuit into one field element, so it is an unusually sharp
    /// check on a substitute evaluator: any disagreement anywhere changes it.
    /// It is also the computation the closed form exists to speed up
    /// (`FIXME(security)` in `registry`).
    #[test]
    fn registry_digest_is_unchanged_by_the_closed_form() -> ragu_core::Result<()> {
        for times in [0usize, 1, 3, 7] {
            let synthesized = crate::registry::RegistryBuilder::<Fp, TestRank>::new()
                .register_circuit(SquareCircuit { times })?
                .finalize()?;
            let accelerated = crate::registry::RegistryBuilder::<Fp, TestRank>::new()
                .register_circuit(AcceleratedSquare {
                    inner: SquareCircuit { times },
                })?
                .finalize()?;

            assert_eq!(
                synthesized.digest(),
                accelerated.digest(),
                "registry digest changed when the closed form replaced synthesis (times={times})"
            );
        }

        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// The closed form must agree with synthesizing the circuit.
        #[test]
        fn analytic_square_matches_synthesis(
            times in 0usize..12,
            x in ragu_testing::strategies::prime_field_element::<Fp>(),
            y in ragu_testing::strategies::prime_field_element::<Fp>(),
        ) {
            let reference =
                crate::into_wiring_object::<Fp, _, TestRank>(SquareCircuit { times }).unwrap();
            let plan = floor_planner::floor_plan(reference.segment_records());
            let analytic = SquareWiring { times };

            let closed = |x, y| <SquareWiring as AnalyticWiring<Fp, TestRank>>::sxy(&analytic, x, y);

            prop_assert_eq!(closed(x, y), reference.sxy(x, y, &plan), "times={}", times);
            // The corners are where a factored form most easily goes wrong.
            prop_assert_eq!(closed(Fp::ZERO, y), reference.sxy(Fp::ZERO, y, &plan));
            prop_assert_eq!(closed(x, Fp::ZERO), reference.sxy(x, Fp::ZERO, &plan));
            prop_assert_eq!(closed(Fp::ZERO, Fp::ZERO), reference.sxy(Fp::ZERO, Fp::ZERO, &plan));
        }
    }
}
