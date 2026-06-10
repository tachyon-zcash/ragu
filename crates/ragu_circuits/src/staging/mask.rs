use ragu_arithmetic::{ff::Field, geosum};
use ragu_core::Result;

use crate::{
    WiringObject,
    polynomials::{Rank, sparse},
};

/// Evaluates the global stage mask polynomial $S\_{\text{global}}(X, Y)$ at
/// the point $(x, y)$.
///
/// The global mask enforces all $4n$ wire slots to zero except the four wires
/// of the SYSTEM gate (gate 0):
///
/// $$S_{\text{global}}(x, y) = \sum_{i=0}^{4n-1} (xy)^i
///     - \bigl((xy)^{2n} + 1\bigr)\bigl((xy)^{2n-1} + 1\bigr)$$
///
/// The polynomial depends only on the product $XY$, so both variables
/// enter only through $xy = x \cdot y$.
///
/// This term is invariant across all [`StageMask`] instances for a given
/// `(R, F)` — it depends only on `R::n()`. The [`Registry`] computes it once
/// and scales by the sum of Lagrange coefficients for all masking polynomials,
/// rather than letting each mask evaluate it redundantly.
///
/// Returns [`Field::ZERO`] when `x == 0` or `y == 0` (bonding polynomials
/// have zero constant term in $Y$).
///
/// [`Registry`]: crate::registry::Registry
pub(crate) fn global_mask<F: Field, R: Rank>(x: F, y: F) -> F {
    if x == F::ZERO || y == F::ZERO {
        return F::ZERO;
    }

    let xy = x * y;
    let xy_2n = xy.pow_vartime([2 * R::n() as u64]);
    let xy_inv = xy.invert().expect("xy is not zero");

    geosum(xy, R::n() << 2) - (xy_2n + F::ONE) * (xy_2n * xy_inv + F::ONE)
}

/// Computes the polynomial restriction $S\_{\text{global}}(p, Y)$ (equivalently
/// $S\_{\text{global}}(X, p)$ by symmetry) as a sparse univariate polynomial.
/// Populates `4(n - 1)` wire positions — all except the four wires of the
/// SYSTEM gate (gate 0).
///
/// Used by [`Registry`](crate::registry::Registry) to add the shared global
/// contribution once, scaled by the sum of masking circuit Lagrange coefficients.
pub(crate) fn global_project<F: Field, R: Rank>(p: F) -> sparse::Polynomial<F, R> {
    if p == F::ZERO {
        return sparse::Polynomial::default();
    }
    let n = R::n();
    let mut view = sparse::View::<F, R, _>::wiring();
    view.d.resize(n, F::ZERO);
    view.a.resize(n, F::ZERO);
    view.b.resize(n, F::ZERO);
    view.c.resize(n, F::ZERO);

    let mut cur = F::ONE;
    for j in 0..n {
        view.d[j] = cur;
        cur *= p;
    }
    for j in (0..n).rev() {
        view.b[j] = cur;
        cur *= p;
    }
    for j in 0..n {
        view.a[j] = cur;
        cur *= p;
    }
    for j in (0..n).rev() {
        view.c[j] = cur;
        cur *= p;
    }

    // The SYSTEM gate wires are always zero in the global mask.
    view.a[0] = F::ZERO;
    view.b[0] = F::ZERO;
    view.c[0] = F::ZERO;
    view.d[0] = F::ZERO;

    view.build()
}

#[derive(Clone)]
pub struct StageMask<R: Rank> {
    skip_gates: usize,
    num_gates: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<R: Rank> StageMask<R> {
    /// Creates a new staging wiring polynomial with the given
    /// `skip_gates` and `num_gates` values. `skip_gates` includes
    /// the SYSTEM gate (gate 0) and must be at least 1. Gate wires are
    /// enforced to zero for gates `1..skip_gates` and
    /// `(skip_gates + num_gates)..n`. The SYSTEM gate is not constrained
    /// here because `a[0]` carries the alpha blinding factor and
    /// `d[0]` may or may not be set to 1; `b[0]` and `c[0]` are
    /// zero in all cases.
    pub fn new(skip_gates: usize, num_gates: usize) -> Result<Self> {
        assert!(skip_gates > 0, "skip_gates must include the SYSTEM gate");
        if skip_gates + num_gates > R::n() {
            return Err(ragu_core::Error::GateBoundExceeded { limit: R::n() });
        }
        Ok(Self {
            skip_gates,
            num_gates,
            _marker: core::marker::PhantomData,
        })
    }

    /// Creates the final staging wiring polynomial with the given
    /// `skip_gates` and maximum possible gates. `skip_gates` must
    /// be at least 1 (it includes the SYSTEM gate). The number
    /// of gates will be `R::n() - skip_gates`, which is the maximum
    /// before bounds are reached.
    pub fn new_final(skip_gates: usize) -> Result<Self> {
        assert!(skip_gates > 0, "skip_gates must include the SYSTEM gate");
        if skip_gates > R::n() {
            return Err(ragu_core::Error::GateBoundExceeded { limit: R::n() });
        }

        let num_gates = R::n() - skip_gates;

        Ok(Self {
            skip_gates,
            num_gates,
            _marker: core::marker::PhantomData,
        })
    }

    /// Returns a sparse polynomial containing the negated notch entries for
    /// the active-stage gate wires at positions `skip_gates..skip_gates + num_gates`.
    /// The SYSTEM gate is excluded (it is already zero in the global mask).
    ///
    /// The result has `4 × num_gates` non-zero entries
    /// (vs `4(n - 1)` for the full mask projection).
    fn notch_project<F: Field>(&self, p: F) -> sparse::Polynomial<F, R> {
        if self.num_gates == 0 || p == F::ZERO {
            return sparse::Polynomial::default();
        }
        let n = R::n();
        let g = self.skip_gates;
        let m = self.num_gates;
        let mut view = sparse::View::<F, R, _>::wiring();
        view.d.resize(g + m, F::ZERO);
        view.a.resize(g + m, F::ZERO);
        view.b.resize(g + m, F::ZERO);
        view.c.resize(g + m, F::ZERO);

        let p_inv = p.invert().expect("p is not zero");
        let mut d = -p.pow_vartime([g as u64]);
        let mut a = -p.pow_vartime([(2 * n + g) as u64]);
        let mut b = -p.pow_vartime([(2 * n - 1 - g) as u64]);
        let mut c = -p.pow_vartime([(4 * n - 1 - g) as u64]);

        for j in g..g + m {
            view.d[j] = d;
            view.a[j] = a;
            view.b[j] = b;
            view.c[j] = c;
            d *= p;
            a *= p;
            b *= p_inv;
            c *= p_inv;
        }

        view.build()
    }
}

impl<F: Field, R: Rank> WiringObject<F, R> for StageMask<R> {
    /// Evaluates the per-instance notch term $-\text{notch}(x, y)$.
    ///
    /// The full stage mask is $S\_{\text{global}} - \text{notch}$, but
    /// the invariant $S\_{\text{global}}$ term is factored out and applied
    /// once by the [`Registry`](crate::registry::Registry). This method
    /// returns only $-\text{notch}$, where
    ///
    /// $$\text{notch}(x, y) = (1 + (xy)^{2n})\bigl((xy)^g + (xy)^{2n-g-m}\bigr)
    ///     \cdot \sum_{i=0}^{m-1} (xy)^i$$
    ///
    /// with $g = \text{skip\_gates}$ and $m = \text{num\_gates}$.
    fn sxy(&self, x: F, y: F, _floor_plan: &[crate::floor_planner::ConstraintSegment]) -> F {
        if x == F::ZERO || y == F::ZERO {
            return F::ZERO;
        }

        let xy = x * y;
        let xy_2n = xy.pow_vartime([2 * R::n() as u64]);

        let gsum = geosum(xy, self.num_gates);
        let skip = xy.pow_vartime([self.skip_gates as u64]);
        let tail = xy.pow_vartime([(2 * R::n() - self.skip_gates - self.num_gates) as u64]);

        -((F::ONE + xy_2n) * (skip + tail) * gsum)
    }

    fn sx(
        &self,
        x: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        self.notch_project(x)
    }

    fn sy(
        &self,
        y: F,
        _floor_plan: &[crate::floor_planner::ConstraintSegment],
    ) -> sparse::Polynomial<F, R> {
        self.notch_project(y)
    }

    fn constraint_counts(&self) -> (usize, usize) {
        let num_gates = R::n();
        // 4n-2 enforce_zero (all degrees from 4n-2 to 1, with dummies for
        // active gates and the SYSTEM gate's inaccessible wires) + 1 enforce_one.
        let num_constraints = 4 * R::n() - 1;
        (num_gates, num_constraints)
    }

    fn segment_records(&self) -> &[crate::SegmentRecord] {
        &[]
    }

    fn is_mask(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use proptest::prelude::*;
    use ragu_arithmetic::{
        CurveAffine, Cycle, FixedGenerators,
        ff::Field,
        group::{Curve, CurveAffine as _},
        rand::RngExt,
    };
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue, LinearExpression, emulator::Emulator},
        gadgets::{Bound, Gadget},
        maybe::Maybe,
        routines::{Prediction, Routine},
    };
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};
    use ragu_primitives::{Element, Endoscalar, Point, consistent::Consistent, io::Write};

    use super::{
        super::{Stage, StageExt},
        StageMask,
    };
    use crate::{
        WiringObject, WithAux, floor_planner, into_raw_wiring_object, into_wiring_object, metrics,
        polynomials::{Rank, sparse},
        staging::StageBuilder,
        tests::SquareCircuit,
    };

    /// Local wrapper that names the four wire handles of one gate. Used by
    /// the [`StageMask`] test impl below to make the four-block iterator
    /// chain readable (`&g.a`, `&g.b`, ...).
    struct Gate<W> {
        a: W,
        b: W,
        c: W,
        d: W,
    }

    impl<F: Field, R: Rank> crate::raw::RawCircuit<F> for StageMask<R> {
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        where
            Self: 'dr,
        {
            assert!(self.skip_gates + self.num_gates <= R::n());

            // Allocate gates 1..n locally; gate 0 (the SYSTEM gate) is
            // allocated by `orchestrate` and is not referenced here. Vec
            // offset `i` corresponds to actual gate index `i + 1`.
            let mut gates: alloc::vec::Vec<Gate<D::Wire>> =
                alloc::vec::Vec::with_capacity(R::n() - 1);
            for _ in 1..R::n() {
                let (a, b, c, extra) = dr.gate(|| unimplemented!())?;
                let d = dr.assign_extra(extra, || unimplemented!())?;
                gates.push(Gate { a, b, c, d });
            }

            let is_active =
                |j: usize| j == 0 || (j >= self.skip_gates && j < self.skip_gates + self.num_gates);

            // Issue 4n-2 enforce_zero in decreasing degree order so that the
            // driver assigns y^k to the constraint at degree k. Dummy (empty
            // LC) constraints fill gaps for active gates.
            //
            // c[j] at degree 4n-1-j (j=1..n-1), a[j] at degree 2n+j (j=n-1 down to 0),
            // b[j] at degree 2n-1-j (j=0..n-1), d[j] at degree j (j=n-1 down to 1).
            // d[0] at degree 0 is the ONE wire slot, not issued here (handled
            // by orchestrate + Stripped for bonding polynomials).
            // c[0] is the registry key slot at degree 4n-1 — not emitted here.
            //
            // The a[j=0] and b[j=0] slots are dummy constraints (the SYSTEM
            // gate is always "active" so its wires are not masked); we
            // reproduce those slots with `iter::once(None)` since gate 0 is
            // not in `gates`.
            let wires = gates
                .iter()
                .enumerate()
                .map(|(i, g)| (!is_active(i + 1)).then_some(&g.c))
                .chain(
                    gates
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(i, g)| (!is_active(i + 1)).then_some(&g.a))
                        .chain(core::iter::once(None)),
                )
                .chain(
                    core::iter::once(None).chain(
                        gates
                            .iter()
                            .enumerate()
                            .map(|(i, g)| (!is_active(i + 1)).then_some(&g.b)),
                    ),
                )
                .chain(
                    gates
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(i, g)| (!is_active(i + 1)).then_some(&g.d)),
                );

            for wire in wires {
                match wire {
                    Some(w) => dr.enforce_zero(|lc| lc.add(w))?,
                    None => dr.enforce_zero(|lc| lc)?,
                }
            }

            Ok(WithAux::new((), D::unit()))
        }
    }

    /// Creates a [`WiringObject`] from a [`StageMask`] via its [`RawCircuit`]
    /// impl.
    fn mask_wiring_object(
        mask: StageMask<R>,
    ) -> alloc::boxed::Box<dyn WiringObject<Fp, R> + 'static> {
        let metrics = metrics::eval_raw::<Fp, _>(&mask).unwrap();
        into_raw_wiring_object::<Fp, _, R>(mask, metrics).unwrap()
    }

    impl<R: Rank> StageMask<R> {
        /// Returns the generator point for the `coefficient_index`-th $a$-wire
        /// coefficient of this stage.
        ///
        /// The $a$-wire at gate $j$ occupies degree $2n - 1 - j$ in the
        /// witness polynomial. The SYSTEM gate is included in `skip_gates`, so the
        /// first active gate is at index `skip_gates` and the formula
        /// becomes $2n - 1 - \text{skip\_gates} - \text{coefficient\_index}$.
        fn generator_for_a_coefficient<C: CurveAffine>(
            &self,
            generators: &impl FixedGenerators<C>,
            coefficient_index: usize,
        ) -> C {
            assert!(
                coefficient_index < self.num_gates,
                "coefficient_index {} exceeds num_gates {}",
                coefficient_index,
                self.num_gates
            );

            let idx = 2 * R::n() - 1 - self.skip_gates - coefficient_index;
            generators.g()[idx]
        }
    }

    type R = crate::polynomials::ProductionRank;

    #[test]
    fn test_staging_valid() -> Result<()> {
        #[derive(Default)]
        struct MyStage1;
        #[derive(Default)]
        struct MyStage2;

        impl Stage<Fp, R> for MyStage1 {
            type Parent = ();

            fn values() -> usize {
                u128::BITS as usize
            }

            type Witness<'source> = u128;
            type OutputKind = Endoscalar<'static, core::marker::PhantomData<Fp>>;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                Endoscalar::alloc(dr, witness)
            }
        }

        impl Stage<Fp, R> for MyStage2 {
            type Parent = MyStage1;

            fn values() -> usize {
                4
            }

            type Witness<'source> = (EpAffine, EpAffine);
            type OutputKind = (
                core::marker::PhantomData<Point<'static, core::marker::PhantomData<Fp>, EpAffine>>,
                core::marker::PhantomData<Point<'static, core::marker::PhantomData<Fp>, EpAffine>>,
            );

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                let a = Point::alloc(dr, witness.as_ref().map(|w| w.0))?;
                let b = Point::alloc(dr, witness.as_ref().map(|w| w.1))?;

                Ok((a, b))
            }
        }

        let endoscalar_a: u128 = ragu_arithmetic::rand::rng().random();
        let endoscalar_b: u128 = ragu_arithmetic::rand::rng().random();
        let p1 = (EpAffine::generator() * Fq::random(&mut ragu_arithmetic::rand::rng())).into();
        let p2 = (EpAffine::generator() * Fq::random(&mut ragu_arithmetic::rand::rng())).into();

        let rx1_a = MyStage1::rx(Fp::ZERO, endoscalar_a)?;
        let rx1_b = MyStage1::rx(Fp::ZERO, endoscalar_b)?;
        let rx2 = MyStage2::rx(Fp::ZERO, (p1, p2))?;

        let circ1 = MyStage1::mask()?.into_inner();
        let circ2 = MyStage2::mask()?.into_inner();

        let z = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        // sy() now returns -notch; add global_project to recover the full mask.
        let full_sy = |circ: &dyn WiringObject<Fp, R>, y| {
            let mut poly = super::global_project::<Fp, R>(y);
            poly += &circ.sy(y, &[]);
            poly
        };

        {
            let rhs = full_sy(&*circ1, y);
            assert_eq!(rx1_a.revdot(&rhs), Fp::ZERO);
            assert_eq!(rx1_b.revdot(&rhs), Fp::ZERO);

            // It is safe to combine an arbitrary number of these into a single
            // revdot claim (separating each stage polynomial by a power of z)
            // because the right hand side is the same for each, and the result
            // must be zero in both cases.
            let mut combined = rx1_a.clone();
            combined.scale(z);
            combined.add_assign(&rx1_b);
            assert_eq!(combined.revdot(&rhs), Fp::ZERO);
        }

        assert_eq!(rx1_a.revdot(&full_sy(&*circ1, y)), Fp::ZERO);
        assert_eq!(rx2.revdot(&full_sy(&*circ2, y)), Fp::ZERO);
        assert!(rx1_a.revdot(&full_sy(&*circ2, y)) != Fp::ZERO);
        assert!(rx2.revdot(&full_sy(&*circ1, y)) != Fp::ZERO);

        Ok(())
    }

    #[test]
    fn test_skip_gates_one() {
        let stage_mask = StageMask::<R>::new(1, 5).unwrap();

        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        // All three return -notch (the global term is factored out by Registry).
        let sxy = stage_mask.sxy(x, y, &[]);
        let sx = stage_mask.sx(x, &[]);
        let sy = stage_mask.sy(y, &[]);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));

        // Cross-check: global + notch reconstructs the full mask.
        let global_xy = super::global_mask::<Fp, R>(x, y);
        let mut full_sx = super::global_project::<Fp, R>(x);
        full_sx += &sx;
        assert_eq!(full_sx.eval(y), sxy + global_xy);
    }

    #[test]
    fn test_stage_mask_all_gates() {
        // Edge case: skip = 1, num = R::n() - 1, reserved = 0.
        let stage = StageMask::<R>::new(1, R::n() - 1).unwrap();
        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        let generic = mask_wiring_object(stage.clone());
        let plan = floor_planner::floor_plan(generic.segment_records());
        let stripped = crate::staging::bonding::Stripped::new(generic);
        let corrected_sxy = stripped.sxy(x, y, &plan);

        // StageMask returns -notch; add global to get the full mask.
        let full_sxy = stage.sxy(x, y, &[]) + super::global_mask::<Fp, R>(x, y);
        assert_eq!(full_sxy, corrected_sxy);
        assert_eq!(corrected_sxy, stripped.sx(x, &plan).eval(y));
        assert_eq!(corrected_sxy, stripped.sy(y, &plan).eval(x));
    }

    #[test]
    fn test_root_routine_has_at_least_one_constraint() {
        // The root segment always gets the ONE constraint from
        // metrics::eval(), so its num_constraints must be at least 1.
        // This invariant prevents the `- 1` underflow in sy::eval's initial
        // y-power computation.
        let circuit = into_wiring_object::<_, _, R>(SquareCircuit { times: 0 }).unwrap();
        let floor_plan = floor_planner::floor_plan(circuit.segment_records());
        assert!(
            floor_plan[0].num_constraints >= 1,
            "root segment must have at least 1 constraint (ONE), got {}",
            floor_plan[0].num_constraints,
        );
    }

    #[test]
    fn test_stage_mask_exact_boundary() {
        let result = StageMask::<R>::new(R::n() - 1, 1);
        assert!(result.is_ok(), "Should accept skip + num == R::n()");

        let result = StageMask::<R>::new(R::n(), 1);
        assert!(result.is_err(), "Should reject skip + num > R::n()");
    }

    #[test]
    fn test_stage_mask_reserved_zero() {
        // When reserved = 0, all gates except the SYSTEM gate are active.
        let stage = StageMask::<R>::new(1, R::n() - 1).expect("valid stage mask");

        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        // All three return -notch (the global term is factored out by Registry).
        let sxy = stage.sxy(x, y, &[]);
        let sx = stage.sx(x, &[]);
        let sy = stage.sy(y, &[]);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    #[test]
    fn test_stage_mask_reserved_computation() {
        // Check we're computing reserved correctly.
        for skip in 1..10 {
            for num in 0..(R::n() - skip) {
                let _ = StageMask::<R>::new(skip, num).expect("valid stage mask");

                // The Circuit impl always issues 4n-2 enforce_zero
                // (with dummies for active gates and the SYSTEM gate).
                let num_constraints_from_gates = 4 * R::n() - 2;
                assert!(
                    num_constraints_from_gates < R::num_coeffs(),
                    "Reserved computation should not cause overflow"
                );
            }
        }
    }

    proptest! {
        #[test]
        fn test_exy_proptest(skip in 1..R::n(), num in 0..R::n()) {
            prop_assume!(skip + num <= R::n());

            let stage_mask = StageMask::<R>::new(skip, num).unwrap();

            let generic = mask_wiring_object(
                StageMask::<R>::new(skip, num).unwrap()
            );
            let plan = floor_planner::floor_plan(generic.segment_records());

            let stripped = crate::staging::bonding::Stripped::new(generic);

            let check = |x: Fp, y: Fp| {
                let sxy = stripped.sxy(x, y, &plan);
                let sx_eval = stripped.sx(x, &plan).eval(y);
                let sy_eval = stripped.sy(y, &plan).eval(x);

                // Internal consistency of the RawCircuit impl (with correction)
                prop_assert_eq!(sy_eval, sxy);
                prop_assert_eq!(sx_eval, sxy);
                // StageMask returns -notch from all three methods.
                let notch_sxy = stage_mask.sxy(x, y, &[]);
                let global_xy = super::global_mask::<Fp, R>(x, y);
                prop_assert_eq!(notch_sxy + global_xy, sxy);
                prop_assert_eq!(stage_mask.sx(x, &[]).eval(y), notch_sxy);
                prop_assert_eq!(stage_mask.sy(y, &[]).eval(x), notch_sxy);

                // Polynomial decomposition: global_project + notch_project == full project.
                let mut reconstructed = super::global_project::<Fp, R>(x);
                reconstructed += &stage_mask.notch_project(x);
                prop_assert_eq!(reconstructed.eval(y), sxy);

                Ok(())
            };

            let x = Fp::random(&mut ragu_arithmetic::rand::rng());
            let y = Fp::random(&mut ragu_arithmetic::rand::rng());
            check(x, y)?;
            check(Fp::ZERO, y)?;
            check(x, Fp::ZERO)?;
            check(Fp::ZERO, Fp::ZERO)?;

        }

        /// Two adjacent `StageMask`s that partition gates `1..n` must have
        /// notch projections that sum to the global projection (negated),
        /// and notch scalars that sum to the global scalar (negated).
        #[test]
        fn test_notch_partition_proptest(split in 1..R::n()) {
            let mask_a = StageMask::<R>::new(1, split - 1).unwrap();
            let mask_b = StageMask::<R>::new(split, R::n() - split).unwrap();

            let p = Fp::random(&mut ragu_arithmetic::rand::rng());
            let x = Fp::random(&mut ragu_arithmetic::rand::rng());
            let y = Fp::random(&mut ragu_arithmetic::rand::rng());

            // Polynomial-level: (-notch_a(p) + -notch_b(p)).eval(q) == -global_project(p).eval(q)
            let q = Fp::random(&mut ragu_arithmetic::rand::rng());
            let mut sum_poly = mask_a.notch_project(p);
            sum_poly += &mask_b.notch_project(p);
            let mut neg_global = super::global_project::<Fp, R>(p);
            neg_global.scale(-Fp::ONE);
            prop_assert_eq!(sum_poly.eval(q), neg_global.eval(q));

            // Scalar-level: -notch_a(x,y) + -notch_b(x,y) == -global_mask(x,y)
            let sxy_a = mask_a.sxy(x, y, &[]);
            let sxy_b = mask_b.sxy(x, y, &[]);
            let global_xy = super::global_mask::<Fp, R>(x, y);
            prop_assert_eq!(sxy_a + sxy_b, -global_xy);
        }
    }

    #[derive(Default)]
    struct ConstrainedStage;

    #[derive(Gadget, Write)]
    struct TwoElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
    }

    // Hand-written because the derive only re-emits each field's own
    // invariants, dropping the cross-field `a == b` constraint that
    // `ConstrainedStage::witness` imposes.
    impl<'dr, D: Driver<'dr>> Consistent<'dr, D> for TwoElements<'dr, D> {
        fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
            self.a.enforce_consistent(dr)?;
            self.b.enforce_consistent(dr)?;
            dr.enforce_zero(|lc| lc.add(self.a.wire()).sub(self.b.wire()))?;
            Ok(())
        }
    }

    impl Stage<Fp, R> for ConstrainedStage {
        type Parent = ();
        type Witness<'source> = (Fp, Fp);
        type OutputKind =
            <TwoElements<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let witness_a = witness.as_ref().map(|w| w.0);
            let witness_b = witness.as_ref().map(|w| w.1);

            let a = Element::alloc(dr, &mut (), witness_a)?;
            let b = Element::alloc(dr, &mut (), witness_b)?;

            dr.enforce_zero(|lc| lc.add(a.wire()).sub(b.wire()))?;

            Ok(TwoElements { a, b })
        }
    }

    #[test]
    fn test_enforce_stage_works() {
        let result =
            Emulator::emulate_wireless((Fp::from(42u64), Fp::from(42u64)), |dr, witness| {
                let builder = StageBuilder::<_, R, (), ConstrainedStage>::new(dr, |_| {});
                let (guard, builder) = builder.add_stage::<ConstrainedStage>()?;
                let _gagdet = guard.enforced(builder.finish(), witness)?;
                Ok(())
            });

        assert!(result.is_ok(), "enforce_stage should succeed");
    }

    #[test]
    fn test_stage_well_formedness_with_valid_witness() {
        let valid_witness = (Fp::from(7u64), Fp::from(7u64));

        let rx = ConstrainedStage::rx(Fp::ZERO, valid_witness).unwrap();

        let stage_mask = ConstrainedStage::mask::<'_>().unwrap().into_inner();

        // sy() returns -notch; add global_project to recover the full mask.
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());
        let mut sy = super::global_project::<Fp, R>(y);
        sy += &stage_mask.sy(y, &[]);

        let check = rx.revdot(&sy);
        assert_eq!(
            check,
            Fp::ZERO,
            "valid witness should produce well-formed stage polynomial"
        );
    }

    #[test]
    fn test_constraint_counts_matches_metrics() {
        for skip in 1..10 {
            for num in 0..(R::n() - skip) {
                let stage_mask = StageMask::<R>::new(skip, num).unwrap();
                let (mul_from_method, linear_from_method) =
                    <StageMask<R> as WiringObject<Fp, R>>::constraint_counts(&stage_mask);

                let metrics = metrics::eval_raw::<Fp, _>(&stage_mask).unwrap();

                assert_eq!(
                    mul_from_method, metrics.num_gates,
                    "gate count mismatch for skip={}, num={}",
                    skip, num
                );
                assert_eq!(
                    linear_from_method, metrics.num_constraints,
                    "constraint count mismatch for skip={}, num={}",
                    skip, num
                );
            }
        }
    }

    #[test]
    fn test_child_routine_zero_constraints() {
        // A routine that only uses a gate and no constraints.
        // This exercises the `.saturating_sub(1)` path in
        // sy::eval's sub-routine y-power initialisation.
        #[derive(Clone)]
        struct MulOnlyRoutine;

        impl Routine<Fp> for MulOnlyRoutine {
            type Input = ();
            type Output = ();
            type Aux<'dr> = ();

            fn execute<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                _input: Bound<'dr, D, Self::Input>,
                _aux: DriverValue<D, Self::Aux<'dr>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                dr.mul(|| unreachable!())?;
                Ok(())
            }

            fn predict<'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                _input: &Bound<'dr, D, Self::Input>,
            ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>>
            {
                Ok(Prediction::Unknown(D::unit()))
            }
        }

        struct TestCircuit;

        impl crate::Circuit<Fp> for TestCircuit {
            type Instance<'source> = ();
            type Witness<'source> = ();
            type Output = ();
            type Aux<'source> = ();

            fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                _dr: &mut D,
                _instance: DriverValue<D, Self::Instance<'source>>,
            ) -> Result<Bound<'dr, D, Self::Output>> {
                Ok(())
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                _witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
            {
                dr.routine(MulOnlyRoutine, ())?;
                Ok(WithAux::new((), D::unit()))
            }
        }

        let circuit = into_wiring_object::<_, _, R>(TestCircuit).unwrap();
        let floor_plan = floor_planner::floor_plan(circuit.segment_records());

        // The child routine (index 1) should have zero constraints.
        assert_eq!(
            floor_plan[1].num_constraints, 0,
            "MulOnlyRoutine should have 0 constraints"
        );

        let x = Fp::random(&mut ragu_arithmetic::rand::rng());
        let y = Fp::random(&mut ragu_arithmetic::rand::rng());

        // None of these must panic — previously sy would underflow on `- 1`.
        let sxy = circuit.sxy(x, y, &floor_plan);
        let sx = circuit.sx(x, &floor_plan);
        let sy = circuit.sy(y, &floor_plan);

        assert_eq!(sxy, sx.eval(y));
        assert_eq!(sxy, sy.eval(x));
    }

    /// A stage that allocates values only in a-positions (d = 0) for challenge smuggling.
    ///
    /// Each value is paired with a zero to ensure it lands in an a-coefficient position
    /// when the polynomial is built. This mimics the pattern used for smuggling challenges.
    #[derive(Default)]
    struct ParentAOnlyStage;

    #[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
    struct ThreeAOnlyElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a0: Element<'dr, D>,
        #[ragu(gadget)]
        b0: Element<'dr, D>,
        #[ragu(gadget)]
        a1: Element<'dr, D>,
        #[ragu(gadget)]
        b1: Element<'dr, D>,
        #[ragu(gadget)]
        a2: Element<'dr, D>,
        #[ragu(gadget)]
        b2: Element<'dr, D>,
    }

    impl Stage<Fp, R> for ParentAOnlyStage {
        type Parent = ();
        type Witness<'source> = [Fp; 3];
        type OutputKind = <ThreeAOnlyElements<'static, PhantomData<Fp>> as Gadget<
            'static,
            PhantomData<Fp>,
        >>::Kind;

        fn values() -> usize {
            6 // 3 multiplication gates
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            // Allocate each challenge value followed by zero, which
            // ensures challenges land in a-positions, zeros in d-positions.
            let a0 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[0]))?;
            let b0 = Element::zero(dr);
            let a1 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[1]))?;
            let b1 = Element::zero(dr);
            let a2 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[2]))?;
            let b2 = Element::zero(dr);

            Ok(ThreeAOnlyElements {
                a0,
                b0,
                a1,
                b1,
                a2,
                b2,
            })
        }
    }

    #[derive(Default)]
    struct ChildOfParentAOnlyStage;

    impl Stage<Fp, R> for ChildOfParentAOnlyStage {
        type Parent = ParentAOnlyStage;
        type Witness<'source> = [Fp; 3];
        type OutputKind = <ThreeAOnlyElements<'static, PhantomData<Fp>> as Gadget<
            'static,
            PhantomData<Fp>,
        >>::Kind;

        fn values() -> usize {
            6 // 3 multiplication gates
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let a0 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[0]))?;
            let b0 = Element::zero(dr);
            let a1 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[1]))?;
            let b1 = Element::zero(dr);
            let a2 = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w[2]))?;
            let b2 = Element::zero(dr);

            Ok(ThreeAOnlyElements {
                a0,
                b0,
                a1,
                b1,
                a2,
                b2,
            })
        }
    }

    /// Tests that `StageMask::generator_for_a_coefficient` returns the generator
    /// at the index computed by `StageExt::generator_index_for_a`.
    #[test]
    fn test_generator_for_a_coefficient() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        // Test via StageMask directly
        let parent_mask = StageMask::<R>::new(
            ParentAOnlyStage::skip_gates(),
            ParentAOnlyStage::num_gates(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = parent_mask.generator_for_a_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }

        let child_mask = StageMask::<R>::new(
            ChildOfParentAOnlyStage::skip_gates(),
            ChildOfParentAOnlyStage::num_gates(),
        )
        .unwrap();

        for i in 0..3 {
            let gen_idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let expected_gen = generators.g()[gen_idx];
            let actual_gen = child_mask.generator_for_a_coefficient(generators, i);
            assert_eq!(actual_gen, expected_gen);
        }
    }

    /// Tests the generator index formula `2n - 1 - skip - i` for both a root
    /// stage and a child stage with non-zero skip.
    #[test]
    fn test_generator_index_edge_cases() {
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(0),
            2 * R::n() - 2
        );
        assert_eq!(
            <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(2),
            2 * R::n() - 4
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(0),
            2 * R::n() - 5
        );
        assert_eq!(
            <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(2),
            2 * R::n() - 7
        );
    }

    /// Tests that committing to an rx polynomial with values only in a-positions
    /// matches a manual MSM using generators from `generator_index_for_a`.
    #[test]
    fn test_a_wire_commitment_for_challenge_smuggling() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];

        let rx: sparse::Polynomial<Fp, R> =
            ChildOfParentAOnlyStage::rx(Fp::ZERO, challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators);

        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ChildOfParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let a_gen = generators.g()[idx];
            let contrib = a_gen * challenge;
            manual_commitment = (manual_commitment.to_curve() + contrib).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "A-wire commitment should match manual computation"
        );
    }

    /// Same as above but for a root stage (no parent, zero skip).
    #[test]
    fn test_a_wire_commitment_via_staging_mechanism() {
        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let challenges = [Fp::from(42u64), Fp::from(123u64), Fp::from(456u64)];

        let rx: sparse::Polynomial<Fp, R> = ParentAOnlyStage::rx(Fp::ZERO, challenges).unwrap();
        let poly_commitment: EqAffine = rx.commit_to_affine(generators);

        // Manually compute expected commitment using StageExt::generator_index_for_a.
        let mut manual_commitment = EqAffine::identity();
        for (i, &challenge) in challenges.iter().enumerate() {
            let idx = <ParentAOnlyStage as StageExt<Fp, R>>::generator_index_for_a(i);
            let a_gen = generators.g()[idx];
            manual_commitment = (manual_commitment.to_curve() + a_gen * challenge).to_affine();
        }

        assert_eq!(
            poly_commitment, manual_commitment,
            "Commitment via staging mechanism should match manual computation"
        );
    }
}
