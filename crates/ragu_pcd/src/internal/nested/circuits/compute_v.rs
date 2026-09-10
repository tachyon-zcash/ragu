//! Circuit for computing and verifying the nested batch evaluation $v_n$.
//!
//! The mirror of the native `compute_v` circuit for the nested batch
//! ([`pcs`]): it recomputes $v_n$ from the query and eval bridge stages'
//! nested values and provides it as the instance's $v_n$ slot.
//!
//! ## Operations
//!
//! ### Revdot folding
//! - Takes the lifted $\mu$, $\nu$, $\mu'$, $\nu'$ from the challenge stage.
//! - Computes $a_n(x_n z_n)$ and $b_n(x_n)$ by the two-layer fold of the
//!   children's claim evaluations, in [`build`] order, exactly as the
//!   prover folded the polynomials.
//!
//! ### $f_n(u_n)$ computation
//! - Batch-inverts the denominators $(u_n - x_i)^{-1}$ of every opening.
//! - Walks the openings in [`Batch::queries`] order, accumulating
//!   $f_n(u_n) = \sum_i \alpha_n^{n-1-i} (p_i(u_n) - v_i) / (u_n - x_i)$
//!   by Horner.
//!
//! ### $v_n$ computation
//! - Takes $\beta_n$ from the beta stage: the lift of the endoscalar the
//!   parent binds through `bind_beta`, so no extraction is needed here. The
//!   endoscalar stage's bits, which the endoscaling steps walk $P$ with,
//!   are enforced to lift to the same value, which binds them through it.
//! - Computes $v_n$ as the $\beta_n$-weighted sum of $f_n(u_n)$ and the eval
//!   stage's nested evaluations, in [`Batch::evaluated`] order.
//!
//! Every challenge is read from the challenge stage; the instance's own $x$,
//! $y$ and $u$ are those same wires by the [`export`](super::export)
//! circuit.
//!
//! [`pcs`]: crate::internal::nested::pcs
//! [`Batch::queries`]: crate::internal::nested::pcs::Batch::queries
//! [`Batch::evaluated`]: crate::internal::nested::pcs::Batch::evaluated
//! [`build`]: claims::build

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{
    WithAux,
    horner::Horner,
    polynomials::{Rank, txz::Evaluate},
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard, vec::FixedVec};

use super::common;
use crate::internal::{
    claims::Source,
    fold_revdot::fold_two_layer,
    inverter::Inverter,
    nested::{
        InternalCircuitIndex, RevdotParameters, RxComponent, RxIndex,
        claims::{self, Processor},
        pcs::{InternalLen, STATIC_F_QUERIES, StaticFQuery},
        stages::{self, challenges, eval as nested_eval, preamble as nested_preamble, query},
        unified,
    },
};

/// Circuit computing the nested batch evaluation $v_n$.
pub struct Circuit<C: CurveAffine, R: Rank> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> Circuit<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> MultiStageCircuit<C::Base, R> for Circuit<C, R> {
    type Last = stages::beta::Stage<C, R>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = common::Witness<'source, C>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages) = common::load_all(dr, &witness)?;

        let allocator = &mut Standard::new();
        let mut unified = unified::OutputBuilder::new(witness.map(|w| w.instance));
        let lift = |i: usize| &stages.challenges.pairs[i].lift;
        let query = &stages.query.nested;
        let eval = &stages.eval.nested;

        // t(x_n z_n), the vanishing polynomial at x_n z_n.
        let x = lift(challenges::X).enforce_invertible(dr)?;
        let z = lift(challenges::Z).enforce_invertible(dr)?;
        let txz = dr.routine(Evaluate::<R>::new(), (x.clone(), z.clone()))?;

        // a_n(x_n z_n) and b_n(x_n), by the two-layer fold of the claims'
        // evaluations.
        let (computed_ax, computed_bx) = {
            let mu = lift(challenges::MU);
            let nu = lift(challenges::NU);
            let mu_prime = lift(challenges::MU_PRIME);
            let nu_prime = lift(challenges::NU_PRIME);
            let mu_inv = mu.invert(dr)?;
            let mu_prime_inv = mu_prime.invert(dr)?;
            let mu_nu = mu.mul(dr, nu)?;
            let mu_prime_nu_prime = mu_prime.mul(dr, nu_prime)?;

            let source = EvaluationSource {
                left: &query.left,
                right: &query.right,
            };
            let mut processor =
                EvaluationProcessor::new(dr, z.element(), &txz, &query.fixed_registry);
            claims::build(&source, &mut processor)?;
            let (ax, bx) = processor.build();
            (
                fold_two_layer::<_, RevdotParameters>(dr, &ax, &mu_inv, &mu_prime_inv)?,
                fold_two_layer::<_, RevdotParameters>(dr, &bx, &mu_nu, &mu_prime_nu_prime)?,
            )
        };

        // f_n(u_n), from the quotients of every opening.
        let fu = {
            let u = lift(challenges::U);
            let denominators = Denominators::new(
                dr,
                u,
                lift(challenges::W),
                x.element(),
                lift(challenges::Y),
                z.element(),
                &stages.preamble,
            )?;
            let mut horner = Horner::new(lift(challenges::ALPHA));
            for (pu, v, denominator) in poly_queries(
                eval,
                query,
                &stages.preamble,
                &denominators,
                &computed_ax,
                &computed_bx,
            ) {
                pu.sub(dr, v).mul(dr, denominator)?.write(dr, &mut horner)?;
            }
            horner.finish(dr)
        };

        // The endoscalar the endoscaling steps walked P with lifts to the
        // beta stage's wire, which the parent's `bind_beta` ties to pre_beta.
        stages
            .endoscalar
            .lift(dr)?
            .enforce_equal(dr, &stages.beta.lift)?;

        // v_n = beta_n-weighted sum of f_n(u_n) and the evaluations at u_n.
        let computed_v = {
            let mut horner = Horner::new(&stages.beta.lift);
            fu.write(dr, &mut horner)?;
            eval.write(dr, &mut horner)?;
            horner.finish(dr)
        };
        unified.v.provide(computed_v);

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}

/// Denominators of a child's openings: $(u_n - \cdot)^{-1}$ at its nested
/// $u$, $y$ and $x$.
struct ChildDenominators<'dr, D: Driver<'dr>> {
    u: Element<'dr, D>,
    y: Element<'dr, D>,
    x: Element<'dr, D>,
}

/// Denominators of the current step's openings.
struct ChallengeDenominators<'dr, D: Driver<'dr>> {
    w: Element<'dr, D>,
    x: Element<'dr, D>,
    y: Element<'dr, D>,
    xz: Element<'dr, D>,
}

/// The inverted denominators of every opening, batch-inverted once.
struct Denominators<'dr, D: Driver<'dr>> {
    left: ChildDenominators<'dr, D>,
    right: ChildDenominators<'dr, D>,
    challenges: ChallengeDenominators<'dr, D>,
    /// One per nested internal circuit, at its $\omega^j$, in
    /// [`InternalCircuitIndex::ALL`] order.
    internal: FixedVec<Element<'dr, D>, InternalLen>,
}

impl<'dr, D: Driver<'dr>> Denominators<'dr, D> {
    fn new<C: CurveAffine<Base = D::F>>(
        dr: &mut D,
        u: &Element<'dr, D>,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        preamble: &nested_preamble::Output<'dr, D, C>,
    ) -> Result<Self>
    where
        D::F: ragu_arithmetic::ff::PrimeField,
    {
        let xz = x.mul(dr, z)?;

        let mut inverter = Inverter::with_base(u.clone());
        let child = |inverter: &mut Inverter<'dr, D>,
                     dr: &mut D,
                     child: &nested_preamble::ChildOutput<'dr, D, C>| {
            Ok::<_, ragu_core::Error>((
                inverter.add(dr, &child.nested.u)?,
                inverter.add(dr, &child.nested.y)?,
                inverter.add(dr, &child.nested.x)?,
            ))
        };
        let left = child(&mut inverter, dr, &preamble.left)?;
        let right = child(&mut inverter, dr, &preamble.right)?;
        let challenges = (
            inverter.add(dr, w)?,
            inverter.add(dr, x)?,
            inverter.add(dr, y)?,
            inverter.add(dr, &xz)?,
        );
        let internal = InternalCircuitIndex::ALL
            .iter()
            .map(|id| inverter.add_circuit(dr, id.circuit_index()))
            .collect::<Result<Vec<_>>>()?;

        let inverted = inverter.invert(dr)?;
        let at = |i: usize| inverted[i].clone();

        Ok(Denominators {
            left: ChildDenominators {
                u: at(left.0),
                y: at(left.1),
                x: at(left.2),
            },
            right: ChildDenominators {
                u: at(right.0),
                y: at(right.1),
                x: at(right.2),
            },
            challenges: ChallengeDenominators {
                w: at(challenges.0),
                x: at(challenges.1),
                y: at(challenges.2),
                xz: at(challenges.3),
            },
            internal: FixedVec::try_from_fn(|i| Ok(at(internal[i])))?,
        })
    }
}

/// The children's claim evaluations, as a claim [`Source`] in the order
/// [`build`](claims::build) fixes.
struct EvaluationSource<'a, 'dr, D: Driver<'dr>> {
    left: &'a query::ChildEvaluations<'dr, D>,
    right: &'a query::ChildEvaluations<'dr, D>,
}

impl<'a, 'dr, D: Driver<'dr>> Source for EvaluationSource<'a, 'dr, D> {
    type RxComponent = RxComponent;
    type Rx = &'a Element<'dr, D>;
    type AppCircuitId = ();

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        let (left, right) = match component {
            RxComponent::AbA => (&self.left.a_poly_at_xz, &self.right.a_poly_at_xz),
            RxComponent::AbB => (&self.left.b_poly_at_x, &self.right.b_poly_at_x),
            RxComponent::Rx(idx) => (
                &self.left.rx[idx.position()],
                &self.right.rx[idx.position()],
            ),
        };
        [left, right].into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        core::iter::empty()
    }
}

/// Builds the `ax` and `bx` vectors the two-layer fold reduces to
/// $a_n(x_n z_n)$ and $b_n(x_n)$: for a circuit claim `ax` takes the summed
/// $r_i(x_n z_n)$ and `bx` adds $s_y$ and $t(x_n z_n)$; for a bonding claim
/// `ax` takes the $z_n$-fold of the group sums and `bx` is $s_y$ alone; a
/// raw claim contributes its own evaluations.
struct EvaluationProcessor<'a, 'dr, D: Driver<'dr>> {
    dr: &'a mut D,
    z: &'a Element<'dr, D>,
    txz: &'a Element<'dr, D>,
    fixed_registry: &'a FixedVec<Element<'dr, D>, InternalLen>,
    ax: Vec<Element<'dr, D>>,
    bx: Vec<Element<'dr, D>>,
}

impl<'a, 'dr, D: Driver<'dr>> EvaluationProcessor<'a, 'dr, D> {
    fn new(
        dr: &'a mut D,
        z: &'a Element<'dr, D>,
        txz: &'a Element<'dr, D>,
        fixed_registry: &'a FixedVec<Element<'dr, D>, InternalLen>,
    ) -> Self {
        Self {
            dr,
            z,
            txz,
            fixed_registry,
            ax: Vec::new(),
            bx: Vec::new(),
        }
    }

    /// The registry's $m_n(\omega^j, x_n, y_n)$ for circuit `id`, from the
    /// query stage.
    fn sy(&self, id: InternalCircuitIndex) -> &'a Element<'dr, D> {
        &self.fixed_registry[usize::from(id.circuit_index())]
    }

    fn build(self) -> (Vec<Element<'dr, D>>, Vec<Element<'dr, D>>) {
        (self.ax, self.bx)
    }
}

impl<'a, 'dr, D: Driver<'dr>> Processor<&'a Element<'dr, D>> for EvaluationProcessor<'a, 'dr, D> {
    fn raw_claim(&mut self, a: &'a Element<'dr, D>, b: &'a Element<'dr, D>) {
        self.ax.push(a.clone());
        self.bx.push(b.clone());
    }

    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'a Element<'dr, D>>,
    ) {
        let sy = self.sy(id);
        let sum = Element::sum(self.dr, rxs);
        self.ax.push(sum.clone());
        self.bx.push(sum.add(self.dr, sy).add(self.dr, self.txz));
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'a Element<'dr, D>>>,
    ) -> Result<()> {
        let sy = self.sy(id);
        let sums: Vec<_> = groups.map(|group| Element::sum(self.dr, group)).collect();
        self.ax.push(Element::fold(self.dr, &sums, self.z)?);
        self.bx.push(sy.clone());
        Ok(())
    }
}

/// The openings $f_n$ covers, as $(p(u_n), v, (u_n - x_i)^{-1})$ triples in
/// [`Batch::queries`](crate::internal::nested::pcs::Batch::queries) order:
/// the static prefix, each child's rx polynomials at $x_n z_n$, then the
/// current `registry_xy` at each internal circuit's $\omega^j$.
#[rustfmt::skip]
fn poly_queries<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
    eval: &'a nested_eval::EvaluationsOutput<'dr, D>,
    query: &'a query::EvaluationsOutput<'dr, D>,
    preamble: &'a nested_preamble::Output<'dr, D, C>,
    d: &'a Denominators<'dr, D>,
    computed_ax: &'a Element<'dr, D>,
    computed_bx: &'a Element<'dr, D>,
) -> impl Iterator<Item = (&'a Element<'dr, D>, &'a Element<'dr, D>, &'a Element<'dr, D>)> {
    STATIC_F_QUERIES.iter().map(move |query_id| match query_id {
        StaticFQuery::LeftP => (&eval.left.p_poly, &preamble.left.nested.v, &d.left.u),
        StaticFQuery::RightP => (&eval.right.p_poly, &preamble.right.nested.v, &d.right.u),
        StaticFQuery::LeftRegistryXyAtW => (
            &eval.left.registry_xy_poly,
            &query.left.child_registry_xy_at_current_w,
            &d.challenges.w,
        ),
        StaticFQuery::RightRegistryXyAtW => (
            &eval.right.registry_xy_poly,
            &query.right.child_registry_xy_at_current_w,
            &d.challenges.w,
        ),
        StaticFQuery::RegistryWx0AtLeftY => (
            &eval.registry_wx0,
            &query.left.child_registry_xy_at_current_w,
            &d.left.y,
        ),
        StaticFQuery::RegistryWx1AtRightY => (
            &eval.registry_wx1,
            &query.right.child_registry_xy_at_current_w,
            &d.right.y,
        ),
        StaticFQuery::RegistryWx0AtY => (
            &eval.registry_wx0,
            &query.left.current_registry_wy_at_child_x,
            &d.challenges.y,
        ),
        StaticFQuery::RegistryWx1AtY => (
            &eval.registry_wx1,
            &query.right.current_registry_wy_at_child_x,
            &d.challenges.y,
        ),
        StaticFQuery::RegistryWyAtLeftX => (
            &eval.registry_wy,
            &query.left.current_registry_wy_at_child_x,
            &d.left.x,
        ),
        StaticFQuery::RegistryWyAtRightX => (
            &eval.registry_wy,
            &query.right.current_registry_wy_at_child_x,
            &d.right.x,
        ),
        StaticFQuery::RegistryWyAtX => (&eval.registry_wy, &query.registry_wxy, &d.challenges.x),
        StaticFQuery::RegistryXyAtW => (&eval.registry_xy, &query.registry_wxy, &d.challenges.w),
        StaticFQuery::LeftAbAAtXz => (&eval.left.a_poly, &query.left.a_poly_at_xz, &d.challenges.xz),
        StaticFQuery::LeftAbBAtX => (&eval.left.b_poly, &query.left.b_poly_at_x, &d.challenges.x),
        StaticFQuery::RightAbAAtXz => (&eval.right.a_poly, &query.right.a_poly_at_xz, &d.challenges.xz),
        StaticFQuery::RightAbBAtX => (&eval.right.b_poly, &query.right.b_poly_at_x, &d.challenges.x),
        StaticFQuery::CurrentAAtXz => (&eval.a_poly, computed_ax, &d.challenges.xz),
        StaticFQuery::CurrentBAtX => (&eval.b_poly, computed_bx, &d.challenges.x),
    })
    // Each child's rx polynomials at x_n z_n, in RxIndex::ALL order.
    .chain([(&eval.left, &query.left), (&eval.right, &query.right)]
        .into_iter()
        .flat_map(move |(eval, query)|
            (0..RxIndex::NUM).map(move |i| (&eval.rx[i], &query.rx[i], &d.challenges.xz))))
    // The current registry_xy at each internal circuit's omega^j.
    .chain((0..InternalCircuitIndex::NUM).map(move |j| {
        (&eval.registry_xy, &query.fixed_registry[j], &d.internal[j])
    }))
}
