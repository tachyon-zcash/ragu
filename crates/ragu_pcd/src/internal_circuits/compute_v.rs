use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt};

use alloc::vec::Vec;
use core::{borrow::Borrow, iter, marker::PhantomData};

use crate::components::fold_revdot::{NativeParameters, Parameters, fold_two_layer};

use super::{
    stages::native::{eval as native_eval, preamble as native_preamble, query as native_query},
    unified::{self, OutputBuilder},
};
use crate::components::horner::Horner;

pub use crate::internal_circuits::InternalCircuitIndex::ComputeVCircuit as CIRCUIT_ID;

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    num_application_steps: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    pub fn new(num_application_steps: usize) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            num_application_steps,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub query_witness: &'a native_query::Witness<C>,
    pub eval_witness: &'a native_eval::Witness<C::CircuitField>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Final = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;

        // TODO: these are unenforced for now, because query/eval stages aren't
        // supposed to contain anything (yet) besides Elements, which require no
        // enforcement logic. Re-evaluate this in the future.
        let query = query.unenforced(dr, witness.view().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let w = unified_output.w.get(dr, unified_instance)?;
        let y = unified_output.y.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;
        let x = unified_output.x.get(dr, unified_instance)?;

        let txz = dr.routine(Evaluate::<R>::new(), (x.clone(), z.clone()))?;

        // Enforce the claimed value `v` in the unified instance is correctly
        // computed based on committed evaluation claims and verifier
        // challenges.
        {
            let (computed_ax, computed_bx) = {
                let mu = unified_output.mu.get(dr, unified_instance)?;
                let nu = unified_output.nu.get(dr, unified_instance)?;
                let mu_prime = unified_output.mu_prime.get(dr, unified_instance)?;
                let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;
                let mu_inv = mu.invert(dr)?;
                let mu_prime_inv = mu_prime.invert(dr)?;
                let munu = mu.mul(dr, &nu)?;
                let mu_prime_nu_prime = mu_prime.mul(dr, &nu_prime)?;

                compute_axbx::<_, NativeParameters>(
                    dr,
                    &query,
                    &z,
                    &txz,
                    &mu_inv,
                    &mu_prime_inv,
                    &munu,
                    &mu_prime_nu_prime,
                )?
            };

            // Compute expected f(u)
            let fu = {
                let alpha = unified_output.alpha.get(dr, unified_instance)?;
                let u = unified_output.u.get(dr, unified_instance)?;
                let denominators = Denominators::new(
                    dr,
                    &u,
                    &w,
                    &x,
                    &y,
                    &z,
                    &preamble,
                    self.num_application_steps,
                )?;
                let mut horner = Horner::new(&alpha);
                for (pu, v, denominator) in poly_queries(
                    &eval,
                    &query,
                    &preamble,
                    &denominators,
                    &computed_ax,
                    &computed_bx,
                ) {
                    pu.sub(dr, v).mul(dr, denominator)?.write(dr, &mut horner)?;
                }
                horner.finish(dr)
            };

            // Compute expected v = p(u)
            let computed_v = {
                let beta = unified_output.beta.get(dr, unified_instance)?;
                let mut horner = Horner::new(&beta);
                fu.write(dr, &mut horner)?;
                eval.write(dr, &mut horner)?;
                horner.finish(dr)
            };

            unified_output.v.set(computed_v);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}

/// Denominator component of all quotient polynomial evaluations.
///
/// Each represents some $(u - x_i)^{-1}$.
struct Denominators<'dr, D: Driver<'dr>> {
    left_u: Element<'dr, D>,
    right_u: Element<'dr, D>,
    w: Element<'dr, D>,
    old_y0: Element<'dr, D>,
    old_y1: Element<'dr, D>,
    y: Element<'dr, D>,
    old_x0: Element<'dr, D>,
    old_x1: Element<'dr, D>,
    x: Element<'dr, D>,

    // Internal circuit omega^j denominators
    internal_preamble_stage: Element<'dr, D>,
    internal_error_m_stage: Element<'dr, D>,
    internal_error_n_stage: Element<'dr, D>,
    internal_query_stage: Element<'dr, D>,
    internal_eval_stage: Element<'dr, D>,
    internal_error_n_final_staged: Element<'dr, D>,
    internal_eval_final_staged: Element<'dr, D>,
    internal_hashes_1_circuit: Element<'dr, D>,
    internal_hashes_2_circuit: Element<'dr, D>,
    internal_partial_collapse_circuit: Element<'dr, D>,
    internal_full_collapse_circuit: Element<'dr, D>,
    internal_compute_v_circuit: Element<'dr, D>,

    // Child proof circuit_id denominators
    left_circuit_id: Element<'dr, D>,
    right_circuit_id: Element<'dr, D>,

    // xz denominator for circuit polynomial checks
    xz: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Denominators<'dr, D> {
    #[rustfmt::skip]
    fn new<C: Cycle, const HEADER_SIZE: usize>(
        dr: &mut D,
        u: &Element<'dr, D>,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        preamble: &native_preamble::Output<'dr, D, C, HEADER_SIZE>,
        num_application_steps: usize,
    ) -> Result<Self>
    where
        D::F: ff::PrimeField,
    {
        use super::InternalCircuitIndex::{self, *};

        let internal_denom = |dr: &mut D, idx: InternalCircuitIndex| -> Result<Element<'dr, D>> {
            let omega_j = Element::constant(dr, idx.circuit_index(num_application_steps).omega_j());
            u.sub(dr, &omega_j).invert(dr)
        };

        let xz = x.mul(dr, z)?;

        Ok(Denominators {
            left_u:  u.sub(dr, &preamble.left.unified.u).invert(dr)?,
            right_u: u.sub(dr, &preamble.right.unified.u).invert(dr)?,
            w:       u.sub(dr, w).invert(dr)?,
            old_y0:  u.sub(dr, &preamble.left.unified.y).invert(dr)?,
            old_y1:  u.sub(dr, &preamble.right.unified.y).invert(dr)?,
            y:       u.sub(dr, y).invert(dr)?,
            old_x0:  u.sub(dr, &preamble.left.unified.x).invert(dr)?,
            old_x1:  u.sub(dr, &preamble.right.unified.x).invert(dr)?,
            x:       u.sub(dr, x).invert(dr)?,
            internal_preamble_stage:           internal_denom(dr, PreambleStage)?,
            internal_error_m_stage:            internal_denom(dr, ErrorMStage)?,
            internal_error_n_stage:            internal_denom(dr, ErrorNStage)?,
            internal_query_stage:              internal_denom(dr, QueryStage)?,
            internal_eval_stage:               internal_denom(dr, EvalStage)?,
            internal_error_n_final_staged:     internal_denom(dr, ErrorNFinalStaged)?,
            internal_eval_final_staged:        internal_denom(dr, EvalFinalStaged)?,
            internal_hashes_1_circuit:         internal_denom(dr, Hashes1Circuit)?,
            internal_hashes_2_circuit:         internal_denom(dr, Hashes2Circuit)?,
            internal_partial_collapse_circuit: internal_denom(dr, PartialCollapseCircuit)?,
            internal_full_collapse_circuit:    internal_denom(dr, FullCollapseCircuit)?,
            internal_compute_v_circuit:        internal_denom(dr, ComputeVCircuit)?,
            left_circuit_id:  u.sub(dr, &preamble.left.circuit_id).invert(dr)?,
            right_circuit_id: u.sub(dr, &preamble.right.circuit_id).invert(dr)?,
            xz:              u.sub(dr, &xz).invert(dr)?,
        })
    }
}

struct SourceBuilder<'dr, D: Driver<'dr>> {
    z: Element<'dr, D>,
    txz: Element<'dr, D>,
    ax: Vec<Element<'dr, D>>,
    bx: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> SourceBuilder<'dr, D> {
    fn new(z: Element<'dr, D>, txz: Element<'dr, D>) -> Self {
        Self {
            z,
            txz,
            ax: Vec::new(),
            bx: Vec::new(),
        }
    }

    fn direct(&mut self, ax_eval: &Element<'dr, D>, bx_eval: &Element<'dr, D>) {
        self.ax.push(ax_eval.clone());
        self.bx.push(bx_eval.clone());
    }

    fn application(
        &mut self,
        dr: &mut D,
        ax_eval: &Element<'dr, D>,
        bx_eval: &Element<'dr, D>,
        bx_mesh: &Element<'dr, D>,
    ) {
        self.ax.push(ax_eval.clone());
        self.bx.push(bx_eval.add(dr, bx_mesh).add(dr, &self.txz));
    }

    fn internal<'b>(
        &'b mut self,
        dr: &mut D,
        ax_evals: impl IntoIterator<Item = &'b Element<'dr, D>>,
        bx_evals: impl IntoIterator<Item = &'b Element<'dr, D>>,
        bx_mesh: &'b Element<'dr, D>,
    ) {
        self.ax.push(Element::sum(dr, ax_evals));
        self.bx.push(Element::sum(
            dr,
            bx_evals
                .into_iter()
                .chain(iter::once(bx_mesh).chain(iter::once(&self.txz))),
        ));
    }

    fn stage<I>(&mut self, dr: &mut D, ax_evals: I, bx_mesh: &Element<'dr, D>) -> Result<()>
    where
        I: IntoIterator<Item: Borrow<Element<'dr, D>>>,
        I::IntoIter: DoubleEndedIterator,
    {
        self.ax.push(Element::fold(dr, ax_evals, &self.z)?);
        self.bx.push(bx_mesh.clone());
        Ok(())
    }

    fn build(self) -> (Vec<Element<'dr, D>>, Vec<Element<'dr, D>>) {
        (self.ax, self.bx)
    }
}

/// Computes the expected value of $a(x), b(x)$ given the evaluations at $x$ of
/// every constituent polynomial at $x, xz$. This function is the authoritative
/// source of the protocol's (recursive) description of the revdot folding
/// structure and is what fundamentally binds the prover's behavior in their
/// choice of $a(X), b(X)$ and thus the correctness of their folded revdot
/// claim.
fn compute_axbx<'dr, D: Driver<'dr>, P: Parameters>(
    dr: &mut D,
    query: &native_query::Output<'dr, D>,
    z: &Element<'dr, D>,
    txz: &Element<'dr, D>,
    mu_inv: &Element<'dr, D>,
    mu_prime_inv: &Element<'dr, D>,
    munu: &Element<'dr, D>,
    mu_prime_nu_prime: &Element<'dr, D>,
) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
    let both = [&query.left, &query.right];

    let mut builder = SourceBuilder::new(z.clone(), txz.clone());

    // Process the claims specific to each child proof.
    for child in both.iter() {
        // << a_i, b_i >> accumulation.
        builder.direct(&child.a_poly_at_x, &child.b_poly_at_x);

        // Application circuit check, given the evaluation m(circuit_id_i, x, y)
        // for adversarially chosen omega^j = circuit_id.
        builder.application(
            dr,
            &child.application_at_x,
            &child.application_at_xz,
            &child.new_mesh_xy_at_old_circuit_id,
        );

        // hashes_1 internal circuit
        builder.internal(
            dr,
            [
                &child.hashes_1_at_x,
                &child.preamble_at_x,
                &child.error_n_at_x,
            ],
            [
                &child.hashes_1_at_xz,
                &child.preamble_at_xz,
                &child.error_n_at_xz,
            ],
            &query.fixed_mesh.hashes_1_circuit,
        );

        // hashes_2 internal circuit
        builder.internal(
            dr,
            [&child.hashes_2_at_x, &child.error_n_at_x],
            [&child.hashes_2_at_xz, &child.error_n_at_xz],
            &query.fixed_mesh.hashes_2_circuit,
        );

        // partial_collapse internal circuit
        builder.internal(
            dr,
            [
                &child.partial_collapse_at_x,
                &child.preamble_at_x,
                &child.error_m_at_x,
                &child.error_n_at_x,
            ],
            [
                &child.partial_collapse_at_xz,
                &child.preamble_at_xz,
                &child.error_m_at_xz,
                &child.error_n_at_xz,
            ],
            &query.fixed_mesh.partial_collapse_circuit,
        );

        // full_collapse internal circuit
        builder.internal(
            dr,
            [
                &child.full_collapse_at_x,
                &child.preamble_at_x,
                &child.error_m_at_x,
                &child.error_n_at_x,
            ],
            [
                &child.full_collapse_at_xz,
                &child.preamble_at_xz,
                &child.error_m_at_xz,
                &child.error_n_at_xz,
            ],
            &query.fixed_mesh.full_collapse_circuit,
        );

        // compute_v internal circuit (recursively!)
        builder.internal(
            dr,
            [
                &child.compute_v_at_x,
                &child.preamble_at_x,
                &child.query_at_x,
                &child.eval_at_x,
            ],
            [
                &child.compute_v_at_xz,
                &child.preamble_at_xz,
                &child.query_at_xz,
                &child.eval_at_xz,
            ],
            &query.fixed_mesh.compute_v_circuit,
        );
    }

    // Stage checks; these each share the same revdot claim because they're of
    // the form << r_i, s >> = 0.

    // ErrorNFinalStaged
    builder.stage(
        dr,
        both.iter().flat_map(|child| {
            [
                &child.hashes_1_at_x,
                &child.hashes_2_at_x,
                &child.partial_collapse_at_x,
                &child.full_collapse_at_x,
            ]
        }),
        &query.fixed_mesh.error_n_final_staged,
    )?;

    // EvalFinalStaged
    builder.stage(
        dr,
        both.iter().map(|child| &child.compute_v_at_x),
        &query.fixed_mesh.eval_final_staged,
    )?;

    // PreambleStage (stages::native::preamble)
    builder.stage(
        dr,
        both.iter().map(|child| &child.preamble_at_x),
        &query.fixed_mesh.preamble_stage,
    )?;

    // ErrorMStage (stages::native::error_m)
    builder.stage(
        dr,
        both.iter().map(|child| &child.error_m_at_x),
        &query.fixed_mesh.error_m_stage,
    )?;

    // ErrorNStage (stages::native::error_n)
    builder.stage(
        dr,
        both.iter().map(|child| &child.error_n_at_x),
        &query.fixed_mesh.error_n_stage,
    )?;

    // QueryStage (stages::native::query)
    builder.stage(
        dr,
        both.iter().map(|child| &child.query_at_x),
        &query.fixed_mesh.query_stage,
    )?;

    // EvalStage (stages::native::eval)
    builder.stage(
        dr,
        both.iter().map(|child| &child.eval_at_x),
        &query.fixed_mesh.eval_stage,
    )?;

    let (ax_sources, bx_sources) = builder.build();
    let ax = fold_two_layer::<_, P>(dr, &ax_sources, mu_inv, mu_prime_inv)?;
    let bx = fold_two_layer::<_, P>(dr, &bx_sources, munu, mu_prime_nu_prime)?;
    Ok((ax, bx))
}

/// Returns an iterator over the polynomial queries.
///
/// Each yielded element represents $(p(u), v, (u - x_i)^{-1})$ where $v =
/// p(x_i)$ is the prover's claim given polynomial $p(X)$.
///
/// The queries must be ordered exactly as in the prover's computation of $f(X)$
/// in [`crate::Application::compute_f`], since the ordering affects the weight
/// (with respect to $\alpha$) of each quotient polynomial.
#[rustfmt::skip]
fn poly_queries<'a, 'dr, D: Driver<'dr>, C: Cycle, const HEADER_SIZE: usize>(
    eval: &'a native_eval::Output<'dr, D>,
    query: &'a native_query::Output<'dr, D>,
    preamble: &'a native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    d: &'a Denominators<'dr, D>,
    computed_ax: &'a Element<'dr, D>,
    computed_bx: &'a Element<'dr, D>,
) -> impl Iterator<Item = (&'a Element<'dr, D>, &'a Element<'dr, D>, &'a Element<'dr, D>)> {
    [
        // Check p(u) = v for each child proof.
        (&eval.left.p_poly,            &preamble.left.unified.v,                   &d.left_u),
        (&eval.right.p_poly,           &preamble.right.unified.v,                  &d.right_u),
        // m(W, x_i, y_i) -> m(w, x_i, Y)
        (&eval.left.mesh_xy_poly,      &query.left.old_mesh_xy_at_new_w,           &d.w),
        (&eval.right.mesh_xy_poly,     &query.right.old_mesh_xy_at_new_w,          &d.w),
        (&eval.mesh_wx0,               &query.left.old_mesh_xy_at_new_w,           &d.old_y0),
        (&eval.mesh_wx1,               &query.right.old_mesh_xy_at_new_w,          &d.old_y1),
        // m(w, x_i, Y) -> m(w, X, y)
        (&eval.mesh_wx0,               &query.left.new_mesh_wy_at_old_x,           &d.y),
        (&eval.mesh_wx1,               &query.right.new_mesh_wy_at_old_x,          &d.y),
        (&eval.mesh_wy,                &query.left.new_mesh_wy_at_old_x,           &d.old_x0),
        (&eval.mesh_wy,                &query.right.new_mesh_wy_at_old_x,          &d.old_x1),
        // m(w, X, y) -> s(W, x, y)
        (&eval.mesh_wy,                &query.mesh_wxy,                            &d.x),
        (&eval.mesh_xy,                &query.mesh_wxy,                            &d.w),
    ].into_iter()
    // m(\omega^j, x, y) evaluations for each internal index j
    .chain([
        (&query.fixed_mesh.preamble_stage,           &d.internal_preamble_stage),
        (&query.fixed_mesh.error_m_stage,            &d.internal_error_m_stage),
        (&query.fixed_mesh.error_n_stage,            &d.internal_error_n_stage),
        (&query.fixed_mesh.query_stage,              &d.internal_query_stage),
        (&query.fixed_mesh.eval_stage,               &d.internal_eval_stage),
        (&query.fixed_mesh.error_n_final_staged,     &d.internal_error_n_final_staged),
        (&query.fixed_mesh.eval_final_staged,        &d.internal_eval_final_staged),
        (&query.fixed_mesh.hashes_1_circuit,         &d.internal_hashes_1_circuit),
        (&query.fixed_mesh.hashes_2_circuit,         &d.internal_hashes_2_circuit),
        (&query.fixed_mesh.partial_collapse_circuit, &d.internal_partial_collapse_circuit),
        (&query.fixed_mesh.full_collapse_circuit,    &d.internal_full_collapse_circuit),
        (&query.fixed_mesh.compute_v_circuit,        &d.internal_compute_v_circuit),
    ].into_iter().map(|(v, denom)| (&eval.mesh_xy, v, denom)))
    .chain([
        // m(circuit_id_i, x, y) evaluations for the ith child proof
        (&eval.mesh_xy,                &query.left.new_mesh_xy_at_old_circuit_id,  &d.left_circuit_id),
        (&eval.mesh_xy,                &query.right.new_mesh_xy_at_old_circuit_id, &d.right_circuit_id),
        // a_i(x), b_i(x) polynomial queries at x for each child proof
        (&eval.left.a_poly,            &query.left.a_poly_at_x,                    &d.x),
        (&eval.left.b_poly,            &query.left.b_poly_at_x,                    &d.x),
        (&eval.right.a_poly,           &query.right.a_poly_at_x,                   &d.x),
        (&eval.right.b_poly,           &query.right.b_poly_at_x,                   &d.x),
        // a(x), b(x) polynomial queries for the new accumulator; crucially, these evaluations
        // are computed by the verifier based on the other evaluations, NOT witnessed by the
        // prover.
        (&eval.a_poly,                 computed_ax,                                &d.x),
        (&eval.b_poly,                 computed_bx,                                &d.x),
    ])
    // Stage and circuit evaluations for each child proof at both x and xz
    // Note: both points are needed to perform circuit checks, which take
    // the form << r, r \circ z + s_y + t_z >> = k_y.
    .chain([(&eval.left, &query.left), (&eval.right, &query.right)]
        .into_iter()
        .flat_map(|(eval, query)| [
            (&eval.preamble,         &query.preamble_at_x,         &query.preamble_at_xz),
            (&eval.error_m,          &query.error_m_at_x,          &query.error_m_at_xz),
            (&eval.error_n,          &query.error_n_at_x,          &query.error_n_at_xz),
            (&eval.query,            &query.query_at_x,            &query.query_at_xz),
            (&eval.eval,             &query.eval_at_x,             &query.eval_at_xz),
            (&eval.application,      &query.application_at_x,      &query.application_at_xz),
            (&eval.hashes_1,         &query.hashes_1_at_x,         &query.hashes_1_at_xz),
            (&eval.hashes_2,         &query.hashes_2_at_x,         &query.hashes_2_at_xz),
            (&eval.partial_collapse, &query.partial_collapse_at_x, &query.partial_collapse_at_xz),
            (&eval.full_collapse,    &query.full_collapse_at_x,    &query.full_collapse_at_xz),
            (&eval.compute_v,        &query.compute_v_at_x,        &query.compute_v_at_xz),
        ].into_iter().flat_map(|(e, qx, qxz)| [(e, qx, &d.x), (e, qxz, &d.xz)])))
}
