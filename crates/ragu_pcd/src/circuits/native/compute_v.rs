//! Circuit for computing and verifying the claimed evaluation value [$v$].
//!
//! ## Operations
//!
//! This circuit computes the claimed output value [$v$] and verifies it matches
//! the unified instance.
//!
//! ### Revdot folding
//! - Retrieve layer 1 challenges [$\mu$], [$\nu$] and layer 2 challenges [$\mu'$], [$\nu'$]
//! - Compute $a(x)$ and $b(x)$ via two-layer revdot folding of evaluation claims
//!
//! ### $f(u)$ computation
//! - Compute inverse denominators $(u - x_i)^{-1}$ for all evaluation points
//! - Iterate polynomial queries $(p(u), v, (u - x_i)^{-1})$ in prover order
//! - Accumulate $f(u) = \sum_i \alpha^{n-1-i} \cdot (p_i(u) - v_i) / (u - x_i)$ via Horner
//!   (first query receives highest $\alpha$ power)
//!
//! ### $v$ computation
//! - Extract endoscalar from [$\beta$] and compute effective beta via field_scale
//! - Compute $v = f(u) + \text{effective\_beta} \cdot \text{eval}$
//! - Set computed [$v$] in unified output, enforcing correctness
//!
//! ## Staging
//!
//! This circuit uses [`eval`] as its final stage, which inherits in the
//! following chain:
//! - [`preamble`] (enforced) - provides child proof data
//! - [`query`] (unenforced) - provides registry and polynomial evaluations
//! - [`eval`] (unenforced) - provides evaluation component polynomials
//!
//! ## Public Inputs
//!
//! Uses [`unified::Output`] as public inputs via [`unified::InternalOutputKind`].
//!
//! [`preamble`]: super::stages::preamble
//! [`query`]: super::stages::query
//! [`eval`]: super::stages::eval
//! [$v$]: unified::Output::v
//! [$\alpha$]: unified::Output::alpha
//! [$\beta$]: unified::Output::pre_beta
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [$\mu'$]: unified::Output::mu_prime
//! [$\nu'$]: unified::Output::nu_prime

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::{Element, Endoscalar, GadgetExt};

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::components::claims::{
    Source,
    native::{self as claims, Processor, RxComponent},
};
use crate::components::fold_revdot::{NativeParameters, Parameters, fold_two_layer};

use super::InternalCircuitIndex;
use super::{
    stages::{
        eval as native_eval, preamble as native_preamble,
        query::{self as native_query, ChildEvaluations, FixedRegistryEvaluations, RxEval},
    },
    unified::{self, OutputBuilder},
};
use crate::components::horner::Horner;

pub(crate) use super::InternalCircuitIndex::ComputeVCircuit as CIRCUIT_ID;

/// Circuit that computes and verifies the claimed evaluation value [$v$].
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
/// [$v$]: unified::Output::v
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Circuit<C, R, HEADER_SIZE> {
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the compute_v circuit.
///
/// Provides all staged data needed to compute [$v$]:
/// - Child proof public inputs from preamble
/// - Polynomial evaluations from query stage
/// - Evaluation component polynomials from eval stage
///
/// [$v$]: unified::Output::v
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Reference to the unified instance shared across internal circuits.
    pub unified_instance: &'a unified::Instance<C>,
    /// Witness for the preamble stage (provides child proof data).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// Witness for the query stage (provides registry and polynomial evaluations).
    pub query_witness: &'a native_query::Witness<C>,
    /// Witness for the eval stage (provides evaluation component polynomials).
    pub eval_witness: &'a native_eval::Witness<C::CircuitField>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE>
{
    type Last = native_eval::Stage<C, R, HEADER_SIZE>;

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
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // Set up multi-stage circuit pipeline: preamble -> query -> eval.
        // Each stage provides data needed for the v computation.
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        // Preamble is enforced because it contains child proof data that must
        // be validated (Points, Booleans, etc.).
        let preamble = preamble.enforced(dr, witness.view().map(|w| w.preamble_witness))?;

        let query = query.unenforced(dr, witness.view().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.view().map(|w| w.eval_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Retrieve Fiat-Shamir challenges from the unified instance.
        let w = unified_output.w.get(dr, unified_instance)?;
        let y = unified_output.y.get(dr, unified_instance)?;
        let z = unified_output.z.get(dr, unified_instance)?;
        let x = unified_output.x.get(dr, unified_instance)?;

        // Compute t(xz), the vanishing polynomial evaluated at xz.
        let txz = dr.routine(Evaluate::<R>::new(), (x.clone(), z.clone()))?;

        // Verify v: compute the expected value and constrain it to match the
        // unified instance. This binds the prover's polynomial commitments to
        // the claimed evaluation.
        {
            // Step 1: Compute a(x) and b(x) via two-layer revdot folding.
            // These aggregate all evaluation claims into a single pair.
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

            // Step 2: Compute f(u) by accumulating quotient terms.
            // f(u) = sum_i alpha^{n-1-i} * (p_i(u) - v_i) / (u - x_i)
            // (Horner accumulation: first query receives highest alpha power)
            let fu = {
                let alpha = unified_output.alpha.get(dr, unified_instance)?;
                let u = unified_output.u.get(dr, unified_instance)?;
                let denominators = Denominators::new(dr, &u, &w, &x, &y, &z, &preamble)?;
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

            // Step 3: Compute v = f(u) + beta * eval via Horner accumulation.
            // This combines f(u) with the evaluation component polynomials.
            // First extract endoscalar from pre_beta and compute effective beta.
            let computed_v = {
                let pre_beta = unified_output.pre_beta.get(dr, unified_instance)?;
                let beta_endo = Endoscalar::extract(dr, pre_beta)?;
                let effective_beta = beta_endo.field_scale(dr)?;
                let mut horner = Horner::new(&effective_beta);
                fu.write(dr, &mut horner)?;
                eval.write(dr, &mut horner)?;
                horner.finish(dr)
            };

            // Constrain v: the computed value must equal the claimed v in the
            // unified instance. This is enforced when finish() serializes the output.
            unified_output.v.set(computed_v);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}

/// Denominators for a single child proof evaluation points.
struct ChildDenominators<'dr, D: Driver<'dr>> {
    u: Element<'dr, D>,
    y: Element<'dr, D>,
    x: Element<'dr, D>,
    circuit_id: Element<'dr, D>,
}

/// Denominators for current step challenge points.
struct ChallengeDenominators<'dr, D: Driver<'dr>> {
    w: Element<'dr, D>,
    x: Element<'dr, D>,
    y: Element<'dr, D>,
    xz: Element<'dr, D>,
}

/// Denominators for internal circuit omega^j evaluation points.
struct InternalCircuitDenominators<'dr, D: Driver<'dr>> {
    preamble_stage: Element<'dr, D>,
    error_n_stage: Element<'dr, D>,
    error_m_stage: Element<'dr, D>,
    query_stage: Element<'dr, D>,
    eval_stage: Element<'dr, D>,
    error_m_final_staged: Element<'dr, D>,
    error_n_final_staged: Element<'dr, D>,
    eval_final_staged: Element<'dr, D>,
    hashes_1_circuit: Element<'dr, D>,
    hashes_2_circuit: Element<'dr, D>,
    partial_collapse_circuit: Element<'dr, D>,
    full_collapse_circuit: Element<'dr, D>,
    compute_v_circuit: Element<'dr, D>,
}

/// Denominator component of all quotient polynomial evaluations.
///
/// Each denominator represents $(u - x_i)^{-1}$ where $x_i$ is an evaluation
/// point. These are precomputed once and reused across all polynomial queries
/// in the [`poly_queries`] iterator.
///
/// The denominators are organized by source:
/// - `left`/`right`: Child proof evaluation points ($u$, $y$, $x$, circuit\_id)
/// - `challenges`: Current step challenge points ($w$, $x$, $y$, $xz$)
/// - `internal`: Internal circuit $\omega^j$ evaluation points
struct Denominators<'dr, D: Driver<'dr>> {
    left: ChildDenominators<'dr, D>,
    right: ChildDenominators<'dr, D>,
    challenges: ChallengeDenominators<'dr, D>,
    internal: InternalCircuitDenominators<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Denominators<'dr, D> {
    fn new<C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>(
        dr: &mut D,
        u: &Element<'dr, D>,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        preamble: &native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    ) -> Result<Self>
    where
        D::F: ff::PrimeField,
    {
        use super::InternalCircuitIndex::*;

        let xz = x.mul(dr, z)?;

        let mut inverter = Inverter::with_base(u.clone());

        let left_u = inverter.add(dr, &preamble.left.unified.u)?;
        let left_y = inverter.add(dr, &preamble.left.unified.y)?;
        let left_x = inverter.add(dr, &preamble.left.unified.x)?;
        let left_circuit_id = inverter.add(dr, &preamble.left.circuit_id)?;
        let right_u = inverter.add(dr, &preamble.right.unified.u)?;
        let right_y = inverter.add(dr, &preamble.right.unified.y)?;
        let right_x = inverter.add(dr, &preamble.right.unified.x)?;
        let right_circuit_id = inverter.add(dr, &preamble.right.circuit_id)?;
        let challenges_w = inverter.add(dr, w)?;
        let challenges_x = inverter.add(dr, x)?;
        let challenges_y = inverter.add(dr, y)?;
        let challenges_xz = inverter.add(dr, &xz)?;

        let preamble_stage = inverter.add_circuit(dr, PreambleStage)?;
        let error_n_stage = inverter.add_circuit(dr, ErrorNStage)?;
        let error_m_stage = inverter.add_circuit(dr, ErrorMStage)?;
        let query_stage = inverter.add_circuit(dr, QueryStage)?;
        let eval_stage = inverter.add_circuit(dr, EvalStage)?;
        let error_m_final_staged = inverter.add_circuit(dr, ErrorMFinalStaged)?;
        let error_n_final_staged = inverter.add_circuit(dr, ErrorNFinalStaged)?;
        let eval_final_staged = inverter.add_circuit(dr, EvalFinalStaged)?;
        let hashes_1_circuit = inverter.add_circuit(dr, Hashes1Circuit)?;
        let hashes_2_circuit = inverter.add_circuit(dr, Hashes2Circuit)?;
        let partial_collapse_circuit = inverter.add_circuit(dr, PartialCollapseCircuit)?;
        let full_collapse_circuit = inverter.add_circuit(dr, FullCollapseCircuit)?;
        let compute_v_circuit = inverter.add_circuit(dr, ComputeVCircuit)?;

        let inverted = inverter.invert(dr)?;

        Ok(Denominators {
            left: ChildDenominators {
                u: inverted[left_u].clone(),
                y: inverted[left_y].clone(),
                x: inverted[left_x].clone(),
                circuit_id: inverted[left_circuit_id].clone(),
            },
            right: ChildDenominators {
                u: inverted[right_u].clone(),
                y: inverted[right_y].clone(),
                x: inverted[right_x].clone(),
                circuit_id: inverted[right_circuit_id].clone(),
            },
            challenges: ChallengeDenominators {
                w: inverted[challenges_w].clone(),
                x: inverted[challenges_x].clone(),
                y: inverted[challenges_y].clone(),
                xz: inverted[challenges_xz].clone(),
            },
            internal: InternalCircuitDenominators {
                preamble_stage: inverted[preamble_stage].clone(),
                error_n_stage: inverted[error_n_stage].clone(),
                error_m_stage: inverted[error_m_stage].clone(),
                query_stage: inverted[query_stage].clone(),
                eval_stage: inverted[eval_stage].clone(),
                error_m_final_staged: inverted[error_m_final_staged].clone(),
                error_n_final_staged: inverted[error_n_final_staged].clone(),
                eval_final_staged: inverted[eval_final_staged].clone(),
                hashes_1_circuit: inverted[hashes_1_circuit].clone(),
                hashes_2_circuit: inverted[hashes_2_circuit].clone(),
                partial_collapse_circuit: inverted[partial_collapse_circuit].clone(),
                full_collapse_circuit: inverted[full_collapse_circuit].clone(),
                compute_v_circuit: inverted[compute_v_circuit].clone(),
            },
        })
    }
}

/// Source providing polynomial evaluations from child proofs for revdot folding.
///
/// Implements [`Source`] to provide evaluations in the canonical order
/// required by [`build`]. The ordering must match exactly
/// to ensure correct folding correspondence with the prover's computation.
///
/// [`build`]: claims::build
struct EvaluationSource<'a, 'dr, D: Driver<'dr>> {
    left: &'a ChildEvaluations<'dr, D>,
    right: &'a ChildEvaluations<'dr, D>,
}

impl<'a, 'dr, D: Driver<'dr>> Source for EvaluationSource<'a, 'dr, D> {
    type RxComponent = RxComponent;
    type Rx = RxEval<'a, 'dr, D>;

    /// For app circuits: the registry evaluation at the circuit's omega^j.
    type AppCircuitId = &'a Element<'dr, D>;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        use RxComponent::*;
        let (left, right) = match component {
            // Raw claims: only x evaluation is available
            AbA => (
                RxEval::X(&self.left.a_poly_at_x),
                RxEval::X(&self.right.a_poly_at_x),
            ),
            AbB => (
                RxEval::X(&self.left.b_poly_at_x),
                RxEval::X(&self.right.b_poly_at_x),
            ),
            // Circuit claims: both x and xz evaluations available
            Application => (
                self.left.application.to_eval(),
                self.right.application.to_eval(),
            ),
            Hashes1 => (self.left.hashes_1.to_eval(), self.right.hashes_1.to_eval()),
            Hashes2 => (self.left.hashes_2.to_eval(), self.right.hashes_2.to_eval()),
            PartialCollapse => (
                self.left.partial_collapse.to_eval(),
                self.right.partial_collapse.to_eval(),
            ),
            FullCollapse => (
                self.left.full_collapse.to_eval(),
                self.right.full_collapse.to_eval(),
            ),
            ComputeV => (
                self.left.compute_v.to_eval(),
                self.right.compute_v.to_eval(),
            ),
            Preamble => (self.left.preamble.to_eval(), self.right.preamble.to_eval()),
            ErrorM => (self.left.error_m.to_eval(), self.right.error_m.to_eval()),
            ErrorN => (self.left.error_n.to_eval(), self.right.error_n.to_eval()),
            Query => (self.left.query.to_eval(), self.right.query.to_eval()),
            Eval => (self.left.eval.to_eval(), self.right.eval.to_eval()),
        };
        [left, right].into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        [
            &self.left.current_registry_xy_at_child_circuit_id,
            &self.right.current_registry_xy_at_child_circuit_id,
        ]
        .into_iter()
    }
}

/// Processor that builds evaluation vectors for two-layer revdot folding.
///
/// Collects evaluations into `ax` and `bx` vectors that will be folded to
/// produce $a(x)$ and $b(x)$. Each claim type (raw, circuit, internal circuit,
/// stage) has different formulas for computing its contribution to the vectors.
struct EvaluationProcessor<'a, 'dr, D: Driver<'dr>> {
    dr: &'a mut D,
    z: &'a Element<'dr, D>,
    txz: &'a Element<'dr, D>,
    fixed_registry: &'a FixedRegistryEvaluations<'dr, D>,
    ax: Vec<Element<'dr, D>>,
    bx: Vec<Element<'dr, D>>,
}

impl<'a, 'dr, D: Driver<'dr>> EvaluationProcessor<'a, 'dr, D> {
    fn new(
        dr: &'a mut D,
        z: &'a Element<'dr, D>,
        txz: &'a Element<'dr, D>,
        fixed_registry: &'a FixedRegistryEvaluations<'dr, D>,
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

    fn build(self) -> (Vec<Element<'dr, D>>, Vec<Element<'dr, D>>) {
        (self.ax, self.bx)
    }
}

impl<'a, 'dr, D: Driver<'dr>> Processor<RxEval<'a, 'dr, D>, &'a Element<'dr, D>>
    for EvaluationProcessor<'a, 'dr, D>
{
    fn raw_claim(&mut self, a: RxEval<'a, 'dr, D>, b: RxEval<'a, 'dr, D>) {
        self.ax.push(a.x().clone());
        self.bx.push(b.x().clone());
    }

    fn circuit(&mut self, sy: &'a Element<'dr, D>, rx: RxEval<'a, 'dr, D>) {
        // b(x) = rx(xz) + s_y + t(xz)
        self.ax.push(rx.x().clone());
        self.bx
            .push(rx.xz().add(self.dr, sy).add(self.dr, self.txz));
    }

    fn internal_circuit(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = RxEval<'a, 'dr, D>>,
    ) {
        let sy = self.fixed_registry.circuit_registry(id);

        let mut a_sum = Element::zero(self.dr);
        let mut b_sum = Element::zero(self.dr);

        for rx in rxs {
            a_sum = a_sum.add(self.dr, rx.x());
            b_sum = b_sum.add(self.dr, rx.xz());
        }

        // a(x) = sum of all rx(x)
        self.ax.push(a_sum);
        // b(x) = sum of all rx(xz) + s_y + t(xz)
        self.bx.push(b_sum.add(self.dr, sy).add(self.dr, self.txz));
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = RxEval<'a, 'dr, D>>,
    ) -> Result<()> {
        let sy = self.fixed_registry.circuit_registry(id);

        // a(x) = fold of all rx(x) with z (Horner's rule)
        self.ax
            .push(Element::fold(self.dr, rxs.map(|rx| rx.x()), self.z)?);
        // b(x) = s_y evaluated at circuit's omega^j
        self.bx.push(sy.clone());
        Ok(())
    }
}

/// Computes the expected value of $a(x), b(x)$ given the evaluations at $x$ of
/// every constituent polynomial at $x, xz$.
///
/// This function is the authoritative source of the protocol's (recursive)
/// description of the revdot folding structure. It fundamentally binds the
/// prover's behavior in their choice of $a(X), b(X)$ and thus the correctness
/// of their folded revdot claim.
///
/// The two-layer folding uses:
/// - Layer 1: $\mu^{-1}$, $\mu'^{-1}$ for $a(x)$; $\mu\nu$, $\mu'\nu'$ for $b(x)$
/// - Layer 2: Internal folding within each layer
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
    // Build ax/bx evaluation vectors using the unified claim building abstraction.
    // This ensures the ordering matches claims::build() exactly.
    let source = EvaluationSource {
        left: &query.left,
        right: &query.right,
    };
    let mut processor = EvaluationProcessor::new(dr, z, txz, &query.fixed_registry);
    claims::build(&source, &mut processor)?;

    let (ax_sources, bx_sources) = processor.build();
    let ax = fold_two_layer::<_, P>(dr, &ax_sources, mu_inv, mu_prime_inv)?;
    let bx = fold_two_layer::<_, P>(dr, &bx_sources, munu, mu_prime_nu_prime)?;
    Ok((ax, bx))
}

/// Returns an iterator over the polynomial queries for computing $f(u)$.
///
/// Each yielded element represents $(p(u), v, (u - x_i)^{-1})$ where:
/// - $p(u)$ is the polynomial evaluation at $u$ (from eval stage)
/// - $v = p(x_i)$ is the prover's claimed evaluation (from query stage)
/// - $(u - x_i)^{-1}$ is the precomputed inverse denominator
///
/// ## Query Categories
///
/// The queries are organized into groups:
/// 1. **Child proof $p(u) = v$ checks** - Verify child proof evaluations
/// 2. **Registry polynomial transitions** - $m(W,x,y) \to m(w,x,Y) \to m(w,X,y) \to s(W,x,y)$
/// 3. **Internal circuit registry evaluations** - $m(\omega^j, x, y)$ for each internal index
/// 4. **Application circuit registry evaluations** - $m(\text{circuit\_id}, x, y)$
/// 5. **$a(x), b(x)$ polynomial queries** - Including verifier-computed values
/// 6. **Stage/circuit evaluations** - At both $x$ and $xz$ points
///
/// The queries must be ordered exactly as in the prover's computation of $f(X)$
/// in [`compute_f`], since the ordering affects the weight
/// (with respect to [$\alpha$]) of each quotient polynomial.
///
/// [`compute_f`]: crate::Application::compute_f
/// [$\alpha$]: unified::Output::alpha
#[rustfmt::skip]
fn poly_queries<'a, 'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>(
    eval: &'a native_eval::Output<'dr, D>,
    query: &'a native_query::Output<'dr, D>,
    preamble: &'a native_preamble::Output<'dr, D, C, HEADER_SIZE>,
    d: &'a Denominators<'dr, D>,
    computed_ax: &'a Element<'dr, D>,
    computed_bx: &'a Element<'dr, D>,
) -> impl Iterator<Item = (&'a Element<'dr, D>, &'a Element<'dr, D>, &'a Element<'dr, D>)> {
    [
        // Check p(u) = v for each child proof.
        (&eval.left.p_poly,        &preamble.left.unified.v,                     &d.left.u),
        (&eval.right.p_poly,       &preamble.right.unified.v,                    &d.right.u),
        // m(W, x_i, y_i) -> m(w, x_i, Y)
        (&eval.left.registry_xy_poly,  &query.left.child_registry_xy_at_current_w,       &d.challenges.w),
        (&eval.right.registry_xy_poly, &query.right.child_registry_xy_at_current_w,      &d.challenges.w),
        (&eval.registry_wx0,           &query.left.child_registry_xy_at_current_w,       &d.left.y),
        (&eval.registry_wx1,           &query.right.child_registry_xy_at_current_w,      &d.right.y),
        // m(w, x_i, Y) -> m(w, X, y)
        (&eval.registry_wx0,           &query.left.current_registry_wy_at_child_x,       &d.challenges.y),
        (&eval.registry_wx1,           &query.right.current_registry_wy_at_child_x,      &d.challenges.y),
        (&eval.registry_wy,            &query.left.current_registry_wy_at_child_x,       &d.left.x),
        (&eval.registry_wy,            &query.right.current_registry_wy_at_child_x,      &d.right.x),
        // m(w, X, y) -> s(W, x, y)
        (&eval.registry_wy,            &query.registry_wxy,                              &d.challenges.x),
        (&eval.registry_xy,            &query.registry_wxy,                              &d.challenges.w),
    ].into_iter()
    // m(\omega^j, x, y) evaluations for each internal index j
    .chain([
        (&query.fixed_registry.preamble_stage,           &d.internal.preamble_stage),
        (&query.fixed_registry.error_n_stage,            &d.internal.error_n_stage),
        (&query.fixed_registry.error_m_stage,            &d.internal.error_m_stage),
        (&query.fixed_registry.query_stage,              &d.internal.query_stage),
        (&query.fixed_registry.eval_stage,               &d.internal.eval_stage),
        (&query.fixed_registry.error_m_final_staged,     &d.internal.error_m_final_staged),
        (&query.fixed_registry.error_n_final_staged,     &d.internal.error_n_final_staged),
        (&query.fixed_registry.eval_final_staged,        &d.internal.eval_final_staged),
        (&query.fixed_registry.hashes_1_circuit,         &d.internal.hashes_1_circuit),
        (&query.fixed_registry.hashes_2_circuit,         &d.internal.hashes_2_circuit),
        (&query.fixed_registry.partial_collapse_circuit, &d.internal.partial_collapse_circuit),
        (&query.fixed_registry.full_collapse_circuit,    &d.internal.full_collapse_circuit),
        (&query.fixed_registry.compute_v_circuit,        &d.internal.compute_v_circuit),
    ].into_iter().map(|(v, denom)| (&eval.registry_xy, v, denom)))
    .chain([
        // m(circuit_id_i, x, y) evaluations for the ith child proof
        (&eval.registry_xy,            &query.left.current_registry_xy_at_child_circuit_id,  &d.left.circuit_id),
        (&eval.registry_xy,            &query.right.current_registry_xy_at_child_circuit_id, &d.right.circuit_id),
        // a_i(x), b_i(x) polynomial queries at x for each child proof
        (&eval.left.a_poly,        &query.left.a_poly_at_x,                          &d.challenges.x),
        (&eval.left.b_poly,        &query.left.b_poly_at_x,                          &d.challenges.x),
        (&eval.right.a_poly,       &query.right.a_poly_at_x,                         &d.challenges.x),
        (&eval.right.b_poly,       &query.right.b_poly_at_x,                         &d.challenges.x),
        // a(x), b(x) polynomial queries for the new accumulator; crucially, these evaluations
        // are computed by the verifier based on the other evaluations, NOT witnessed by the
        // prover.
        (&eval.a_poly,             computed_ax,                                      &d.challenges.x),
        (&eval.b_poly,             computed_bx,                                      &d.challenges.x),
    ])
    // Stage and circuit evaluations for each child proof at both x and xz
    // Note: both points are needed to perform circuit checks, which take
    // the form << r, r \circ z + s_y + t_z >> = k_y.
    .chain([(&eval.left, &query.left), (&eval.right, &query.right)]
        .into_iter()
        .flat_map(|(eval, query)| [
            (&eval.preamble,         &query.preamble),
            (&eval.error_n,          &query.error_n),
            (&eval.error_m,          &query.error_m),
            (&eval.query,            &query.query),
            (&eval.eval,             &query.eval),
            (&eval.application,      &query.application),
            (&eval.hashes_1,         &query.hashes_1),
            (&eval.hashes_2,         &query.hashes_2),
            (&eval.partial_collapse, &query.partial_collapse),
            (&eval.full_collapse,    &query.full_collapse),
            (&eval.compute_v,        &query.compute_v),
        ].into_iter().flat_map(|(e, q)| [(e, &q.at_x, &d.challenges.x), (e, &q.at_xz, &d.challenges.xz)])))
}

/// Batch inverter for computing denominators.
///
/// Computes differences `(base - value)` for each added value and accumulates
/// their field representations for batch inversion. After calling
/// [`invert`](Self::invert), the inverted differences can be retrieved using
/// the returned indices.
struct Inverter<'dr, D: Driver<'dr>> {
    /// Base [`Element`] from which differences are computed.
    ///
    /// Each call to [`add`](Self::add) subtracts the provided value from this
    /// base.
    base: Element<'dr, D>,

    /// Accumulated difference [`Element`]s: `(base - value)` for each added
    /// value.
    ///
    /// These differences will be batch-inverted when [`invert`](Self::invert)
    /// is called.
    differences: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr, F: ff::PrimeField>> Inverter<'dr, D> {
    /// Creates a batch inverter with the provided base [`Element`].
    ///
    /// The base represents a fixed evaluation point (e.g., $u$ or $y$
    /// coordinate) from which all added values will be subtracted. This allows
    /// efficient batch inversion of differences $(u - x_i)$ using Montgomery's
    /// trick.
    fn with_base(base: Element<'dr, D>) -> Self {
        Self {
            base,
            differences: Vec::new(),
        }
    }

    /// Adds a value to subtract from the base: computes `(base - value)`.
    ///
    /// Returns an index that can be used to retrieve the inverted difference
    /// after calling [`invert`](Self::invert).
    fn add(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<usize> {
        let index = self.differences.len();
        let diff = self.base.sub(dr, value);
        self.differences.push(diff);
        Ok(index)
    }

    /// Adds a constant field value to subtract from the base: computes `(base -
    /// constant)`.
    ///
    /// This is a convenience method for adding known field values (such as
    /// fixed points in the FFT domain) without first wrapping them in an
    /// [`Element`]. It creates a constant [`Element`] internally and calls
    /// [`add`](Self::add).
    ///
    /// Returns an index that can be used to retrieve the inverted difference
    /// after calling [`invert`](Self::invert).
    fn add_constant(&mut self, dr: &mut D, value: D::F) -> Result<usize> {
        let constant = Element::constant(dr, value);
        self.add(dr, &constant)
    }

    /// Adds an internal circuit's $\omega^j$ value to subtract from the base.
    ///
    /// This is a convenience method for adding the FFT domain element
    /// corresponding to an internal circuit's index. The $\omega^j$ value is
    /// computed from `circuit.circuit_index().omega_j()` at compile time.
    fn add_circuit(&mut self, dr: &mut D, circuit: InternalCircuitIndex) -> Result<usize> {
        self.add_constant(dr, circuit.circuit_index().omega_j())
    }

    /// Performs batch inversion on all accumulated differences.
    ///
    /// Consumes the inverter and returns a vector of inverted [`Element`]s.
    /// Each difference [`Element`] is inverted using [`Element::invert_with`]
    /// with the batch-inverted field value as advice.
    ///
    /// During proving, this function batch inverts the accumulated field values
    /// using Montgomery's trick and uses them as advice for constraint
    /// generation. During verification, the field values are not available, but
    /// the inversion constraints are still enforced through the [`Element`]
    /// wiring.
    fn invert(self, dr: &mut D) -> Result<Vec<Element<'dr, D>>> {
        let mut advice = D::just(|| {
            let mut differences = self
                .differences
                .iter()
                .map(|diff| **diff.value().snag())
                .collect::<Vec<_>>();

            let mut scratch = differences.clone();
            ff::BatchInverter::invert_with_external_scratch(&mut differences, &mut scratch);

            differences.into_iter()
        });

        self.differences
            .into_iter()
            .map(|e| e.invert_with(dr, advice.view_mut().map(|e| e.next().unwrap())))
            .collect()
    }
}
