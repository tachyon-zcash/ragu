//! Query stage for fuse operations.
//!
//! Witnesses the claimed polynomial evaluations needed for the `compute_v`
//! circuit to verify the $f(u)$ quotient polynomial. Each child proof's `rx`
//! polynomials are evaluated at $xz$:
//!
//! - $r\_i(xz)$ — used to recompute both $A(xz)$ (undilated) and $B(x)$ (since
//!   $b\_i(x) = r\_i(xz) + s\_y + t\_z$).
//!
//! Because $A$ has no $Z$-dilation, checking it at $xz$ instead of $x$ lets
//! both $A$ and $B$ share the same $\{r\_i(xz)\}$ evaluations, eliminating the
//! need for separate $r\_i(x)$ queries.
//!
//! Additionally witnesses the $a$/$b$ polynomial evaluations and registry
//! transition evaluations needed for mesh consistency checks.

use ff::PrimeField;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, structured, unstructured},
    staging,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::Element;

use core::marker::PhantomData;

use crate::Proof;

use crate::circuits::native::{InternalCircuitIndex, NUM_INTERNAL_CIRCUITS};

pub(crate) use InternalCircuitIndex::QueryStage as STAGING_ID;

/// Pre-computed evaluations of registry_xy at each internal circuit's omega^j.
pub struct FixedRegistryWitness<F> {
    pub preamble_stage: F,
    pub error_n_stage: F,
    pub error_m_stage: F,
    pub query_stage: F,
    pub eval_stage: F,
    pub error_m_final_staged: F,
    pub error_n_final_staged: F,
    pub eval_final_staged: F,
    pub hashes_1_circuit: F,
    pub hashes_2_circuit: F,
    pub partial_collapse_circuit: F,
    pub full_collapse_circuit: F,
    pub compute_v_circuit: F,
    pub endoscale_challenges_circuit: F,
}

/// Witness for a child proof's polynomial evaluations.
pub struct ChildEvaluationsWitness<F> {
    /// Preamble stage `rx` polynomial evaluation at $xz$.
    pub preamble: F,

    /// Error N stage `rx` polynomial evaluation at $xz$.
    pub error_n: F,

    /// Error M stage `rx` polynomial evaluation at $xz$.
    pub error_m: F,

    /// Query stage `rx` polynomial evaluation at $xz$.
    pub query: F,

    /// Eval stage `rx` polynomial evaluation at $xz$.
    pub eval: F,

    /// Application circuit `rx` polynomial evaluation at $xz$.
    pub application: F,

    /// Hashes 1 circuit `rx` polynomial evaluation at $xz$.
    pub hashes_1: F,

    /// Hashes 2 circuit `rx` polynomial evaluation at $xz$.
    pub hashes_2: F,

    /// Partial collapse circuit `rx` polynomial evaluation at $xz$.
    pub partial_collapse: F,

    /// Full collapse circuit `rx` polynomial evaluation at $xz$.
    pub full_collapse: F,

    /// Compute V circuit `rx` polynomial evaluation at $xz$.
    pub compute_v: F,

    /// Endoscale challenges circuit `rx` polynomial evaluation at $xz$.
    pub endoscale_challenges: F,

    /// $A$ polynomial evaluation at $xz$.
    pub a_poly_at_xz: F,

    /// $B$ polynomial evaluation at $x$.
    pub b_poly_at_x: F,

    /// Child's `registry_xy` polynomial evaluated at current step's $w$.
    pub child_registry_xy_at_current_w: F,

    /// Current `registry_xy` polynomial evaluated at child's `circuit_id`.
    pub current_registry_xy_at_child_circuit_id: F,

    /// Current `registry_wy` polynomial evaluated at child's $x$.
    pub current_registry_wy_at_child_x: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Creates a child evaluations witness from a proof evaluated at the given points.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(
        proof: &Proof<C, R>,
        w: F,
        x: F,
        xz: F,
        registry_xy: &unstructured::Polynomial<F, R>,
        registry_wy: &structured::Polynomial<F, R>,
    ) -> Self {
        ChildEvaluationsWitness {
            preamble: proof.preamble.native_rx.eval(xz),
            error_m: proof.error_m.native_rx.eval(xz),
            error_n: proof.error_n.native_rx.eval(xz),
            query: proof.query.native_rx.eval(xz),
            eval: proof.eval.native_rx.eval(xz),
            application: proof.application.rx.eval(xz),
            hashes_1: proof.circuits.hashes_1_rx.eval(xz),
            hashes_2: proof.circuits.hashes_2_rx.eval(xz),
            partial_collapse: proof.circuits.partial_collapse_rx.eval(xz),
            full_collapse: proof.circuits.full_collapse_rx.eval(xz),
            compute_v: proof.circuits.compute_v_rx.eval(xz),
            endoscale_challenges: proof.circuits.endoscale_challenges_rx.eval(xz),
            a_poly_at_xz: proof.ab.a_poly.eval(xz),
            b_poly_at_x: proof.ab.b_poly.eval(x),
            child_registry_xy_at_current_w: proof.query.registry_xy_poly.eval(w),
            current_registry_xy_at_child_circuit_id: registry_xy
                .eval(proof.application.circuit_id.omega_j()),
            current_registry_wy_at_child_x: registry_wy.eval(proof.challenges.x),
        }
    }
}

/// Witness data for the query stage.
pub struct Witness<C: Cycle> {
    /// Pre-computed registry_xy evaluations at each internal circuit's omega^j.
    pub fixed_registry: FixedRegistryWitness<C::CircuitField>,
    /// m(w, x, y) - verifies registry_xy/registry_wy consistency at current coordinates.
    pub registry_wxy: C::CircuitField,
    /// Left child proof polynomial evaluations.
    pub left: ChildEvaluationsWitness<C::CircuitField>,
    /// Right child proof polynomial evaluations.
    pub right: ChildEvaluationsWitness<C::CircuitField>,
}

/// Evaluations of registry_xy at each internal circuit's circuit_id (omega^j).
#[derive(Gadget)]
pub struct FixedRegistryEvaluations<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub preamble_stage: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_n_stage: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_m_stage: Element<'dr, D>,
    #[ragu(gadget)]
    pub query_stage: Element<'dr, D>,
    #[ragu(gadget)]
    pub eval_stage: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_m_final_staged: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_n_final_staged: Element<'dr, D>,
    #[ragu(gadget)]
    pub eval_final_staged: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_1_circuit: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_2_circuit: Element<'dr, D>,
    #[ragu(gadget)]
    pub partial_collapse_circuit: Element<'dr, D>,
    #[ragu(gadget)]
    pub full_collapse_circuit: Element<'dr, D>,
    #[ragu(gadget)]
    pub compute_v_circuit: Element<'dr, D>,
    #[ragu(gadget)]
    pub endoscale_challenges_circuit: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> FixedRegistryEvaluations<'dr, D> {
    /// Allocate fixed registry evaluations from pre-computed witness values.
    pub fn alloc(dr: &mut D, witness: DriverValue<D, &FixedRegistryWitness<D::F>>) -> Result<Self> {
        Ok(FixedRegistryEvaluations {
            preamble_stage: Element::alloc(dr, witness.view().map(|w| w.preamble_stage))?,
            error_n_stage: Element::alloc(dr, witness.view().map(|w| w.error_n_stage))?,
            error_m_stage: Element::alloc(dr, witness.view().map(|w| w.error_m_stage))?,
            query_stage: Element::alloc(dr, witness.view().map(|w| w.query_stage))?,
            eval_stage: Element::alloc(dr, witness.view().map(|w| w.eval_stage))?,
            error_m_final_staged: Element::alloc(
                dr,
                witness.view().map(|w| w.error_m_final_staged),
            )?,
            error_n_final_staged: Element::alloc(
                dr,
                witness.view().map(|w| w.error_n_final_staged),
            )?,
            eval_final_staged: Element::alloc(dr, witness.view().map(|w| w.eval_final_staged))?,
            hashes_1_circuit: Element::alloc(dr, witness.view().map(|w| w.hashes_1_circuit))?,
            hashes_2_circuit: Element::alloc(dr, witness.view().map(|w| w.hashes_2_circuit))?,
            partial_collapse_circuit: Element::alloc(
                dr,
                witness.view().map(|w| w.partial_collapse_circuit),
            )?,
            full_collapse_circuit: Element::alloc(
                dr,
                witness.view().map(|w| w.full_collapse_circuit),
            )?,
            compute_v_circuit: Element::alloc(dr, witness.view().map(|w| w.compute_v_circuit))?,
            endoscale_challenges_circuit: Element::alloc(
                dr,
                witness.view().map(|w| w.endoscale_challenges_circuit),
            )?,
        })
    }

    /// Look up the registry evaluation for the given internal circuit index.
    pub fn circuit_registry(&self, id: InternalCircuitIndex) -> &Element<'dr, D> {
        use InternalCircuitIndex::*;
        match id {
            Hashes1Circuit => &self.hashes_1_circuit,
            Hashes2Circuit => &self.hashes_2_circuit,
            PartialCollapseCircuit => &self.partial_collapse_circuit,
            FullCollapseCircuit => &self.full_collapse_circuit,
            ComputeVCircuit => &self.compute_v_circuit,
            PreambleStage => &self.preamble_stage,
            ErrorMStage => &self.error_m_stage,
            ErrorNStage => &self.error_n_stage,
            QueryStage => &self.query_stage,
            EvalStage => &self.eval_stage,
            ErrorMFinalStaged => &self.error_m_final_staged,
            ErrorNFinalStaged => &self.error_n_final_staged,
            EvalFinalStaged => &self.eval_final_staged,
            EndoscaleChallengesCircuit => &self.endoscale_challenges_circuit,
        }
    }
}

/// Gadget for a child proof's polynomial evaluations.
#[derive(Gadget)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    /// Preamble stage `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub preamble: Element<'dr, D>,

    /// Error N stage `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub error_n: Element<'dr, D>,

    /// Error M stage `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub error_m: Element<'dr, D>,

    /// Query stage `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub query: Element<'dr, D>,

    /// Eval stage `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub eval: Element<'dr, D>,

    /// Application circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub application: Element<'dr, D>,

    /// Hashes 1 circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub hashes_1: Element<'dr, D>,

    /// Hashes 2 circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub hashes_2: Element<'dr, D>,

    /// Partial collapse circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub partial_collapse: Element<'dr, D>,

    /// Full collapse circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub full_collapse: Element<'dr, D>,

    /// Compute V circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub compute_v: Element<'dr, D>,

    /// Endoscale challenges circuit `rx` polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub endoscale_challenges: Element<'dr, D>,

    /// $A$ polynomial evaluation at $xz$.
    #[ragu(gadget)]
    pub a_poly_at_xz: Element<'dr, D>,

    /// $B$ polynomial evaluation at $x$.
    #[ragu(gadget)]
    pub b_poly_at_x: Element<'dr, D>,

    /// Child's `registry_xy` polynomial evaluated at current step's $w$.
    #[ragu(gadget)]
    pub child_registry_xy_at_current_w: Element<'dr, D>,

    /// Current `registry_xy` polynomial evaluated at child's `circuit_id`.
    #[ragu(gadget)]
    pub current_registry_xy_at_child_circuit_id: Element<'dr, D>,

    /// Current `registry_wy` polynomial evaluated at child's $x$.
    #[ragu(gadget)]
    pub current_registry_wy_at_child_x: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
    ) -> Result<Self> {
        Ok(ChildEvaluations {
            preamble: Element::alloc(dr, witness.view().map(|w| w.preamble))?,
            error_m: Element::alloc(dr, witness.view().map(|w| w.error_m))?,
            error_n: Element::alloc(dr, witness.view().map(|w| w.error_n))?,
            query: Element::alloc(dr, witness.view().map(|w| w.query))?,
            eval: Element::alloc(dr, witness.view().map(|w| w.eval))?,
            application: Element::alloc(dr, witness.view().map(|w| w.application))?,
            hashes_1: Element::alloc(dr, witness.view().map(|w| w.hashes_1))?,
            hashes_2: Element::alloc(dr, witness.view().map(|w| w.hashes_2))?,
            partial_collapse: Element::alloc(dr, witness.view().map(|w| w.partial_collapse))?,
            full_collapse: Element::alloc(dr, witness.view().map(|w| w.full_collapse))?,
            compute_v: Element::alloc(dr, witness.view().map(|w| w.compute_v))?,
            endoscale_challenges: Element::alloc(
                dr,
                witness.view().map(|w| w.endoscale_challenges),
            )?,
            a_poly_at_xz: Element::alloc(dr, witness.view().map(|w| w.a_poly_at_xz))?,
            b_poly_at_x: Element::alloc(dr, witness.view().map(|w| w.b_poly_at_x))?,
            child_registry_xy_at_current_w: Element::alloc(
                dr,
                witness.view().map(|w| w.child_registry_xy_at_current_w),
            )?,
            current_registry_xy_at_child_circuit_id: Element::alloc(
                dr,
                witness
                    .view()
                    .map(|w| w.current_registry_xy_at_child_circuit_id),
            )?,
            current_registry_wy_at_child_x: Element::alloc(
                dr,
                witness.view().map(|w| w.current_registry_wy_at_child_x),
            )?,
        })
    }
}

/// Prover-internal output gadget for the query stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// Fixed registry evaluations at each internal circuit's omega^j.
    #[ragu(gadget)]
    pub fixed_registry: FixedRegistryEvaluations<'dr, D>,
    /// m(w, x, y) - verifies registry_xy/registry_wy consistency at current coordinates.
    #[ragu(gadget)]
    pub registry_wxy: Element<'dr, D>,
    /// Left child proof polynomial evaluations.
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D>,
    /// Right child proof polynomial evaluations.
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D>,
}

/// The query stage of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _>];

    fn values() -> usize {
        // FixedRegistryEvaluations (14) + registry_wxy (1) + 2 * ChildEvaluations (17 each)
        NUM_INTERNAL_CIRCUITS + 1 + 2 * 17
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let fixed_registry =
            FixedRegistryEvaluations::alloc(dr, witness.view().map(|w| &w.fixed_registry))?;
        let registry_wxy = Element::alloc(dr, witness.view().map(|w| w.registry_wxy))?;
        let left = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.right))?;
        Ok(Output {
            fixed_registry,
            registry_wxy,
            left,
            right,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::native::stages::tests::{HEADER_SIZE, R, assert_stage_values};
    use ragu_pasta::Pasta;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
