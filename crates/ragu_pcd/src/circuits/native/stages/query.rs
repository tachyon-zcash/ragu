//! Query stage for fuse operations.

use arithmetic::Cycle;
use ff::PrimeField;
use ragu_circuits::{
    polynomials::{Rank, structured, unstructured},
    staging,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::Element;

use core::marker::PhantomData;

use crate::Proof;

use crate::circuits::native::{InternalCircuitIndex, NUM_INTERNAL_CIRCUITS};

pub(crate) use InternalCircuitIndex::QueryStage as STAGING_ID;

/// Witness for a polynomial evaluated at both x and xz.
pub struct XzQueryWitness<T> {
    /// Evaluation at x.
    pub at_x: T,
    /// Evaluation at xz.
    pub at_xz: T,
}

impl<T> XzQueryWitness<T> {
    /// Evaluate a polynomial at both x and xz.
    ///
    /// The closure `f` should evaluate the polynomial at the given point.
    pub fn eval(x: T, xz: T, f: impl Fn(T) -> T) -> Self {
        XzQueryWitness {
            at_x: f(x),
            at_xz: f(xz),
        }
    }
}

/// Gadget for a polynomial evaluated at both x and xz.
#[derive(Gadget)]
pub struct XzQuery<'dr, D: Driver<'dr>> {
    /// Evaluation at x.
    #[ragu(gadget)]
    pub at_x: Element<'dr, D>,
    /// Evaluation at xz.
    #[ragu(gadget)]
    pub at_xz: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> XzQuery<'dr, D> {
    /// Allocate an XzQuery from witness values.
    pub fn alloc(dr: &mut D, witness: DriverValue<D, &XzQueryWitness<D::F>>) -> Result<Self> {
        Ok(XzQuery {
            at_x: Element::alloc(dr, witness.view().map(|w| w.at_x))?,
            at_xz: Element::alloc(dr, witness.view().map(|w| w.at_xz))?,
        })
    }
}

/// Evaluation(s) of an rx polynomial at x and optionally xz.
///
/// For circuit claims, both x and xz evaluations are available. For raw a/b
/// claims, only the x evaluation is available.
pub enum RxEval<'a, 'dr, D: Driver<'dr>> {
    /// Only the x evaluation is available (used for raw a/b queries).
    X(&'a Element<'dr, D>),
    /// Both x and xz evaluations are available.
    Xz(&'a Element<'dr, D>, &'a Element<'dr, D>),
}

impl<'a, 'dr, D: Driver<'dr>> RxEval<'a, 'dr, D> {
    /// Returns the evaluation at x.
    pub fn x(&self) -> &'a Element<'dr, D> {
        match self {
            Self::X(x) | Self::Xz(x, _) => x,
        }
    }

    /// Returns the evaluation at xz. Panics if only x is available.
    pub fn xz(&self) -> &'a Element<'dr, D> {
        match self {
            Self::X(_) => panic!("xz evaluation not available for x-only RxEval"),
            Self::Xz(_, xz) => xz,
        }
    }
}

impl<'dr, D: Driver<'dr>> XzQuery<'dr, D> {
    /// Convert to an RxEval with both x and xz evaluations.
    pub fn to_eval(&self) -> RxEval<'_, 'dr, D> {
        RxEval::Xz(&self.at_x, &self.at_xz)
    }
}

/// Pre-computed evaluations of mesh_xy at each internal circuit's omega^j.
pub struct FixedMeshWitness<F> {
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
}

/// Witness for a child proof's polynomial evaluations.
pub struct ChildEvaluationsWitness<F> {
    /// Preamble stage rx polynomial evaluations.
    pub preamble: XzQueryWitness<F>,
    /// Error N stage rx polynomial evaluations.
    pub error_n: XzQueryWitness<F>,
    /// Error M stage rx polynomial evaluations.
    pub error_m: XzQueryWitness<F>,
    /// Query stage rx polynomial evaluations.
    pub query: XzQueryWitness<F>,
    /// Eval stage rx polynomial evaluations.
    pub eval: XzQueryWitness<F>,
    /// Application circuit rx polynomial evaluations.
    pub application: XzQueryWitness<F>,
    /// Hashes 1 circuit rx polynomial evaluations.
    pub hashes_1: XzQueryWitness<F>,
    /// Hashes 2 circuit rx polynomial evaluations.
    pub hashes_2: XzQueryWitness<F>,
    /// Partial collapse circuit rx polynomial evaluations.
    pub partial_collapse: XzQueryWitness<F>,
    /// Full collapse circuit rx polynomial evaluations.
    pub full_collapse: XzQueryWitness<F>,
    /// Compute V circuit rx polynomial evaluations.
    pub compute_v: XzQueryWitness<F>,
    /// A polynomial evaluation at x.
    pub a_poly_at_x: F,
    /// B polynomial evaluation at x.
    pub b_poly_at_x: F,
    /// Child's mesh_xy polynomial evaluated at current step's w.
    pub child_mesh_xy_at_current_w: F,
    /// Current mesh_xy polynomial evaluated at child's circuit_id.
    pub current_mesh_xy_at_child_circuit_id: F,
    /// Current mesh_wy polynomial evaluated at child's x.
    pub current_mesh_wy_at_child_x: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Create child evaluations witness from a proof evaluated at the given points.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(
        proof: &Proof<C, R>,
        w: F,
        x: F,
        xz: F,
        mesh_xy: &unstructured::Polynomial<F, R>,
        mesh_wy: &structured::Polynomial<F, R>,
    ) -> Self {
        ChildEvaluationsWitness {
            preamble: XzQueryWitness::eval(x, xz, |pt| proof.preamble.native_rx.eval(pt)),
            error_m: XzQueryWitness::eval(x, xz, |pt| proof.error_m.native_rx.eval(pt)),
            error_n: XzQueryWitness::eval(x, xz, |pt| proof.error_n.native_rx.eval(pt)),
            query: XzQueryWitness::eval(x, xz, |pt| proof.query.native_rx.eval(pt)),
            eval: XzQueryWitness::eval(x, xz, |pt| proof.eval.native_rx.eval(pt)),
            application: XzQueryWitness::eval(x, xz, |pt| proof.application.rx.eval(pt)),
            hashes_1: XzQueryWitness::eval(x, xz, |pt| proof.circuits.hashes_1_rx.eval(pt)),
            hashes_2: XzQueryWitness::eval(x, xz, |pt| proof.circuits.hashes_2_rx.eval(pt)),
            partial_collapse: XzQueryWitness::eval(x, xz, |pt| {
                proof.circuits.partial_collapse_rx.eval(pt)
            }),
            full_collapse: XzQueryWitness::eval(x, xz, |pt| {
                proof.circuits.full_collapse_rx.eval(pt)
            }),
            compute_v: XzQueryWitness::eval(x, xz, |pt| proof.circuits.compute_v_rx.eval(pt)),
            a_poly_at_x: proof.ab.a_poly.eval(x),
            b_poly_at_x: proof.ab.b_poly.eval(x),
            child_mesh_xy_at_current_w: proof.query.mesh_xy_poly.eval(w),
            current_mesh_xy_at_child_circuit_id: mesh_xy
                .eval(proof.application.circuit_id.omega_j()),
            current_mesh_wy_at_child_x: mesh_wy.eval(proof.challenges.x),
        }
    }
}

/// Witness data for the query stage.
pub struct Witness<C: Cycle> {
    /// Pre-computed mesh_xy evaluations at each internal circuit's omega^j.
    pub fixed_mesh: FixedMeshWitness<C::CircuitField>,
    /// m(w, x, y) - verifies mesh_xy/mesh_wy consistency at current coordinates.
    pub mesh_wxy: C::CircuitField,
    /// Left child proof polynomial evaluations.
    pub left: ChildEvaluationsWitness<C::CircuitField>,
    /// Right child proof polynomial evaluations.
    pub right: ChildEvaluationsWitness<C::CircuitField>,
}

/// Evaluations of mesh_xy at each internal circuit's circuit_id (omega^j).
#[derive(Gadget)]
pub struct FixedMeshEvaluations<'dr, D: Driver<'dr>> {
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
}

impl<'dr, D: Driver<'dr>> FixedMeshEvaluations<'dr, D> {
    /// Allocate fixed mesh evaluations from pre-computed witness values.
    pub fn alloc(dr: &mut D, witness: DriverValue<D, &FixedMeshWitness<D::F>>) -> Result<Self> {
        Ok(FixedMeshEvaluations {
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
        })
    }

    /// Look up the mesh evaluation for the given internal circuit index.
    pub fn circuit_mesh(&self, id: InternalCircuitIndex) -> &Element<'dr, D> {
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
        }
    }
}

/// Gadget for a child proof's polynomial evaluations.
#[derive(Gadget)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    /// Preamble stage rx polynomial evaluations.
    #[ragu(gadget)]
    pub preamble: XzQuery<'dr, D>,
    /// Error N stage rx polynomial evaluations.
    #[ragu(gadget)]
    pub error_n: XzQuery<'dr, D>,
    /// Error M stage rx polynomial evaluations.
    #[ragu(gadget)]
    pub error_m: XzQuery<'dr, D>,
    /// Query stage rx polynomial evaluations.
    #[ragu(gadget)]
    pub query: XzQuery<'dr, D>,
    /// Eval stage rx polynomial evaluations.
    #[ragu(gadget)]
    pub eval: XzQuery<'dr, D>,
    /// Application circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub application: XzQuery<'dr, D>,
    /// Hashes 1 circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub hashes_1: XzQuery<'dr, D>,
    /// Hashes 2 circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub hashes_2: XzQuery<'dr, D>,
    /// Partial collapse circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub partial_collapse: XzQuery<'dr, D>,
    /// Full collapse circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub full_collapse: XzQuery<'dr, D>,
    /// Compute V circuit rx polynomial evaluations.
    #[ragu(gadget)]
    pub compute_v: XzQuery<'dr, D>,
    /// A polynomial evaluation at x.
    #[ragu(gadget)]
    pub a_poly_at_x: Element<'dr, D>,
    /// B polynomial evaluation at x.
    #[ragu(gadget)]
    pub b_poly_at_x: Element<'dr, D>,
    /// Child's mesh_xy polynomial evaluated at current step's w.
    #[ragu(gadget)]
    pub child_mesh_xy_at_current_w: Element<'dr, D>,
    /// Current mesh_xy polynomial evaluated at child's circuit_id.
    #[ragu(gadget)]
    pub current_mesh_xy_at_child_circuit_id: Element<'dr, D>,
    /// Current mesh_wy polynomial evaluated at child's x.
    #[ragu(gadget)]
    pub current_mesh_wy_at_child_x: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
    ) -> Result<Self> {
        Ok(ChildEvaluations {
            preamble: XzQuery::alloc(dr, witness.view().map(|w| &w.preamble))?,
            error_m: XzQuery::alloc(dr, witness.view().map(|w| &w.error_m))?,
            error_n: XzQuery::alloc(dr, witness.view().map(|w| &w.error_n))?,
            query: XzQuery::alloc(dr, witness.view().map(|w| &w.query))?,
            eval: XzQuery::alloc(dr, witness.view().map(|w| &w.eval))?,
            application: XzQuery::alloc(dr, witness.view().map(|w| &w.application))?,
            hashes_1: XzQuery::alloc(dr, witness.view().map(|w| &w.hashes_1))?,
            hashes_2: XzQuery::alloc(dr, witness.view().map(|w| &w.hashes_2))?,
            partial_collapse: XzQuery::alloc(dr, witness.view().map(|w| &w.partial_collapse))?,
            full_collapse: XzQuery::alloc(dr, witness.view().map(|w| &w.full_collapse))?,
            compute_v: XzQuery::alloc(dr, witness.view().map(|w| &w.compute_v))?,
            a_poly_at_x: Element::alloc(dr, witness.view().map(|w| w.a_poly_at_x))?,
            b_poly_at_x: Element::alloc(dr, witness.view().map(|w| w.b_poly_at_x))?,
            child_mesh_xy_at_current_w: Element::alloc(
                dr,
                witness.view().map(|w| w.child_mesh_xy_at_current_w),
            )?,
            current_mesh_xy_at_child_circuit_id: Element::alloc(
                dr,
                witness
                    .view()
                    .map(|w| w.current_mesh_xy_at_child_circuit_id),
            )?,
            current_mesh_wy_at_child_x: Element::alloc(
                dr,
                witness.view().map(|w| w.current_mesh_wy_at_child_x),
            )?,
        })
    }
}

/// Output gadget for the query stage.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// Fixed mesh evaluations at each internal circuit's omega^j.
    #[ragu(gadget)]
    pub fixed_mesh: FixedMeshEvaluations<'dr, D>,
    /// m(w, x, y) - verifies mesh_xy/mesh_wy consistency at current coordinates.
    #[ragu(gadget)]
    pub mesh_wxy: Element<'dr, D>,
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
        // FixedMeshEvaluations (12) + mesh_wxy (1) + 2 * ChildEvaluations (27 each)
        NUM_INTERNAL_CIRCUITS + 1 + 2 * 27
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let fixed_mesh = FixedMeshEvaluations::alloc(dr, witness.view().map(|w| &w.fixed_mesh))?;
        let mesh_wxy = Element::alloc(dr, witness.view().map(|w| w.mesh_wxy))?;
        let left = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.right))?;
        Ok(Output {
            fixed_mesh,
            mesh_wxy,
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
