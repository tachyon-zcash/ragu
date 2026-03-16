//! Native curve circuits for recursive verification.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_core::Result;
use ragu_primitives::vec::ConstLen;

use crate::internal::fold_revdot::Parameters;
use crate::step;

/// Default parameters for native revdot folding.
#[derive(Clone, Copy, Default)]
pub struct RevdotParameters;

impl Parameters for RevdotParameters {
    type N = ConstLen<19>;
    type M = ConstLen<7>;
}

pub mod stages;

pub mod circuits;
pub mod claims;
pub mod unified;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    // Native circuits
    Hashes1Circuit,
    Hashes2Circuit,
    PartialCollapseCircuit,
    FullCollapseCircuit,
    ComputeVCircuit,
    // Native stages
    PreambleStage,
    ErrorMStage,
    ErrorNStage,
    QueryStage,
    EvalStage,
    // Final stage masks
    ErrorMFinalStaged,
    ErrorNFinalStaged,
    EvalFinalStaged,
}

/// The number of internal circuits registered by [`register_all`],
/// equal to the number of variants in [`InternalCircuitIndex`].
pub const NUM_INTERNAL_CIRCUITS: usize = 13;

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub const fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits = num_application_steps + step::NUM_INTERNAL_STEPS + NUM_INTERNAL_CIRCUITS;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
    pub const ALL: [Self; NUM_INTERNAL_CIRCUITS] = [
        Self::Hashes1Circuit,
        Self::Hashes2Circuit,
        Self::PartialCollapseCircuit,
        Self::FullCollapseCircuit,
        Self::ComputeVCircuit,
        Self::PreambleStage,
        Self::ErrorMStage,
        Self::ErrorNStage,
        Self::QueryStage,
        Self::EvalStage,
        Self::ErrorMFinalStaged,
        Self::ErrorNFinalStaged,
        Self::EvalFinalStaged,
    ];

    pub fn circuit_index(self) -> CircuitIndex {
        let pos = Self::ALL
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in ALL");
        CircuitIndex::from_u32(pos as u32)
    }
}

/// Per-internal-circuit storage indexed by [`InternalCircuitIndex`].
///
/// Each field corresponds 1:1 to a variant of [`InternalCircuitIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`from_fn`](Self::from_fn) / [`try_from_fn`](Self::try_from_fn) to
/// construct from a closure.
#[derive(Clone)]
pub struct InternalCircuitValues<T> {
    pub hashes_1_circuit: T,
    pub hashes_2_circuit: T,
    pub partial_collapse_circuit: T,
    pub full_collapse_circuit: T,
    pub compute_v_circuit: T,
    pub preamble_stage: T,
    pub error_m_stage: T,
    pub error_n_stage: T,
    pub query_stage: T,
    pub eval_stage: T,
    pub error_m_final_staged: T,
    pub error_n_final_staged: T,
    pub eval_final_staged: T,
}

impl<T> InternalCircuitValues<T> {
    /// Look up the value for the given internal circuit index.
    pub fn get(&self, id: InternalCircuitIndex) -> &T {
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

    /// Construct from a closure called once per variant in [`ALL`](InternalCircuitIndex::ALL)
    /// order.
    pub fn from_fn(mut f: impl FnMut(InternalCircuitIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](InternalCircuitIndex::ALL) order.
    pub fn try_from_fn<E>(
        mut f: impl FnMut(InternalCircuitIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use InternalCircuitIndex::*;
        Ok(InternalCircuitValues {
            hashes_1_circuit: f(Hashes1Circuit)?,
            hashes_2_circuit: f(Hashes2Circuit)?,
            partial_collapse_circuit: f(PartialCollapseCircuit)?,
            full_collapse_circuit: f(FullCollapseCircuit)?,
            compute_v_circuit: f(ComputeVCircuit)?,
            preamble_stage: f(PreambleStage)?,
            error_m_stage: f(ErrorMStage)?,
            error_n_stage: f(ErrorNStage)?,
            query_stage: f(QueryStage)?,
            eval_stage: f(EvalStage)?,
            error_m_final_staged: f(ErrorMFinalStaged)?,
            error_n_final_staged: f(ErrorNFinalStaged)?,
            eval_final_staged: f(EvalFinalStaged)?,
        })
    }
}

/// Enum identifying which rx polynomial component to index within [`RxValues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    Preamble,
    ErrorM,
    ErrorN,
    Query,
    Eval,
    Application,
    Hashes1,
    Hashes2,
    PartialCollapse,
    FullCollapse,
    ComputeV,
}

/// The number of rx polynomial components.
const NUM_RX_COMPONENTS: usize = 11;

impl RxIndex {
    /// All variants in canonical order.
    ///
    /// This order matches the evaluation order in `poly_queries` (compute_v.rs)
    /// and `_08_f.rs`, and drives the `Write` impl for `RxValues`.
    pub const ALL: [Self; NUM_RX_COMPONENTS] = [
        Self::Preamble,
        Self::ErrorM,
        Self::ErrorN,
        Self::Query,
        Self::Eval,
        Self::Application,
        Self::Hashes1,
        Self::Hashes2,
        Self::PartialCollapse,
        Self::FullCollapse,
        Self::ComputeV,
    ];
}

/// Per-rx-component storage indexed by [`RxIndex`].
///
/// Each field corresponds 1:1 to a variant of [`RxIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`try_from_fn`](Self::try_from_fn) to construct from a closure.
#[derive(Clone)]
pub struct RxValues<T> {
    pub preamble: T,
    pub error_m: T,
    pub error_n: T,
    pub query: T,
    pub eval: T,
    pub application: T,
    pub hashes_1: T,
    pub hashes_2: T,
    pub partial_collapse: T,
    pub full_collapse: T,
    pub compute_v: T,
}

impl<T> RxValues<T> {
    /// Look up the value for the given rx index.
    pub fn get(&self, id: RxIndex) -> &T {
        use RxIndex::*;
        match id {
            Preamble => &self.preamble,
            ErrorM => &self.error_m,
            ErrorN => &self.error_n,
            Query => &self.query,
            Eval => &self.eval,
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            PartialCollapse => &self.partial_collapse,
            FullCollapse => &self.full_collapse,
            ComputeV => &self.compute_v,
        }
    }

    /// Construct from a closure called once per variant in [`ALL`](RxIndex::ALL) order.
    pub fn from_fn(mut f: impl FnMut(RxIndex) -> T) -> Self {
        match Self::try_from_fn(|id| Ok::<_, core::convert::Infallible>(f(id))) {
            Ok(v) => v,
            Err(e) => match e {},
        }
    }

    /// Fallible construction from a closure called once per variant.
    ///
    /// The closure is called in [`ALL`](RxIndex::ALL) order.
    pub fn try_from_fn<E>(
        mut f: impl FnMut(RxIndex) -> core::result::Result<T, E>,
    ) -> core::result::Result<Self, E> {
        use RxIndex::*;
        Ok(RxValues {
            preamble: f(Preamble)?,
            error_m: f(ErrorM)?,
            error_n: f(ErrorN)?,
            query: f(Query)?,
            eval: f(Eval)?,
            application: f(Application)?,
            hashes_1: f(Hashes1)?,
            hashes_2: f(Hashes2)?,
            partial_collapse: f(PartialCollapse)?,
            full_collapse: f(FullCollapse)?,
            compute_v: f(ComputeV)?,
        })
    }
}

/// Identifies a native-field polynomial within a proof — either one of the
/// two AB polynomials (which are not rx polynomials) or one of the 11 rx
/// polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`RxIndex`].
    Rx(RxIndex),
}

/// Registers internal native circuits and masks into the provided registry.
///
/// Does not register internal steps (rerandomize, trivial); those are
/// registered by the caller after this function returns.
pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        registry = match id {
            PreambleStage => {
                registry.register_internal_mask::<stages::preamble::Stage<C, R, HEADER_SIZE>>()?
            }
            ErrorMStage => {
                registry.register_internal_mask::<stages::error_m::Stage<C, R, HEADER_SIZE, RevdotParameters>>()?
            }
            ErrorNStage => {
                registry.register_internal_mask::<stages::error_n::Stage<C, R, HEADER_SIZE, RevdotParameters>>()?
            }
            QueryStage => {
                registry.register_internal_mask::<stages::query::Stage<C, R, HEADER_SIZE>>()?
            }
            EvalStage => {
                registry.register_internal_mask::<stages::eval::Stage<C, R, HEADER_SIZE>>()?
            }
            ErrorMFinalStaged => {
                registry.register_internal_final_mask::<stages::error_m::Stage<C, R, HEADER_SIZE, RevdotParameters>>()?
            }
            ErrorNFinalStaged => {
                registry.register_internal_final_mask::<stages::error_n::Stage<C, R, HEADER_SIZE, RevdotParameters>>()?
            }
            EvalFinalStaged => {
                registry.register_internal_final_mask::<stages::eval::Stage<C, R, HEADER_SIZE>>()?
            }
            Hashes1Circuit => {
                registry.register_internal_circuit(circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, RevdotParameters>::new(params, log2_circuits))?
            }
            Hashes2Circuit => {
                registry.register_internal_circuit(circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, RevdotParameters>::new(params))?
            }
            PartialCollapseCircuit => {
                registry.register_internal_circuit(circuits::partial_collapse::Circuit::<C, R, HEADER_SIZE, RevdotParameters>::new())?
            }
            FullCollapseCircuit => {
                registry.register_internal_circuit(circuits::full_collapse::Circuit::<C, R, HEADER_SIZE, RevdotParameters>::new())?
            }
            ComputeVCircuit => {
                registry.register_internal_circuit(circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new())?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
