//! Native curve circuits for recursive verification.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::StageExt,
};
use ragu_core::Result;
use ragu_primitives::vec::ConstLen;

use crate::{internal::fold_revdot::Parameters, step};

/// Default parameters for native revdot folding
#[derive(Clone, Copy, Default)]
pub struct RevdotParameters;

impl Parameters for RevdotParameters {
    type NumGroups = ConstLen<19>;
    type GroupSize = ConstLen<7>;
}

pub mod stages {
    pub mod eval;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
}

pub mod circuits {
    pub mod compute_v;
    pub mod hashes_1;
    pub mod hashes_2;
    pub mod inner_collapse;
    pub mod outer_collapse;
}

pub mod claims;
pub mod unified;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    // Native circuits
    Hashes1Circuit,
    Hashes2Circuit,
    InnerCollapseCircuit,
    OuterCollapseCircuit,
    ComputeVCircuit,
    // Native stages
    PreambleStage,
    InnerErrorStage,
    OuterErrorStage,
    QueryStage,
    EvalStage,
    // Final stage masks
    InnerErrorFinalStaged,
    OuterErrorFinalStaged,
    EvalFinalStaged,
}

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub const fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits =
        num_application_steps + step::NUM_INTERNAL_STEPS + InternalCircuitIndex::NUM;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    /// The number of internal circuits registered by [`register_all`],
    /// equal to the number of variants in [`InternalCircuitIndex`].
    pub const NUM: usize = 13;

    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        push(&mut slots, &mut c, Self::Hashes1Circuit);
        push(&mut slots, &mut c, Self::Hashes2Circuit);
        push(&mut slots, &mut c, Self::InnerCollapseCircuit);
        push(&mut slots, &mut c, Self::OuterCollapseCircuit);
        push(&mut slots, &mut c, Self::ComputeVCircuit);
        push(&mut slots, &mut c, Self::PreambleStage);
        push(&mut slots, &mut c, Self::InnerErrorStage);
        push(&mut slots, &mut c, Self::OuterErrorStage);
        push(&mut slots, &mut c, Self::QueryStage);
        push(&mut slots, &mut c, Self::EvalStage);
        push(&mut slots, &mut c, Self::InnerErrorFinalStaged);
        push(&mut slots, &mut c, Self::OuterErrorFinalStaged);
        push(&mut slots, &mut c, Self::EvalFinalStaged);
        assert!(c == Self::NUM);
        slots
    }

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
    pub inner_collapse_circuit: T,
    pub outer_collapse_circuit: T,
    pub compute_v_circuit: T,
    pub preamble_stage: T,
    pub inner_error_stage: T,
    pub outer_error_stage: T,
    pub query_stage: T,
    pub eval_stage: T,
    pub inner_error_final_staged: T,
    pub outer_error_final_staged: T,
    pub eval_final_staged: T,
}

impl<T> InternalCircuitValues<T> {
    /// Look up the value for the given internal circuit index.
    pub fn get(&self, id: InternalCircuitIndex) -> &T {
        use InternalCircuitIndex::*;
        match id {
            Hashes1Circuit => &self.hashes_1_circuit,
            Hashes2Circuit => &self.hashes_2_circuit,
            InnerCollapseCircuit => &self.inner_collapse_circuit,
            OuterCollapseCircuit => &self.outer_collapse_circuit,
            ComputeVCircuit => &self.compute_v_circuit,
            PreambleStage => &self.preamble_stage,
            InnerErrorStage => &self.inner_error_stage,
            OuterErrorStage => &self.outer_error_stage,
            QueryStage => &self.query_stage,
            EvalStage => &self.eval_stage,
            InnerErrorFinalStaged => &self.inner_error_final_staged,
            OuterErrorFinalStaged => &self.outer_error_final_staged,
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
            inner_collapse_circuit: f(InnerCollapseCircuit)?,
            outer_collapse_circuit: f(OuterCollapseCircuit)?,
            compute_v_circuit: f(ComputeVCircuit)?,
            preamble_stage: f(PreambleStage)?,
            inner_error_stage: f(InnerErrorStage)?,
            outer_error_stage: f(OuterErrorStage)?,
            query_stage: f(QueryStage)?,
            eval_stage: f(EvalStage)?,
            inner_error_final_staged: f(InnerErrorFinalStaged)?,
            outer_error_final_staged: f(OuterErrorFinalStaged)?,
            eval_final_staged: f(EvalFinalStaged)?,
        })
    }
}

/// Enum identifying which rx polynomial component to index within [`RxValues`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxIndex {
    // Circuits
    Application,
    Hashes1,
    Hashes2,
    InnerCollapse,
    OuterCollapse,
    ComputeV,
    // Stages
    Preamble,
    InnerError,
    OuterError,
    Query,
    Eval,
}

impl RxIndex {
    /// The number of rx polynomial components.
    pub const NUM: usize = 11;

    /// All variants in canonical order.
    ///
    /// This order matches the evaluation order in `poly_queries` (compute_v.rs)
    /// and `_08_f.rs`, and drives the `Write` impl for `RxValues`.
    pub const ALL: [Self; Self::NUM] = super::const_fns::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; Self::NUM] {
        use super::const_fns::push;

        let mut slots = [None; Self::NUM];
        let mut c = 0;
        push(&mut slots, &mut c, Self::Application);
        push(&mut slots, &mut c, Self::Hashes1);
        push(&mut slots, &mut c, Self::Hashes2);
        push(&mut slots, &mut c, Self::InnerCollapse);
        push(&mut slots, &mut c, Self::OuterCollapse);
        push(&mut slots, &mut c, Self::ComputeV);
        push(&mut slots, &mut c, Self::Preamble);
        push(&mut slots, &mut c, Self::InnerError);
        push(&mut slots, &mut c, Self::OuterError);
        push(&mut slots, &mut c, Self::Query);
        push(&mut slots, &mut c, Self::Eval);
        assert!(c == Self::NUM);
        slots
    }
}

/// Per-rx-component storage indexed by [`RxIndex`].
///
/// Each field corresponds 1:1 to a variant of [`RxIndex`].
/// Use [`get`](Self::get) to look up by variant, and
/// [`try_from_fn`](Self::try_from_fn) to construct from a closure.
#[derive(Clone)]
pub struct RxValues<T> {
    pub application: T,
    pub hashes_1: T,
    pub hashes_2: T,
    pub inner_collapse: T,
    pub outer_collapse: T,
    pub compute_v: T,
    pub preamble: T,
    pub inner_error: T,
    pub outer_error: T,
    pub query: T,
    pub eval: T,
}

impl<T> RxValues<T> {
    /// Look up the value for the given rx index.
    pub fn get(&self, id: RxIndex) -> &T {
        use RxIndex::*;
        match id {
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            InnerCollapse => &self.inner_collapse,
            OuterCollapse => &self.outer_collapse,
            ComputeV => &self.compute_v,
            Preamble => &self.preamble,
            InnerError => &self.inner_error,
            OuterError => &self.outer_error,
            Query => &self.query,
            Eval => &self.eval,
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
            application: f(Application)?,
            hashes_1: f(Hashes1)?,
            hashes_2: f(Hashes2)?,
            inner_collapse: f(InnerCollapse)?,
            outer_collapse: f(OuterCollapse)?,
            compute_v: f(ComputeV)?,
            preamble: f(Preamble)?,
            inner_error: f(InnerError)?,
            outer_error: f(OuterError)?,
            query: f(Query)?,
            eval: f(Eval)?,
        })
    }
}

/// Identifies a native-field polynomial within a proof — either one of the
/// two AB polynomials (which are not rx polynomials) or one of the 11 rx
/// polynomials addressed by [`RxIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxComponent {
    /// The `a` polynomial from the AB proof (revdot claim).
    AbA,
    /// The `b` polynomial from the AB proof (revdot claim).
    AbB,
    /// An rx polynomial component indexed by [`RxIndex`].
    Rx(RxIndex),
}

/// Static prefix of the polynomial-query order used to construct and verify
/// the fuse quotient polynomial $f(X)$.
///
/// These queries are consumed by both the prover-side `compute_f` path and the
/// `compute_v` circuit. Keeping this prefix in one ordered list prevents the
/// two implementations from drifting independently; the dynamic suffixes are
/// still driven by [`RxIndex::ALL`] and [`InternalCircuitIndex::ALL`].
pub(crate) enum StaticFQuery {
    /// Left child proof $p(u)=v$ check.
    LeftP,
    /// Right child proof $p(u)=v$ check.
    RightP,
    /// Left child registry-xy polynomial queried at the current $w$.
    LeftRegistryXyAtW,
    /// Right child registry-xy polynomial queried at the current $w$.
    RightRegistryXyAtW,
    /// Current $m(w, x_0, Y)$ queried at the left child's $y$.
    RegistryWx0AtLeftY,
    /// Current $m(w, x_1, Y)$ queried at the right child's $y$.
    RegistryWx1AtRightY,
    /// Current $m(w, x_0, Y)$ queried at the current $y$.
    RegistryWx0AtY,
    /// Current $m(w, x_1, Y)$ queried at the current $y$.
    RegistryWx1AtY,
    /// Current $m(w, X, y)$ queried at the left child's $x$.
    RegistryWyAtLeftX,
    /// Current $m(w, X, y)$ queried at the right child's $x$.
    RegistryWyAtRightX,
    /// Current $m(w, X, y)$ queried at the current $x$.
    RegistryWyAtX,
    /// Current registry-xy polynomial queried at the current $w$.
    RegistryXyAtW,
    /// Current registry-xy polynomial queried at the left child's circuit id.
    RegistryXyAtLeftCircuitId,
    /// Current registry-xy polynomial queried at the right child's circuit id.
    RegistryXyAtRightCircuitId,
    /// Left child $a$ polynomial queried at $xz$.
    LeftAbAAtXz,
    /// Left child $b$ polynomial queried at $x$.
    LeftAbBAtX,
    /// Right child $a$ polynomial queried at $xz$.
    RightAbAAtXz,
    /// Right child $b$ polynomial queried at $x$.
    RightAbBAtX,
    /// Current accumulator $a$ polynomial queried at $xz$.
    CurrentAAtXz,
    /// Current accumulator $b$ polynomial queried at $x$.
    CurrentBAtX,
}

/// Ordered static prefix for fuse quotient polynomial queries.
pub(crate) const STATIC_F_QUERIES: [StaticFQuery; 20] = [
    StaticFQuery::LeftP,
    StaticFQuery::RightP,
    StaticFQuery::LeftRegistryXyAtW,
    StaticFQuery::RightRegistryXyAtW,
    StaticFQuery::RegistryWx0AtLeftY,
    StaticFQuery::RegistryWx1AtRightY,
    StaticFQuery::RegistryWx0AtY,
    StaticFQuery::RegistryWx1AtY,
    StaticFQuery::RegistryWyAtLeftX,
    StaticFQuery::RegistryWyAtRightX,
    StaticFQuery::RegistryWyAtX,
    StaticFQuery::RegistryXyAtW,
    StaticFQuery::RegistryXyAtLeftCircuitId,
    StaticFQuery::RegistryXyAtRightCircuitId,
    StaticFQuery::LeftAbAAtXz,
    StaticFQuery::LeftAbBAtX,
    StaticFQuery::RightAbAAtXz,
    StaticFQuery::RightAbBAtX,
    StaticFQuery::CurrentAAtXz,
    StaticFQuery::CurrentBAtX,
];

/// Registers internal native circuits and masks into the provided registry.
///
/// Does not register internal steps (rerandomize, bootstrap); those are
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
                registry.register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            InnerErrorStage => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::mask()?),
            OuterErrorStage => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::mask()?),
            QueryStage => {
                registry.register_bonding(stages::query::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            EvalStage => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            InnerErrorFinalStaged => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::final_mask()?),
            OuterErrorFinalStaged => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::final_mask()?),
            EvalFinalStaged => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE>::final_mask()?)
            }
            Hashes1Circuit => {
                registry.register_internal_circuit(circuits::hashes_1::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters,
                >::new(params, log2_circuits))?
            }
            Hashes2Circuit => registry.register_internal_circuit(circuits::hashes_2::Circuit::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters,
            >::new(params))?,
            InnerCollapseCircuit => {
                registry.register_internal_circuit(circuits::inner_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters,
                >::new())?
            }
            OuterCollapseCircuit => {
                registry.register_internal_circuit(circuits::outer_collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters,
                >::new())?
            }
            ComputeVCircuit => {
                registry.register_internal_circuit(circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new())?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::NUM,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
