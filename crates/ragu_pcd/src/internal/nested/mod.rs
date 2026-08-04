//! Nested field circuits for the scalar field.
//!
//! Contains three groups of circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Copying**: enforces that [`ChildWitness`] stash fields in
//!   `BridgePreamble` match the corresponding child proof's bridge
//!   stage contents.
//!
//! [`ChildWitness`]: stages::preamble::ChildWitness
//! [`PointsStage`]: crate::internal::endoscalar::PointsStage

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;
use ragu_primitives::vec::Len;

pub mod circuits {
    pub mod copying;
    pub mod loading;
}

use crate::internal::{
    Side, endoscalar,
    native::{RxIndex as NativeRxIndex, stages::eval::CURRENT_STEP_COMPONENTS},
};

/// One child's block in the `_10_p` commitment walk: its native rx
/// commitments, four extras (`ab_a`, `ab_b`, `registry_xy`, `p`), and one
/// stashed commitment per witnessed polynomial. Shared with the nested
/// preamble and the native eval stage, so the accumulation, stash, and `v`
/// fold orders cannot drift apart.
pub const fn child_endoscaling_points(polys: usize) -> usize {
    NativeRxIndex::NUM + 4 + polys
}

/// Number of curve points accumulated during `compute_p`: the `f.commitment`
/// base point, one block per child ([`child_endoscaling_points`]), and the
/// current step's stage components. See `_10_p` for the accumulation order.
pub const fn num_endoscaling_points(polys: usize) -> usize {
    // The leading point is `f.commitment`'s base point.
    1 + 2 * child_endoscaling_points(polys) + CURRENT_STEP_COMPONENTS
}

/// The number of endoscaling step circuits a fuse runs.
pub const fn num_endoscaling_steps(polys: usize) -> usize {
    endoscalar::num_steps(num_endoscaling_points(polys))
}

/// [`num_endoscaling_points`] at the type level, for a poly count `L`.
pub struct EndoscalingPoints<L: Len>(PhantomData<L>);

impl<L: Len> Len for EndoscalingPoints<L> {
    fn len() -> usize {
        num_endoscaling_points(L::len())
    }
}

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the wiring objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
    /// Bridge `preamble` stage mask.
    BridgePreamble,
    /// Bridge `s_prime` stage mask.
    BridgeSPrime,
    /// Bridge `inner_error` stage mask.
    BridgeInnerError,
    /// Bridge `outer_error` stage mask.
    BridgeOuterError,
    /// Bridge `ab` stage mask.
    BridgeAB,
    /// Bridge `query` stage mask.
    BridgeQuery,
    /// Bridge `f` stage mask.
    BridgeF,
    /// Bridge `eval` stage mask.
    BridgeEval,
    /// Loading circuit over all nested stages.
    Loading,
    /// Copying circuit relating current preamble to a child proof's stages.
    Copying(Side),
}

impl InternalCircuitIndex {
    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this list.
    pub fn all(polys: usize) -> impl Iterator<Item = Self> {
        (0..num_endoscaling_steps(polys))
            .map(|step| Self::EndoscalingStep(step as u32))
            .chain([
                Self::EndoscalarStage,
                Self::PointsStage,
                Self::PointsFinalStaged,
                Self::BridgePreamble,
                Self::BridgeSPrime,
                Self::BridgeInnerError,
                Self::BridgeOuterError,
                Self::BridgeAB,
                Self::BridgeQuery,
                Self::BridgeF,
                Self::BridgeEval,
            ])
            .chain([
                Self::Loading,
                Self::Copying(Side::Left),
                Self::Copying(Side::Right),
            ])
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self, polys: usize) -> CircuitIndex {
        let pos = Self::all(polys)
            .position(|v| v == self)
            .expect("every variant appears in `all`");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in
/// the proof's nested-field polynomial storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildBridgeKind {
    /// Child proof's `BridgeSPrime` rx polynomial.
    SPrime,
    /// Child proof's `BridgeInnerError` rx polynomial.
    InnerError,
    /// Child proof's `BridgeOuterError` rx polynomial.
    OuterError,
    /// Child proof's `BridgeAB` rx polynomial.
    AB,
    /// Child proof's `BridgeQuery` rx polynomial.
    Query,
    /// Child proof's `BridgeEval` rx polynomial.
    Eval,
}

#[derive(Clone, Copy, Debug)]
pub enum RxIndex {
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// Bridge `preamble` rx polynomial.
    BridgePreamble,
    /// Bridge `s_prime` rx polynomial.
    BridgeSPrime,
    /// Bridge `inner_error` rx polynomial.
    BridgeInnerError,
    /// Bridge `outer_error` rx polynomial.
    BridgeOuterError,
    /// Bridge `ab` rx polynomial.
    BridgeAB,
    /// Bridge `query` rx polynomial.
    BridgeQuery,
    /// Bridge `f` rx polynomial.
    BridgeF,
    /// Bridge `eval` rx polynomial.
    BridgeEval,
    /// Child proof's `PointsStage` rx polynomial (per-side, for copying).
    ChildPointsStage(Side),
    /// Child proof's bridge rx polynomial (per-side, for copying),
    /// keyed by which bridge stage it comes from.
    ChildBridge(ChildBridgeKind, Side),
}

pub mod claims;

pub mod stages {
    pub mod ab;
    pub mod eval;
    pub mod f;
    pub mod inner_error;
    pub mod outer_error;
    pub mod preamble;
    pub mod query;
    pub mod s_prime;
}

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank, L: Len>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all(L::len()) {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    endoscalar::EndoscalingStep::<C::HostCurve, R, EndoscalingPoints<L>>::new(
                        step as usize,
                    );
                registry.register_internal_circuit(MultiStage::new(step_circuit))?
            }
            EndoscalarStage => registry.register_bonding(endoscalar::EndoscalarStage::mask()?),
            PointsStage => registry
                .register_bonding(
                    endoscalar::PointsStage::<C::HostCurve, EndoscalingPoints<L>>::mask()?,
                ),
            PointsFinalStaged => registry
                .register_bonding(
                    endoscalar::PointsStage::<C::HostCurve, EndoscalingPoints<L>>::final_mask()?,
                ),
            BridgePreamble => {
                registry.register_bonding(stages::preamble::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeSPrime => {
                registry.register_bonding(stages::s_prime::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeInnerError => {
                registry.register_bonding(stages::inner_error::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeOuterError => {
                registry.register_bonding(stages::outer_error::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeAB => registry.register_bonding(stages::ab::Stage::<C::HostCurve, R, L>::mask()?),
            BridgeQuery => {
                registry.register_bonding(stages::query::Stage::<C::HostCurve, R, L>::mask()?)
            }
            BridgeF => registry.register_bonding(stages::f::Stage::<C::HostCurve, R, L>::mask()?),
            BridgeEval => {
                registry.register_bonding(stages::eval::Stage::<C::HostCurve, R, L>::mask()?)
            }
            Loading => {
                let circuit = circuits::loading::Circuit::<C::HostCurve, R, L>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            // A copying circuit walks a child, but children expose the same
            // layout, so the same `L` serves here.
            Copying(side) => {
                let circuit = circuits::copying::Circuit::<C::HostCurve, R, L>::new(side);
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
        };
    }

    Ok(registry)
}
