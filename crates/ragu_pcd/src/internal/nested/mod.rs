//! Nested field circuits for endoscaling verification.
//!
//! These circuits operate over the scalar field and verify that the
//! commitment accumulation was computed correctly via Horner's rule.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;

use crate::internal::endoscalar;

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of:
/// - 2 proofs × 15 commitment components = 30
/// - 6 stage proof components (registry_wx0, registry_wx1, registry_wy, ab.a, ab.b, registry_xy)
/// - 1 f.commitment (base polynomial)
///
/// The endoscaling circuits process these points across
/// [`NUM_ENDOSCALING_STEPS`] steps.
pub const NUM_ENDOSCALING_POINTS: usize = 37;

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
const NUM_ENDOSCALING_STEPS: usize = endoscalar::num_steps(NUM_ENDOSCALING_POINTS);

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final stage mask.
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
}

/// The number of internal circuits registered by [`register_all`],
/// equal to the number of entries in [`InternalCircuitIndex::ALL`].
pub const NUM_INTERNAL_CIRCUITS: usize = NUM_ENDOSCALING_STEPS + 11;

impl InternalCircuitIndex {
    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before bonding polynomials), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
    pub const ALL: [Self; NUM_INTERNAL_CIRCUITS] = super::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; NUM_INTERNAL_CIRCUITS] {
        let mut slots = [None; NUM_INTERNAL_CIRCUITS];
        let mut c = 0;
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                super::push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        super::push(&mut slots, &mut c, Self::EndoscalarStage);
        super::push(&mut slots, &mut c, Self::PointsStage);
        super::push(&mut slots, &mut c, Self::PointsFinalStaged);
        super::push(&mut slots, &mut c, Self::BridgePreamble);
        super::push(&mut slots, &mut c, Self::BridgeSPrime);
        super::push(&mut slots, &mut c, Self::BridgeInnerError);
        super::push(&mut slots, &mut c, Self::BridgeOuterError);
        super::push(&mut slots, &mut c, Self::BridgeAB);
        super::push(&mut slots, &mut c, Self::BridgeQuery);
        super::push(&mut slots, &mut c, Self::BridgeF);
        super::push(&mut slots, &mut c, Self::BridgeEval);
        assert!(c == NUM_INTERNAL_CIRCUITS);
        slots
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal bonding polynomials.
    pub fn circuit_index(self) -> CircuitIndex {
        let pos = Self::ALL
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in ALL");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in
/// [`NestedP`](crate::proof::components::NestedP).
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
}

/// The number of rx components in the nested field,
/// equal to the number of entries in [`RxIndex::ALL`].
pub const NUM_RX_COMPONENTS: usize = NUM_ENDOSCALING_STEPS + 10;

impl RxIndex {
    /// All variants in canonical order (circuits, then stages).
    ///
    /// Must maintain the same ordering convention as
    /// [`native::RxIndex::ALL`](super::native::RxIndex::ALL).
    pub const ALL: [Self; NUM_RX_COMPONENTS] = super::unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; NUM_RX_COMPONENTS] {
        let mut slots = [None; NUM_RX_COMPONENTS];
        let mut c = 0;
        {
            let mut step = 0;
            while step < NUM_ENDOSCALING_STEPS {
                super::push(&mut slots, &mut c, Self::EndoscalingStep(step as u32));
                step += 1;
            }
        }
        super::push(&mut slots, &mut c, Self::EndoscalarStage);
        super::push(&mut slots, &mut c, Self::PointsStage);
        super::push(&mut slots, &mut c, Self::BridgePreamble);
        super::push(&mut slots, &mut c, Self::BridgeSPrime);
        super::push(&mut slots, &mut c, Self::BridgeInnerError);
        super::push(&mut slots, &mut c, Self::BridgeOuterError);
        super::push(&mut slots, &mut c, Self::BridgeAB);
        super::push(&mut slots, &mut c, Self::BridgeQuery);
        super::push(&mut slots, &mut c, Self::BridgeF);
        super::push(&mut slots, &mut c, Self::BridgeEval);
        assert!(c == NUM_RX_COMPONENTS);
        slots
    }
}

pub mod claims;

pub mod stages;

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then bonding polynomials — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    endoscalar::EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(
                        step as usize,
                    );
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            EndoscalarStage => {
                registry.register_internal_bonding(endoscalar::EndoscalarStage::mask()?)?
            }
            PointsStage => registry.register_internal_bonding(endoscalar::PointsStage::<
                C::HostCurve,
                NUM_ENDOSCALING_POINTS,
            >::mask()?)?,
            PointsFinalStaged => registry.register_internal_bonding(endoscalar::PointsStage::<
                C::HostCurve,
                NUM_ENDOSCALING_POINTS,
            >::final_mask(
            )?)?,
            BridgePreamble => registry
                .register_internal_bonding(stages::preamble::Stage::<C::HostCurve, R>::mask()?)?,
            BridgeSPrime => registry
                .register_internal_bonding(stages::s_prime::Stage::<C::HostCurve, R>::mask()?)?,
            BridgeInnerError => registry
                .register_internal_bonding(stages::inner_error::Stage::<C::HostCurve, R>::mask()?)?,
            BridgeOuterError => registry
                .register_internal_bonding(stages::outer_error::Stage::<C::HostCurve, R>::mask()?)?,
            BridgeAB => {
                registry.register_internal_bonding(stages::ab::Stage::<C::HostCurve, R>::mask()?)?
            }
            BridgeQuery => registry
                .register_internal_bonding(stages::query::Stage::<C::HostCurve, R>::mask()?)?,
            BridgeF => {
                registry.register_internal_bonding(stages::f::Stage::<C::HostCurve, R>::mask()?)?
            }
            BridgeEval => registry
                .register_internal_bonding(stages::eval::Stage::<C::HostCurve, R>::mask()?)?,
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(registry)
}
