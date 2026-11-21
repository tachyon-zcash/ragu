//! Registration of the nested recursive verifier circuits and stage masks.

use ragu_circuits::{
    polynomials::Rank,
    registry::RegistryBuilder,
    staging::{MultiStage, StageExt},
};
use ragu_core::Result;

use crate::{
    profile::{BondingSlot, CircuitSlot, Profile, ProfiledCycle},
    protocol::{gadgets::endoscalar, nested::*},
};
/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: ProfiledCycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
    params: &'params C::Params,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    crate::protocol::nested::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(
                        step as usize,
                    );
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            Collapse => {
                let circuit = super::collapse::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            ComputeV => {
                let circuit = super::compute_v::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_internal_circuit(MultiStage::new(circuit))?
            }
            EndoscalarStage => registry.register_bonding(endoscalar::EndoscalarStage::mask()?),
            PointsStage => registry.register_bonding(crate::protocol::nested::PointsStage::<
                C::HostCurve,
                C::Profile,
            >::mask()?),
            PointsFinalStaged => registry.register_bonding(crate::protocol::nested::PointsStage::<
                C::HostCurve,
                C::Profile,
            >::final_mask()?),
            BridgePreamble => {
                registry.register_bonding(
                    stages::preamble::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeHash => {
                registry.register_bonding(stages::bridge_hash::Stage::<C::HostCurve>::mask()?)
            }
            BridgeSPrime => registry.register_bonding(stages::s_prime::Stage::<
                C::HostCurve,
                R,
                C::Profile,
            >::mask()?),
            BridgeInnerError => {
                registry.register_bonding(
                    stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeOuterError => {
                registry.register_bonding(
                    stages::outer_error::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            BridgeAB => {
                registry.register_bonding(stages::ab::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeQuery => {
                registry
                    .register_bonding(stages::query::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeF => {
                registry.register_bonding(stages::f::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            BridgeEval => {
                registry
                    .register_bonding(stages::eval::Stage::<C::HostCurve, R, C::Profile>::mask()?)
            }
            ChallengeStage => {
                registry.register_bonding(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::mask()?,
                )
            }
            ChallengeFinalStaged => {
                registry.register_bonding(
                    stages::challenges::Stage::<C::HostCurve, R, C::Profile>::final_mask()?,
                )
            }
            Loading => {
                let circuit = super::loading::Circuit::<C::HostCurve, R, C::Profile>::new();
                registry.register_bonding(MultiStage::new(circuit).into_bonding_object()?)
            }
            ExtensionCircuit(k) => C::Profile::register_nested_circuit::<C::Base, R>(
                k as usize,
                CircuitSlot::new(registry),
                params,
            )?
            .into_registry(),
            ExtensionBonding(j) => C::Profile::register_nested_bonding::<C::Base, R>(
                j as usize,
                BondingSlot::new(registry),
                params,
            )?
            .into_registry(),
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num::<C::Profile>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}

use crate::protocol::nested::stages;
