//! Registration of the native recursive verifier circuits and stage masks.

use ragu_circuits::{polynomials::Rank, registry::RegistryBuilder, staging::StageExt};
use ragu_core::Result;

use crate::{
    profile::{BondingSlot, CircuitSlot, Profile, ProfiledCycle},
    protocol::native::*,
};
/// Registers internal native circuits and masks into the provided registry.
///
/// Does not register internal steps (rerandomize, bootstrap); those are
/// registered by the caller after this function returns.
///
/// `stage_size` is the application stage's size in values, the largest any
/// registered step stages, which fixes the layout of the application masks.
pub fn register_all<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    mut registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
    stage_size: usize,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>> {
    C::Profile::check()?;
    let initial_internal_circuits = registry.num_internal_circuits();
    // The application stage follows the SYSTEM gate in every step circuit.
    let stage_gates = ragu_circuits::staging::stage_gates(stage_size);

    for id in InternalCircuitIndex::all::<C::Profile>() {
        use InternalCircuitIndex::*;
        registry = match id {
            ExtensionCircuit(k) => C::Profile::register_native_circuit::<C::Base, R, HEADER_SIZE>(
                k as usize,
                CircuitSlot::new(registry),
                params,
            )?
            .into_registry(),
            ExtensionBonding(j) => C::Profile::register_native_bonding::<C::Base, R, HEADER_SIZE>(
                j as usize,
                BondingSlot::new(registry),
                params,
            )?
            .into_registry(),
            PreambleStage => {
                registry.register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::mask()?)
            }
            ApplicationStage => {
                registry.register_bonding(ragu_circuits::staging::stage_mask(1, stage_gates)?)
            }
            ApplicationFinalStaged => registry
                .register_bonding(ragu_circuits::staging::final_stage_mask(1 + stage_gates)?),
            InnerErrorStage => registry.register_bonding(stages::inner_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::mask()?),
            OuterErrorStage => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
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
                RevdotParameters<C::Profile>,
            >::final_mask()?),
            OuterErrorFinalStaged => registry.register_bonding(stages::outer_error::Stage::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::final_mask()?),
            EvalFinalStaged => {
                registry.register_bonding(stages::eval::Stage::<C, R, HEADER_SIZE>::final_mask()?)
            }
            PreambleFinalStaged => {
                registry
                    .register_bonding(stages::preamble::Stage::<C, R, HEADER_SIZE>::final_mask()?)
            }
            PointsBindingStage => registry.register_bonding(<stages::points::BindingStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsPreambleStage => registry.register_bonding(<stages::points::PreambleStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsRegistryWxStage => registry.register_bonding(<stages::points::RegistryWxStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsAbStage => registry.register_bonding(<stages::points::AbStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsFStage => registry.register_bonding(<stages::points::FStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkStage => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::mask(
            )?),
            PointsWalkFinalStaged => registry.register_bonding(<stages::points::WalkStage<
                C::NestedCurve,
                C::Profile,
            > as StageExt<C::CircuitField, R>>::final_mask(
            )?),
            BindEndoscalarCircuit => registry
                .register_internal_circuit(circuits::bind_endoscalar::Circuit::<C, R>::new())?,
            EndoscalingStep(step) => registry.register_internal_circuit(
                circuits::endoscaling_step::Circuit::<C, R>::new(step as usize),
            )?,
            Hashes1Circuit => {
                registry.register_internal_circuit(circuits::hashes_1::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<C::Profile>,
                >::new(params, log2_circuits))?
            }
            Hashes2Circuit => registry.register_internal_circuit(circuits::hashes_2::Circuit::<
                C,
                R,
                HEADER_SIZE,
                RevdotParameters<C::Profile>,
            >::new(params))?,
            CollapseCircuit => {
                registry.register_internal_circuit(circuits::collapse::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                    RevdotParameters<C::Profile>,
                >::new())?
            }
            ComputeVCircuit => {
                registry.register_internal_circuit(circuits::compute_v::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new())?
            }
            BindChallengesCircuit(k) => {
                crate::with_binder!(k, C, R, HEADER_SIZE, params, |circuit| {
                    registry.register_internal_circuit(circuit)?
                })
            }
            BindBetaCircuit => {
                registry.register_internal_circuit(circuits::bind_beta::Circuit::<
                    C,
                    R,
                    HEADER_SIZE,
                >::new(params))?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + InternalCircuitIndex::num::<C::Profile>(),
        "internal circuit count mismatch"
    );

    Ok(registry)
}

use crate::verifier::recursive::native::{circuits, stages};
