//! Stage and helper checks independent of the production fuse integration.

use alloc::vec;

use ragu_circuits::{
    CircuitExt,
    polynomials::{ProductionRank, Rank},
    staging::MultiStage,
};
use ragu_core::{
    Result,
    pasta::{Fp, Fq},
};
use ragu_primitives::vec::FixedVec;
use udon::field::Field;

use super::{
    Challenge, Layout, Opening, Phase, Point,
    batch::Challenges,
    circuit,
    stages::{self, Side},
};
use crate::{
    SelectableBackend,
    ipa::IpaCycle,
    profile::{Profile, ProfiledCycle, Standard},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Batched;
impl Profile for Batched {
    const NAME: &'static str = "online-stage-test";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ONLINE: Layout = Layout {
        polynomials: &[Phase::BeforeW],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Input(0),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 1,
            },
            Opening {
                polynomial: 0,
                point: Point::Witness(0),
                value: 2,
            },
        ],
        inputs: 1,
        points: 1,
        values: 3,
    };
    const NESTED_ONLINE: Layout = Self::NATIVE_ONLINE;
    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

fn check<F: Field, S: Side>() -> Result<()> {
    use crate::internal::tests::assert_stage_values;
    assert_stage_values::<F, ProductionRank, _>(&stages::InputStage::<Batched, S>::default());
    assert_stage_values::<F, ProductionRank, _>(&stages::QueryStage::<Batched, S>::default());
    assert_stage_values::<F, ProductionRank, _>(&stages::EvalStage::<Batched, S>::default());
    let inputs = stages::InputWitness {
        source_tag: FixedVec::new(vec![])?,
        values: FixedVec::new(vec![F::from(4)])?,
        foreign: FixedVec::new(vec![F::from(101), F::from(103)])?,
    };
    let query = stages::QueryWitness {
        challenges: FixedVec::new(vec![F::from(5), F::from(7), F::from(11)])?,
        points: FixedVec::new(vec![F::from(6)])?,
        values: FixedVec::new(vec![F::from(9), F::from(11), F::from(13)])?,
    };
    let eval = FixedVec::new(vec![F::from(35)])?;
    let circuit =
        MultiStage::<F, ProductionRank, _>::new(circuit::Circuit::<F, Batched, S>::default());
    let traced = circuit.trace(circuit::Witness {
        inputs: &inputs,
        query: &query,
        eval: &eval,
        challenges: Challenges {
            w: F::from(5),
            y: F::from(7),
            x: F::from(11),
            alpha: F::from(13),
            u: F::from(17),
            beta: F::from(3),
        },
    })?;
    assert_eq!(traced.into_aux(), [F::from(366), F::from(35)]);
    Ok(())
}

#[test]
fn helper_uses_the_independent_stage_chain_on_both_fields() -> Result<()> {
    check::<Fp, stages::Native>()?;
    check::<Fq, stages::Nested>()
}

#[test]
fn online_stages_and_helper_are_registered_in_claim_order() -> Result<()> {
    use ragu_circuits::registry::RegistryBuilder;

    use super::extension::{self, Bonding};
    use crate::{
        internal::{native, nested},
        profile::{BondingSlot, CircuitSlot, Shape},
    };

    fn register<F: Field, S: Side>() -> Result<()> {
        let layout = extension::layout::<Batched, S>();
        assert_eq!(layout.circuits, vec![vec![0, 1, 2]]);
        assert_eq!(layout.final_masks, vec![vec![0]]);
        assert_eq!(layout.stages, 3);
        assert_eq!(extension::helper::<Batched, S>(), Some(0));
        extension::check::<Batched, S>()?;
        let mut registry = extension::register_circuit::<F, ProductionRank, Batched, S>(
            CircuitSlot::new(RegistryBuilder::new()),
            None,
        )?
        .into_registry();
        for j in 0..layout.bondings() {
            let Bonding::Online(mask) = extension::bonding::<F, ProductionRank, Batched, S>(j)?
            else {
                panic!("batch-only profile has no user bonding");
            };
            registry = BondingSlot::new(registry).register(mask).into_registry();
        }
        assert_eq!(registry.num_internal_circuits(), layout.internal());
        assert!(extension::bonding::<F, ProductionRank, Batched, S>(layout.bondings()).is_err());
        Ok(())
    }
    register::<Fp, stages::Native>()?;
    register::<Fq, stages::Nested>()?;
    let shape = Shape::of::<Batched>();
    assert_eq!(shape.native_rx, native::RxIndex::all::<Batched>().len());
    assert_eq!(shape.nested_rx, nested::RxIndex::all::<Batched>().len());
    assert!(shape.native_rx > Shape::of::<Standard>().native_rx);
    Batched::check()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Consumers<const KIND: u8>;
impl<const KIND: u8> Profile for Consumers<KIND> {
    const NAME: &'static str = "online-consumer-layout-test";
    const NATIVE_EXTENSION: usize = 4;
    const NESTED_EXTENSION: usize = 4;
    const NATIVE_ONLINE: Layout = if KIND == 3 {
        Layout::EMPTY
    } else {
        Batched::NATIVE_ONLINE
    };
    const NESTED_ONLINE: Layout = Batched::NESTED_ONLINE;
    const NATIVE_ONLINE_CONSUMERS: &'static [u32] = match KIND {
        1 => &[0, 0],
        2 => &[3],
        _ => &[0, 1],
    };
    const NESTED_ONLINE_CONSUMERS: &'static [u32] = &[1];
    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
    fn native_extension() -> crate::profile::Extension {
        use crate::profile::{Binding, Extension};
        Extension {
            circuits: vec![vec![], vec![0], vec![]],
            stages: 1,
            final_masks: vec![vec![1]],
            statement: Some(0),
            binding: Some(Binding {
                circuit: 2,
                stages: vec![0],
            }),
        }
    }
    fn nested_extension() -> crate::profile::Extension {
        let mut extension = Self::native_extension();
        extension.statement = None;
        extension
    }
}

#[test]
fn consumer_prefixes_preserve_user_indices_and_cross_field_bindings() -> Result<()> {
    use super::extension::{self, Bonding};
    type P = Consumers<0>;
    extension::check::<P, stages::Native>()?;
    extension::check::<P, stages::Nested>()?;
    let native = extension::layout::<P, stages::Native>();
    assert_eq!(
        native.circuits,
        vec![vec![0, 1], vec![0, 1, 3], vec![], vec![0, 1, 2]]
    );
    assert_eq!(native.final_masks, vec![vec![1], vec![3], vec![0]]);
    assert_eq!(native.binding.unwrap().stages, vec![3]);
    assert_eq!(native.statement, Some(0));
    for (merged, user) in [(3, 0), (4, 1)] {
        assert!(
            matches!(extension::bonding::<Fp, ProductionRank, P, stages::Native>(merged)?, Bonding::User(j) if j == user)
        );
    }
    assert_eq!(
        extension::layout::<Standard, stages::Native>(),
        crate::profile::Extension::EMPTY
    );
    assert_eq!(extension::helper::<Standard, stages::Native>(), None);
    assert!(extension::check::<Consumers<1>, stages::Native>().is_err());
    assert!(extension::check::<Consumers<2>, stages::Native>().is_err());
    assert!(extension::check::<Consumers<3>, stages::Native>().is_err());
    Ok(())
}

#[cfg(feature = "baked")]
#[test]
fn preparation_commits_each_phase_once_and_rejects_zero_polynomials() -> Result<()> {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::sparse,
        registry::{CircuitIndex, RegistryBuilder},
    };
    use ragu_core::{Cycle, pasta::Pasta};

    use super::{prepared::PreparationChallenges, prover::State};

    type C = <Pasta as Cycle>::HostCurve;
    type R = ProductionRank;
    type S = stages::Native;
    let generators = Pasta::host_generators(crate::pasta::baked());
    let mut rng = rand::rng();
    let mut state = State::<C, R, Batched, S>::new(vec![Fp::from(4)])?;
    assert!(
        state
            .commit_eval::<ReferenceBackend, _, _>(Fp::from(17), generators, &mut rng)
            .is_err()
    );
    // The zero polynomial commits to the identity, which the walk cannot
    // take; the rejected call leaves the phase open.
    assert!(
        state
            .supply::<ReferenceBackend, _>(
                Phase::BeforeW,
                vec![sparse::Polynomial::new()],
                generators,
            )
            .is_err()
    );
    // 1 + 2X, which `check` opens at 4, w = 5 and 6, and evaluates at u = 17.
    let poly = sparse::Polynomial::from_coeffs(vec![Fp::ONE, Fp::from(2)]);
    state.supply::<ReferenceBackend, _>(Phase::BeforeW, vec![poly.clone()], generators)?;
    assert_eq!(
        state.commitments(),
        &[ReferenceBackend::sparse_commit_to_affine(&poly, generators)]
    );
    assert!(
        state
            .supply::<ReferenceBackend, _>(Phase::BeforeY, vec![], generators)
            .is_err()
    );
    assert!(
        state
            .commit_inputs::<ReferenceBackend, _, _>(vec![], generators, &mut rng)
            .is_err()
    );
    state.commit_inputs::<ReferenceBackend, _, _>(vec![Fp::ZERO; 2], generators, &mut rng)?;
    assert!(
        state
            .commit_inputs::<ReferenceBackend, _, _>(vec![Fp::ZERO; 2], generators, &mut rng)
            .is_err()
    );
    let inputs_commitment = state.stage_commitment(0);
    for phase in [Phase::BeforeY, Phase::BeforeX, Phase::BeforeAlpha] {
        state.supply::<ReferenceBackend, _>(phase, vec![], generators)?;
    }
    assert!(
        state
            .supply::<ReferenceBackend, _>(Phase::BeforeAlpha, vec![], generators)
            .is_err()
    );
    assert!(
        state
            .commit_query::<ReferenceBackend, _, _>(
                vec![Fp::from(6)],
                PreparationChallenges::default(),
                generators,
                &mut rng
            )
            .is_err()
    );
    let available = PreparationChallenges {
        w: Some(Fp::from(5)),
        y: Some(Fp::from(7)),
        x: Some(Fp::from(11)),
    };
    state.commit_query::<ReferenceBackend, _, _>(
        vec![Fp::from(6)],
        available,
        generators,
        &mut rng,
    )?;
    assert_eq!(
        &*state.query().values,
        &[Fp::from(9), Fp::from(11), Fp::from(13)]
    );
    assert_eq!(state.stage_commitment(0), inputs_commitment);
    state.commit_eval::<ReferenceBackend, _, _>(Fp::from(17), generators, &mut rng)?;
    let eval_commitment = state.stage_commitment(2);
    assert!(
        state
            .commit_eval::<ReferenceBackend, _, _>(Fp::from(19), generators, &mut rng)
            .is_err()
    );
    assert_eq!(state.stage_commitment(2), eval_commitment);
    let registry = RegistryBuilder::<Fp, R>::new()
        .register_internal_circuit(MultiStage::<Fp, R, _>::new(circuit::Circuit::<
            Fp,
            Batched,
            S,
        >::default()))?
        .finalize()?;
    let challenges = Challenges {
        w: Fp::from(5),
        y: Fp::from(7),
        x: Fp::from(11),
        alpha: Fp::from(13),
        u: Fp::from(17),
        beta: Fp::from(3),
    };
    let sums = state.trace(challenges, &registry, |_| CircuitIndex::new(0), &mut rng)?;
    assert_eq!(&*sums, &[Fp::from(366), Fp::from(35)]);
    assert_eq!(state.fold()?, &*sums);
    assert_eq!(state.polynomials().len(), 1);
    let commitments = core::array::from_fn::<_, 3, _>(|i| state.stage_commitment(i));
    let rxs = state.extension_rxs(crate::profile::ExtensionRxs::default())?;
    assert_eq!(rxs.circuits.len(), 1);
    for (stage, commitment) in rxs.stages.iter().zip(commitments) {
        assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(stage, generators),
            commitment
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NestedOnly;
impl Profile for NestedOnly {
    const NAME: &'static str = "nested-online-targets";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NESTED_ONLINE: Layout = Batched::NESTED_ONLINE;
    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

#[cfg(feature = "baked")]
#[test]
fn an_identity_online_eval_stage_is_resampled() -> Result<()> {
    use core::convert::Infallible;

    use ragu_backend::ReferenceBackend;
    use ragu_circuits::polynomials::sparse;
    use ragu_core::{Cycle, pasta::Pasta};
    use rand::{TryCryptoRng, TryRng};
    use udon::curve::Affine;

    use super::{prepared::PreparationChallenges, prover::State};

    #[derive(Default)]
    struct StageBlindings(u8);

    impl TryRng for StageBlindings {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
            unreachable!("stage blinders are sampled with fill_bytes")
        }

        fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
            unreachable!("stage blinders are sampled with fill_bytes")
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Infallible> {
            dest.fill(0);
            dest[0] = self.0;
            self.0 += 1;
            Ok(())
        }
    }

    impl TryCryptoRng for StageBlindings {}

    type C = <Pasta as Cycle>::NestedCurve;
    let generators = Pasta::nested_generators(crate::pasta::baked());
    let mut state = State::<C, ProductionRank, NestedOnly, stages::Nested>::new(vec![Fq::ONE])?;
    // P(X) = X gives a zero evaluation at u = 0.
    state.supply::<ReferenceBackend, _>(
        Phase::BeforeW,
        vec![sparse::Polynomial::from_coeffs(vec![Fq::ZERO, Fq::ONE])],
        generators,
    )?;
    let mut rng = rand::rng();
    state.commit_inputs::<ReferenceBackend, _, _>(vec![], generators, &mut rng)?;
    for phase in [Phase::BeforeY, Phase::BeforeX, Phase::BeforeAlpha] {
        state.supply::<ReferenceBackend, _>(phase, vec![], generators)?;
    }
    state.commit_query::<ReferenceBackend, _, _>(
        vec![Fq::from(6)],
        PreparationChallenges {
            w: Some(Fq::from(5)),
            y: Some(Fq::from(7)),
            x: Some(Fq::from(11)),
        },
        generators,
        &mut rng,
    )?;
    let mut blindings = StageBlindings::default();
    state.commit_eval::<ReferenceBackend, _, _>(Fq::ZERO, generators, &mut blindings)?;
    assert_eq!(blindings.0, 2);
    assert!(!state.stage_commitment(2).is_identity());
    Ok(())
}

#[test]
fn nested_online_targets_bind_the_actual_helper_output_and_claim_order() -> Result<()> {
    use ragu_circuits::{horner::Horner, staging::MultiStageCircuit};
    use ragu_core::{Cycle, drivers::emulator::Emulator, maybe::Maybe, pasta::Pasta};
    use ragu_primitives::{Element, GadgetExt, vec::Len};
    use udon::curve::Affine;

    use crate::internal::{ky, nested};

    type C = <Pasta as Cycle>::HostCurve;
    type S = stages::Nested;
    let unified = nested::unified::Instance::<C> {
        c: Fq::from(2),
        v: Fq::from(3),
        x: Fq::from(5),
        y: Fq::from(7),
        u: Fq::from(11),
        exported: [C::generator(); nested::unified::NUM_EXPORTED],
        coverage: Default::default(),
    };
    let online_values = [13, 17, 19, 23, 29].map(Fq::from);
    let helper = circuit::Instance::<_, NestedOnly, S> {
        mesh: FixedVec::new(vec![])?,
        challenges: Challenges {
            w: online_values[0],
            y: unified.y,
            x: unified.x,
            alpha: online_values[1],
            u: unified.u,
            beta: online_values[2],
        },
        sums: [online_values[3], online_values[4]],
        foreign: FixedVec::from_fn(|_| unreachable!()),
    };
    Emulator::emulate_wireless((unified, helper, online_values), |dr, witness| {
        let (unified, helper, online_values) = witness.cast();
        let y = Element::constant(dr, Fq::from(31));
        let unified = nested::unified::Output::<_, C>::alloc(dr, &mut (), unified.as_ref())?;
        let online_values = FixedVec::<_, stages::Present<NestedOnly, S, 5>>::try_from_fn(|i| {
            Element::alloc(dr, &mut (), online_values.as_ref().map(|p| p[i]))
        })?;
        let unified_ky = unified.ky(dr, &y)?;
        let (compute_target, helper_target) = ky::nested_online_ky::<_, _, NestedOnly>(
            dr,
            &y,
            &unified,
            &unified_ky,
            &online_values,
            &[],
            &[],
            &[],
        )?;
        let output = nested::circuits::compute_v::Output::<_, C, NestedOnly> {
            inherited_coordinates: FixedVec::new(vec![])?,
            unified: unified.clone(),
            online_values: online_values.clone(),
            online_stages: FixedVec::from_fn(|_| unreachable!()),
            online_points: FixedVec::from_fn(|_| unreachable!()),
        };
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(
            compute_target.value().take(),
            actual.finish_ky(dr)?.value().take()
        );
        let output = <circuit::Circuit<Fq, NestedOnly, S> as MultiStageCircuit<
            Fq,
            ProductionRank,
        >>::instance(&circuit::Circuit::default(), dr, helper.as_ref())?;
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(
            helper_target.as_ref().unwrap().value().take(),
            ky::finish_extension_ky(actual, dr)?.value().take()
        );
        // Every public challenge and sum is held by both claims. Changing a
        // helper value independently cannot retain either claim's target.
        for i in 0..online_values.len() {
            let mut corrupt = online_values.clone();
            corrupt[i] = corrupt[i].add(dr, &Element::one());
            let (compute, helper) = ky::nested_online_ky::<_, _, NestedOnly>(
                dr,
                &y,
                &unified,
                &unified_ky,
                &corrupt,
                &[],
                &[],
                &[],
            )?;
            assert_ne!(compute.value().take(), compute_target.value().take());
            assert_ne!(
                helper.unwrap().value().take(),
                helper_target.as_ref().unwrap().value().take()
            );
        }
        Ok(())
    })?;
    let targets = ky::NestedKy {
        c: Fq::from(2),
        unified: Fq::from(3),
        compute_v: Fq::from(5),
        online_helper: Some(Fq::from(7)),
        binding: None,
    };
    let prefix: alloc::vec::Vec<_> = nested::claims::ky_prefix::<NestedOnly, _>(&targets).collect();
    let collapse = 1 + nested::NumSteps::<NestedOnly>::len();
    assert_eq!(
        &prefix[collapse..],
        &[Fq::from(3), Fq::from(5), Fq::from(7)]
    );
    Ok(())
}

#[test]
fn online_stage_bindings_are_in_the_native_claims() -> Result<()> {
    use alloc::vec::Vec;

    use ragu_circuits::registry::CircuitIndex;
    use ragu_core::{Cycle, pasta::Pasta};

    use crate::{
        internal::{claims::Source, native, tests::assert_stage_values},
        profile::Profiled,
    };
    type C = Profiled<Pasta, NestedOnly>;
    type R = ProductionRank;
    assert_stage_values::<Fp, R, _>(&native::stages::points::BindingStage::<
        <C as Cycle>::NestedCurve,
        NestedOnly,
    >::default());
    assert_stage_values::<Fp, R, _>(&native::stages::query::Stage::<C, R, 2>::default());
    assert_stage_values::<Fp, R, _>(&native::stages::eval::Stage::<C, R, 2>::default());

    struct Components;
    impl Source for Components {
        type RxComponent = native::RxComponent;
        type Rx = native::RxComponent;
        type AppCircuitId = CircuitIndex;
        fn rx(&self, component: Self::Rx) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(component)
        }
        fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [Self::Rx; 2])> {
            core::iter::once((
                CircuitIndex::new(0),
                [
                    native::RxComponent::Rx(native::RxIndex::Application),
                    native::RxComponent::Rx(native::RxIndex::ApplicationStage),
                ],
            ))
        }
    }
    #[derive(Default)]
    struct Recorder(Vec<(native::InternalCircuitIndex, Vec<native::RxComponent>)>);
    impl<P: Profile> native::claims::Processor<P, native::RxComponent, CircuitIndex> for Recorder {
        fn raw_claim(&mut self, _: native::RxComponent, _: native::RxComponent) {}
        fn circuit_claim(&mut self, _: CircuitIndex, _: impl Iterator<Item = native::RxComponent>) {
        }
        fn internal_circuit_claim(
            &mut self,
            id: native::InternalCircuitIndex,
            rxs: impl Iterator<Item = native::RxComponent>,
        ) {
            self.0.push((id, rxs.collect()));
        }
        fn grouped_bonding_claim(
            &mut self,
            _: native::InternalCircuitIndex,
            _: impl Iterator<Item = impl Iterator<Item = native::RxComponent>>,
        ) -> Result<()> {
            Ok(())
        }
    }
    for active in [false, true] {
        let mut claims = Recorder::default();
        if active {
            native::claims::build::<NestedOnly, _, _>(&Components, &mut claims)?;
        } else {
            native::claims::build::<Standard, _, _>(&Components, &mut claims)?;
        }
        for id in [
            native::InternalCircuitIndex::ComputeVCircuit,
            native::InternalCircuitIndex::CollapseCircuit,
        ] {
            let components = &claims
                .0
                .iter()
                .find(|(circuit, _)| *circuit == id)
                .unwrap()
                .1;
            assert_eq!(
                components.contains(&native::RxComponent::Rx(native::RxIndex::PointsBinding)),
                active
            );
        }
    }
    use crate::internal::{ky, nested::RxIndex};
    assert_eq!(
        ky::nested_online_stages::<NestedOnly, _>(|index| index),
        [
            RxIndex::ExtensionStage(0),
            RxIndex::ExtensionStage(1),
            RxIndex::ExtensionStage(2)
        ]
    );
    assert!(ky::nested_online_stages::<Standard, _>(|index| index).is_empty());
    Ok(())
}

#[test]
fn native_online_targets_share_sums_and_actual_foreign_points() -> Result<()> {
    use ragu_circuits::{horner::Horner, staging::MultiStageCircuit};
    use ragu_core::{
        drivers::emulator::Emulator,
        maybe::Maybe,
        pasta::{EpAffine, Pasta},
    };
    use ragu_primitives::{Element, GadgetExt, Point as CurvePoint};
    use udon::curve::Affine;

    use crate::{
        internal::{ky, native},
        profile::Profiled,
    };
    type C = Profiled<Pasta, Batched>;
    type S = stages::Native;
    let unified = native::unified::Instance::<C> {
        bridge_preamble_commitment: EpAffine::generator(),
        bridge_hash_commitment: EpAffine::generator(),
        w: Fp::from(4),
        bridge_s_prime_commitment: EpAffine::generator(),
        y: Fp::from(6),
        z: Fp::from(7),
        bridge_inner_error_commitment: EpAffine::generator(),
        mu: Fp::from(9),
        bridge_outer_error_commitment: EpAffine::generator(),
        mu_prime: Fp::from(11),
        c: Fp::from(12),
        bridge_ab_commitment: EpAffine::generator(),
        x: Fp::from(14),
        bridge_query_commitment: EpAffine::generator(),
        alpha: Fp::from(16),
        bridge_f_commitment: EpAffine::generator(),
        u: Fp::from(18),
        bridge_eval_commitment: EpAffine::generator(),
        pre_beta: Fp::from(20),
        v: Fp::from(21),
        nested_challenges_partial: EpAffine::generator(),
        nested_p_commitment: EpAffine::generator(),
        nested_a_commitment: EpAffine::generator(),
        nested_b_commitment: EpAffine::generator(),
        nested_registry_xy_commitment: EpAffine::generator(),
        coverage: Default::default(),
    };
    let sums = [Fp::from(101), Fp::from(103)];
    let (px, py) = EpAffine::generator().coordinates().unwrap();
    let helper = circuit::Instance::<_, Batched, S> {
        mesh: FixedVec::new(vec![])?,
        challenges: Challenges {
            w: unified.w,
            y: unified.y,
            x: unified.x,
            alpha: unified.alpha,
            u: unified.u,
            beta: unified.pre_beta,
        },
        sums,
        foreign: FixedVec::new(vec![px, py])?,
    };
    let online = [native::online::Query {
        x: Fp::from(5),
        y: Fp::from(7),
    }; native::online::NUM_ONLINE_FP_QUERIES];
    Emulator::emulate_wireless(
        (
            unified,
            helper,
            online,
            [Fp::ZERO; 2],
            [EpAffine::generator()],
            sums,
            [EpAffine::generator(); 3],
        ),
        |dr, witness| {
            let (unified, helper, online, header, points, sums, stages) = witness.cast();
            let y = Element::constant(dr, Fp::from(107));
            let mut inputs = native::stages::preamble::ProofInputs::<_, C, 2>::alloc_from_parts(
                dr,
                header.as_ref().map(|h| h.as_slice()),
                header.as_ref().map(|h| h.as_slice()),
                header.as_ref().map(|h| h.as_slice()),
                online.as_ref(),
                header.as_ref().map(|_| Fp::ONE),
                unified.as_ref(),
                points.as_ref().map(|p| p.as_slice()),
                sums.as_ref().map(|s| s.as_slice()),
                sums.as_ref().map(|s| &s[..0]),
            )?;
            let stages =
                FixedVec::<_, stages::Present<Batched, stages::Nested, 3>>::try_from_fn(|i| {
                    CurvePoint::alloc(dr, stages.as_ref().map(|p| p[i]))
                })?;
            let mut stage_coordinates = alloc::vec::Vec::new();
            for point in stages.iter() {
                point.write(dr, &mut stage_coordinates)?;
            }
            let compute_target = inputs.compute_v_bridge_ky(dr, &y, &stages)?;
            let helper_target = inputs.online_helper_ky(dr, &y)?.unwrap();
            let (unified_ky, _) = inputs.unified_ky_values(dr, &y)?;
            let points_target = inputs.bind_endoscalar_ky(dr, &y, &unified_ky)?;
            let output = native::circuits::compute_v::Output::<_, C> {
                inherited_coordinates: FixedVec::new(vec![])?,
                inherited_points: FixedVec::new(vec![])?,
                online_auxiliaries: FixedVec::from_fn(|_| unreachable!("no later auxiliary phase")),
                unified: inputs.unified.clone(),
                online: inputs.online.clone(),
                online_fold: inputs.online_fold.clone(),
                online_stages: FixedVec::from_fn(|i| stage_coordinates[i].clone()),
            };
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                compute_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            let output = <circuit::Circuit<Fp, Batched, S> as MultiStageCircuit<
                Fp,
                ProductionRank,
            >>::instance(
                &circuit::Circuit::default(), dr, helper.as_ref()
            )?;
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                helper_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            let output = native::circuits::bind_endoscalar::Output::<_, C> {
                unified: inputs.unified.clone(),
                online_points: inputs.online_points.clone(),
            };
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                points_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            for i in 0..2 {
                let original = inputs.online_fold[i].clone();
                inputs.online_fold[i] = original.add(dr, &Element::one());
                assert_ne!(
                    compute_target.value().take(),
                    inputs.compute_v_bridge_ky(dr, &y, &stages)?.value().take()
                );
                assert_ne!(
                    helper_target.value().take(),
                    inputs.online_helper_ky(dr, &y)?.unwrap().value().take()
                );
                inputs.online_fold[i] = original;
            }
            inputs.online_points[0] = CurvePoint::alloc(dr, points.as_ref().map(|p| -p[0]))?;
            assert_ne!(
                helper_target.value().take(),
                inputs.online_helper_ky(dr, &y)?.unwrap().value().take()
            );
            assert_ne!(
                points_target.value().take(),
                inputs
                    .bind_endoscalar_ky(dr, &y, &unified_ky)?
                    .value()
                    .take()
            );
            Ok(())
        },
    )?;
    let targets = ky::NativeKy {
        c: Some(Fp::from(2)),
        application: Fp::from(3),
        unified: Fp::from(5),
        unified_bridge: Fp::from(7),
        compute_v_bridge: Fp::from(11),
        bind_endoscalar: Fp::from(13),
        online_helper: Some(Fp::from(17)),
        statement: None,
        binding: None,
    };
    let prefix: alloc::vec::Vec<_> = native::claims::ky_prefix::<Batched, _>(&targets).collect();
    assert_eq!(prefix.last(), Some(&Fp::from(17)));
    assert_eq!(prefix.iter().filter(|&&v| v == Fp::from(13)).count(), 1);
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeOnly;
impl Profile for NativeOnly {
    const NAME: &'static str = "native-online-targets";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ONLINE: Layout = Batched::NATIVE_ONLINE;
    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

#[test]
fn native_online_stage_targets_use_actual_extension_commitments() -> Result<()> {
    use ragu_circuits::horner::Horner;
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe, pasta::EqAffine};
    use ragu_primitives::{Element, GadgetExt, Point as CurvePoint};
    use udon::curve::Affine;

    use crate::internal::{ky, native, nested, tests::assert_stage_values};
    type P = NativeOnly;
    type C = EqAffine;
    assert_stage_values::<Fq, ProductionRank, _>(&nested::stages::preamble::Stage::<
        C,
        ProductionRank,
        P,
    >::default());
    assert_stage_values::<Fq, ProductionRank, _>(&nested::stages::query::Stage::<
        C,
        ProductionRank,
        P,
    >::default());
    assert_stage_values::<Fq, ProductionRank, _>(&nested::stages::eval::Stage::<
        C,
        ProductionRank,
        P,
    >::default());
    assert_eq!(
        ky::native_online_stages::<P, _>(|index| index),
        (0..3)
            .map(native::RxIndex::ExtensionStage)
            .collect::<alloc::vec::Vec<_>>()
    );
    assert!(ky::native_online_stages::<NestedOnly, _>(|index| index).is_empty());
    let unified = nested::unified::Instance::<C> {
        c: Fq::from(2),
        v: Fq::from(3),
        x: Fq::from(5),
        y: Fq::from(7),
        u: Fq::from(11),
        exported: [C::generator(); nested::unified::NUM_EXPORTED],
        coverage: Default::default(),
    };
    Emulator::emulate_wireless((unified, [C::generator(); 3]), |dr, witness| {
        let (unified, points) = witness.cast();
        let y = Element::constant(dr, Fq::from(31));
        let unified = nested::unified::Output::<_, C>::alloc(dr, &mut (), unified.as_ref())?;
        let stages = FixedVec::<_, stages::Present<P, stages::Native, 3>>::try_from_fn(|i| {
            CurvePoint::alloc(dr, points.as_ref().map(|p| p[i]))
        })?;
        let online_points =
            FixedVec::<_, stages::PolynomialsLen<P, stages::Native>>::try_from_fn(|_| {
                CurvePoint::alloc(dr, points.as_ref().map(|p| p[0]))
            })?;
        let base = unified.ky(dr, &y)?;
        let (target, helper) = ky::nested_online_ky::<_, _, P>(
            dr,
            &y,
            &unified,
            &base,
            &[],
            &stages,
            &online_points,
            &[],
        )?;
        assert!(helper.is_none());
        let output = nested::circuits::compute_v::Output::<_, C, P> {
            inherited_coordinates: FixedVec::new(vec![])?,
            unified: unified.clone(),
            online_values: FixedVec::from_fn(|_| unreachable!()),
            online_stages: stages.clone(),
            online_points: online_points.clone(),
        };
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(target.value().take(), actual.finish_ky(dr)?.value().take());
        for i in 0..3 {
            let mut corrupt = stages.clone();
            corrupt[i] = CurvePoint::alloc(dr, points.as_ref().map(|p| -p[i]))?;
            let (changed, helper) = ky::nested_online_ky::<_, _, P>(
                dr,
                &y,
                &unified,
                &base,
                &[],
                &corrupt,
                &online_points,
                &[],
            )?;
            assert!(helper.is_none());
            assert_ne!(target.value().take(), changed.value().take());
        }
        Ok(())
    })
}

#[test]
fn nested_online_targets_share_the_actual_foreign_commitments() -> Result<()> {
    use ragu_circuits::{horner::Horner, staging::MultiStageCircuit};
    use ragu_core::{drivers::emulator::Emulator, maybe::Maybe, pasta::EqAffine};
    use ragu_primitives::{Element, GadgetExt, Point as CurvePoint};
    use udon::curve::Affine;

    use crate::internal::{ky, nested};
    type C = EqAffine;
    type P = Batched;
    type S = stages::Nested;
    let unified = nested::unified::Instance::<C> {
        c: Fq::from(2),
        v: Fq::from(3),
        x: Fq::from(5),
        y: Fq::from(7),
        u: Fq::from(11),
        exported: [C::generator(); nested::unified::NUM_EXPORTED],
        coverage: Default::default(),
    };
    let online_values = [13, 17, 19, 23, 29].map(Fq::from);
    let (gx, gy) = C::generator()
        .coordinates()
        .expect("the generator is finite");
    let helper = circuit::Instance::<_, P, S> {
        mesh: FixedVec::new(vec![])?,
        challenges: Challenges {
            w: online_values[0],
            y: unified.y,
            x: unified.x,
            alpha: online_values[1],
            u: unified.u,
            beta: online_values[2],
        },
        sums: [online_values[3], online_values[4]],
        foreign: FixedVec::new(vec![gx, gy])?,
    };
    Emulator::emulate_wireless(
        (
            unified,
            helper,
            online_values,
            C::generator(),
            -C::generator(),
        ),
        |dr, witness| {
            let (unified, helper, online_values, generator, negated) = witness.cast();
            let y = Element::constant(dr, Fq::from(31));
            let unified = nested::unified::Output::<_, C>::alloc(dr, &mut (), unified.as_ref())?;
            let online_values = FixedVec::<_, stages::Present<P, S, 5>>::try_from_fn(|i| {
                Element::alloc(dr, &mut (), online_values.as_ref().map(|p| p[i]))
            })?;
            let points =
                FixedVec::<_, stages::PolynomialsLen<P, stages::Native>>::try_from_fn(|_| {
                    CurvePoint::alloc(dr, generator.clone())
                })?;
            let online_stages =
                FixedVec::<_, stages::Present<P, stages::Native, 3>>::try_from_fn(|_| {
                    CurvePoint::alloc(dr, generator.clone())
                })?;
            let base = unified.ky(dr, &y)?;
            let (target, helper_target) = ky::nested_online_ky::<_, _, P>(
                dr,
                &y,
                &unified,
                &base,
                &online_values,
                &online_stages,
                &points,
                &[],
            )?;
            let output = nested::circuits::compute_v::Output::<_, C, P> {
                inherited_coordinates: FixedVec::new(vec![])?,
                unified: unified.clone(),
                online_values: online_values.clone(),
                online_stages: online_stages.clone(),
                online_points: points.clone(),
            };
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(target.value().take(), actual.finish_ky(dr)?.value().take());
            let helper_output = <circuit::Circuit<Fq, P, S> as MultiStageCircuit<
                Fq,
                ProductionRank,
            >>::instance(
                &circuit::Circuit::default(), dr, helper.as_ref()
            )?;
            let mut actual = Horner::new(&y);
            GadgetExt::write(&helper_output, dr, &mut actual)?;
            assert_eq!(
                helper_target.as_ref().unwrap().value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            let changed = [CurvePoint::alloc(dr, negated)?];
            let (corrupt, corrupt_helper) = ky::nested_online_ky::<_, _, P>(
                dr,
                &y,
                &unified,
                &base,
                &online_values,
                &online_stages,
                &changed,
                &[],
            )?;
            assert_ne!(target.value().take(), corrupt.value().take());
            assert_ne!(
                helper_target.unwrap().value().take(),
                corrupt_helper.unwrap().value().take()
            );
            Ok(())
        },
    )
}

#[test]
fn point_consumers_use_the_authenticated_foreign_wires() -> Result<()> {
    use ragu_core::{
        maybe::Maybe,
        pasta::{EpAffine, EqAffine},
    };
    use ragu_primitives::{Element, GadgetExt, Simulator};
    use udon::curve::EndomorphismAffine;
    fn read<C: EndomorphismAffine, S: stages::Side>(coordinates: (C::Base, C::Base)) -> Result<C> {
        let mut read = None;
        Simulator::<C::Base>::simulate(coordinates, |dr, witness| {
            let x = Element::alloc(dr, &mut (), witness.as_ref().map(|p| p.0))?;
            let y = Element::alloc(dr, &mut (), witness.as_ref().map(|p| p.1))?;
            let inputs = stages::InputOutput::<_, Batched, S> {
                source_tag: FixedVec::new(vec![])?,
                values: FixedVec::from_fn(|_| Element::one()),
                foreign: FixedVec::new(vec![x.clone(), y.clone()])?,
            };
            let point = inputs.foreign_point::<C>(dr, 0)?;
            let mut wires = alloc::vec::Vec::new();
            point.write(dr, &mut wires)?;
            assert_eq!(wires[0].value().take(), x.value().take());
            assert_eq!(wires[1].value().take(), y.value().take());
            read = Some(point.value().take());
            Ok(())
        })?;
        Ok(read.expect("the simulation read the point"))
    }
    fn check<C: EndomorphismAffine, S: stages::Side>() -> Result<()> {
        let generator = C::generator();
        assert_eq!(
            read::<C, S>(generator.coordinates().expect("finite"))?,
            generator
        );
        // The identity has no affine coordinates, and (0, 0) is off the curve.
        assert!(read::<C, S>((C::Base::ZERO, C::Base::ZERO)).is_err());
        Ok(())
    }
    check::<EpAffine, stages::Native>()?;
    check::<EqAffine, stages::Nested>()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SourceMesh;
impl Profile for SourceMesh {
    const NAME: &'static str = "source-mesh-setup-test";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeX,
            Phase::BeforeAlpha,
        ],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 2,
                point: Point::Input(1),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Challenge(Challenge::W),
                value: 1,
            },
            Opening {
                polynomial: 3,
                point: Point::Input(3),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Challenge(Challenge::Y),
                value: 2,
            },
            Opening {
                polynomial: 4,
                point: Point::Input(0),
                value: 2,
            },
            Opening {
                polynomial: 3,
                point: Point::Challenge(Challenge::Y),
                value: 3,
            },
            Opening {
                polynomial: 4,
                point: Point::Input(2),
                value: 3,
            },
            Opening {
                polynomial: 4,
                point: Point::Challenge(Challenge::X),
                value: 4,
            },
            Opening {
                polynomial: 5,
                point: Point::Challenge(Challenge::W),
                value: 4,
            },
        ],
        inputs: 4,
        points: 0,
        values: 5,
    };
    const NESTED_ONLINE: Layout = Self::NATIVE_ONLINE;
    const NATIVE_MESH: Option<super::mesh::Mesh> = Some(super::mesh::Mesh {
        inherited: [
            super::mesh::Restriction {
                polynomial: 0,
                x: 0,
                y: 1,
                helper: 2,
            },
            super::mesh::Restriction {
                polynomial: 1,
                x: 2,
                y: 3,
                helper: 3,
            },
        ],
        introduced: &[],
        helpers: &[
            super::mesh::Helper {
                polynomial: 2,
                x: 0,
            },
            super::mesh::Helper {
                polynomial: 3,
                x: 2,
            },
        ],
        u: 4,
        outgoing: 5,
    });
    const NESTED_MESH: Option<super::mesh::Mesh> = Self::NATIVE_MESH;
    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

#[test]
fn source_tag_is_a_constraint_fixed_by_the_helper_setup() -> Result<()> {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        registry::{CircuitIndex, RegistryBuilder},
        staging::StageExt,
    };

    fn check<F: Field, S: Side>() -> Result<()> {
        S::mesh::<SourceMesh>()
            .unwrap()
            .check(S::layout::<SourceMesh>())?;
        crate::internal::tests::assert_stage_values::<F, ProductionRank, _>(&stages::InputStage::<
            SourceMesh,
            S,
        >::default());
        assert!(circuit::Circuit::<F, SourceMesh, S>::with_source_tag(None).is_err());
        assert!(circuit::Circuit::<F, Batched, S>::with_source_tag(Some(F::from(23))).is_err());
        let query = stages::QueryWitness::<F, SourceMesh, S> {
            challenges: FixedVec::new(vec![F::from(5), F::from(7), F::from(11)])?,
            points: FixedVec::new(vec![])?,
            values: FixedVec::new(vec![F::ZERO; 5])?,
        };
        let eval = FixedVec::new(vec![F::ZERO; 6])?;
        for tag in [23, 29] {
            let inputs = stages::InputWitness::<F, SourceMesh, S> {
                source_tag: FixedVec::new(vec![F::from(tag)])?,
                values: FixedVec::new(vec![F::from(2), F::from(3), F::from(13), F::from(19)])?,
                foreign: FixedVec::new(vec![F::ZERO; 4])?,
            };
            let helper =
                MultiStage::<F, ProductionRank, _>::new(
                    circuit::Circuit::<F, SourceMesh, S>::with_source_tag(Some(F::from(23)))?,
                );
            let witness = circuit::Witness {
                inputs: &inputs,
                query: &query,
                eval: &eval,
                challenges: Challenges {
                    w: F::from(5),
                    y: F::from(7),
                    x: F::from(11),
                    alpha: F::from(13),
                    u: F::from(17),
                    beta: F::from(3),
                },
            };
            // A staged trace must be checked with its committed stage
            // polynomials: Simulator's reserved stage wires contain zeroes.
            let (trace, sums) = helper.trace(witness)?.into_parts();
            let registry = RegistryBuilder::<F, ProductionRank>::new()
                .with_tag(F::ZERO)
                .register_internal_circuit(MultiStage::<F, ProductionRank, _>::new(
                    circuit::Circuit::<F, SourceMesh, S>::with_source_tag(Some(F::from(23)))?,
                ))?
                .finalize()?;
            let index = CircuitIndex::new(0);
            let mut assignment = registry.assemble_with_alpha(&trace, index, F::ZERO)?;
            assignment.add_assign(&<stages::InputStage<SourceMesh, S> as StageExt<
                F,
                ProductionRank,
            >>::rx(F::ZERO, &inputs)?);
            assignment.add_assign(&<stages::QueryStage<SourceMesh, S> as StageExt<
                F,
                ProductionRank,
            >>::rx(F::ZERO, &query)?);
            assignment.add_assign(&<stages::EvalStage<SourceMesh, S> as StageExt<
                F,
                ProductionRank,
            >>::rx(F::ZERO, &eval)?);
            let instance = circuit::Instance {
                mesh: S::mesh::<SourceMesh>()
                    .unwrap()
                    .claim_values(S::layout::<SourceMesh>(), &inputs.values, &query.values)?
                    .try_into()?,
                challenges: Challenges {
                    w: F::from(5),
                    y: F::from(7),
                    x: F::from(11),
                    alpha: F::from(13),
                    u: F::from(17),
                    beta: F::from(3),
                },
                sums,
                foreign: inputs.foreign.clone(),
            };
            for (y, z) in [(F::from(31), F::from(37)), (F::from(41), F::from(43))] {
                let mut rhs = assignment.clone();
                rhs.dilate(z);
                rhs.add_assign(&registry.circuit_y(index, y));
                rhs.add_assign(&ProductionRank::tz(z));
                assert_eq!(
                    assignment.revdot(&rhs) == helper.ky(&instance, y)?,
                    tag == 23,
                    "source tag {tag}"
                );
                if tag == 23 {
                    for i in 0..instance.mesh.len() {
                        let mut altered = instance.clone();
                        altered.mesh[i] += F::ONE;
                        assert_ne!(
                            assignment.revdot(&rhs),
                            helper.ky(&altered, y)?,
                            "unbound mesh metadata {i}"
                        );
                    }
                }
            }
        }
        let registry = |tag| {
            RegistryBuilder::<F, ProductionRank>::new()
                .with_tag(F::from(101))
                .register_internal_circuit(MultiStage::<F, ProductionRank, _>::new(
                    circuit::Circuit::<F, SourceMesh, S>::with_source_tag(Some(F::from(tag)))?,
                ))?
                .finalize()
        };
        assert_ne!(
            ReferenceBackend::registry_wxy(&registry(23)?, F::from(2), F::from(3), F::from(5)),
            ReferenceBackend::registry_wxy(&registry(29)?, F::from(2), F::from(3), F::from(5)),
        );
        Ok(())
    }
    check::<Fp, stages::Native>()?;
    check::<Fq, stages::Nested>()
}

#[test]
fn backend_selection_preserves_source_setup_and_undeclared_sources_reject() -> Result<()> {
    use ragu_backend::ReferenceBackend;
    use ragu_circuits::{polynomials::TestRank, registry::RegistryBuilder};
    use ragu_core::pasta::Pasta;

    let registry = RegistryBuilder::<Fp, TestRank>::new()
        .with_tag(Fp::from(23))
        .register_circuit(())?
        .finalize()?;
    let source = super::source::SourceRegistry::new::<_, ReferenceBackend>(&registry);
    let builder = crate::ApplicationBuilder::<Pasta, ProductionRank, 2>::new()
        .with_source_registries(Some(source), None)
        .with_backend::<ReferenceBackend>();
    assert_eq!(builder.native_source.as_ref().unwrap().tag(), Fp::from(23));
    assert!(builder.finalize(crate::pasta::baked()).is_err());
    Ok(())
}

#[test]
fn mesh_preparation_uses_source_restrictions_and_preserves_both_child_obligations() -> Result<()> {
    use alloc::vec::Vec;

    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::{TestRank, sparse},
        registry::RegistryBuilder,
    };

    use super::{
        mesh_preparation::PhaseWitness, prepared::PreparationChallenges, source::SourceRegistry,
    };

    fn check<F: Field>() -> Result<()> {
        let registry = RegistryBuilder::<F, TestRank>::new()
            .with_tag(F::from(23))
            .register_circuit(())?
            .finalize()?;
        let source = SourceRegistry::new::<_, ReferenceBackend>(&registry);
        let mesh = SourceMesh::NATIVE_MESH.unwrap();
        let layout = SourceMesh::NATIVE_ONLINE;
        let inherited = [
            source.xy::<ProductionRank>(F::from(2), F::from(3))?,
            source.xy::<ProductionRank>(F::from(13), F::from(19))?,
        ];
        let inputs = mesh.carry_inputs(
            layout,
            vec![F::ZERO; 4],
            [[F::from(2), F::from(3)], [F::from(13), F::from(19)]],
        )?;
        assert_eq!(
            inputs,
            vec![F::from(2), F::from(3), F::from(13), F::from(19)]
        );
        let challenges = Challenges {
            w: F::from(5),
            y: F::from(7),
            x: F::from(11),
            alpha: F::from(13),
            u: F::from(17),
            beta: F::from(3),
        };
        let prepare = |phase, preparation, inherited| {
            mesh.prepare(
                layout,
                &source,
                PhaseWitness {
                    phase,
                    inputs: &inputs,
                    challenges: preparation,
                    inherited,
                    supplied: vec![],
                },
            )
        };
        let mut polynomials = Vec::new();
        for (phase, preparation) in [
            (Phase::BeforeW, PreparationChallenges::default()),
            (
                Phase::BeforeY,
                PreparationChallenges {
                    w: Some(challenges.w),
                    y: None,
                    x: None,
                },
            ),
            (
                Phase::BeforeX,
                PreparationChallenges {
                    w: Some(challenges.w),
                    y: Some(challenges.y),
                    x: None,
                },
            ),
            (
                Phase::BeforeAlpha,
                PreparationChallenges {
                    w: Some(challenges.w),
                    y: Some(challenges.y),
                    x: Some(challenges.x),
                },
            ),
        ] {
            polynomials.extend(prepare(
                phase,
                preparation,
                Some([&inherited[0], &inherited[1]]),
            )?);
        }
        let queries = layout.query::<_, _, ReferenceBackend>(
            &polynomials,
            inputs.clone(),
            vec![],
            &challenges,
        )?;
        assert_eq!(
            queries.values,
            vec![
                source.evaluate::<ReferenceBackend>(challenges.w, inputs[0], inputs[1]),
                source.evaluate::<ReferenceBackend>(challenges.w, inputs[2], inputs[3]),
                source.evaluate::<ReferenceBackend>(challenges.w, inputs[0], challenges.y),
                source.evaluate::<ReferenceBackend>(challenges.w, inputs[2], challenges.y),
                source.evaluate::<ReferenceBackend>(challenges.w, challenges.x, challenges.y),
            ]
        );
        assert_eq!(
            ReferenceBackend::sparse_eval(&polynomials[mesh.outgoing], F::from(29)),
            source.evaluate::<ReferenceBackend>(F::from(29), challenges.x, challenges.y)
        );
        // A bad inherited obligation must remain bad, so the shared edge
        // fails. Recomputing it from source would silently erase the fault.
        for child in 0..2 {
            let mut altered = inherited.clone();
            altered[child] = sparse::Polynomial::new();
            let carried = mesh.prepare(
                layout,
                &source,
                PhaseWitness {
                    phase: Phase::BeforeW,
                    inputs: &inputs,
                    challenges: PreparationChallenges::default(),
                    inherited: Some([&altered[0], &altered[1]]),
                    supplied: vec![],
                },
            )?;
            assert_eq!(
                ReferenceBackend::sparse_eval(&carried[child], challenges.w),
                F::ZERO
            );
            let mut forged = polynomials.clone();
            forged[..2].clone_from_slice(&carried);
            assert!(
                layout
                    .query::<_, _, ReferenceBackend>(&forged, inputs.clone(), vec![], &challenges)
                    .is_err()
            );
        }
        assert!(prepare(Phase::BeforeW, PreparationChallenges::default(), None).is_err());
        for phase in [Phase::BeforeY, Phase::BeforeX, Phase::BeforeAlpha] {
            assert!(prepare(phase, PreparationChallenges::default(), None).is_err());
        }
        assert!(
            mesh.prepare(
                layout,
                &source,
                PhaseWitness {
                    phase: Phase::BeforeW,
                    inputs: &inputs,
                    challenges: PreparationChallenges::default(),
                    inherited: Some([&inherited[0], &inherited[1]]),
                    supplied: vec![sparse::Polynomial::new()],
                }
            )
            .is_err()
        );
        Ok(())
    }
    check::<Fp>()?;
    check::<Fq>()
}

#[test]
fn terminal_mesh_opens_both_ends_and_counts_each_polynomial_once() -> Result<()> {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{polynomials::TestRank, registry::RegistryBuilder};

    use super::{mesh_terminal::Coordinates, source::SourceRegistry};
    fn check<F: Field>() -> Result<()> {
        let registry = RegistryBuilder::<F, TestRank>::new()
            .with_tag(F::from(23))
            .register_circuit(())?
            .finalize()?;
        let source = SourceRegistry::new::<_, ReferenceBackend>(&registry);
        let mesh = SourceMesh::NATIVE_MESH.unwrap();
        let layout = SourceMesh::NATIVE_ONLINE;
        let coordinates = Coordinates {
            w: F::from(5),
            y: F::from(7),
            x: F::from(11),
        };
        let inputs = vec![F::from(2), F::from(3), F::from(13), F::from(19)];
        let values = vec![
            source.evaluate::<ReferenceBackend>(coordinates.w, inputs[0], inputs[1]),
            source.evaluate::<ReferenceBackend>(coordinates.w, inputs[2], inputs[3]),
            source.evaluate::<ReferenceBackend>(coordinates.w, inputs[0], coordinates.y),
            source.evaluate::<ReferenceBackend>(coordinates.w, inputs[2], coordinates.y),
            source.evaluate::<ReferenceBackend>(coordinates.w, coordinates.x, coordinates.y),
        ];
        let metadata = mesh.claim_values(layout, &inputs, &values)?;
        assert_eq!(
            mesh.inherited_values(&metadata).as_slice(),
            inputs.as_slice()
        );
        let polynomials =
            mesh.terminal_polynomials::<_, ProductionRank>(&source, &metadata, coordinates)?;
        let tau = F::from(29);
        let expected = source.evaluate::<ReferenceBackend>(tau, coordinates.x, coordinates.y);
        let claims = mesh.terminal_claims(layout, &metadata, coordinates, tau, expected, 7)?;
        assert_eq!(polynomials.len(), 6);
        assert_eq!(claims.len(), 11);
        for claim in &claims {
            assert_eq!(
                ReferenceBackend::sparse_eval(&polynomials[claim.poly - 7], claim.point),
                claim.value
            );
        }
        for edge in claims[..10].chunks_exact(2) {
            assert_eq!(edge[0].value, edge[1].value);
            assert_ne!(edge[0].poly, edge[1].poly);
        }
        assert_eq!(claims[10].poly, 7 + mesh.outgoing);
        assert_eq!(claims[10].point, tau);
        for i in mesh.coordinate_indices().len()..metadata.len() {
            let mut altered = metadata.clone();
            altered[i] += F::ONE;
            let forged = mesh.terminal_claims(layout, &altered, coordinates, tau, expected, 7)?;
            assert!(forged.iter().any(|claim| ReferenceBackend::sparse_eval(
                &polynomials[claim.poly - 7],
                claim.point
            ) != claim.value));
        }
        assert!(
            mesh.terminal_claims(
                layout,
                &metadata[..metadata.len() - 1],
                coordinates,
                tau,
                expected,
                0
            )
            .is_err()
        );
        Ok(())
    }
    check::<Fp>()?;
    check::<Fq>()
}
