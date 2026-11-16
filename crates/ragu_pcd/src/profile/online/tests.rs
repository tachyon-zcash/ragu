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
        MultiStage::<F, ProductionRank, _>::new(circuit::Circuit::<Batched, S>::default());
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
fn private_stages_and_helper_are_registered_in_claim_order() -> Result<()> {
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
        )?
        .into_registry();
        for j in 0..layout.bondings() {
            let Bonding::Private(mask) = extension::bonding::<F, ProductionRank, Batched, S>(j)?
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
    assert!(Batched::check().is_err(), "integration gate stays closed");
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
fn preparation_commits_each_phase_once_and_keeps_zero_polynomials() -> Result<()> {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::sparse,
        registry::{CircuitIndex, RegistryBuilder},
    };
    use ragu_core::{Cycle, pasta::Pasta};
    use udon::curve::Affine;

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
    state.supply::<ReferenceBackend, _>(
        Phase::BeforeW,
        vec![sparse::Polynomial::new()],
        generators,
    )?;
    assert_eq!(state.commitments(), &[C::identity()]);
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
    assert_eq!(&*state.query().values, &[Fp::ZERO; 3]);
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
        .register_internal_circuit(MultiStage::<Fp, R, _>::new(
            circuit::Circuit::<Batched, S>::default(),
        ))?
        .finalize()?;
    let challenges = Challenges {
        w: Fp::from(5),
        y: Fp::from(7),
        x: Fp::from(11),
        alpha: Fp::from(13),
        u: Fp::from(17),
        beta: Fp::from(3),
    };
    let (_, sums) = state.trace(challenges, &registry, CircuitIndex::new(0), &mut rng)?;
    assert_eq!(sums, [Fp::ZERO; 2]);
    assert_eq!(state.polynomials().len(), 1);
    let commitments = core::array::from_fn::<_, 3, _>(|i| state.stage_commitment(i));
    for (stage, commitment) in state.take_stages().iter().zip(commitments) {
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
    const NAME: &'static str = "nested-private-targets";
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

#[test]
fn nested_private_targets_bind_the_actual_helper_output_and_claim_order() -> Result<()> {
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
    let private = [13, 17, 19, 23, 29].map(Fq::from);
    let helper = circuit::Instance::<_, NestedOnly, S> {
        challenges: Challenges {
            w: private[0],
            y: unified.y,
            x: unified.x,
            alpha: private[1],
            u: unified.u,
            beta: private[2],
        },
        sums: [private[3], private[4]],
        foreign: FixedVec::from_fn(|_| unreachable!()),
    };
    Emulator::emulate_wireless((unified, helper, private), |dr, witness| {
        let (unified, helper, private) = witness.cast();
        let y = Element::constant(dr, Fq::from(31));
        let unified = nested::unified::Output::<_, C>::alloc(dr, &mut (), unified.as_ref())?;
        let private = FixedVec::<_, stages::Present<NestedOnly, S, 5>>::try_from_fn(|i| {
            Element::alloc(dr, &mut (), private.as_ref().map(|p| p[i]))
        })?;
        let unified_ky = unified.ky(dr, &y)?;
        let (compute_target, helper_target) = ky::nested_private_ky::<_, _, NestedOnly>(
            dr,
            &y,
            &unified,
            &unified_ky,
            &private,
            &[],
        )?;
        let output = nested::circuits::compute_v::Output::<_, C, NestedOnly> {
            unified: unified.clone(),
            private: private.clone(),
            private_stages: FixedVec::from_fn(|_| unreachable!()),
        };
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(
            compute_target.value().take(),
            actual.finish_ky(dr)?.value().take()
        );
        let output =
            <circuit::Circuit<NestedOnly, S> as MultiStageCircuit<Fq, ProductionRank>>::instance(
                &circuit::Circuit::default(),
                dr,
                helper.as_ref(),
            )?;
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(
            helper_target.as_ref().unwrap().value().take(),
            ky::finish_extension_ky(actual, dr)?.value().take()
        );
        // Every public challenge and sum is held by both claims. Changing a
        // helper value independently cannot retain either claim's target.
        for i in 0..private.len() {
            let mut corrupt = private.clone();
            corrupt[i] = corrupt[i].add(dr, &Element::one());
            let (compute, helper) = ky::nested_private_ky::<_, _, NestedOnly>(
                dr,
                &y,
                &unified,
                &unified_ky,
                &corrupt,
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
        private_helper: Some(Fq::from(7)),
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
fn private_stage_bindings_are_in_the_native_claims() -> Result<()> {
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
        fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
            core::iter::once(CircuitIndex::new(0))
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
        ky::nested_private_stages::<NestedOnly, _>(|index| index),
        [
            RxIndex::ExtensionStage(0),
            RxIndex::ExtensionStage(1),
            RxIndex::ExtensionStage(2)
        ]
    );
    assert!(ky::nested_private_stages::<Standard, _>(|index| index).is_empty());
    Ok(())
}

#[test]
fn native_private_targets_share_sums_and_actual_foreign_points() -> Result<()> {
    use ragu_circuits::{horner::Horner, staging::MultiStageCircuit};
    use ragu_core::{
        drivers::emulator::Emulator,
        maybe::Maybe,
        pasta::{EpAffine, Pasta},
    };
    use ragu_primitives::{CompletePoint, Element, GadgetExt, Point as CurvePoint};
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
            )?;
            let stages =
                FixedVec::<_, stages::Present<Batched, stages::Nested, 3>>::try_from_fn(|i| {
                    CurvePoint::alloc(dr, stages.as_ref().map(|p| p[i]))
                })?;
            let compute_target = inputs.compute_v_bridge_ky(dr, &y, &stages)?;
            let helper_target = inputs.private_helper_ky(dr, &y)?.unwrap();
            let (unified_ky, _) = inputs.unified_ky_values(dr, &y)?;
            let points_target = inputs.bind_endoscalar_ky(dr, &y, &unified_ky)?;
            let output = native::circuits::compute_v::Output::<_, C> {
                unified: inputs.unified.clone(),
                online: inputs.online.clone(),
                private_sums: inputs.private_sums.clone(),
                private_stages: FixedVec::from_fn(|i| {
                    let point = CompletePoint::from_affine(stages[i / 2].clone());
                    let (x, y) = point.coordinates();
                    if i % 2 == 0 { x.clone() } else { y.clone() }
                }),
            };
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                compute_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            let output =
                <circuit::Circuit<Batched, S> as MultiStageCircuit<Fp, ProductionRank>>::instance(
                    &circuit::Circuit::default(),
                    dr,
                    helper.as_ref(),
                )?;
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                helper_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            let output = native::circuits::bind_endoscalar::Output::<_, C> {
                unified: inputs.unified.clone(),
                private_points: inputs.private_points.clone(),
            };
            let mut actual = Horner::new(&y);
            GadgetExt::write(&output, dr, &mut actual)?;
            assert_eq!(
                points_target.value().take(),
                ky::finish_extension_ky(actual, dr)?.value().take()
            );
            for i in 0..2 {
                let original = inputs.private_sums[i].clone();
                inputs.private_sums[i] = original.add(dr, &Element::one());
                assert_ne!(
                    compute_target.value().take(),
                    inputs.compute_v_bridge_ky(dr, &y, &stages)?.value().take()
                );
                assert_ne!(
                    helper_target.value().take(),
                    inputs.private_helper_ky(dr, &y)?.unwrap().value().take()
                );
                inputs.private_sums[i] = original;
            }
            inputs.private_points[0] = CompletePoint::alloc(dr, points.as_ref().map(|p| -p[0]))?;
            assert_ne!(
                helper_target.value().take(),
                inputs.private_helper_ky(dr, &y)?.unwrap().value().take()
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
        private_helper: Some(Fp::from(17)),
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
    const NAME: &'static str = "native-private-targets";
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
fn native_private_stage_targets_use_actual_extension_commitments() -> Result<()> {
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
        ky::native_private_stages::<P, _>(|index| index),
        (0..3)
            .map(native::RxIndex::ExtensionStage)
            .collect::<alloc::vec::Vec<_>>()
    );
    assert!(ky::native_private_stages::<NestedOnly, _>(|index| index).is_empty());
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
        let base = unified.ky(dr, &y)?;
        let (target, helper) =
            ky::nested_private_ky::<_, _, P>(dr, &y, &unified, &base, &[], &stages)?;
        assert!(helper.is_none());
        let output = nested::circuits::compute_v::Output::<_, C, P> {
            unified: unified.clone(),
            private: FixedVec::from_fn(|_| unreachable!()),
            private_stages: stages.clone(),
        };
        let mut actual = Horner::new(&y);
        GadgetExt::write(&output, dr, &mut actual)?;
        assert_eq!(target.value().take(), actual.finish_ky(dr)?.value().take());
        for i in 0..3 {
            let mut corrupt = stages.clone();
            corrupt[i] = CurvePoint::alloc(dr, points.as_ref().map(|p| -p[i]))?;
            let (changed, helper) =
                ky::nested_private_ky::<_, _, P>(dr, &y, &unified, &base, &[], &corrupt)?;
            assert!(helper.is_none());
            assert_ne!(target.value().take(), changed.value().take());
        }
        Ok(())
    })
}
