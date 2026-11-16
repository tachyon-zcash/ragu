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
