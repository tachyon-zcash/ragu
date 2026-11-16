//! Private nested batches, including zero commitments and transcript-copy attacks.

use alloc::{vec, vec::Vec};
use core::cell::Cell;

use ragu_circuits::{
    CircuitExt, WithAux,
    polynomials::{R, Rank, sparse},
    registry::Registry,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fq, Pasta},
};
use ragu_primitives::GadgetExt;
use rand::{CryptoRng, SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    ipa::IpaCycle,
    profile::{
        CircuitSlot, Extension, ExtensionRxs, Profile, Profiled, ProfiledCycle, Registered,
        Standard,
        online::{
            Challenge, Layout, Opening, Phase, Point,
            batch::Challenges,
            circuit,
            prepared::PreparationChallenges,
            stages::{InputStage, InputWitness, Nested, QueryStage, QueryWitness},
        },
        testing::UnitStep,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrivateBatch;
impl Profile for PrivateBatch {
    const NAME: &'static str = "private-nested-batch";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 1;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ONLINE_CONSUMERS: &'static [u32] = &[0];

    fn nested_extension() -> Extension {
        Extension {
            circuits: vec![vec![]],
            ..Extension::EMPTY
        }
    }

    fn register_nested_circuit<'params, Base, Rk: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, Rk>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert_eq!(circuit, 0);
        slot.register(MultiStage::<Base::ScalarField, Rk, _>::new(Consumer))
    }

    fn nested_extension_rxs_with_online<'params, Base, Rk, const HS: usize, B, RNG>(
        _: &Self::Context<'params, Base, Rk, B>,
        registry: &Registry<'params, Base::ScalarField, Rk>,
        online: Option<&circuit::Witness<'_, Base::ScalarField, Self, Nested>>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let online = online.expect("declared consumer has private stages");
        let circuit = MultiStage::<Base::ScalarField, Rk, _>::new(Consumer);
        let trace = circuit.trace((online.inputs, online.query))?.into_parts().0;
        let index = crate::internal::nested::InternalCircuitIndex::ExtensionCircuit(0)
            .circuit_index::<Self>();
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, index, rng)?],
            stages: Vec::new(),
        })
    }

    const NESTED_ONLINE: Layout = Layout {
        polynomials: &[Phase::BeforeW, Phase::BeforeW],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Constant(0),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 1,
            },
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::X),
                value: 2,
            },
            Opening {
                polynomial: 0,
                point: Point::Input(0),
                value: 3,
            },
            Opening {
                polynomial: 0,
                point: Point::Witness(0),
                value: 4,
            },
        ],
        inputs: 1,
        points: 1,
        values: 5,
    };
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;

    fn nested_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![Base::ScalarField::from(4)])
    }
    fn nested_online_points<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: &[Base::ScalarField],
        _: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![Base::ScalarField::from(6)])
    }
    fn nested_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        phase: Phase,
        _: &[Base::ScalarField],
        _: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == Phase::BeforeW {
            vec![
                sparse::Polynomial::from_coeffs(vec![
                    Base::ScalarField::ZERO,
                    -Base::ScalarField::ONE,
                    Base::ScalarField::ONE,
                ]),
                sparse::Polynomial::new(),
            ]
        } else {
            Vec::new()
        })
    }
}

type C = Profiled<Pasta, PrivateBatch>;
type Rk = R<14>;
type App = Application<'static, C, Rk, 2>;

std::thread_local! { static ALTER_STAGE: Cell<Option<usize>> = const { Cell::new(None) }; }

/// Alter only the copies that enter the transcript and compute-v. The
/// helper's actual committed stage remains unchanged, including its cache.
pub(crate) fn mutate_stage_commitment<P: Affine>(index: usize, point: P) -> P {
    if ALTER_STAGE.get() == Some(index) {
        -point
    } else {
        point
    }
}

fn altered<T>(stage: usize, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALTER_STAGE.set(None);
        }
    }
    assert!(ALTER_STAGE.replace(Some(stage)).is_none());
    let _reset = Reset;
    f()
}

fn application() -> Result<App> {
    ApplicationBuilder::<C, Rk, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())
}

fn verify(app: &App, pcd: &Pcd<C, Rk, ()>, rng: &mut StdRng, expected: bool) -> Result<()> {
    assert_eq!(app.verify_uncompressed(pcd, &mut *rng)?, expected);
    let compressed = app.compress(pcd, rng)?;
    let bytes = compressed
        .proof()
        .to_bytes()
        .expect("encode private points");
    let compressed = crate::CompressedProof::<C>::from_bytes(&bytes)
        .expect("decode private points")
        .carry::<()>(());
    assert_eq!(app.verify_compressed(&compressed)?, expected);
    Ok(())
}

#[test]
fn nested_private_batch_round_trip_and_sum_binding() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x6060);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let bytes = parent
        .proof()
        .to_bytes()
        .expect("encode active private batch");
    let decoded = Proof::<C, Rk>::from_bytes(&bytes)
        .expect("decode active private batch")
        .carry::<()>(());
    verify(&app, &decoded, &mut rng, true)?;

    assert!(child.proof().nested_private_commitments[1].is_identity());
    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.nested_private_commitments[i] = if i == 0 {
            -proof.nested_private_commitments[0]
        } else {
            proof.nested_private_commitments[0]
        };
        let bad = proof.carry::<()>(());
        verify(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
        verify(&app, &parent, &mut rng, false)?;
    }
    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.nested_private_sums[i] += Fq::ONE;
        let bad = proof.carry::<()>(());
        verify(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
        verify(&app, &parent, &mut rng, false)?;
    }
    Ok(())
}

#[test]
fn nested_private_stage_copies_bind_at_all_three_deadlines() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x6061);
    let (sibling, ()) = app.seed(&mut rng, UnitStep, ())?;
    for stage in 0..3 {
        let (bad, ()) = altered(stage, || app.seed(&mut rng, UnitStep, ()))?;
        verify(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, sibling.clone())?;
        verify(&app, &parent, &mut rng, false)?;
    }
    Ok(())
}

/// A scalar consumer reserves only the independent private input/query prefix.
/// It checks the known formula at the authenticated w and at an early input.
struct Consumer;
impl<F: Field, Rk: Rank> MultiStageCircuit<F, Rk> for Consumer {
    type Last = QueryStage<PrivateBatch, Nested>;
    type Instance<'source> = ();
    type Witness<'source> = (
        &'source InputWitness<F, PrivateBatch, Nested>,
        &'source QueryWitness<F, PrivateBatch, Nested>,
    );
    type Output = Kind![F; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, Rk, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (inputs, builder) = builder.add_stage::<InputStage<PrivateBatch, Nested>>()?;
        let (query, builder) = builder.add_stage::<QueryStage<PrivateBatch, Nested>>()?;
        let dr = builder.finish();
        let inputs = inputs.unenforced(dr, witness.as_ref().map(|w| w.0))?;
        let query = query.unenforced(dr, witness.as_ref().map(|w| w.1))?;
        for (point, value) in [
            (&query.challenges[0], &query.values[1]),
            (&inputs.values[0], &query.values[3]),
        ] {
            point
                .mul(dr, point)?
                .sub(dr, point)
                .enforce_equal(dr, value)?;
        }
        Ok(WithAux::new((), D::just(|| ())))
    }
}

std::thread_local! { static ALTER_CHALLENGE: Cell<bool> = const { Cell::new(false) }; }

/// q(w) = q(1-w), so the scalar consumer still accepts the forged w.
/// Only the helper target ties this staged challenge to the outer transcript.
pub(crate) fn mutate_query_challenges<F: Field>(mut challenges: Challenges<F>) -> Challenges<F> {
    if ALTER_CHALLENGE.get() {
        challenges.w = F::ONE - challenges.w;
    }
    challenges
}

#[test]
fn private_consumer_challenges_are_bound_to_the_enclosing_step() -> Result<()> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALTER_CHALLENGE.set(false);
        }
    }
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x6062);
    let (sibling, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (bad, ()) = {
        assert!(!ALTER_CHALLENGE.replace(true));
        let _reset = Reset;
        app.seed(&mut rng, UnitStep, ())?
    };
    verify(&app, &bad, &mut rng, false)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, sibling)?;
    verify(&app, &parent, &mut rng, false)?;
    Ok(())
}
