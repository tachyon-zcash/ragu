//! Online batches, the identity commitments they reject, and transcript-copy
//! attacks.

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
use ragu_primitives::{Element, GadgetExt};
use rand::{CryptoRng, SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    ipa::IpaCycle,
    profile::{
        CircuitSlot, Extension, ExtensionRxs, Profile, Profiled, ProfiledCycle, ProverContext,
        Registered, Standard,
        online::{
            Challenge, Layout, Opening, Phase, Point, PreparationChallenges,
            circuit::{self, Challenges},
            stages::{InputStage, InputWitness, Nested, QueryStage, QueryWitness},
        },
        testing::UnitStep,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OnlineBatch;
impl Profile for OnlineBatch {
    const NAME: &'static str = "online-nested-batch";
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
        slot.register_staged(MultiStage::<Base::ScalarField, Rk, _>::new(Consumer))
    }

    fn nested_extension_rxs_with_online<'params, Base, Rk, const HS: usize, B, RNG>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&core::convert::Infallible>,
        _: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, Rk>,
        online: Option<&circuit::Witness<'_, Base::ScalarField, Self, Nested>>,
        _: &[Base::HostCurve],
        _: &[ragu_circuits::paging::Planned<Base::ScalarField>],
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let online = online.expect("declared consumer has online stages");
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
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
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
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
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
                    Base::ScalarField::ONE,
                    -Base::ScalarField::ONE,
                    Base::ScalarField::ONE,
                ]),
                sparse::Polynomial::from_coeffs(vec![Base::ScalarField::ONE]),
            ]
        } else {
            Vec::new()
        })
    }
}

type C = Profiled<Pasta, OnlineBatch>;
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
    let bytes = compressed.proof().to_bytes().expect("encode online points");
    let compressed = crate::CompressedProof::<C>::from_bytes(&bytes)
        .expect("decode online points")
        .carry::<()>(());
    assert_eq!(app.verify_compressed(&compressed)?, expected);
    Ok(())
}

#[test]
fn nested_online_batch_round_trip_and_sum_binding() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x6060);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify(&app, &child, &mut rng, true)?;
    check_identity_online_commitments(&app, &child, &mut rng, &[], &[0, 1])?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let bytes = parent
        .proof()
        .to_bytes()
        .expect("encode active online batch");
    let decoded = Proof::<C, Rk>::from_bytes(&bytes)
        .expect("decode active online batch")
        .carry::<()>(());
    verify(&app, &decoded, &mut rng, true)?;

    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.nested_online_commitments[i] = if i == 0 {
            -proof.nested_online_commitments[0]
        } else {
            proof.nested_online_commitments[0]
        };
        let bad = proof.carry::<()>(());
        verify(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
        verify(&app, &parent, &mut rng, false)?;
    }
    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.nested_online_fold[i] += Fq::ONE;
        let bad = proof.carry::<()>(());
        verify(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
        verify(&app, &parent, &mut rng, false)?;
    }
    Ok(())
}

#[test]
fn nested_online_stage_copies_bind_at_all_three_deadlines() -> Result<()> {
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

/// A scalar consumer reserves only the independent online input/query prefix.
/// It checks the known formula $q(X) = X^2 - X + 1$ at the authenticated w and
/// at an early input.
struct Consumer;
impl<F: Field, Rk: Rank> MultiStageCircuit<F, Rk> for Consumer {
    type Last = QueryStage<OnlineBatch, Nested>;
    type Instance<'source> = ();
    type Witness<'source> = (
        &'source InputWitness<F, OnlineBatch, Nested>,
        &'source QueryWitness<F, OnlineBatch, Nested>,
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
        let (inputs, builder) = builder.add_stage::<InputStage<OnlineBatch, Nested>>()?;
        let (query, builder) = builder.add_stage::<QueryStage<OnlineBatch, Nested>>()?;
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
                .add(dr, &Element::one())
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
fn online_consumer_challenges_are_bound_to_the_enclosing_step() -> Result<()> {
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

/// Exercise the native batch both on its own and alongside the nested batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeBatch<const WITH_NESTED: bool>;
impl<const WITH_NESTED: bool> Profile for NativeBatch<WITH_NESTED> {
    const NAME: &'static str = if WITH_NESTED {
        "online-both-batches"
    } else {
        "online-native-batch"
    };
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
    const NATIVE_ONLINE: Layout = OnlineBatch::NESTED_ONLINE;
    const NESTED_ONLINE: Layout = if WITH_NESTED {
        Self::NATIVE_ONLINE
    } else {
        Layout::EMPTY
    };
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;

    fn native_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![Base::CircuitField::from(4)])
    }
    fn native_online_points<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: &[Base::CircuitField],
        _: PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![Base::CircuitField::from(6)])
    }
    fn native_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
        phase: Phase,
        _: &[Base::CircuitField],
        _: PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<sparse::Polynomial<Base::CircuitField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == Phase::BeforeW {
            vec![
                sparse::Polynomial::from_coeffs(vec![
                    Base::CircuitField::ONE,
                    -Base::CircuitField::ONE,
                    Base::CircuitField::ONE,
                ]),
                sparse::Polynomial::from_coeffs(vec![Base::CircuitField::ONE]),
            ]
        } else {
            Vec::new()
        })
    }
    fn nested_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if WITH_NESTED {
            vec![Base::ScalarField::from(4)]
        } else {
            Vec::new()
        })
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
        Ok(if WITH_NESTED {
            vec![Base::ScalarField::from(6)]
        } else {
            Vec::new()
        })
    }
    fn nested_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
        phase: Phase,
        _: &[Base::ScalarField],
        _: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if WITH_NESTED && phase == Phase::BeforeW {
            vec![
                sparse::Polynomial::from_coeffs(vec![
                    Base::ScalarField::ONE,
                    -Base::ScalarField::ONE,
                    Base::ScalarField::ONE,
                ]),
                sparse::Polynomial::from_coeffs(vec![Base::ScalarField::ONE]),
            ]
        } else {
            Vec::new()
        })
    }
}

fn verify_profile<P: Profile>(
    app: &Application<'_, Profiled<Pasta, P>, Rk, 2>,
    pcd: &Pcd<Profiled<Pasta, P>, Rk, ()>,
    rng: &mut StdRng,
    expected: bool,
) -> Result<()> {
    assert_eq!(app.verify_uncompressed(pcd, &mut *rng)?, expected);
    let compressed = app.compress(pcd, rng)?;
    let bytes = compressed.proof().to_bytes().expect("encode online batch");
    let decoded = crate::CompressedProof::<Profiled<Pasta, P>>::from_bytes(&bytes)
        .expect("decode online batch")
        .carry::<()>(());
    assert_eq!(app.verify_compressed(&decoded)?, expected);
    Ok(())
}

/// An online commitment is never the identity. For each listed slot, a proof
/// holding the identity there cannot be encoded, both verifiers reject it,
/// and no parent can be fused over it.
pub(crate) fn check_identity_online_commitments<P: Profile>(
    app: &Application<'_, Profiled<Pasta, P>, Rk, 2>,
    pcd: &Pcd<Profiled<Pasta, P>, Rk, ()>,
    rng: &mut StdRng,
    native: &[usize],
    nested: &[usize],
) -> Result<()> {
    type Host<P> = <Profiled<Pasta, P> as ragu_core::Cycle>::HostCurve;
    type Nest<P> = <Profiled<Pasta, P> as ragu_core::Cycle>::NestedCurve;
    let compressed = app.compress(pcd, &mut *rng)?;
    for (field, slots) in [("native", native), ("nested", nested)] {
        for &slot in slots {
            let mut proof = pcd.proof().clone();
            let mut instance = compressed.proof().clone();
            if field == "native" {
                proof.native_online_commitments[slot] = Host::<P>::identity();
                instance.instance.native_online_commitments[slot] = Host::<P>::identity();
            } else {
                proof.nested_online_commitments[slot] = Nest::<P>::identity();
                instance.instance.nested_online_commitments[slot] = Nest::<P>::identity();
            }
            assert!(
                proof.to_bytes().is_err(),
                "encoded an identity {field} commitment at {slot}"
            );
            let bad = proof.carry::<()>(());
            assert!(
                !app.verify_uncompressed(&bad, &mut *rng)?,
                "accepted an identity {field} commitment at {slot}"
            );
            assert!(
                app.fuse(&mut *rng, UnitStep, (), pcd.clone(), bad).is_err(),
                "fused over an identity {field} commitment at {slot}"
            );
            assert!(
                instance.to_bytes().is_err(),
                "encoded a compressed identity {field} commitment at {slot}"
            );
            assert!(
                !app.verify_compressed(&instance.carry::<()>(()))?,
                "accepted a compressed identity {field} commitment at {slot}"
            );
        }
    }
    Ok(())
}

fn native_round_trip<const WITH_NESTED: bool, const CHECK_MUTATIONS: bool>() -> Result<()> {
    type Cycle<const N: bool> = Profiled<Pasta, NativeBatch<N>>;
    let app = ApplicationBuilder::<Cycle<WITH_NESTED>, Rk, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x6160 + u64::from(WITH_NESTED));
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify_profile(&app, &child, &mut rng, true)?;
    if CHECK_MUTATIONS {
        let nested: &[usize] = if WITH_NESTED { &[0, 1] } else { &[] };
        check_identity_online_commitments(&app, &child, &mut rng, &[0, 1], nested)?;
    }
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let bytes = parent
        .proof()
        .to_bytes()
        .expect("encode native online proof");
    let decoded = Proof::<Cycle<WITH_NESTED>, Rk>::from_bytes(&bytes)
        .expect("decode native online proof")
        .carry::<()>(());
    verify_profile(&app, &decoded, &mut rng, true)?;
    if !CHECK_MUTATIONS {
        return Ok(());
    }
    // Both foreign helper exports and the actual walk use these common points.
    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.native_online_commitments[i] = if i == 0 {
            -proof.native_online_commitments[0]
        } else {
            proof.native_online_commitments[0]
        };
        let bad = proof.carry::<()>(());
        verify_profile(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), bad)?;
        verify_profile(&app, &parent, &mut rng, false)?;
    }
    for i in 0..2 {
        let mut proof = child.proof().clone();
        proof.native_online_fold[i] += ragu_core::pasta::Fp::ONE;
        let bad = proof.carry::<()>(());
        verify_profile(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), bad)?;
        verify_profile(&app, &parent, &mut rng, false)?;
    }
    Ok(())
}

#[test]
fn native_online_batches_round_trip_without_a_nested_helper() -> Result<()> {
    native_round_trip::<false, true>()
}

#[test]
fn both_online_batches_round_trip() -> Result<()> {
    native_round_trip::<true, false>()
}

#[cfg(ragu_pcd_nightly_tests)]
#[test]
#[ignore = "proof regressions run in the scheduled Heavy tests workflow"]
fn both_online_batches_round_trip_and_bind_points_and_sums() -> Result<()> {
    native_round_trip::<true, true>()
}

std::thread_local! { static ALTER_NATIVE_STAGE: Cell<Option<usize>> = const { Cell::new(None) }; }
pub(crate) fn mutate_native_stage_commitment<P: Affine>(index: usize, point: P) -> P {
    if ALTER_NATIVE_STAGE.get() == Some(index) {
        -point
    } else {
        point
    }
}

#[test]
fn native_online_stage_copies_bind_at_all_three_deadlines() -> Result<()> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALTER_NATIVE_STAGE.set(None);
        }
    }
    let app = ApplicationBuilder::<Profiled<Pasta, NativeBatch<true>>, Rk, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x6162);
    let (sibling, ()) = app.seed(&mut rng, UnitStep, ())?;
    for stage in 0..3 {
        let (bad, ()) = {
            assert!(ALTER_NATIVE_STAGE.replace(Some(stage)).is_none());
            let _reset = Reset;
            app.seed(&mut rng, UnitStep, ())?
        };
        verify_profile(&app, &bad, &mut rng, false)?;
        let (parent, ()) = app.fuse(&mut rng, UnitStep, (), sibling.clone(), bad)?;
        verify_profile(&app, &parent, &mut rng, false)?;
    }
    Ok(())
}

#[cfg(feature = "unstable-fuzzing")]
mod capture {
    use ragu_circuits::Circuit;
    use ragu_testing::patcher::{capture_with_stage_values, constraints_hold, playback};

    use super::*;
    use crate::fuzzing::patcher::{
        CircuitSpec, InternalCircuitVisitor, capture_internal_circuits,
        capture_internal_circuits_bootstrap,
    };
    struct Visitor([usize; 2]);
    impl<Cy: ProfiledCycle> InternalCircuitVisitor<Cy> for Visitor {
        fn visit<'w, Cir: Circuit<Cy::CircuitField>>(
            &mut self,
            spec: &CircuitSpec,
            circuit: &Cir,
            stage_values: &[Cy::CircuitField],
            make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
        ) -> Result<()> {
            if spec.name == "compute_v" {
                let capture = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
                assert!(constraints_hold(
                    &capture.recorder.events,
                    &capture.recorder.values
                ));
                assert!(playback(circuit, make_witness()?, capture.recorder.values)?);
                self.0[0] += 1;
            }
            Ok(())
        }
        fn visit_nested<'w, Cir: Circuit<Cy::ScalarField>>(
            &mut self,
            spec: &CircuitSpec,
            circuit: &Cir,
            stage_values: &[Cy::ScalarField],
            make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
        ) -> Result<()> {
            if spec.name == "nested_compute_v" {
                let capture = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
                assert!(constraints_hold(
                    &capture.recorder.events,
                    &capture.recorder.values
                ));
                assert!(playback(circuit, make_witness()?, capture.recorder.values)?);
                self.0[1] += 1;
            }
            Ok(())
        }
    }
    #[test]
    fn both_online_compute_v_circuits_capture_and_replay() -> Result<()> {
        let app = ApplicationBuilder::<Profiled<Pasta, NativeBatch<true>>, Rk, 2>::new()
            .register(UnitStep)?
            .finalize(crate::pasta::baked_aggregator())?;
        let mut rng = StdRng::seed_from_u64(0x6163);
        let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
        let mut visitor = Visitor([0; 2]);
        capture_internal_circuits(
            &app,
            &mut rng,
            UnitStep,
            (),
            child.clone(),
            child,
            &mut visitor,
        )?;
        capture_internal_circuits_bootstrap(&app, &mut rng, &mut visitor)?;
        assert_eq!(visitor.0, [2; 2]);
        Ok(())
    }
}

/// Four restrictions with shared intersection values, prepared at the four
/// transcript boundaries. This exercises the batch schedule, independently of
/// the later source-registry identity accumulator.
#[cfg(ragu_pcd_nightly_tests)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativePhases;
#[cfg(ragu_pcd_nightly_tests)]
impl Profile for NativePhases {
    const NAME: &'static str = "native-online-phases";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
    const NATIVE_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
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
                polynomial: 1,
                point: Point::Input(1),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Challenge(Challenge::Y),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Input(0),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Challenge(Challenge::X),
                value: 2,
            },
            Opening {
                polynomial: 3,
                point: Point::Challenge(Challenge::W),
                value: 2,
            },
        ],
        inputs: 2,
        points: 0,
        values: 3,
    };
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    fn native_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![
            Base::CircuitField::from(2),
            Base::CircuitField::from(3),
        ])
    }
    fn native_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
        phase: Phase,
        inputs: &[Base::CircuitField],
        challenges: PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<sparse::Polynomial<Base::CircuitField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        let constant = match phase {
            Phase::BeforeW => {
                assert!(challenges.w.is_none() && challenges.y.is_none() && challenges.x.is_none());
                inputs[0] + inputs[1]
            }
            Phase::BeforeY => {
                assert!(challenges.y.is_none() && challenges.x.is_none());
                challenges.w.expect("w precedes T") + inputs[0]
            }
            Phase::BeforeX => {
                assert!(challenges.x.is_none());
                challenges.w.expect("w precedes U") + challenges.y.expect("y precedes U")
            }
            Phase::BeforeAlpha => {
                assert!(challenges.w.is_some());
                challenges.x.expect("x precedes outgoing restriction")
                    + challenges.y.expect("y precedes outgoing restriction")
            }
        };
        Ok(vec![sparse::Polynomial::from_coeffs(vec![
            constant,
            Base::CircuitField::ONE,
        ])])
    }
}

std::thread_local! { static ALTER_NATIVE_PHASE: Cell<Option<usize>> = const { Cell::new(None) }; }
pub(crate) fn mutate_native_phase<P: Affine>(phase: usize, point: P) -> P {
    if ALTER_NATIVE_PHASE.get() == Some(phase) {
        -point
    } else {
        point
    }
}

#[cfg(ragu_pcd_nightly_tests)]
#[test]
#[ignore = "proof regressions run in the scheduled Heavy tests workflow"]
fn native_auxiliaries_bind_at_every_deadline_and_survive_recursion() -> Result<()> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALTER_NATIVE_PHASE.set(None);
        }
    }
    type Cycle = Profiled<Pasta, NativePhases>;
    let app = ApplicationBuilder::<Cycle, Rk, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x6260);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify_profile(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let bytes = parent.proof().to_bytes().expect("encode phased batch");
    let decoded = Proof::<Cycle, Rk>::from_bytes(&bytes)
        .expect("decode phased batch")
        .carry::<()>(());
    verify_profile(&app, &decoded, &mut rng, true)?;
    for phase in 0..4 {
        // Only the transcript copies are altered; the state used to build the
        // quotient, helper and actual point fold remains honest.
        let (bad_stage, ()) = {
            assert!(ALTER_NATIVE_PHASE.replace(Some(phase)).is_none());
            let _reset = Reset;
            app.seed(&mut rng, UnitStep, ())?
        };
        verify_profile(&app, &bad_stage, &mut rng, false)?;
        let mut proof = child.proof().clone();
        proof.native_online_commitments[phase] = -proof.native_online_commitments[phase];
        let bad = proof.carry::<()>(());
        verify_profile(&app, &bad, &mut rng, false)?;
        for (left, right) in [(bad_stage, child.clone()), (child.clone(), bad)] {
            let parent = app.fuse(&mut rng, UnitStep, (), left, right);
            if Phase::ALL[phase] == Phase::BeforeX {
                // The before-x commitment is part of the canonical ab bridge.
                assert!(matches!(parent, Err(ragu_core::Error::InvalidWitness(_))));
            } else {
                verify_profile(&app, &parent?.0, &mut rng, false)?;
            }
        }
    }
    Ok(())
}

/// Four restrictions with shared intersection values, prepared at the four
/// transcript boundaries. This exercises the batch schedule, independently of
/// the later source-registry identity accumulator.
#[cfg(ragu_pcd_nightly_tests)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NestedPhases;
#[cfg(ragu_pcd_nightly_tests)]
impl Profile for NestedPhases {
    const NAME: &'static str = "nested-online-phases";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
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
                polynomial: 1,
                point: Point::Input(1),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Challenge(Challenge::Y),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Input(0),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Challenge(Challenge::X),
                value: 2,
            },
            Opening {
                polynomial: 3,
                point: Point::Challenge(Challenge::W),
                value: 2,
            },
        ],
        inputs: 2,
        points: 0,
        values: 3,
    };
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    fn nested_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(vec![Base::ScalarField::from(2), Base::ScalarField::from(3)])
    }
    fn nested_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
        phase: Phase,
        inputs: &[Base::ScalarField],
        challenges: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        let constant = match phase {
            Phase::BeforeW => {
                assert!(challenges.w.is_none() && challenges.y.is_none() && challenges.x.is_none());
                inputs[0] + inputs[1]
            }
            Phase::BeforeY => {
                assert!(challenges.y.is_none() && challenges.x.is_none());
                challenges.w.expect("w precedes T") + inputs[0]
            }
            Phase::BeforeX => {
                assert!(challenges.x.is_none());
                challenges.w.expect("w precedes U") + challenges.y.expect("y precedes U")
            }
            Phase::BeforeAlpha => {
                assert!(challenges.w.is_some());
                challenges.x.expect("x precedes outgoing restriction")
                    + challenges.y.expect("y precedes outgoing restriction")
            }
        };
        Ok(vec![sparse::Polynomial::from_coeffs(vec![
            constant,
            Base::ScalarField::ONE,
        ])])
    }
}

std::thread_local! { static ALTER_NESTED_PHASE: Cell<Option<usize>> = const { Cell::new(None) }; }
pub(crate) fn mutate_nested_phase<P: Affine>(phase: usize, point: P) -> P {
    if ALTER_NESTED_PHASE.get() == Some(phase) {
        -point
    } else {
        point
    }
}

#[cfg(ragu_pcd_nightly_tests)]
#[test]
#[ignore = "proof regressions run in the scheduled Heavy tests workflow"]
fn nested_auxiliaries_bind_at_every_deadline_and_survive_recursion() -> Result<()> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALTER_NESTED_PHASE.set(None);
        }
    }
    type Cycle = Profiled<Pasta, NestedPhases>;
    let app = ApplicationBuilder::<Cycle, Rk, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x6261);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify_profile(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let bytes = parent.proof().to_bytes().expect("encode phased batch");
    let decoded = Proof::<Cycle, Rk>::from_bytes(&bytes)
        .expect("decode phased batch")
        .carry::<()>(());
    verify_profile(&app, &decoded, &mut rng, true)?;
    for phase in 0..4 {
        // Only the transcript copies are altered; the state used to build the
        // quotient, helper and actual point fold remains honest.
        let (bad, ()) = {
            assert!(ALTER_NESTED_PHASE.replace(Some(phase)).is_none());
            let _reset = Reset;
            app.seed(&mut rng, UnitStep, ())?
        };
        verify_profile(&app, &bad, &mut rng, false)?;
        let (bad_parent, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
        verify_profile(&app, &bad_parent, &mut rng, false)?;
        let mut proof = child.proof().clone();
        proof.nested_online_commitments[phase] = -proof.nested_online_commitments[phase];
        let bad = proof.carry::<()>(());
        verify_profile(&app, &bad, &mut rng, false)?;
        let (bad_parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), bad)?;
        verify_profile(&app, &bad_parent, &mut rng, false)?;
    }
    let (bad, ()) = {
        struct ResetQuery;
        impl Drop for ResetQuery {
            fn drop(&mut self) {
                ALTER_NESTED_QUERY.set(false);
            }
        }
        assert!(!ALTER_NESTED_QUERY.replace(true));
        let _reset = ResetQuery;
        app.seed(&mut rng, UnitStep, ())?
    };
    verify_profile(&app, &bad, &mut rng, false)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child, bad)?;
    verify_profile(&app, &parent, &mut rng, false)?;
    Ok(())
}

std::thread_local! { static ALTER_NESTED_QUERY: Cell<bool> = const { Cell::new(false) }; }
/// Alter only the copy committed before alpha. The later point stage, actual
/// polynomial fold and exported commitment stay unchanged.
pub(crate) fn mutate_nested_auxiliary_query<P: Affine>(point: P) -> P {
    if ALTER_NESTED_QUERY.get() {
        -point
    } else {
        point
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Multipoint;
/// The test profile's context, a slope its prover reads; no step supplies
/// anything to its extension.
impl crate::profile::ProverContext for u64 {
    type Source = core::convert::Infallible;
}

impl Profile for Multipoint {
    const NAME: &'static str = "multipoint-batch";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ONLINE: Layout = Layout {
        polynomials: &[Phase::BeforeW],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::X),
                value: 1,
            },
        ],
        inputs: 0,
        points: 0,
        values: 2,
    };
    type Context<'params, Base, Rk, B>
        = u64
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    fn nested_online_polynomials<'params, Base, Rk, B>(
        slope: &Self::Context<'params, Base, Rk, B>,
        _: Option<&<Self::Context<'params, Base, Rk, B> as ProverContext>::Source>,
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
            vec![sparse::Polynomial::from_coeffs(vec![
                Base::ScalarField::ONE,
                Base::ScalarField::from(*slope),
            ])]
        } else {
            vec![]
        })
    }
}

#[test]
fn a_multipoint_slot_is_one_commitment() -> Result<()> {
    type Mixed = Profiled<Pasta, Multipoint>;
    let app = ApplicationBuilder::<Mixed, Rk, 2>::new()
        .register(UnitStep)?
        .finalize_with(crate::pasta::baked_aggregator(), 2)?;
    assert_eq!(crate::profile::Shape::of::<Multipoint>().nested_online, 1);
    let mut rng = StdRng::seed_from_u64(0x606050);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    for proof in [child, parent] {
        assert_eq!(proof.proof().nested_online_commitments.len(), 1);
        assert!(app.verify_uncompressed(&proof, &mut rng)?);
        let compressed = app.compress(&proof, &mut rng)?;
        assert!(app.verify_compressed(&compressed)?);
    }
    Ok(())
}

#[test]
fn a_nonzero_constant_nested_polynomial_compresses_with_a_zero_quotient_fold() -> Result<()> {
    type Mixed = Profiled<Pasta, Multipoint>;
    let app = ApplicationBuilder::<Mixed, Rk, 2>::new()
        .register(UnitStep)?
        .finalize_with(crate::pasta::baked_aggregator(), 0)?;
    let mut rng = StdRng::seed_from_u64(0x606051);
    let (pcd, ()) = app.seed(&mut rng, UnitStep, ())?;
    assert_eq!(pcd.proof().nested_online_fold, [Fq::ZERO, Fq::ONE]);
    verify_profile(&app, &pcd, &mut rng, true)
}
