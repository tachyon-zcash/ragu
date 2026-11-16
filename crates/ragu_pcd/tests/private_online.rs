//! Private nested batches, including zero commitments and transcript-copy attacks.

use alloc::{vec, vec::Vec};
use core::cell::Cell;

use ragu_circuits::polynomials::{R, Rank, sparse};
use ragu_core::{
    Result,
    pasta::{Fq, Pasta},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    ipa::IpaCycle,
    profile::{
        Profile, Profiled, ProfiledCycle, Standard,
        online::{Challenge, Layout, Opening, Phase, Point, prepared::PreparationChallenges},
        testing::UnitStep,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PrivateBatch;
impl Profile for PrivateBatch {
    const NAME: &'static str = "private-nested-batch";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 3;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 3;
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
