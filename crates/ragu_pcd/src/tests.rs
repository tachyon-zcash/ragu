//! Fabrications no [`Step`](crate::step::Step) can express through
//! [`StepCtx`](crate::step::StepCtx): [`PolyHandle`](crate::PolyHandle)'s
//! constructors are crate-private, so a step cannot name a commitment the proof
//! does not carry. A malicious prover can still commit to one — which is what
//! `verify`'s native claim checks are for — so each case here is a direct edit
//! of a proof's fields, and lives in-crate to reach them.
//!
//! The proof edited is a seeded [`Leaf`], whose hook slots hold the adapter's
//! own padding. That is a real proof — it has been through `seed` — so the
//! control below is not vacuous, and each refusal is attributable to its edit.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    pasta::{Fp, Pasta},
};
use ragu_primitives::allocator::Standard;
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    AppHooks, Application, ApplicationBuilder, HookConfig, Pcd, Proof,
    step::{Encoded, Index, Step, StepCtx},
};

/// A seed that uses no hook, so every slot holds the adapter's padding.
struct Leaf;

impl Step<Pasta> for Leaf {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        Ok((
            (
                Encoded::new(ctx.dr, allocator, left)?,
                Encoded::new(ctx.dr, allocator, right)?,
                Encoded::new(ctx.dr, allocator, D::unit())?,
            ),
            (),
            D::unit(),
            D::unit(),
        ))
    }
}

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// Two queries, so a slot loop has something to iterate.
type Hooks = AppHooks<1, 2>;
type App = Application<'static, Pasta, R, HEADER_SIZE, Hooks>;

fn app() -> Result<App> {
    ApplicationBuilder::<Pasta, R, HEADER_SIZE, Hooks>::new()
        .register(Leaf)?
        .finalize(crate::pasta::baked())
}

fn seeded(app: &App, rng: &mut StdRng) -> Result<Pcd<Pasta, R, ()>> {
    Ok(app.seed(rng, Leaf, ())?.0)
}

/// The control every test below rests on.
#[test]
fn a_seeded_proof_verifies() -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(1);
    let proof = seeded(&app, &mut rng)?;
    assert!(app.verify(&proof, &mut rng)?);
    Ok(())
}

/// Edits a copy of a seeded proof and asserts the root refuses it.
fn refuse(seed: u64, apply: impl FnOnce(&App, &mut Proof<Pasta, R>)) -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut proof = seeded(&app, &mut rng)?.into_parts().0;
    apply(&app, &mut proof);
    assert!(!app.verify(&proof.carry::<()>(()), &mut rng)?);
    Ok(())
}

/// A poly-query whose commitment is no carried polynomial's. Negating it leaves
/// a valid curve point that nothing in the stage commits to.
#[test]
fn a_poly_query_against_an_uncarried_commitment_is_refused() -> Result<()> {
    for slot in 0..Hooks::layout().poly_queries {
        refuse(4242 + slot as u64, |_, proof| {
            proof.application_poly_queries[slot].com = -proof.application_poly_queries[slot].com;
        })?;
    }
    Ok(())
}
