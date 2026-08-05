//! Fabrications no [`Step`](crate::step::Step) can express through
//! [`StepCtx`](crate::step::StepCtx): `derive_challenge` computes its own digest,
//! and [`PolyHandle`](crate::PolyHandle)'s constructors are crate-private, so a step
//! cannot name a commitment the proof does not carry. A malicious prover can still
//! commit to either — which is what `verify`'s native claim checks are for — so each
//! case here is a direct edit of a proof's fields, and lives in-crate to reach them.
//!
//! The proof edited is a seeded [`Trivial`], whose hook slots hold the adapter's
//! own padding. That is a real proof — it has been through `seed` — so the
//! control below is not vacuous, and each refusal is attributable to its edit.

use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};

use crate::{
    AppHooks, Application, ApplicationBuilder, HookConfig, Pcd, Proof,
    internal::challenge::challenge_of, step::internal::trivial::Trivial,
};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// Two queries and one derivation, so a slot loop has something to iterate.
type Hooks = AppHooks<1, 2, 1, 2>;
type App = Application<'static, Pasta, R, HEADER_SIZE, Hooks>;

fn app() -> Result<App> {
    ApplicationBuilder::<Pasta, R, HEADER_SIZE, Hooks>::new(Pasta::baked()).finalize()
}

fn seeded(app: &App, rng: &mut StdRng) -> Result<Pcd<Pasta, R, ()>> {
    Ok(app.seed(rng, Trivial::new(), ())?.0)
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
/// a valid curve point that nothing in the instance commits to.
#[test]
fn a_poly_query_against_an_uncarried_commitment_is_refused() -> Result<()> {
    for slot in 0..Hooks::layout().poly_queries {
        refuse(4242 + slot as u64, |_, proof| {
            proof.application_poly_queries[slot].com = -proof.application_poly_queries[slot].com;
        })?;
    }
    Ok(())
}

/// A derived challenge that is not its recorded inputs' hash. The binding
/// circuit alone is pinned in `internal::native::circuits::challenge_binding`.
#[test]
fn a_forged_challenge_is_refused() -> Result<()> {
    for slot in 0..Hooks::layout().challenge_calls {
        refuse(99 + slot as u64, |_, proof| {
            proof.application_challenges[slot].challenge += Fp::from(1u64);
        })?;
    }
    Ok(())
}

/// An edited input with the challenge re-derived from it, so `challenge ==
/// Hash(inputs)` still holds. The instance binding is what refuses it: the step
/// pinned those inputs, as wires or as constants.
#[test]
fn a_challenge_re_derived_from_edited_inputs_is_refused() -> Result<()> {
    for slot in 0..Hooks::layout().challenge_calls {
        for position in 0..Hooks::layout().challenge_width {
            refuse(271828 + slot as u64, |app, proof| {
                let derived = &mut proof.application_challenges[slot];
                derived.inputs[position] += Fp::from(1u64);
                derived.challenge = challenge_of::<Pasta>(app.params, &derived.inputs)
                    .expect("the sponge runs on this application's own parameters");
            })?;
        }
    }
    Ok(())
}
