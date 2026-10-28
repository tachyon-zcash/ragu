//! Malformed ordinary proofs must reject before indexing, compression or
//! fusion.

use alloc::format;

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, R, Rank};
use ragu_core::{Error, pasta::Pasta};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::Proof;
use crate::{
    Application, ApplicationBuilder,
    ipa::IpaCycle,
    profile::{
        Profile, Profiled, ProfiledCycle,
        testing::{Crossing, CrossingBack, CrossingContext},
    },
    step::internal::rerandomize::Rerandomize,
};

const HEADER_SIZE: usize = 4;

fn check_shapes<C: IpaCycle + ProfiledCycle, R: Rank>(app: &Application<'_, C, R, HEADER_SIZE>) {
    let honest = app.bootstrap_pcd();
    let mut rng = StdRng::seed_from_u64(0x908_5a9e);
    assert!(app.verify_uncompressed(&honest, &mut rng).unwrap());
    let compressed = app.compress(&honest, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());

    let mut reject = |proof: Proof<C, R>, label: &str| {
        let malformed = proof.carry::<()>(());
        assert!(
            !app.verify_uncompressed(&malformed, &mut rng).unwrap(),
            "ordinary verification accepted {label}"
        );
        assert!(
            matches!(
                app.compress(&malformed, &mut rng),
                Err(Error::InvalidWitness(_))
            ),
            "compression did not reject {label}"
        );
        // The prover reads its children by this profile's layout too, and
        // refuses one of another shape in either position.
        for (left, right) in [
            (malformed.clone(), honest.clone()),
            (honest.clone(), malformed.clone()),
        ] {
            assert!(
                matches!(
                    app.fuse(&mut rng, Rerandomize::<()>::new(), (), left, right),
                    Err(Error::InvalidWitness(_))
                ),
                "fusion did not reject {label}"
            );
        }
    };

    // Mutate polynomial and cache lengths independently, and together: equal
    // lengths are not enough if both disagree with the receiving profile.
    macro_rules! check_pair {
        ($polys:ident, $cache:ident, $poly:expr, $commitment:expr) => {
            for (polys, cache) in [(true, false), (false, true), (true, true)] {
                let label = format!(
                    "{} (polynomials={polys}, cache={cache})",
                    stringify!($polys)
                );
                let mut proof = honest.proof().clone();
                if polys {
                    proof.$polys.push(($poly).clone());
                }
                if cache {
                    proof.$cache.push(($commitment).clone());
                }
                reject(proof, &format!("trailing {label}"));

                if !honest.proof().$polys.is_empty() {
                    let mut proof = honest.proof().clone();
                    if polys {
                        proof.$polys.pop().unwrap();
                    }
                    if cache {
                        proof.$cache.pop().unwrap();
                    }
                    reject(proof, &format!("missing {label}"));
                }
            }
        };
    }

    check_pair!(
        native_extension_circuit_rxs,
        native_extension_circuit_commitments,
        honest.proof().native_application_rx,
        honest.proof().native_application_commitment
    );
    check_pair!(
        native_extension_stage_rxs,
        native_extension_stage_commitments,
        honest.proof().native_application_rx,
        honest.proof().native_application_commitment
    );
    check_pair!(
        nested_extension_circuit_rxs,
        nested_extension_circuit_commitments,
        honest.proof().nested_export_rx,
        honest.proof().nested_export_commitment
    );
    check_pair!(
        nested_extension_stage_rxs,
        nested_extension_stage_commitments,
        honest.proof().nested_export_rx,
        honest.proof().nested_export_commitment
    );
    check_pair!(
        native_endoscaling_step_rxs,
        native_endoscaling_step_commitments,
        honest.proof().native_application_rx,
        honest.proof().native_application_commitment
    );
    check_pair!(
        nested_endoscaling_step_rxs,
        nested_endoscaling_step_commitments,
        honest.proof().nested_export_rx,
        honest.proof().nested_export_commitment
    );
    check_pair!(
        native_bind_challenges_rxs,
        native_bind_challenges_commitments,
        honest.proof().native_application_rx,
        honest.proof().native_application_commitment
    );

    macro_rules! check_header {
        ($header:ident) => {
            let mut proof = honest.proof().clone();
            proof.$header.push(C::CircuitField::ZERO);
            reject(proof, concat!("trailing ", stringify!($header)));
            let mut proof = honest.proof().clone();
            proof.$header.pop().unwrap();
            reject(proof, concat!("missing ", stringify!($header)));
        };
    }
    check_header!(left_header);
    check_header!(right_header);
}

#[test]
fn malformed_standard_proof_shapes_are_rejected() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked_aggregator())
        .unwrap();
    check_shapes(&app);
}

fn check_extension<P>()
where
    P: Profile<Context<'static, Pasta, R<14>, ReferenceBackend> = CrossingContext<'static, Pasta>>,
{
    let params = crate::pasta::baked_aggregator();
    let bits = [true, false, false, true];
    let app = ApplicationBuilder::<Profiled<Pasta, P>, R<14>, HEADER_SIZE>::new()
        .finalize_with(
            params,
            CrossingContext {
                params,
                native: bits,
                nested: bits,
            },
        )
        .unwrap();
    check_shapes(&app);
}

#[test]
fn malformed_native_extension_proof_shapes_are_rejected() {
    check_extension::<CrossingBack>();
}

#[test]
fn malformed_nested_extension_proof_shapes_are_rejected() {
    check_extension::<Crossing>();
}
