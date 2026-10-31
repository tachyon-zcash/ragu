//! Malformed proof points reject without hiding header computation errors.

use alloc::string::ToString;

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::{ProductionRank, R, Rank};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    pasta::Pasta,
};
use ragu_primitives::allocator::Allocator;
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder,
    compress::revdot::{native_position, nested_position},
    header::{Header, Suffix},
    internal::{native, nested},
    ipa::IpaCycle,
    profile::{
        Profile, Profiled, ProfiledCycle,
        testing::{Crossing, CrossingBack, CrossingContext},
    },
};

const HEADER_SIZE: usize = 4;

fn check_identity_commitments<C: IpaCycle + ProfiledCycle, R: Rank>(
    app: &Application<'_, C, R, HEADER_SIZE>,
) -> Result<()> {
    let mut rng = StdRng::seed_from_u64(0x908_1de);
    let honest = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&honest, &mut rng)?);
    let compressed = app.compress(&honest, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);

    for index in nested::RxIndex::all::<C::Profile>() {
        use nested::RxIndex::*;
        let mut proof = honest.proof().clone();
        let point = match index {
            BridgePreamble => &mut proof.bridge_preamble_commitment,
            BridgeSPrime => &mut proof.bridge_s_prime_commitment,
            BridgeInnerError => &mut proof.bridge_inner_error_commitment,
            BridgeOuterError => &mut proof.bridge_outer_error_commitment,
            BridgeAB => &mut proof.bridge_ab_commitment.0,
            BridgeQuery => &mut proof.bridge_query_commitment,
            BridgeF => &mut proof.bridge_f_commitment,
            BridgeEval => &mut proof.bridge_eval_commitment,
            ExtensionStage(j) => &mut proof.nested_extension_stage_commitments[j as usize].0,
            _ => continue,
        };
        *point = C::NestedCurve::identity();
        assert!(proof.well_formed::<HEADER_SIZE>());
        assert!(
            !app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?,
            "identity nested commitment {index:?}"
        );

        let mut proof = compressed.proof().clone();
        let position = nested_position::<C::Profile>(nested::RxComponent::Rx(index));
        proof.instance.nested[position] = C::NestedCurve::identity();
        assert!(!app.verify_compressed(&proof.carry::<()>(()))?);
    }

    for j in 0..honest.proof().native_extension_stage_commitments.len() {
        let mut proof = honest.proof().clone();
        proof.native_extension_stage_commitments[j].0 = C::HostCurve::identity();
        assert!(proof.well_formed::<HEADER_SIZE>());
        assert!(
            !app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?,
            "identity native extension commitment {j}"
        );

        let mut proof = compressed.proof().clone();
        let position = native_position::<C::Profile>(native::RxComponent::Rx(
            native::RxIndex::ExtensionStage(j as u32),
        ));
        proof.instance.native[position] = C::HostCurve::identity();
        assert!(!app.verify_compressed(&proof.carry::<()>(()))?);
    }

    // The unified claim targets also allocate the accumulator commitments
    // as points, before the verifier replays the bridge transcript.
    let mut proof = honest.proof().clone();
    proof.native_p_commitment.0 = C::HostCurve::identity();
    assert!(!app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?);
    let mut proof = compressed.proof().clone();
    proof.instance.native_p = C::HostCurve::identity();
    assert!(!app.verify_compressed(&proof.carry::<()>(()))?);

    let mut proof = honest.proof().clone();
    proof.nested_p_commitment.0 = C::NestedCurve::identity();
    assert!(!app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?);
    let mut proof = compressed.proof().clone();
    proof.instance.nested_p = C::NestedCurve::identity();
    assert!(!app.verify_compressed(&proof.carry::<()>(()))?);
    Ok(())
}

#[test]
fn identity_bridge_commitments_are_rejected() -> Result<()> {
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())?;
    check_identity_commitments(&app)
}

fn check_extension<P>() -> Result<()>
where
    P: Profile<Context<'static, Pasta, R<14>, ReferenceBackend> = CrossingContext<'static, Pasta>>,
{
    let params = crate::pasta::baked_aggregator();
    let bits = [true, false, false, true];
    let app = ApplicationBuilder::<Profiled<Pasta, P>, R<14>, HEADER_SIZE>::new().finalize_with(
        params,
        CrossingContext {
            params,
            native: bits,
            nested: bits,
        },
    )?;
    check_identity_commitments(&app)
}

#[test]
fn identity_native_extension_commitments_are_rejected() -> Result<()> {
    check_extension::<CrossingBack>()
}

#[test]
fn identity_nested_extension_commitments_are_rejected() -> Result<()> {
    check_extension::<Crossing>()
}

struct FailingHeader;

impl<F: Field> Header<F> for FailingHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = ();
    type Output = ();

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Err(Error::InvalidWitness("header computation failed".into()))
    }
}

#[test]
fn header_computation_errors_are_preserved() -> Result<()> {
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x908_e77);
    let honest = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&honest, &mut rng)?);
    let compressed = app.compress(&honest, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);

    let pcd = honest.into_parts().0.carry::<FailingHeader>(());
    assert!(matches!(
        app.verify_uncompressed(&pcd, &mut rng),
        Err(Error::InvalidWitness(message)) if message.to_string() == "header computation failed"
    ));
    let pcd = compressed.into_parts().0.carry::<FailingHeader>(());
    assert!(matches!(
        app.verify_compressed(&pcd),
        Err(Error::InvalidWitness(message)) if message.to_string() == "header computation failed"
    ));
    Ok(())
}
