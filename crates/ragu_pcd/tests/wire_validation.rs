//! Proof decoding must preserve values and reject malformed protocol layouts.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use ragu_primitives::wire::{Decode, Encode, Limits, Minimize};
use rand::{SeedableRng, rngs::StdRng};

use super::MinimalProof;
use crate::ApplicationBuilder;

#[test]
fn decoded_proof_preserves_derived_fields_and_rejects_wrong_vector_lengths() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let pcd = app.bootstrap_pcd();
    assert!(app.verify(&pcd, &mut rng).unwrap());
    let (proof, ()) = pcd.into_parts();
    let bytes = proof.minimize().to_bytes();
    let decode = |bytes: &[u8]| {
        MinimalProof::<Pasta, ProductionRank>::from_bytes(bytes, Limits::default()).unwrap()
    };
    let expanded = app.expand(decode(&bytes)).unwrap();
    assert_eq!(proof.test_mismatch(&expanded), None);
    assert!(app.verify(&expanded.carry::<()>(()), &mut rng).unwrap());

    // Each vector has a protocol-fixed length. Test both missing and surplus
    // entries independently, including the commitment side of each pair.
    macro_rules! reject_lengths {
        ($($field:ident),* $(,)?) => {$(
            for extra in [false, true] {
                let mut minimal = proof.minimize();
                if extra {
                    minimal.$field.push(minimal.$field[0].clone());
                } else {
                    minimal.$field.pop().unwrap();
                }
                let malformed = minimal.to_bytes();
                assert!(
                    matches!(MinimalProof::<Pasta, ProductionRank>::from_bytes(&malformed, Limits::default()),
                        Err(ragu_primitives::wire::Error::Invalid { reason: "incorrect fixed sequence length", .. })),
                    "{} (extra: {extra})", stringify!($field),
                );
            }
        )*};
    }
    reject_lengths!(
        native_bind_challenges_rxs,
        native_bind_challenges_commitments,
        native_endoscaling_step_rxs,
        native_endoscaling_step_commitments,
        nested_endoscaling_step_rxs,
        nested_endoscaling_step_commitments,
    );
}

#[test]
fn minimal_verification_preserves_header_encoding_errors() {
    use ragu_core::{
        Error, Result,
        drivers::{Driver, DriverValue},
        gadgets::Bound,
    };
    use ragu_primitives::allocator::Allocator;
    use udon::field::Field;

    use crate::header::{Header, Suffix};

    struct BrokenHeader;
    impl<F: Field> Header<F> for BrokenHeader {
        const SUFFIX: Suffix = <() as Header<F>>::SUFFIX;
        type Data = ();
        type Output = ();

        fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
            _: &mut D,
            _: &mut A,
            _: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Err(Error::ConstraintBoundExceeded { limit: 42 })
        }
    }

    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let proof = app.bootstrap_pcd().into_parts().0;
    let bytes = proof.minimize().to_bytes();
    let minimal =
        MinimalProof::<Pasta, ProductionRank>::from_bytes(&bytes, Limits::default()).unwrap();
    assert!(matches!(
        app.verify_minimal::<_, BrokenHeader>(minimal, (), StdRng::seed_from_u64(0x5eed)),
        Err(Error::ConstraintBoundExceeded { limit: 42 })
    ));
}
