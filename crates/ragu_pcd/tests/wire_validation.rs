//! Proof decoding must preserve values and reject malformed protocol layouts.

use alloc::vec::Vec;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{SeedableRng, rngs::StdRng};

use super::MinimalProof;
use crate::{
    ApplicationBuilder,
    wire::{Decode, Encode, Error},
};

type Minimal = MinimalProof<Pasta, ProductionRank, 4>;

#[test]
fn decoded_proof_preserves_derived_fields_and_rejects_wrong_vector_lengths() {
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let pcd = app.bootstrap_pcd();
    assert!(app.verify_uncompressed(&pcd, &mut rng).unwrap());
    let (proof, ()) = pcd.into_parts();
    let bytes = proof.minimize::<4>().to_bytes();
    let expanded = app.expand(Minimal::from_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(proof.test_mismatch(&expanded), None);
    assert!(
        app.verify_uncompressed(&expanded.carry::<()>(()), &mut rng)
            .unwrap()
    );

    // Each vector has a protocol-fixed length, so a vector of another length
    // changes the total and is rejected before any byte is interpreted.
    // Debug builds assert the length while encoding; use the raw byte layout.
    macro_rules! reject_lengths {
        ($($field:ident),* $(,)?) => {$(
            let element = {
                let mut bytes = Vec::new();
                proof.$field[0].encode(&mut bytes);
                bytes
            };
            for extra in [false, true] {
                let mut malformed = bytes.clone();
                if extra {
                    malformed.extend_from_slice(&element);
                } else {
                    malformed.truncate(malformed.len() - element.len());
                }
                assert!(
                    matches!(Minimal::from_bytes(&malformed),
                        Err(Error::Length { expected, actual })
                            if expected == bytes.len() && actual == malformed.len()),
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
    let buffer = proof.native_endoscaling_step_rxs.as_ptr();
    let moved = proof.into_minimal::<4>();
    assert_eq!(moved.native_endoscaling_step_rxs.as_ptr(), buffer);
    assert_eq!(moved.to_bytes(), bytes);
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
    let bytes = proof.minimize::<4>().to_bytes();
    let minimal = Minimal::from_bytes(&bytes).unwrap();
    assert!(matches!(
        app.verify_minimal::<_, BrokenHeader>(minimal, (), StdRng::seed_from_u64(0x5eed)),
        Err(Error::ConstraintBoundExceeded { limit: 42 })
    ));
}
