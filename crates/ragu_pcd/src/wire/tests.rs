use alloc::{vec, vec::Vec};

use proptest::prelude::*;
use ragu_core::pasta::{EpAffine, EqAffine, Fp, Fq};
use ragu_primitives::vec::ConstLen;

use super::*;

// The values here have layouts their types fix alone.
const DIMS: Dimensions = Dimensions {
    rank: 0,
    header_size: 0,
};

type Pair = FixedSequence<DefaultEncoding, ConstLen<2>>;

#[test]
fn integer_and_fixed_sequence_known_bytes() {
    assert_eq!(
        0x0102030405060708u64.to_bytes(DIMS),
        [8, 7, 6, 5, 4, 3, 2, 1]
    );
    // No count precedes the elements: the codec fixes it.
    let values = vec![0x0102u16, 0x0304];
    let bytes = <Vec<u16> as Encode<Pair>>::to_bytes(&values, DIMS);
    assert_eq!(bytes, [2, 1, 4, 3]);
    assert_eq!(
        <Vec<u16> as Decode<Pair>>::from_bytes(&bytes, DIMS).unwrap(),
        values
    );
    // A vector of another length has no encoding.
    let mut output = Vec::new();
    assert_eq!(
        <Vec<u16> as Encode<Pair>>::encode(&vec![1u16], &mut output, DIMS),
        Err(Error::Unencodable)
    );
}

#[test]
fn field_and_point_roundtrips() {
    let mut one = vec![0; 32];
    one[0] = 1;
    assert_eq!(<Fp as Encode<Scalar>>::to_bytes(&Fp::ONE, DIMS), one);
    fn fields<F: Field>() {
        for value in [F::ZERO, F::ONE, -F::ONE, F::from(17)] {
            let bytes = <F as Encode<Scalar>>::to_bytes(&value, DIMS);
            assert_eq!(
                <F as Decode<Scalar>>::from_bytes(&bytes, DIMS).unwrap(),
                value
            );
        }
    }
    fn points<G: Affine>() {
        for value in [G::generator(), -G::generator()] {
            let bytes = <G as Encode<Point>>::to_bytes(&value, DIMS);
            assert_eq!(
                <G as Decode<Point>>::from_bytes(&bytes, DIMS).unwrap(),
                value
            );
        }
        // The identity has no encoding, and its canonical bytes do not decode.
        let mut output = Vec::new();
        assert_eq!(
            <G as Encode<Point>>::encode(&G::identity(), &mut output, DIMS),
            Err(Error::Unencodable)
        );
        let bytes = Affine::to_bytes(&G::identity());
        let Error::Invalid { offset, reason, .. } =
            <G as Decode<Point>>::from_bytes(bytes.as_ref(), DIMS).unwrap_err()
        else {
            panic!("expected an identity point error")
        };
        assert_eq!((offset, reason), (0, "identity point"));
    }
    fields::<Fp>();
    fields::<Fq>();
    points::<EpAffine>();
    points::<EqAffine>();
    let values = vec![Fp::from(7), -Fp::ONE];
    let bytes = <Vec<Fp> as Encode<FixedSequence<Scalar, ConstLen<2>>>>::to_bytes(&values, DIMS);
    assert_eq!(
        <Vec<Fp> as Decode<FixedSequence<Scalar, ConstLen<2>>>>::from_bytes(&bytes, DIMS).unwrap(),
        values
    );
}

#[test]
fn rejects_noncanonical_representations() {
    fn fields<F: Field>() {
        // p, obtained by adding one to the canonical little-endian spelling of p-1.
        let mut modulus = Field::to_bytes(&(-F::ONE));
        for byte in modulus.as_mut() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        let Error::Invalid {
            offset,
            bytes: offending,
            ..
        } = <F as Decode<Scalar>>::from_bytes(modulus.as_ref(), DIMS).unwrap_err()
        else {
            panic!("expected a non-canonical field error")
        };
        assert_eq!(offset, 0);
        assert_eq!(offending, modulus.as_ref());
    }
    fn points<G: Affine>() {
        let bytes = [0xff; 32];
        let Error::Invalid {
            offset,
            bytes: offending,
            ..
        } = <G as Decode<Point>>::from_bytes(&bytes, DIMS).unwrap_err()
        else {
            panic!("expected an invalid point error")
        };
        assert_eq!(offset, 0);
        assert_eq!(offending, &bytes[..]);
    }
    fields::<Fp>();
    fields::<Fq>();
    points::<EpAffine>();
    points::<EqAffine>();
}

#[test]
fn rejects_other_lengths() {
    let bytes = <Vec<u64> as Encode<Pair>>::to_bytes(&vec![1, 2], DIMS);
    assert_eq!(bytes.len(), 16);
    for length in 0..bytes.len() {
        let Error::Length { expected, actual } =
            <Vec<u64> as Decode<Pair>>::from_bytes(&bytes[..length], DIMS).unwrap_err()
        else {
            panic!("expected a length error")
        };
        assert_eq!(expected, 16);
        assert_eq!(actual, length);
    }
    let mut trailing = bytes;
    trailing.push(0);
    let Error::Length { expected, actual } =
        <Vec<u64> as Decode<Pair>>::from_bytes(&trailing, DIMS).unwrap_err()
    else {
        panic!("expected a length error")
    };
    assert_eq!((expected, actual), (16, 17));
}

#[test]
fn short_reader_reports_the_missing_value() {
    let mut reader = Reader::new(&[1, 2, 3]);
    let Error::Truncated {
        offset,
        requested,
        bytes,
    } = u64::decode(&mut reader, DIMS).unwrap_err()
    else {
        panic!("expected truncation")
    };
    assert_eq!(offset, 0);
    assert_eq!(requested, 8);
    assert_eq!(bytes, [1, 2, 3]);
}

/// The re-encoding of `payload` as a scalar, if it decodes as one.
fn scalar_spelling<F: Field>(payload: &[u8]) -> Option<Vec<u8>> {
    <F as Decode<Scalar>>::from_bytes(payload, DIMS)
        .ok()
        .map(|value| <F as Encode<Scalar>>::to_bytes(&value, DIMS))
}

/// The re-encoding of `payload` as a point, if it decodes as one, and
/// whether the point is the identity.
fn point_spelling<G: Affine>(payload: &[u8]) -> Option<(Vec<u8>, bool)> {
    <G as Decode<Point>>::from_bytes(payload, DIMS)
        .ok()
        .map(|value| {
            (
                <G as Encode<Point>>::to_bytes(&value, DIMS),
                value.is_identity(),
            )
        })
}

proptest! {
    // About a quarter of random payloads are canonical scalars and a quarter
    // decode as points, so each run exercises both outcomes.
    #[test]
    fn accepted_scalar_bytes_have_one_spelling(payload in proptest::collection::vec(any::<u8>(), 32)) {
        for spelling in [scalar_spelling::<Fp>(&payload), scalar_spelling::<Fq>(&payload)].into_iter().flatten() {
            prop_assert_eq!(&spelling, &payload);
        }
    }

    #[test]
    fn accepted_point_bytes_have_one_spelling_and_are_not_the_identity(payload in proptest::collection::vec(any::<u8>(), 32)) {
        for (spelling, identity) in [point_spelling::<EpAffine>(&payload), point_spelling::<EqAffine>(&payload)].into_iter().flatten() {
            prop_assert_eq!(&spelling, &payload);
            prop_assert!(!identity);
        }
    }

    #[test]
    fn scalar_sequences_roundtrip(seed in proptest::collection::vec(any::<u8>(), 64)) {
        let seed: [u8; 64] = seed.try_into().unwrap();
        let values = vec![Fp::from_uniform_bytes(&seed), -Fp::from_uniform_bytes(&seed)];
        let bytes = <Vec<Fp> as Encode<FixedSequence<Scalar, ConstLen<2>>>>::to_bytes(&values, DIMS);
        prop_assert_eq!(
            <Vec<Fp> as Decode<FixedSequence<Scalar, ConstLen<2>>>>::from_bytes(&bytes, DIMS).unwrap(),
            values
        );
    }
}
