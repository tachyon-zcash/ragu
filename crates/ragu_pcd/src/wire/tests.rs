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
        0x0102030405060708u64.to_bytes(),
        [1, 8, 7, 6, 5, 4, 3, 2, 1]
    );
    // No count precedes the elements: the codec fixes it.
    let values = vec![0x0102u16, 0x0304];
    let bytes =
        <Vec<u16> as Encode<FixedSequence<DefaultEncoding, ConstLen<2>>>>::to_bytes(&values);
    assert_eq!(bytes, [1, 2, 1, 4, 3]);
    assert_eq!(
        <Vec<u16> as Decode<FixedSequence<DefaultEncoding, ConstLen<2>>>>::from_bytes(&bytes, DIMS)
            .unwrap(),
        values
    );
}

#[test]
fn field_and_point_roundtrips() {
    let mut one = vec![0; 33];
    one[0] = VERSION;
    one[1] = 1;
    assert_eq!(<Fp as Encode<Scalar>>::to_bytes(&Fp::ONE), one);
    fn fields<F: Field>() {
        for value in [F::ZERO, F::ONE, -F::ONE, F::from(17)] {
            let bytes = <F as Encode<Scalar>>::to_bytes(&value);
            assert_eq!(
                <F as Decode<Scalar>>::from_bytes(&bytes, DIMS).unwrap(),
                value
            );
        }
    }
    fn points<G: Affine>() {
        for value in [G::generator(), -G::generator()] {
            let bytes = <G as Encode<Point>>::to_bytes(&value);
            assert_eq!(
                <G as Decode<Point>>::from_bytes(&bytes, DIMS).unwrap(),
                value
            );
        }
        let bytes = <G as Encode<Point>>::to_bytes(&G::identity());
        let Error::Invalid { offset, reason, .. } =
            <G as Decode<Point>>::from_bytes(&bytes, DIMS).unwrap_err()
        else {
            panic!("expected an identity point error")
        };
        assert_eq!((offset, reason), (1, "identity point"));
    }
    fields::<Fp>();
    fields::<Fq>();
    points::<EpAffine>();
    points::<EqAffine>();
    let values = vec![Fp::from(7), -Fp::ONE];
    let bytes = <Vec<Fp> as Encode<FixedSequence<Scalar, ConstLen<2>>>>::to_bytes(&values);
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
        let mut bytes = vec![VERSION];
        bytes.extend_from_slice(modulus.as_ref());
        let Error::Invalid {
            offset,
            bytes: offending,
            ..
        } = <F as Decode<Scalar>>::from_bytes(&bytes, DIMS).unwrap_err()
        else {
            panic!("expected a non-canonical field error")
        };
        assert_eq!(offset, 1);
        assert_eq!(offending, modulus.as_ref());
    }
    fn points<G: Affine>() {
        let mut bytes = vec![0xff; 33];
        bytes[0] = VERSION;
        let Error::Invalid {
            offset,
            bytes: offending,
            ..
        } = <G as Decode<Point>>::from_bytes(&bytes, DIMS).unwrap_err()
        else {
            panic!("expected an invalid point error")
        };
        assert_eq!(offset, 1);
        assert_eq!(offending, &bytes[1..]);
    }
    fields::<Fp>();
    fields::<Fq>();
    points::<EpAffine>();
    points::<EqAffine>();
}

#[test]
fn rejects_other_lengths_and_versions() {
    let bytes = <Vec<u64> as Encode<Pair>>::to_bytes(&vec![1, 2]);
    assert_eq!(bytes.len(), 17);
    for length in 0..bytes.len() {
        let Error::Length { expected, actual } =
            <Vec<u64> as Decode<Pair>>::from_bytes(&bytes[..length], DIMS).unwrap_err()
        else {
            panic!("expected a length error")
        };
        assert_eq!(expected, 17);
        assert_eq!(actual, length);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    let Error::Length { expected, actual } =
        <Vec<u64> as Decode<Pair>>::from_bytes(&trailing, DIMS).unwrap_err()
    else {
        panic!("expected a length error")
    };
    assert_eq!((expected, actual), (17, 18));
    let mut wrong_version = bytes;
    wrong_version[0] = 2;
    let Error::Invalid { offset, reason, .. } =
        <Vec<u64> as Decode<Pair>>::from_bytes(&wrong_version, DIMS).unwrap_err()
    else {
        panic!("expected a version error")
    };
    assert_eq!(offset, 0);
    assert_eq!(reason, "unsupported wire version");
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

proptest! {
    #[test]
    fn pairs_roundtrip(values in proptest::collection::vec(any::<u64>(), 2)) {
        let bytes = <Vec<u64> as Encode<Pair>>::to_bytes(&values);
        prop_assert_eq!(<Vec<u64> as Decode<Pair>>::from_bytes(&bytes, DIMS).unwrap(), values);
    }

    #[test]
    fn accepted_bytes_have_one_spelling(bytes in proptest::collection::vec(any::<u8>(), 17)) {
        if let Ok(value) = <Vec<u64> as Decode<Pair>>::from_bytes(&bytes, DIMS) {
            prop_assert_eq!(<Vec<u64> as Encode<Pair>>::to_bytes(&value), bytes);
        }
    }
}

// Captured at #875's pre-Udon head, 887e0abc. Keep the wire spelling stable
// when changing arithmetic implementations.
#[test]
fn pre_udon_encodings() {
    fn fields<F: Field>(bytes: &[u8]) {
        let values = [F::ZERO, F::ONE, -F::ONE, F::from(17)];
        let encoded: Vec<_> = values
            .iter()
            .flat_map(<F as Encode<Scalar>>::to_bytes)
            .collect();
        assert_eq!(encoded, bytes);
        for (value, bytes) in values.iter().zip(bytes.chunks_exact(33)) {
            assert_eq!(
                <F as Decode<Scalar>>::from_bytes(bytes, DIMS).unwrap(),
                *value
            );
        }
    }
    fn points<G: Affine>(bytes: &[u8]) {
        let values = [G::identity(), G::generator(), -G::generator()];
        let encoded: Vec<_> = values
            .iter()
            .flat_map(<G as Encode<Point>>::to_bytes)
            .collect();
        assert_eq!(encoded, bytes);
        // The identity's spelling is pinned too, although no proof slot
        // admits it, so decoding rejects it.
        let (identity, rest) = bytes.split_at(33);
        let Error::Invalid { reason, .. } =
            <G as Decode<Point>>::from_bytes(identity, DIMS).unwrap_err()
        else {
            panic!("expected an identity point error")
        };
        assert_eq!(reason, "identity point");
        for (value, bytes) in values[1..].iter().zip(rest.chunks_exact(33)) {
            assert_eq!(
                <G as Decode<Point>>::from_bytes(bytes, DIMS).unwrap(),
                *value
            );
        }
    }
    fields::<Fp>(include_bytes!("../../tests/fixtures/wire/fp.bin"));
    fields::<Fq>(include_bytes!("../../tests/fixtures/wire/fq.bin"));
    points::<EpAffine>(include_bytes!("../../tests/fixtures/wire/pallas.bin"));
    points::<EqAffine>(include_bytes!("../../tests/fixtures/wire/vesta.bin"));
}
