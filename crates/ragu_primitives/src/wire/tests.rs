use alloc::{vec, vec::Vec};

use proptest::prelude::*;
use ragu_arithmetic::{ff::Field, group::prime::PrimeCurveAffine};
use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};

use super::*;

#[test]
fn integer_vector_known_bytes() {
    assert_eq!(
        0x0102030405060708u64.to_bytes(),
        [1, 8, 7, 6, 5, 4, 3, 2, 1]
    );
    let values = vec![0x0102u16, 0x0304];
    let bytes = <Vec<u16> as Encode>::to_bytes(&values);
    assert_eq!(bytes, [1, 2, 0, 0, 0, 0, 0, 0, 0, 2, 1, 4, 3]);
    assert_eq!(
        <Vec<u16> as Decode>::from_bytes(&bytes, Limits::default()).unwrap(),
        values
    );
    assert_eq!(
        <usize as Encode>::to_bytes(&42),
        <u64 as Encode>::to_bytes(&42)
    );
}

#[test]
fn field_and_point_roundtrips() {
    let mut one = vec![0; 33];
    one[0] = VERSION;
    one[1] = 1;
    assert_eq!(<Fp as Encode<Scalar>>::to_bytes(&Fp::ONE), one);
    fn fields<F: PrimeField + core::fmt::Debug>() {
        for value in [F::ZERO, F::ONE, -F::ONE, F::from(17)] {
            let bytes = <F as Encode<Scalar>>::to_bytes(&value);
            assert_eq!(
                <F as Decode<Scalar>>::from_bytes(&bytes, Limits::default()).unwrap(),
                value
            );
        }
    }
    fn points<G: PrimeCurveAffine + GroupEncoding + core::fmt::Debug>() {
        for value in [G::identity(), G::generator(), -G::generator()] {
            let bytes = <G as Encode<Point>>::to_bytes(&value);
            assert_eq!(
                <G as Decode<Point>>::from_bytes(&bytes, Limits::default()).unwrap(),
                value
            );
        }
    }
    fields::<Fp>();
    fields::<Fq>();
    points::<EpAffine>();
    points::<EqAffine>();
    let values = vec![Fp::ZERO, Fp::from(7), -Fp::ONE];
    let bytes = <Vec<Fp> as Encode<Sequence<Scalar>>>::to_bytes(&values);
    assert_eq!(
        <Vec<Fp> as Decode<Sequence<Scalar>>>::from_bytes(&bytes, Limits::default()).unwrap(),
        values
    );
}

#[test]
fn rejects_noncanonical_representations() {
    // p, obtained by adding one to the canonical little-endian spelling of p-1.
    let mut modulus = (-Fp::ONE).to_repr();
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
    } = <Fp as Decode<Scalar>>::from_bytes(&bytes, Limits::default()).unwrap_err()
    else {
        panic!("expected a non-canonical field error")
    };
    assert_eq!(offset, 1);
    assert_eq!(offending, modulus.as_ref());

    let mut bytes = vec![0xff; 33];
    bytes[0] = VERSION;
    let Error::Invalid {
        offset,
        bytes: offending,
        ..
    } = <EpAffine as Decode<Point>>::from_bytes(&bytes, Limits::default()).unwrap_err()
    else {
        panic!("expected an invalid point error")
    };
    assert_eq!(offset, 1);
    assert_eq!(offending, &bytes[1..]);
}

#[test]
fn rejects_truncation_versions_and_trailing_bytes() {
    let bytes = <Vec<u64> as Encode>::to_bytes(&vec![1, 2, 3]);
    for length in 0..bytes.len() {
        <Vec<u64> as Decode>::from_bytes(&bytes[..length], Limits::default()).unwrap_err();
    }
    let mut bytes = bytes;
    bytes[0] = 2;
    <Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()).unwrap_err();
    bytes[0] = VERSION;
    bytes.push(0);
    let Error::Invalid {
        bytes: trailing,
        reason,
        ..
    } = <Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()).unwrap_err()
    else {
        panic!("expected trailing bytes")
    };
    assert_eq!(trailing, [0]);
    assert_eq!(reason, "trailing bytes");
}

#[test]
fn rejects_impossible_counts_and_aggregate_budget_exhaustion() {
    let mut bytes = vec![VERSION];
    u64::MAX.encode(&mut bytes);
    <Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()).unwrap_err();
    let mut bytes = vec![VERSION];
    3u64.encode(&mut bytes);
    let Error::Truncated {
        requested,
        bytes: available,
        ..
    } = <Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()).unwrap_err()
    else {
        panic!("expected truncated vector")
    };
    assert_eq!(requested, 24);
    assert!(available.is_empty());

    let bytes = <Vec<Vec<u64>> as Encode>::to_bytes(&vec![vec![1, 2], vec![3, 4]]);
    for (limits, expected) in [
        (
            Limits {
                elements: 5,
                ..Limits::default()
            },
            "elements",
        ),
        (
            Limits {
                allocation: 0,
                ..Limits::default()
            },
            "allocation",
        ),
    ] {
        let Error::Limit { resource, .. } =
            <Vec<Vec<u64>> as Decode>::from_bytes(&bytes, limits).unwrap_err()
        else {
            panic!("expected a resource limit")
        };
        assert_eq!(resource, expected);
    }
    // Exactly two vector headers and four scalars consume six elements.
    <Vec<Vec<u64>> as Decode>::from_bytes(
        &bytes,
        Limits {
            elements: 6,
            ..Limits::default()
        },
    )
    .unwrap();
}

#[test]
fn reservation_overflow_reports_the_wire_count() {
    // With no per-element minimum and unbounded budgets, only the size
    // computation can reject this count.
    let limits = Limits {
        elements: usize::MAX,
        allocation: usize::MAX,
    };
    let count = u64::MAX / 2;
    let Error::Length { offset, value } = Reader::new(&[], limits)
        .reserve::<u64>(count, 0)
        .unwrap_err()
    else {
        panic!("expected a length error")
    };
    assert_eq!(offset, 0);
    assert_eq!(value, count);
}

proptest! {
    #[test]
    fn vectors_roundtrip(values in proptest::collection::vec(any::<u64>(), 0..64)) {
        let bytes = <Vec<u64> as Encode>::to_bytes(&values);
        prop_assert_eq!(<Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()).unwrap(), values);
    }

    #[test]
    fn accepted_bytes_have_one_spelling(bytes in proptest::collection::vec(any::<u8>(), 0..160)) {
        if let Ok(value) = <Vec<u64> as Decode>::from_bytes(&bytes, Limits::default()) {
            prop_assert_eq!(<Vec<u64> as Encode>::to_bytes(&value), bytes);
        }
    }
}
