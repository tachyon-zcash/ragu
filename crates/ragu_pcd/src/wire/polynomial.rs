//! Dense polynomial payloads: exactly `2^rank` canonical coefficients.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
use udon::field::Field;

use super::{Decode, Encode, Error, Reader, Scalar};

// The rank fixes the coefficient count, so the layout carries no counts and
// does not depend on the in-memory block structure or its gap tolerance.
impl<F: Field, R: Rank> Encode for Polynomial<F, R> {
    fn encode(&self, output: &mut Vec<u8>) {
        for coefficient in self.iter_coeffs() {
            <F as Encode<Scalar>>::encode(&coefficient, output);
        }
    }
}

impl<F: Field, R: Rank> Decode for Polynomial<F, R> {
    fn encoded_len() -> usize {
        R::num_coeffs() * <F as Decode<Scalar>>::encoded_len()
    }

    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        // Check the whole polynomial is present before allocating for it.
        let offset = reader.offset();
        let bytes = reader.remaining();
        if bytes.len() < Self::encoded_len() {
            return Err(Error::Truncated {
                offset,
                requested: Self::encoded_len(),
                bytes,
            });
        }
        let coeffs = (0..R::num_coeffs())
            .map(|_| <F as Decode<Scalar>>::decode(reader))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_coeffs(coeffs))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use proptest::prelude::*;
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fp;

    use super::*;
    use crate::wire::VERSION;

    type Poly = Polynomial<Fp, TestRank>;

    fn encoded(coeffs: &[Fp]) -> Vec<u8> {
        let mut bytes = vec![VERSION];
        for value in coeffs {
            <Fp as Encode<Scalar>>::encode(value, &mut bytes);
        }
        bytes.resize(1 + Poly::encoded_len(), 0);
        bytes
    }

    #[test]
    fn encoding_is_dense_and_ignores_storage_layout() {
        let a = Fp::from(3);
        let b = Fp::from(7);
        let dense = Poly::from_coeffs(vec![a, b, Fp::ZERO, a]);
        let padded = Poly::from_coeffs(vec![a, b, Fp::ZERO, a, Fp::ZERO]);
        let expected = encoded(&[a, b, Fp::ZERO, a]);
        assert_eq!(expected.len(), 1 + TestRank::num_coeffs() * 32);
        assert_eq!(dense.to_bytes(), expected);
        assert_eq!(padded.to_bytes(), expected);
        let decoded = Poly::from_bytes(&expected).unwrap();
        assert!(decoded.iter_coeffs().eq(dense.iter_coeffs()));
        assert!(decoded.iter_stored_coeffs().eq(dense.iter_stored_coeffs()));
        assert_eq!(decoded.to_bytes(), expected);
        assert_eq!(Poly::new().to_bytes(), encoded(&[]));
    }

    #[test]
    fn encoding_ignores_view_boundaries() {
        use ragu_circuits::polynomials::sparse::View;
        let mut view = View::trace();
        // Consecutive values straddle the independently built wire buffers.
        view.a.push(Fp::ONE);
        view.b.push(Fp::from(7));
        let from_view: Poly = view.build();
        let dense = Poly::from_coeffs(from_view.iter_coeffs().collect());
        assert_eq!(from_view.to_bytes(), dense.to_bytes());
        let decoded = Poly::from_bytes(&from_view.to_bytes()).unwrap();
        assert!(decoded.iter_stored_coeffs().eq(dense.iter_stored_coeffs()));
    }

    #[test]
    fn rejects_other_lengths_and_bad_coefficients() {
        let bytes = Poly::from_coeffs(vec![Fp::ONE, Fp::from(2)]).to_bytes();
        for end in [0, 1, 33, bytes.len() - 1] {
            let Error::Length { expected, actual } = Poly::from_bytes(&bytes[..end]).unwrap_err()
            else {
                panic!("expected a length error")
            };
            assert_eq!(expected, bytes.len());
            assert_eq!(actual, end);
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        Poly::from_bytes(&trailing).unwrap_err();

        // A short reader (no outer length check) reports the whole polynomial.
        let mut reader = Reader::new(&bytes[1..40]);
        let Error::Truncated {
            offset, requested, ..
        } = Poly::decode(&mut reader).unwrap_err()
        else {
            panic!("expected truncation")
        };
        assert_eq!(offset, 0);
        assert_eq!(requested, Poly::encoded_len());

        let mut bad = bytes;
        bad[1..33].fill(0xff);
        let Error::Invalid { offset, reason, .. } = Poly::from_bytes(&bad).unwrap_err() else {
            panic!("expected a non-canonical coefficient")
        };
        assert_eq!(offset, 1);
        assert_eq!(reason, "non-canonical field element");
    }

    proptest! {
        #[test]
        fn storage_independent_roundtrip(values in proptest::collection::vec(0u64..5, 0..=TestRank::num_coeffs())) {
            let coeffs: Vec<_> = values.into_iter().map(Fp::from).collect();
            let canonical = Poly::from_coeffs(coeffs.clone());
            let mut padded = coeffs.clone();
            padded.resize(TestRank::num_coeffs(), Fp::ZERO);
            let chunked = Poly::from_coeffs(padded);
            let bytes = canonical.to_bytes();
            prop_assert_eq!(bytes.len(), 1 + Poly::encoded_len());
            prop_assert_eq!(&chunked.to_bytes(), &bytes);
            let decoded = Poly::from_bytes(&bytes).unwrap();
            prop_assert!(decoded.iter_coeffs().eq(canonical.iter_coeffs()));
            prop_assert!(decoded.iter_stored_coeffs().eq(canonical.iter_stored_coeffs()));
            prop_assert_eq!(decoded.to_bytes(), bytes);
        }

        #[test]
        fn accepted_bytes_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 1 + Poly::encoded_len())) {
            if let Ok(poly) = Poly::from_bytes(&bytes) {
                prop_assert_eq!(poly.to_bytes(), bytes);
            }
        }
    }
}
