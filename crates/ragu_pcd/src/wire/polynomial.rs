//! Canonical storage-independent polynomial payloads.

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use ragu_circuits::polynomials::{Rank, sparse::Polynomial};
use udon::field::Field;

use super::{Decode, Encode, Error, Reader, Scalar};

/// Error context for a rejected sparse-polynomial block.
#[derive(Debug)]
pub struct InvalidBlock {
    /// Zero-based block index.
    pub index: u64,
    /// Encoded start degree.
    pub start: u64,
    /// Encoded coefficient count.
    pub length: u64,
    /// The violated canonical-form invariant.
    pub reason: &'static str,
}

impl fmt::Display for InvalidBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block {} (start {}, length {}): {}",
            self.index, self.start, self.length, self.reason
        )
    }
}
impl core::error::Error for InvalidBlock {}

// Maximal runs of nonzero coefficients are unique for a polynomial. The wire
// layout does not inherit the in-memory GAP_TOLERANCE or block boundaries.
impl<F: Field, R: Rank> Encode for Polynomial<F, R> {
    fn encode(&self, output: &mut Vec<u8>) {
        let nonzero = self
            .iter_stored_coeffs()
            .filter(|(_, value)| **value != F::ZERO);
        let mut count = 0u64;
        let mut previous = None;
        for (index, _) in nonzero.clone() {
            if previous != Some(index) {
                count += 1;
            }
            previous = Some(index + 1);
        }
        count.encode(output);
        let mut coeffs = nonzero.peekable();
        while let Some((start, first)) = coeffs.next() {
            let length = 1 + coeffs
                .clone()
                .enumerate()
                .take_while(|(offset, (index, _))| *index == start + 1 + offset)
                .count();
            (start as u64).encode(output);
            (length as u64).encode(output);
            <F as Encode<Scalar>>::encode(first, output);
            for (_, value) in coeffs.by_ref().take(length - 1) {
                <F as Encode<Scalar>>::encode(value, output);
            }
        }
    }
}

impl<F: Field, R: Rank> Decode for Polynomial<F, R> {
    fn min_encoded_len() -> usize {
        8
    }

    fn decode<'a>(reader: &mut Reader<'a>) -> Result<Self, Error<'a>> {
        let offset = reader.offset();
        let input = reader.remaining();
        let count = u64::decode(reader)?;
        if count > (R::num_coeffs() as u64).div_ceil(2) {
            return Err(Error::Invalid {
                offset,
                bytes: &input[..8],
                reason: "block count exceeds rank",
            });
        }
        let width = <F as Decode<Scalar>>::min_encoded_len();
        // Scan the borrowed input first. The existing public constructor takes
        // dense coefficients, so determine the required prefix before allocating.
        let mut scan = reader.clone();
        let mut previous_end = None;
        for index in 0..count {
            let (start, length) = read_block::<R>(&mut scan, index, previous_end)?;
            let bytes = length.checked_mul(width).ok_or(Error::Length {
                offset: scan.offset(),
                value: length as u64,
            })?;
            scan.take(bytes)?;
            previous_end = Some(start + length);
        }
        let end = previous_end.unwrap_or(0);
        if end == 0 {
            return Ok(Self::new());
        }
        let mut coeffs = reader.reserve::<F>(end as u64, 0)?;
        // Polynomial::from_coeffs grows its vectors geometrically. Charge
        // conservative capacity bounds before calling it: up to twice the
        // prefix length for coefficients and twice the wire-run count for
        // block slots, with Vec's minimum nonzero capacity (four) allowed.
        // These allocations use the existing constructor's infallible allocator.
        reader.charge::<F>((2 * end + 4) as u64, 0)?;
        reader.charge::<(usize, Vec<F>)>(2 * count + 4, 0)?;
        coeffs.resize(end, F::ZERO);
        let mut previous_end = None;
        for index in 0..count {
            let (start, length) = read_block::<R>(reader, index, previous_end)?;
            for slot in &mut coeffs[start..start + length] {
                let offset = reader.offset();
                let bytes = reader.remaining();
                let invalid = |offset, bytes, reason| Error::Value {
                    offset,
                    bytes,
                    source: Box::new(InvalidBlock {
                        index,
                        start: start as u64,
                        length: length as u64,
                        reason,
                    }),
                };
                let value = <F as Decode<Scalar>>::decode(reader).map_err(|error| match error {
                    Error::Invalid {
                        offset,
                        bytes,
                        reason,
                    } => invalid(offset, bytes, reason),
                    other => other,
                })?;
                if value == F::ZERO {
                    return Err(invalid(offset, &bytes[..width], "stored zero coefficient"));
                }
                *slot = value;
            }
            previous_end = Some(start + length);
        }
        Ok(Self::from_coeffs(coeffs))
    }
}

fn read_block<'a, R: Rank>(
    reader: &mut Reader<'a>,
    index: u64,
    previous_end: Option<usize>,
) -> Result<(usize, usize), Error<'a>> {
    let offset = reader.offset();
    let header = reader.take(16)?;
    let start = u64::from_le_bytes(header[..8].try_into().expect("eight bytes"));
    let length = u64::from_le_bytes(header[8..].try_into().expect("eight bytes"));
    let invalid = |reason| Error::Value {
        offset,
        bytes: header,
        source: Box::new(InvalidBlock {
            index,
            start,
            length,
            reason,
        }),
    };
    if length == 0 {
        return Err(invalid("empty block"));
    }
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("degree overflow"))?;
    if end > R::num_coeffs() as u64 {
        return Err(invalid("block exceeds rank"));
    }
    if previous_end.is_some_and(|end| start <= end as u64) {
        return Err(invalid("blocks overlap, are unsorted, or are adjacent"));
    }
    Ok((start as usize, length as usize))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use proptest::prelude::*;
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fp;

    use super::*;
    use crate::wire::{Limits, VERSION};

    type Poly = Polynomial<Fp, TestRank>;

    fn encoded_blocks(blocks: &[(u64, u64, &[Fp])]) -> Vec<u8> {
        let mut bytes = vec![VERSION];
        (blocks.len() as u64).encode(&mut bytes);
        for (start, length, coeffs) in blocks {
            start.encode(&mut bytes);
            length.encode(&mut bytes);
            for value in *coeffs {
                <Fp as Encode<Scalar>>::encode(value, &mut bytes);
            }
        }
        bytes
    }

    #[test]
    fn encoding_ignores_storage_layout() {
        let a = Fp::from(3);
        let b = Fp::from(7);
        let dense = Poly::from_coeffs(vec![a, b, Fp::ZERO, a]);
        let split = Poly::from_coeffs(vec![a, b, Fp::ZERO, a]);
        let padded = Poly::from_coeffs(vec![a, b, Fp::ZERO, a, Fp::ZERO]);
        let expected = encoded_blocks(&[(0, 2, &[a, b]), (3, 1, &[a])]);
        assert_eq!(dense.to_bytes(), expected);
        assert_eq!(split.to_bytes(), expected);
        assert_eq!(padded.to_bytes(), expected);
        let decoded = Poly::from_bytes(&expected, Limits::default()).unwrap();
        assert!(decoded.iter_coeffs().eq(dense.iter_coeffs()));
        assert!(decoded.iter_stored_coeffs().eq(dense.iter_stored_coeffs()));
        assert_eq!(decoded.to_bytes(), expected);
        assert_eq!(
            Poly::from_coeffs(vec![Fp::ZERO; 8]).to_bytes(),
            encoded_blocks(&[])
        );
    }

    #[test]
    fn pre_udon_polynomial_encoding() {
        let bytes = include_bytes!("../../tests/fixtures/wire/polynomial.bin");
        let poly = Poly::from_coeffs(vec![Fp::ONE, Fp::ZERO, Fp::from(17), -Fp::ONE]);
        assert_eq!(poly.to_bytes(), bytes);
        let decoded = Poly::from_bytes(bytes, Limits::default()).unwrap();
        assert!(decoded.iter_coeffs().eq(poly.iter_coeffs()));
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
        let decoded = Poly::from_bytes(&from_view.to_bytes(), Limits::default()).unwrap();
        assert!(decoded.iter_stored_coeffs().eq(dense.iter_stored_coeffs()));
    }

    #[test]
    fn normalized_storage_respects_decode_budgets() {
        // Two wire runs become one three-coefficient block. The final buffer
        // must be charged in addition to the temporary decoded runs.
        let bytes = encoded_blocks(&[(0, 1, &[Fp::ONE]), (2, 1, &[Fp::ONE])]);
        for limits in [
            Limits {
                elements: 8,
                ..Limits::default()
            },
            Limits {
                allocation: 4 * core::mem::size_of::<(usize, Vec<Fp>)>()
                    + 4 * core::mem::size_of::<Fp>(),
                ..Limits::default()
            },
        ] {
            let Error::Limit {
                requested,
                remaining,
                ..
            } = Poly::from_bytes(&bytes, limits).unwrap_err()
            else {
                panic!("expected a normalization budget error")
            };
            assert!(requested > remaining);
        }

        // A distant coefficient needs a dense prefix through the public
        // constructor, and that temporary storage is included in the budget.
        let start = TestRank::num_coeffs() as u64 - 1;
        let bytes = encoded_blocks(&[(start, 1, &[Fp::ONE])]);
        assert!(matches!(
            Poly::from_bytes(
                &bytes,
                Limits {
                    elements: 4,
                    allocation: usize::MAX
                }
            ),
            Err(Error::Limit { .. })
        ));
        let decoded = Poly::from_bytes(&bytes, Limits::default()).unwrap();
        assert_eq!(
            decoded
                .iter_stored_coeffs()
                .map(|(i, v)| (i, *v))
                .collect::<Vec<_>>(),
            vec![(start as usize, Fp::ONE)]
        );
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn invalid_blocks_report_offending_values() {
        let one = Fp::ONE;
        let cases: &[(&[(u64, u64, &[Fp])], u64, &str)] = &[
            (&[(0, 0, &[])], 0, "empty block"),
            (&[(u64::MAX, 1, &[])], 0, "degree overflow"),
            (
                &[(TestRank::num_coeffs() as u64, 1, &[])],
                0,
                "block exceeds rank",
            ),
            (&[(0, 1, &[Fp::ZERO])], 0, "stored zero coefficient"),
            (
                &[(0, 1, &[one]), (1, 1, &[])],
                1,
                "blocks overlap, are unsorted, or are adjacent",
            ),
            (
                &[(2, 1, &[one]), (0, 1, &[])],
                1,
                "blocks overlap, are unsorted, or are adjacent",
            ),
            (
                &[(0, 2, &[one, one]), (1, 1, &[])],
                1,
                "blocks overlap, are unsorted, or are adjacent",
            ),
        ];
        for (blocks, bad_index, reason) in cases {
            let bytes = encoded_blocks(blocks);
            let Error::Value {
                source,
                offset,
                bytes: offending,
            } = Poly::from_bytes(&bytes, Limits::default()).unwrap_err()
            else {
                panic!("expected a block error")
            };
            let block = source.downcast_ref::<InvalidBlock>().unwrap();
            assert_eq!(block.index, *bad_index);
            assert_eq!(block.start, blocks[*bad_index as usize].0);
            assert_eq!(block.length, blocks[*bad_index as usize].1);
            assert_eq!(block.reason, *reason);
            if *reason != "stored zero coefficient" {
                assert_eq!(offending.len(), 16);
                assert_eq!(offending, &bytes[offset..offset + 16]);
            }
        }
    }

    #[test]
    fn valid_header_still_requires_coefficient_bytes() {
        let bytes = encoded_blocks(&[(0, 1, &[])]);
        let Error::Truncated {
            offset,
            requested,
            bytes: available,
        } = Poly::from_bytes(&bytes, Limits::default()).unwrap_err()
        else {
            panic!("expected missing coefficient bytes")
        };
        assert_eq!(offset, 25);
        assert_eq!(requested, 32);
        assert!(available.is_empty());
    }

    #[test]
    fn rejects_truncated_and_excessive_polynomials() {
        let bytes = Poly::from_coeffs(vec![Fp::ONE, Fp::from(2)]).to_bytes();
        for end in 0..bytes.len() {
            Poly::from_bytes(&bytes[..end], Limits::default()).unwrap_err();
        }
        let bytes = encoded_blocks(&[(0, u64::MAX, &[Fp::ONE])]);
        Poly::from_bytes(&bytes, Limits::default()).unwrap_err();
        let bytes = Poly::from_coeffs(vec![Fp::ONE; 8]).to_bytes();
        Poly::from_bytes(
            &bytes,
            Limits {
                elements: 8,
                ..Limits::default()
            },
        )
        .unwrap_err();
    }

    #[test]
    fn bad_field_bytes_identify_their_block() {
        let mut bytes = encoded_blocks(&[(0, 1, &[Fp::ONE])]);
        bytes[25..].fill(0xff);
        let Error::Value {
            source,
            offset,
            bytes: offending,
        } = Poly::from_bytes(&bytes, Limits::default()).unwrap_err()
        else {
            panic!("expected block context on the bad field")
        };
        assert_eq!(offset, 25);
        assert_eq!(offending, [0xff; 32]);
        let block = source.downcast_ref::<InvalidBlock>().unwrap();
        assert_eq!(block.index, 0);
        assert_eq!(block.reason, "non-canonical field element");
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
            prop_assert_eq!(&chunked.to_bytes(), &bytes);
            let decoded = Poly::from_bytes(&bytes, Limits::default()).unwrap();
            prop_assert!(decoded.iter_coeffs().eq(canonical.iter_coeffs()));
            prop_assert!(decoded.iter_stored_coeffs().eq(canonical.iter_stored_coeffs()));
            prop_assert_eq!(decoded.to_bytes(), bytes);
        }

        #[test]
        fn accepted_bytes_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            if let Ok(poly) = Poly::from_bytes(&bytes, Limits::default()) {
                prop_assert_eq!(poly.to_bytes(), bytes);
            }
        }
    }
}
