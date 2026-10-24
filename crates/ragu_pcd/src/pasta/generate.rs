//! Derives Ragu's generators and stores checked Udon points through Bento POD.
//!
//! `pasta_curves` supplies hash-to-curve. Compressed encodings bridge its
//! output to Udon's checked nonidentity affine points at build time. Each
//! artifact contains the vector generators in order, followed by the blinding
//! generator and the IPA's generator, stored in Udon's Montgomery
//! representation.

use std::{fs, io::Result, path::Path};

use pasta_curves::{arithmetic::CurveExt, group::GroupEncoding, pallas, vesta};
use udon::curve::{AffinePoint, Pallas, PastaCurve, Point, Vesta};

const DOMAIN_PREFIX: &str = "Ragu-Parameters";

// Copies of `pasta::DEFAULT_EP_K` and `pasta::DEFAULT_EQ_K`, which the build
// script cannot import. Bento checks the artifact lengths against the
// consumer's array types, so a mismatch is rejected at compile time.
const DEFAULT_EP_K: usize = 14;
const DEFAULT_EQ_K: usize = 14;

/// `n` vector generators from `0 || i`, then the blinding generator from `1`,
/// then the IPA's generator from `2`.
fn points_for_curve<C: PastaCurve>(
    hash: impl Fn(&[u8]) -> [u8; 32],
    n: usize,
) -> Vec<AffinePoint<C>> {
    let point = |message: &[u8]| {
        let point = Point::<C>::from_bytes(hash(message)).expect("a valid Pasta point encoding");
        *point.as_affine().expect("no generated point is identity")
    };
    let mut points = Vec::with_capacity(n + 2);
    for index in 0..u32::try_from(n).expect("generator indices fit in u32") {
        let mut message = [0u8; 5];
        message[1..].copy_from_slice(&index.to_le_bytes());
        points.push(point(&message));
    }
    points.push(point(&[1]));
    points.push(point(&[2]));
    points
}

pub(super) fn write_parameters(directory: &Path) -> Result<()> {
    let hash = pallas::Point::hash_to_curve(DOMAIN_PREFIX);
    let pallas = points_for_curve::<Pallas>(|message| hash(message).to_bytes(), 1 << DEFAULT_EP_K);
    fs::write(
        directory.join(format!("pallas-generators-v1-{}.bin", udon::STORED_FORM)),
        bento::bytes_of_slice(&pallas),
    )?;

    let hash = vesta::Point::hash_to_curve(DOMAIN_PREFIX);
    let vesta = points_for_curve::<Vesta>(|message| hash(message).to_bytes(), 1 << DEFAULT_EQ_K);
    fs::write(
        directory.join(format!("vesta-generators-v1-{}.bin", udon::STORED_FORM)),
        bento::bytes_of_slice(&vesta),
    )
}
