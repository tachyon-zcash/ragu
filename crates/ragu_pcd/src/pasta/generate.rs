//! Derives Ragu's generators and stores checked Udon points through Bento POD.
//!
//! `pasta_curves` supplies hash-to-curve. Compressed encodings bridge its
//! output to Udon's checked nonidentity affine points at build time. Each
//! table artifact contains the vector generators in order, followed by the
//! blinding generator and the IPA's generator, stored in Udon's Montgomery
//! representation; the stage artifact contains the nested curve's vector
//! generators the compression's run stages reach past the Standard table.

use std::{fs, io::Result, path::Path};

use pasta_curves::{arithmetic::CurveExt, group::GroupEncoding, pallas, vesta};
use udon::curve::{AffinePoint, Pallas, PastaCurve, Point, Vesta};

const DOMAIN_PREFIX: &str = "Ragu-Parameters";

// Copies of `pasta::DEFAULT_EP_K` and `pasta::DEFAULT_EQ_K`, which the build
// script cannot import. Bento checks the artifact lengths against the
// consumer's array types, so a mismatch is rejected at compile time.
const DEFAULT_EP_K: usize = 13;
const DEFAULT_EQ_K: usize = 13;
// Copies of the optional Aggregator table capacities, the aggregator rank's,
// checked by Bento too.
const AGGREGATOR_EP_K: usize = 15;
const AGGREGATOR_EQ_K: usize = 15;
// Copies of `pasta::STAGE_REACH` and of the aggregator rank's $n$, $2^{13}$:
// a stage trace at that rank lands the even wire of gate $g$ at degree
// $2n - 1 - g$ and the odd at $4n - 1 - g$, and the stage artifact holds the
// nested generators of the first `STAGE_REACH` gates after the SYSTEM gate,
// each range ascending.
const STAGE_REACH: usize = 256;
const STAGE_N: usize = 1 << (15 - 2);

/// A checked affine point from the hash of `message`.
fn point_of<C: PastaCurve>(hash: &impl Fn(&[u8]) -> [u8; 32], message: &[u8]) -> AffinePoint<C> {
    let point = Point::<C>::from_bytes(hash(message)).expect("a valid Pasta point encoding");
    *point.as_affine().expect("no generated point is identity")
}

/// The vector generator `index`, from `0 || index`.
fn generator<C: PastaCurve>(hash: &impl Fn(&[u8]) -> [u8; 32], index: u32) -> AffinePoint<C> {
    let mut message = [0u8; 5];
    message[1..].copy_from_slice(&index.to_le_bytes());
    point_of(hash, &message)
}

/// `n` vector generators from `0 || i`, then the blinding generator from `1`,
/// then the IPA's generator from `2`.
fn points_for_curve<C: PastaCurve>(
    hash: impl Fn(&[u8]) -> [u8; 32],
    n: usize,
) -> Vec<AffinePoint<C>> {
    let mut points = Vec::with_capacity(n + 2);
    for index in 0..u32::try_from(n).expect("generator indices fit in u32") {
        points.push(generator(&hash, index));
    }
    points.push(point_of(&hash, &[1]));
    points.push(point_of(&hash, &[2]));
    points
}

/// The vector generators of the stage reach: those of the first
/// `STAGE_REACH` gates' even wires, then of their odd wires, each range in
/// ascending index.
fn stage_points<C: PastaCurve>(hash: impl Fn(&[u8]) -> [u8; 32]) -> Vec<AffinePoint<C>> {
    (2 * STAGE_N - 1 - STAGE_REACH..2 * STAGE_N - 1)
        .chain(4 * STAGE_N - 1 - STAGE_REACH..4 * STAGE_N - 1)
        .map(|index| {
            generator(
                &hash,
                u32::try_from(index).expect("stage indices fit in u32"),
            )
        })
        .collect()
}

fn write_tables(directory: &Path, name: &str, ep_k: usize, eq_k: usize) -> Result<()> {
    let hash = pallas::Point::hash_to_curve(DOMAIN_PREFIX);
    let pallas = points_for_curve::<Pallas>(|message| hash(message).to_bytes(), 1 << ep_k);
    fs::write(
        directory.join(format!(
            "pallas-generators-{name}-{}.bin",
            udon::STORED_FORM
        )),
        bento::bytes_of_slice(&pallas),
    )?;

    let hash = vesta::Point::hash_to_curve(DOMAIN_PREFIX);
    let vesta = points_for_curve::<Vesta>(|message| hash(message).to_bytes(), 1 << eq_k);
    fs::write(
        directory.join(format!("vesta-generators-{name}-{}.bin", udon::STORED_FORM)),
        bento::bytes_of_slice(&vesta),
    )
}

fn write_stage_table(directory: &Path) -> Result<()> {
    let hash = pallas::Point::hash_to_curve(DOMAIN_PREFIX);
    let pallas = stage_points::<Pallas>(|message| hash(message).to_bytes());
    fs::write(
        directory.join(format!(
            "pallas-generators-stages-v1-{}.bin",
            udon::STORED_FORM
        )),
        bento::bytes_of_slice(&pallas),
    )
}

pub(super) fn write_parameters(directory: &Path, aggregator: bool) -> Result<()> {
    write_tables(directory, "v1", DEFAULT_EP_K, DEFAULT_EQ_K)?;
    write_stage_table(directory)?;
    if aggregator {
        write_tables(directory, "aggregator-v1", AGGREGATOR_EP_K, AGGREGATOR_EQ_K)?;
    }
    Ok(())
}
