//! The wire format: byte round trips of production-rank proofs through the
//! application's envelope, the compressed transport path and the serde
//! adapters.
//!
//! `malformed_proofs.rs` and `validation.rs` beside these edit a proof's
//! private fields, so `proof/codec.rs` mounts them into the crate's own
//! tests instead of this target.

#[allow(dead_code)]
#[path = "../nontrivial_support.rs"]
mod nontrivial_support;

mod compressed;
mod format;
#[cfg(feature = "serde")]
mod serde;

/// The envelope ahead of every payload, under envelope version 3.
const ENVELOPE: usize = 28;

type TestProof =
    ragu_pcd::Proof<nontrivial_support::C, ragu_pcd::Uncompressed<nontrivial_support::R>>;
type TestCompressed = ragu_pcd::Proof<nontrivial_support::C, ragu_pcd::Compressed>;

/// A consumer generic over the form needs neither a proof trait nor an
/// associated carried type. Exercise every shared operation on both forms.
fn roundtrip<C, F, H>(pcd: &ragu_pcd::Pcd<C, F, H>) -> ragu_pcd::Pcd<C, F, H>
where
    C: ragu_pcd::profile::ProfiledCycle,
    F: ragu_pcd::Form,
    H: ragu_pcd::header::Header<C::CircuitField>,
{
    let (proof, data) = pcd.clone().into_parts();
    let bytes = proof.to_bytes().unwrap();
    let decoded = ragu_pcd::Proof::<C, F>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
    assert_eq!(decoded.online_commitments(), proof.online_commitments());
    let carried = decoded.carry::<H>(data);
    assert_eq!(carried.commitments(), pcd.commitments());
    assert_eq!(carried.online_commitments(), pcd.online_commitments());
    carried
}
