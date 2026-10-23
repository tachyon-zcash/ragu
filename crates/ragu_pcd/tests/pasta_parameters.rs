//! Pin the embedded generators independently of their derivation and storage
//! representation by comparing their canonical coordinates with the original.

use ragu_core::{Cycle, FixedGenerators, pasta::Pasta};
use ragu_pcd::ipa::IpaCycle;
use udon::{curve::Affine, field::Field};

/// The canonical coordinates of the first `vector` vector generators and the
/// blinding generator of both curves, nested then host.
fn canonical_blob(vector: usize) -> Vec<u8> {
    fn append<C: Affine<Base: Field>>(
        out: &mut Vec<u8>,
        generators: &impl FixedGenerators<C>,
        vector: usize,
    ) {
        for point in generators.g()[..vector].iter().chain([generators.h()]) {
            let (x, y) = point.coordinates().expect("nonidentity generator");
            out.extend_from_slice(x.to_bytes().as_ref());
            out.extend_from_slice(y.to_bytes().as_ref());
        }
    }

    let params = ragu_pcd::pasta::baked();
    let mut loaded = Vec::new();
    append(&mut loaded, Pasta::nested_generators(params), vector);
    append(&mut loaded, Pasta::host_generators(params), vector);
    loaded
}

/// The production rank's generators, the first $2^{13}$ of each table and
/// the blinding generator, are the original ones: a proof at that rank is
/// unchanged by the tables growing for the aggregator rank.
#[test]
fn baked_points_match_original_parameters() {
    let loaded = canonical_blob(1 << 13);
    assert_eq!(loaded.len(), 16_386 * 64);

    // BLAKE2b-256 of the original canonical generator blob at Ragu commit
    // 4df34e723c4ee3a1541921aa24821ff86daf4c76, before the Udon migration.
    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "f5b1146e2b607c83dcfd8630d117af24c8ea12593395a764100d81efca818ef2"
    );
}

/// The whole tables, $2^{15}$ vector generators per curve for the aggregator
/// rank, pinned the same way.
#[test]
fn baked_points_are_pinned_for_the_aggregator_rank() {
    let loaded = canonical_blob(1 << 15);
    assert_eq!(loaded.len(), 65_538 * 64);

    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "a2d16c4588ec5814cf2ceb17af275f42729d5357ce7ca991ab01cfb5493a8db3"
    );
}

/// The IPA's generators are hash-to-curve outputs on the message `2`, after
/// the vector generators' `0 || i` and the blinding generator's `1`, so
/// their canonical coordinates are pinned the same way.
#[test]
fn baked_ipa_generators_are_pinned() {
    fn append<C: Affine<Base: Field>>(out: &mut Vec<u8>, point: &C) {
        let (x, y) = point.coordinates().expect("nonidentity generator");
        out.extend_from_slice(x.to_bytes().as_ref());
        out.extend_from_slice(y.to_bytes().as_ref());
    }

    let params = ragu_pcd::pasta::baked();
    let mut loaded = Vec::new();
    append(&mut loaded, Pasta::nested_u(params));
    append(&mut loaded, Pasta::host_u(params));
    assert_eq!(loaded.len(), 2 * 64);

    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "53ae67b2466d46ac35933f2e2f8ada4e66b67b88bfba180473eaab3cfca7e3ae"
    );
}
