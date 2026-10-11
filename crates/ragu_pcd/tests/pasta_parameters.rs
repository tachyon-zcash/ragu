//! Pin the original generator prefix independently of derivation and storage
//! representation by comparing its canonical coordinates with the original.

use ragu_core::{Cycle, FixedGenerators, pasta::Pasta};
use ragu_pcd::ipa::IpaCycle;
use udon::{curve::Affine, field::Field};

#[test]
fn baked_points_match_original_parameters() {
    fn append<C: Affine<Base: Field>>(out: &mut Vec<u8>, generators: &impl FixedGenerators<C>) {
        // The increased production rank extends the vector generators; its
        // first 8192 entries and blinding generator retain the original values.
        for point in generators.g().iter().take(1 << 13).chain([generators.h()]) {
            let (x, y) = point.coordinates().expect("nonidentity generator");
            out.extend_from_slice(x.to_bytes().as_ref());
            out.extend_from_slice(y.to_bytes().as_ref());
        }
    }

    let params = ragu_pcd::pasta::baked();
    let mut loaded = Vec::new();
    append(&mut loaded, Pasta::nested_generators(params));
    append(&mut loaded, Pasta::host_generators(params));
    assert_eq!(loaded.len(), 16_386 * 64);

    // BLAKE2b-256 of the original canonical generator blob at Ragu commit
    // 4df34e723c4ee3a1541921aa24821ff86daf4c76, before the Udon migration.
    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "f5b1146e2b607c83dcfd8630d117af24c8ea12593395a764100d81efca818ef2"
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
