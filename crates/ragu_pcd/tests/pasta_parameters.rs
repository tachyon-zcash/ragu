//! Pin the embedded generators independently of their derivation and storage
//! representation by comparing their canonical coordinates with the original.

use ragu_core::{
    Cycle, FixedGenerators,
    pasta::{Pasta, PastaParams},
};
use ragu_pcd::ipa::IpaCycle;
use udon::{curve::Affine, field::Field};

/// The canonical coordinates of the first `vector` vector generators and the
/// blinding generator of both curves, nested then host.
fn canonical_blob(params: &PastaParams, vector: usize) -> Vec<u8> {
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

    let mut loaded = Vec::new();
    append(&mut loaded, Pasta::nested_generators(params), vector);
    append(&mut loaded, Pasta::host_generators(params), vector);
    loaded
}

/// The complete Standard tables retain their original size and values, even
/// when the optional Aggregator tables are also compiled into this binary.
#[test]
fn baked_points_match_original_parameters() {
    let params = ragu_pcd::pasta::baked();
    assert_eq!(Pasta::nested_generators(params).g().len(), 1 << 13);
    assert_eq!(Pasta::host_generators(params).g().len(), 1 << 13);
    let loaded = canonical_blob(params, 1 << 13);
    assert_eq!(loaded.len(), 16_386 * 64);

    // BLAKE2b-256 of the original canonical generator blob at Ragu commit
    // 4df34e723c4ee3a1541921aa24821ff86daf4c76, before the Udon migration.
    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "f5b1146e2b607c83dcfd8630d117af24c8ea12593395a764100d81efca818ef2"
    );
}

/// The optional Aggregator tables, $2^{15}$ vector generators per curve for
/// the aggregator rank, pinned in full.
#[cfg(feature = "baked-aggregator")]
#[test]
fn aggregator_points_are_pinned_in_full() {
    let params = ragu_pcd::pasta::baked_aggregator();
    assert_eq!(Pasta::nested_generators(params).g().len(), 1 << 15);
    assert_eq!(Pasta::host_generators(params).g().len(), 1 << 15);
    let loaded = canonical_blob(params, 1 << 15);
    assert_eq!(loaded.len(), 65_538 * 64);

    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "a2d16c4588ec5814cf2ceb17af275f42729d5357ce7ca991ab01cfb5493a8db3"
    );
}

/// Both parameter sets use identical vector prefixes and blinding generators;
/// loading Aggregator parameters does not replace or enlarge Standard's tables.
#[cfg(feature = "baked-aggregator")]
#[test]
fn aggregator_parameters_preserve_standard_tables() {
    let standard = ragu_pcd::pasta::baked();
    let before = canonical_blob(standard, 1 << 13);
    let aggregator = ragu_pcd::pasta::baked_aggregator();
    assert_eq!(before, canonical_blob(aggregator, 1 << 13));
    assert!(core::ptr::eq(standard, ragu_pcd::pasta::baked()));
    assert!(!core::ptr::eq(standard, aggregator));
    assert_eq!(Pasta::nested_generators(standard).g().len(), 1 << 13);
    assert_eq!(Pasta::host_generators(standard).g().len(), 1 << 13);
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

/// The stage reach baked into the Standard parameters: the nested
/// generators of the first `STAGE_REACH` gates of a stage trace at the
/// aggregator rank, which the compression's runs land on past the Standard
/// table, pinned in full and, under the Aggregator tables, the same points
/// as the table's at those indices.
#[test]
fn stage_reach_is_pinned() {
    use ragu_pcd::pasta::STAGE_REACH;

    let params = ragu_pcd::pasta::baked();
    let n = 1usize << 13;
    let indices: Vec<usize> = (2 * n - 1 - STAGE_REACH..2 * n - 1)
        .chain(4 * n - 1 - STAGE_REACH..4 * n - 1)
        .collect();
    let mut loaded = Vec::new();
    for &index in &indices {
        let point = Pasta::nested_generator(params, index).expect("within the stage reach");
        let (x, y) = point.coordinates().expect("nonidentity generator");
        loaded.extend_from_slice(x.to_bytes().as_ref());
        loaded.extend_from_slice(y.to_bytes().as_ref());
    }
    assert_eq!(loaded.len(), 2 * STAGE_REACH * 64);
    assert_eq!(Pasta::nested_generator(params, 2 * n - 1), None);
    assert_eq!(Pasta::nested_generator(params, 4 * n - 1), None);
    assert_eq!(
        Pasta::nested_generator(params, 2 * n - 2 - STAGE_REACH),
        None
    );

    let digest = blake2b_simd::Params::new().hash_length(32).hash(&loaded);
    assert_eq!(
        digest.to_hex().as_str(),
        "8dfdb0d3662c659dac55b3cc6cc9e24fc5b6f64a65df83ac663bed7a0b40105c"
    );

    #[cfg(feature = "baked-aggregator")]
    {
        let table = Pasta::nested_generators(ragu_pcd::pasta::baked_aggregator()).g();
        for &index in &indices {
            assert_eq!(Pasta::nested_generator(params, index), Some(table[index]));
        }
    }
}
