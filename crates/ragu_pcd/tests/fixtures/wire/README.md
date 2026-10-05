# Pre-Udon proof fixture

`pre_udon_proof.bin` is a complete serialized leaf proof produced by source
commit `887e0abc39e0f04ea6cdb0798a02e6420b056a66`, before the Udon port.
`pre_udon_header.bin` contains its accompanying field-valued header, encoded
with the old scalar codec including its outer version byte.

The source test harness is `crates/ragu_pcd/tests/nontrivial_support.rs` at
that commit: Pasta, `ProductionRank`, header size 4, the registered
`WitnessLeaf`, `Hash2`, and `Merge2` application. The leaf uses witness 7 and
`StdRng::seed_from_u64(0x5eed)`. The old verifier accepted it before capture.

To reproduce in a checkout of that commit, append this test to
`crates/ragu_pcd/tests/wire.rs`, create an `artifacts` directory in the
`crates/ragu_pcd` package, and run
`cargo test -p ragu_pcd --release --test wire capture_pre_udon -- --exact`:

```rust
#[test]
fn capture_pre_udon() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (proof, data) = leaf(&app, &mut rng, 7).into_parts();
    assert!(app.verify(&proof.clone().carry::<LeafNode>(data), &mut rng).unwrap());
    std::fs::write("artifacts/proof.bin", proof.compress().to_bytes()).unwrap();
    std::fs::write(
        "artifacts/header.bin",
        <ragu_pasta::Fp as Encode<ragu_primitives::wire::Scalar>>::to_bytes(&data),
    ).unwrap();
}
```

SHA-256 and byte lengths:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `pre_udon_proof.bin` | 11521101 | `3aeb40fe2eabff9463f619547dd04659d275de4495741e447a3f42a2cf3d0ae7` |
| `pre_udon_header.bin` | 33 | `1ce9b256d684bbe7ff63c483e14ac080a17a740674b3513d667450b083c5cc36` |

The current `pre_udon_proof_decodes_and_verifies` test decodes these exact
bytes, requires byte-identical re-encoding, and verifies against the matching
application and header. This covers one complete proof across the migration;
future schema changes follow the versioning contract in `../../../WIRE_FORMAT.md`.

The scalar (`fp.bin`, `fq.bin`), point (`pallas.bin`, `vesta.bin`), and
`polynomial.bin` fixtures were also captured at `887e0abc`, originally under
`ragu_primitives` and `ragu_circuits`. They now live here with their codec tests;
their bytes were moved unchanged when serialization was isolated in `ragu_pcd`.
