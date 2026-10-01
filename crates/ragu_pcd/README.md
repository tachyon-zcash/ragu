<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

# `ragu_pcd`

This crate contains internal implementation code for the [`ragu`](https://crates.io/crates/ragu) crate.

The [`pasta`](src/pasta/) module owns Ragu's fixed generator derivation and
loading. With the `baked` feature, `build.rs` derives the generators on the host
using `pasta_curves` only for hash-to-curve, converts them to checked Udon points,
and writes them through Bento POD. The runtime embeds those typed points with
Bento; `pasta::baked()` adapts them once into Udon's parameter containers without
decoding coordinates. The derivation preserves Ragu's existing generators. The
feature enables `alloc` and supports `no_std`.

## Proof serialization

`Proof::minimize` produces the retained `MinimalProof` representation.
`Proof::into_minimal` moves its fields when the expanded proof is no longer
needed, avoiding polynomial-buffer clones. Both methods come from
`ragu_primitives::wire::Minimize`.

For storage or transport, create `Application::proof_format(ProofContext)`
using suite and application identifiers from your trusted setup manifest.
`ProofFormat::encode` writes the versioned envelope and proof payload;
`ProofFormat::decode` checks versions, rank, header size and context before
allocating proof data. Call `Application::verify_minimal` with the accompanying
header data to accept or reject the decoded proof.

[WIRE_FORMAT.md](WIRE_FORMAT.md) specifies schema v1, version changes, context
requirements, resource bounds and migration. The pre-Udon full-proof fixture
pins the unchanged low-level payload; a separate envelope test pins its header.
The IPA representation in [#462](https://github.com/tachyon-zcash/ragu/pull/462)
requires its own codec integration.

The optional Serde adapter on `MinimalProof` carries the low-level payload
for embedding in an already context-bound container. It uses rank-derived
encoded-byte and decoded-storage limits and ignores untrusted sequence size
hints. Applications must separately limit transport/deserializer buffering.
`ProofFormat::decode_with_limits` supports stricter deployment budgets.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
