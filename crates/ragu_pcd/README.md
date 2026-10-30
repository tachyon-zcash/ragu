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

Serialization lives entirely in this crate: a private schema macro declares
each `Proof` field as retained, with its codec, or derived, and an internal
`wire` module owns the byte codecs. A proof's encoding holds the retained
fields alone. Decoding yields a `Proof` whose derived fields, the nine
transcript challenges and two stages, the application recomputes when one of
its methods (`fuse`, `compress` or a verifier) first takes the proof, so they
are never read from untrusted bytes.

Every encoding has one length, fixed by the application's profile, rank and
header size: no count or length is read from the payload, and polynomials are
dense. For storage or transport, create `Application::proof_format(ProofContext)`
using suite and application identifiers from your trusted setup manifest.
`ProofFormat::encode` writes the versioned envelope and proof payload;
`ProofFormat::decode` rejects any other length before reading a byte, then
checks versions, rank, header size, an explicit profile tag and context before
allocating proof data. A receiver then compresses the decoded proof and accepts
it on `Application::verify_compressed`.

[WIRE_FORMAT.md](WIRE_FORMAT.md) specifies schema v1, version changes, context
requirements and the length formula. `ProofFormat::encode_compressed` and
`decode_compressed` carry the IPA representation under payload kind 2 in the
same envelope. Attach the accompanying data with `carry` and verify with
`verify_compressed`. `compressed_encoded_len` gives the exact transport size
before reading.

With the `serde` feature, `Proof` and `CompressedProof` implement `Serialize`
and `Deserialize` directly: the same payload behind a short prelude recording
the rank and header size, for embedding in a container that supplies its own
context. Deserialization accepts exactly the length the prelude implies and
ignores untrusted sequence size hints.

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
