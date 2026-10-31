# PCD proof format: envelope v2, payload schemas v1

`Application::proof_format` selects a format using trusted `ProofContext`
identifiers. The profile, rank and header size determine each payload's length.
`encoded_len` gives the complete proof size; `compressed_encoded_len` gives the
complete compressed-proof size. With the `serde` feature, `Proof` and
`CompressedProof` also serialize directly, as the same payloads behind a short
prelude (see [Serde](#serde)).

Both encoders check the proof's structure before writing. Both decoders check
exact length first, then the envelope, then canonical field and point encodings.
Decoding does not establish cryptographic validity. A decoded proof holds the
fields its payload retains; the application derives the rest when one of its
methods first takes the proof. Compress it before calling
`Application::verify_compressed`. For a compressed proof, attach the
accompanying header data and call that verifier directly. Header data is not
included in these bytes.

## Envelope

All integers are unsigned little-endian. The header is exactly 124 bytes.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic: `52 41 47 55 50 43 44 00` (`RAGUPCD` plus NUL) |
| 8 | 2 | Envelope version: 2 |
| 10 | 2 | Payload kind: 1 proof, 2 compressed |
| 12 | 2 | Schema version of that payload kind: 1 |
| 14 | 2 | Verification protocol version: 1 (`ragu-pcd-v1`) |
| 16 | 4 | Polynomial rank exponent (`Rank::RANK`) |
| 20 | 8 | Application header size in field elements |
| 28 | 32 | Profile tag |
| 60 | 32 | Suite identifier |
| 92 | 32 | Application/setup identifier |
| 124 | remainder | The payload, without an additional version byte |

Each header component must exactly match the expected value. Unknown versions
are rejected; there is no heuristic interpretation or automatic downgrade.

The profile tag is BLAKE2b-256 of the UTF-8 bytes of the receiving
`Profile::NAME`, personalized with `ragu-profile-v1` (zero-padded to BLAKE2b's
16-byte personalization field). The name must be stable and unique as required
by `Profile`. This checks the profile independently of the application ID,
even when profiles have the same layout. The tag does not authenticate the
profile's implementation or replace the complete setup manifest.

Envelope v1 (92 bytes, without the profile tag) is not accepted by this decoder.
There is no implicit fallback; migrate by decoding with the old format and
re-encoding under the intended current setup after verification.

The two identifiers come from the receiver's trusted deployment manifest,
never from the received envelope. They should be collision-resistant digests
of canonically encoded manifests. The suite manifest identifies the ordered
curves and fields, their canonical byte encodings, generators, and Poseidon
parameters. The application manifest identifies the ordered circuits,
registry setup including tags, and accompanying data/header semantics. Rank
and header size are additionally checked explicitly. Assign a new identifier
when any identified configuration changes. Ragu cannot infer these manifests
from Rust type names and does not compute these caller-owned identifiers.
An identifier match is a context check, not authentication or verification.

## Version and compatibility rules

This initial format targets the protocol after #897 (`2ed70cf9`), including
143-bit endoscalars. The shape and protocol pin also checks that width: transcript
tags alone do not identify this change. Application manifests must identify the
current registry and challenge semantics; pre-#897 setup identifiers must not be
reused for the updated protocol.

Schema v1 fixes the field order below, codec encodings, the standard profile's
shape (its vector sizes), and classification of retained and omitted fields. Changes to these require a
new schema version and explicit decoder dispatch. Envelope layout changes
require a new envelope version. Incompatible transcript or verification
semantics require a new protocol version here and a new tag for the affected
transcript (`RAGU_TAG` for fuse, `IPA_TAG` for compression).
A crate release or an implementation optimization alone changes none of these.
Never reinterpret an old version using a new layout or new verifier semantics.

Preserve the envelope tests when adding versions. Supporting an old schema
requires an explicit migration path and compatibility tests; an unsupported
old version must fail closed.

## Payload codecs

No length or count appears in the payload. The schema fixes the field order,
the rank fixes every polynomial's coefficient count, the application's header
size fixes both child headers, and the application's profile fixes every
vector count: the four native binders, each side's endoscaling steps and each
side's extension circuits and stages (`profile::Shape`; the standard profile
has 23 native and 26 nested steps and no extension). A decoder therefore reads
a known number of bytes for each field and a payload of another length is not
an encoding of anything.

Integers have their declared fixed widths; circuit indices are `u32`. Field
elements and compressed points use the canonical representations specified by
the suite, with decode/re-encode equality checks, so each value has one
spelling. The identity is rejected in every point slot: the verifier allocates
each point by its coordinates. Cached points encode only the point. An `Arc` encodes its value,
without ownership metadata.

A polynomial is its `2^rank` coefficients in ascending degree order, zeros
included. This is independent of the sparse in-memory storage and its gap
tolerance. A fixed sequence is its elements, one after another. A child header
is its `HEADER_SIZE` field elements.

The envelope decoder never accepts a bare payload, nor the Serde framing.

Fields appear in the following order. `C::CircuitField` is the native field;
`C::ScalarField` is the nested field. Host and nested curves follow the suite's
ordered cycle. The two derived stages and nine transcript challenges are
absent. Field names identify the schema; Rust names are not encoded.

| Field | Payload type / codec |
| --- | --- |
| `bridge_alpha` | `C::ScalarField`; `Scalar` |
| `circuit_id` | `CircuitIndex` |
| `left_header` | `Vec<C::CircuitField>`; `SizedSequence<Scalar, HeaderSize>` |
| `right_header` | `Vec<C::CircuitField>`; `SizedSequence<Scalar, HeaderSize>` |
| `native_application_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_preamble_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_inner_error_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_outer_error_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_a_poly` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_b_poly` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_query_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_registry_xy_poly` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_eval_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_p_poly` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_hashes_1_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_hashes_2_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_collapse_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_compute_v_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_bind_challenges_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `FixedSequence<DefaultEncoding, ConstLen<{ native::NUM_BINDERS }>>` |
| `native_bind_beta_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_bind_endoscalar_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_endoscaling_step_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `FixedSequence<DefaultEncoding, native::NumSteps<C::Profile>>` |
| `native_extension_circuit_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `FixedSequence<DefaultEncoding, native::NumExtensionCircuits<C::Profile>>` |
| `native_extension_stage_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `FixedSequence<DefaultEncoding, native::NumExtensionStages<C::Profile>>` |
| `native_points_binding_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_points_children_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_points_registry_wx_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_points_ab_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_points_f_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_points_walk_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `bridge_preamble_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_s_prime_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_inner_error_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_outer_error_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_query_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_f_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `bridge_eval_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `nested_endoscaling_step_rxs` | `Vec<sparse::Polynomial<C::ScalarField, R>>`; `FixedSequence<DefaultEncoding, nested::NumSteps<C::Profile>>` |
| `nested_extension_circuit_rxs` | `Vec<sparse::Polynomial<C::ScalarField, R>>`; `FixedSequence<DefaultEncoding, nested::NumExtensionCircuits<C::Profile>>` |
| `nested_extension_stage_rxs` | `Vec<sparse::Polynomial<C::ScalarField, R>>`; `FixedSequence<DefaultEncoding, nested::NumExtensionStages<C::Profile>>` |
| `nested_endoscalar_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_points_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `nested_a_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_b_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_registry_xy_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_p_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_challenges_partial` | `C::NestedCurve`; `Point` |
| `nested_collapse_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_compute_v_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_endoscaling_step_commitments` | `Vec<Cached<C::NestedCurve>>`; `FixedSequence<CachedPoint, nested::NumSteps<C::Profile>>` |
| `nested_extension_circuit_commitments` | `Vec<Cached<C::NestedCurve>>`; `FixedSequence<CachedPoint, nested::NumExtensionCircuits<C::Profile>>` |
| `nested_extension_stage_commitments` | `Vec<Cached<C::NestedCurve>>`; `FixedSequence<CachedPoint, nested::NumExtensionStages<C::Profile>>` |
| `nested_endoscalar_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_points_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_a_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_b_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_registry_xy_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_p_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_challenges_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_collapse_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_compute_v_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `native_application_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_preamble_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_inner_error_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_outer_error_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_a_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_b_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_query_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_registry_xy_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_eval_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_p_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_hashes_1_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_hashes_2_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_collapse_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_compute_v_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_bind_challenges_commitments` | `Vec<Cached<C::HostCurve>>`; `FixedSequence<CachedPoint, ConstLen<{ native::NUM_BINDERS }>>` |
| `native_bind_beta_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_bind_endoscalar_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_endoscaling_step_commitments` | `Vec<Cached<C::HostCurve>>`; `FixedSequence<CachedPoint, native::NumSteps<C::Profile>>` |
| `native_extension_circuit_commitments` | `Vec<Cached<C::HostCurve>>`; `FixedSequence<CachedPoint, native::NumExtensionCircuits<C::Profile>>` |
| `native_extension_stage_commitments` | `Vec<Cached<C::HostCurve>>`; `FixedSequence<CachedPoint, native::NumExtensionStages<C::Profile>>` |
| `native_points_binding_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_children_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_registry_wx_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_ab_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_f_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_walk_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `bridge_preamble_commitment` | `C::NestedCurve`; `Point` |
| `bridge_s_prime_commitment` | `C::NestedCurve`; `Point` |
| `bridge_inner_error_commitment` | `C::NestedCurve`; `Point` |
| `bridge_outer_error_commitment` | `C::NestedCurve`; `Point` |
| `bridge_query_commitment` | `C::NestedCurve`; `Point` |
| `bridge_f_commitment` | `C::NestedCurve`; `Point` |
| `bridge_eval_commitment` | `C::NestedCurve`; `Point` |
| `bridge_ab_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |

## Length

Let N = `2^rank`, H the header size, s the element width of the suite (32
bytes for Pasta fields and compressed points), and P the polynomial count of
the profile's shape (`Shape::polynomials`; 92 for the standard profile). Schema
v1 retains P − 2 polynomials (every one but the two derived stages), P + 1
points (a commitment per polynomial and the nested challenges partial), two
child headers, one scalar and one `u32` circuit index. The payload is therefore

    (P − 2) · N · s + (P + 1) · s + 2 · H · s + s + 4

bytes, and the complete encoding adds the 124-byte envelope. At rank 13 with
Pasta, the standard profile and a four-element header this is 23,596,228 bytes
of payload. The test `encoded_length_is_a_function_of_profile_rank_and_header_size`
pins this formula and `schema_v1_pins_protocol_and_shape` the shape.

Decoding allocates one coefficient vector per polynomial, of N elements, only
after confirming the input holds the whole encoding; nothing is sized from the
input. Transport should bound buffered input to `ProofFormat::encoded_len`
before reading it, and may compress the bytes in flight: dense polynomials
compress well, and the fixed decoded length bounds the inflated size exactly.

## Compressed payload (kind 2, schema 1)

`ProofFormat::compressed_encoded_len`, `encode_compressed`, and
`decode_compressed` use the same 124-byte envelope. The payload kind is checked
before decoding, and the two representations cannot be interchanged. Attach
the separately transmitted output data with `CompressedProof::carry` and call
`Application::verify_compressed`; decoding never establishes validity.

The instance comes first, followed by the native and nested messages. Instance
field order is `circuit_id`, left and right headers, native commitments,
`native_registry_xy`, `native_p`, nested commitments, `nested_registry_xy`,
`nested_p`, `nested_challenges_partial`, `bridge_alpha`, `c`, `v`, `nested_c`,
`nested_v`, left and right child triples `(x,y,id)`, `a_at_u`, `b_at_u`, nested
left and right child pairs `(x,y)`, `nested_a_at_u`, `nested_b_at_u`.
The component vectors follow `native_components` and `nested_components` for
the receiving profile; headers have the receiving application's fixed size.

Each side's messages have this order:

1. Fold inner and outer commitments, then inner and outer epsilon scalars.
2. Reduction p and q commitments, five derived openings in `Derived::ALL`
   order, then `p_at_inverse_r` and `q_at_r`.
3. Batch f commitment and eleven evaluations (five derived polynomials, p, q,
   and the four instance openings).
4. IPA masking commitment, exactly `Rank::RANK` pairs `(L,R)`, and final c.

Points are canonical compressed nonidentity points, scalars are canonical field
elements, and the circuit id is a little-endian u32. There are no vector counts.
The instance uses 93 points and 27 scalars for Standard/Pasta/header-size 4;
each side adds `6 + 2*rank` points and 21 scalars. At rank 13, the envelope and
payload together occupy 7,360 bytes. Other profiles obtain counts from their
component iterators, not from this example. The receiving setup manifest must
identify the profile and both transcript parameter sets as well as the circuits.

## Serde

With the `serde` feature, `Proof` and `CompressedProof` implement `Serialize`
and `Deserialize`. Each is one byte string, so every Serde data format carries
the same bytes:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 1 | Codec version: 1 |
| 1 | 4 | Polynomial rank exponent (`Rank::RANK`) |
| 5 | 8 | Header size in field elements |
| 13 | remainder | The payload, exactly as under the envelope |

Neither type carries its header size, and a compressed proof does not carry its
rank, so this prelude records them. A proof's rank must equal its type's; a
compressed proof's may be at most 32, and the header size at most 4096. The
prelude fixes the exact length, which deserialization checks before decoding
the payload, and formats without a bytes type are buffered only up to it,
ignoring sequence size hints. Serializing a value whose headers or rounds
disagree in length is an error: no prelude describes it.

The prelude is not a trusted context. It identifies no suite, application or
profile, so use it only inside a container that supplies its own context, and
prefer `ProofFormat` for storage and transport. As there, a deserialized
`Proof` holds the retained fields alone.

## Structural preflight and fuzz coverage

The same codec declarations generate retained-field validation for proofs and
for compressed messages. Fixed vectors check their expected length before
traversal; point slots reject identity. Every application method that takes a
proof (fusion, compression and verification) first checks its shape, then
derives a decoded proof's omitted fields: its challenges are reconstructed from
the bridge commitments, since they are not carried in the payload, and a
decoded proof whose challenges have no lift is rejected.

Malformed proof failures become `Ok(false)` at the verification boundary.
Decoders continue to return representation errors, and application header or
computation errors propagate rather than being disguised as invalid proofs.
This is structural validation, not a replacement for cryptographic verification.

`qa/fuzz` provides `fuzz_proof_wire` and `fuzz_compressed_wire`. Each exercises
raw bytes and bounded mutations of a valid proof generated once per process.
Successful decoding must re-encode identically and is followed by the production
verification path (including derivation and compression for proofs).
Mutations are not assumed invalid: the oracle checks canonicality, absence of
panics, and acceptance of the unmodified seed. No complete proof blobs are stored.

Both targets are registered in the scheduled fuzz and coverage matrices. Rust CI
runs the shared decode-to-verify smoke test and replays the small committed
control inputs through both target binaries. From `qa/fuzz`, the smoke test is:

```sh
cargo test --release --locked --lib proof_wire::tests::decode_to_verify_smoke -- --ignored --exact
```

The PCD regression suite also decodes a child, folds it into a new proof, then
compresses and verifies that result. Golden proof bytes, RNG tapes
and verifier fingerprints remain separate work.

## Encoding precedents

The Orchard codecs separate canonical element readers from bundle parsing and
use `Bundle::try_from_parts` to enforce the expected proof size. See
[librustzcash's bundle reader](https://github.com/zcash/librustzcash/blob/main/zcash_primitives/src/transaction/components/orchard.rs)
and [Orchard's proof size calculation](https://github.com/zcash/orchard/blob/main/src/lib.rs).
The caller selects [BundleVersion](https://github.com/zcash/orchard/blob/main/src/bundle.rs)
from trusted context.

Ragu follows those boundaries: element codecs enforce canonical representations,
the envelope checks the receiver's context, and verification establishes proof
validity. Orchard carries length prefixes for vectors; Ragu's receiving types
fix all payload lengths, so its decoder needs no counts from the input.
