# PCD proof format v1

`Application::proof_format` selects an envelope using trusted `ProofContext`
identifiers. `encode` checks structure and writes the envelope and minimal
payload. `decode` checks the envelope before reading the payload, enforces
resource bounds and rejects malformed structure or trailing bytes. Acceptance
still requires `Application::verify_minimal` with the accompanying header data.
The accompanying data is not included in these proof bytes.

## Envelope

All integers are unsigned little-endian. The header is exactly 90 bytes.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | Magic: `52 41 47 55 50 43 44 00` (`RAGUPCD` plus NUL) |
| 8 | 2 | Envelope version: 1 |
| 10 | 2 | Minimal-proof schema version: 1 |
| 12 | 2 | Verification protocol version: 1 (`ragu-pcd-v1`) |
| 14 | 4 | Polynomial rank exponent (`Rank::RANK`) |
| 18 | 8 | Application header size in field elements |
| 26 | 32 | Suite identifier |
| 58 | 32 | Application/setup identifier |
| 90 | remainder | Minimal-proof payload, without an additional version byte |

Each header component must exactly match the expected value. Unknown versions
are rejected; there is no heuristic interpretation or automatic downgrade.

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

Schema v1 fixes the field order below, codec encodings, protocol vector sizes,
and classification of retained and omitted fields. Changes to these require a
new schema version and explicit decoder dispatch. Envelope layout changes
require a new envelope version. Incompatible transcript or verification
semantics require both a new protocol version here and a new `RAGU_TAG`.
A crate release or an implementation optimization alone changes none of these.
Never reinterpret an old version using a new layout or new verifier semantics.

Preserve the golden payload and envelope tests when adding versions. Supporting
an old schema requires an explicit migration path and compatibility tests; an
unsupported old version must fail closed. Schema v1 retains the exact payload
captured before the Udon migration. `tests/fixtures/wire/README.md` documents
its independently reproduced source and checksums. The fixture demonstrates
one concrete proof's compatibility; the specification defines the general
contract, not that single example.

The low-level `Encode::to_bytes` and Serde adapter prepend the codec framing
byte `01` to the payload and carry no context. They support embedding in a
container that already supplies trusted context. To migrate an old payload,
decode it explicitly using its known configuration, verify it, then call
`ProofFormat::encode` with the correct context. The envelope decoder never
accepts a bare legacy payload. Re-encoding does not itself verify a proof.

## Payload codecs

Integers have their declared fixed widths; circuit indices are `u32`.
Field elements and compressed points use the canonical representations specified
by the suite, with decode/re-encode equality checks. Cached points encode only
the point. An `Arc` encodes its value, without ownership metadata.

A sequence has a `u64` count followed by its elements. The six protocol vectors
must have their fixed schema counts, checked before allocating their elements.
Native binder vectors have 5 elements, native endoscaling vectors have 25,
and nested endoscaling vectors have 28. Their count prefixes are retained for compatibility. Child headers also have
`u64` counts, and both must equal the application's declared header size before
any proof allocation. The low-level decoder caps each header at `2^rank`.

A polynomial is a `u64` block count followed by maximal runs of nonzero
coefficients. Each block is a `u64` starting degree, a `u64` coefficient count,
and that many field elements. Blocks must be nonempty, sorted, disjoint and
nonadjacent, end within `2^rank`, and contain no zero coefficients. The zero
polynomial has no blocks. This encoding is independent of local sparse storage
and its treatment of short zero gaps.

Fields appear in the following order. `C::CircuitField` is the native field;
`C::ScalarField` is the nested field. Host and nested curves follow the suite's
ordered cycle. The two derived stages and eleven transcript challenges are
absent. Field names identify the schema; Rust names are not encoded.

| Field | Payload type / codec |
| --- | --- |
| `bridge_alpha` | `C::ScalarField`; `wire::Scalar` |
| `circuit_id` | `CircuitIndex` |
| `left_header` | `Vec<C::CircuitField>`; `format::HeaderSequence<R>` |
| `right_header` | `Vec<C::CircuitField>`; `format::HeaderSequence<R>` |
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
| `native_inner_collapse_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_outer_collapse_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_compute_v_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_bind_challenges_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `wire::FixedSequence<wire::DefaultEncoding, ConstLen<{ native::NUM_BINDERS }>>` |
| `native_bind_beta_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_bind_endoscalar_rx` | `sparse::Polynomial<C::CircuitField, R>` |
| `native_endoscaling_step_rxs` | `Vec<sparse::Polynomial<C::CircuitField, R>>`; `wire::FixedSequence<wire::DefaultEncoding, ConstLen<{ native::NUM_ENDOSCALING_STEPS }>>` |
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
| `nested_endoscaling_step_rxs` | `Vec<sparse::Polynomial<C::ScalarField, R>>`; `wire::FixedSequence<wire::DefaultEncoding, NumStepsLen>` |
| `nested_endoscalar_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_points_rx` | `Arc<sparse::Polynomial<C::ScalarField, R>>` |
| `nested_a_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_b_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_registry_xy_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_p_poly` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_challenges_partial` | `C::NestedCurve`; `wire::Point` |
| `nested_export_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_collapse_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_compute_v_rx` | `sparse::Polynomial<C::ScalarField, R>` |
| `nested_endoscaling_step_commitments` | `Vec<Cached<C::NestedCurve>>`; `wire::FixedSequence<CachedPoint, NumStepsLen>` |
| `nested_endoscalar_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_points_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_a_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_b_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_registry_xy_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_p_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_challenges_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
| `nested_export_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |
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
| `native_inner_collapse_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_outer_collapse_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_compute_v_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_bind_challenges_commitments` | `Vec<Cached<C::HostCurve>>`; `wire::FixedSequence<CachedPoint, ConstLen<{ native::NUM_BINDERS }>>` |
| `native_bind_beta_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_bind_endoscalar_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_endoscaling_step_commitments` | `Vec<Cached<C::HostCurve>>`; `wire::FixedSequence<CachedPoint, ConstLen<{ native::NUM_ENDOSCALING_STEPS }>>` |
| `native_points_binding_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_children_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_registry_wx_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_ab_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_f_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `native_points_walk_commitment` | `Cached<C::HostCurve>`; `CachedPoint` |
| `bridge_preamble_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_s_prime_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_inner_error_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_outer_error_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_query_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_f_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_eval_commitment` | `C::NestedCurve`; `wire::Point` |
| `bridge_ab_commitment` | `Cached<C::NestedCurve>`; `CachedPoint` |

## Resource policy

Let N = `2^rank`, V = `NUM_BINDERS + NUM_ENDOSCALING_STEPS + NumStepsLen::len()`
and P = 39 + V retained polynomials. Schema v1 has 23 individual native, seven
bridge and nine individual nested polynomials. It also has three polynomial
vectors and three commitment vectors, with V slots in each group.

Per polynomial, the decoder charges at most N/2 temporary block slots, N
coefficient slots, N/2 final block slots and N final coefficient slots, including
zeros inserted when normalizing short gaps. `MinimalProof::decode_limits`
therefore allows P × 3N + 2V + 2N aggregate elements. Its allocation bound uses
the largest field, block, polynomial and point storage sizes for the selected
cycle: P × N × (block + 2 × field) + V × (polynomial + point) + 2N × field.
This includes the six protocol vectors and two maximum-size child headers.

The encoded-byte bound includes the fixed/minimum payload, at most N canonical
coefficients and N/2 sixteen-byte block headers per polynomial, and two
maximum-size headers. Arithmetic fits supported ranks (7 and 13) and the
supported cycle representations on 32-bit and 64-bit hosts. Any new rank,
cycle, or schema must revalidate these bounds. Tests fill every retained
polynomial densely, with alternating zeros, and with separated sparse runs.

`ProofFormat::decode` uses these schema bounds. `decode_with_limits` intersects
them with a caller's smaller aggregate element/allocation policy. Serde uses
the same schema bounds, grows sequence buffers fallibly, and ignores size
hints. Low-level `Decode::from_bytes` remains available with explicit budgets.
Limits cover requested vector storage, not allocator bookkeeping, fixed-size
Arc allocations, the caller's input buffer, outer deserializer buffers, or
verification computation. Enforce transport limits before buffering and
choose stricter budgets when required by the deployment.
