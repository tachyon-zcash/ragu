# PCD implementation map

This map is for reading `ragu_pcd` and reviewing it: where each operation
lives, an order to read the code in, and which code a proof's soundness rests
on. Paths are relative to `src/`.

## Directories

| Path | Holds |
| --- | --- |
| `lib.rs`, `application.rs` | The crate docs, module list and re-exports; `ApplicationBuilder` and `Application` in `application.rs`, with setup (`finalize`), `seed` and `rerandomize`. |
| `header/`, `step/` | What a proof claims: headers and the online polynomials they name, and the steps that produce them. `step/internal/` holds the internal steps. |
| `profile/` | Proof shapes: the `Profile` trait, the built-in profiles and their extensions. `profile/online/` declares the online batches. |
| `pasta/` | The Pasta parameters. |
| `proof/` | Both proof forms: `Proof` and `Pcd` in `mod.rs`, `CompressedProof` and `CompressedPcd` in `compressed.rs`; the uncompressed proof's builder (`builder.rs`) and byte codec (`codec.rs`). |
| `internal/` | The recursion. Per side (`native/`, `nested/`): the canonical sizes and orders (`mod.rs`), the claim order (`claims.rs`), the unified instance (`unified.rs`), the online slots (`online.rs`), the stages a proof commits to (`stages/`) and the recursive verifier's circuits (`circuits/`). Shared by both sides: revdot claims and their folding, $k(y)$, the transcript, and the endoscalar and inverter gadgets. |
| `fuse/` | The prover: `Application::fuse` in `mod.rs`, its phases in transcript order (`_01_application.rs` to `_11_circuits.rs`), and the helpers the phases share. |
| `verify.rs` | The reference decider, `Application::verify_uncompressed`: a test oracle under `test-utils`. |
| `compress/` | The decider restated over commitments, ending in one IPA opening per curve: `prover.rs` and `verifier.rs`, the shared instance, messages and transcript, and `batch/` and `revdot/`, each with its own `prover.rs` and `verifier.rs`. |
| `ipa/` | The inner product argument: shared definitions, `prover.rs` and `verifier.rs`. |
| `decompress/` | A compressed proof verified inside a fresh accumulator proof, so that the recursion can continue from it. |
| `wire/` | Byte encodings of both proof forms, and their decoding from untrusted input. |
| `bridge_hash.rs`, `backend.rs`, `multicore.rs` | The bridge hash computed natively, backend selection, and the prover's parallelism. |
| `fuzzing/` | The hidden fuzzing surface, under `unstable-fuzzing`. |

## Entry points

| Operation | Where |
| --- | --- |
| `ApplicationBuilder::finalize` | `application.rs` |
| `Application::seed`, `Application::rerandomize` | `application.rs` |
| `Application::fuse` | `fuse/mod.rs`, then `fuse/_01_application.rs` to `fuse/_11_circuits.rs` |
| Recursive verification | `internal/{native,nested}/circuits/`, registered by `register_all` in `internal/{native,nested}/mod.rs` |
| `Application::compress` | `compress/prover.rs` |
| `Application::verify_compressed` | `compress/verifier.rs` |
| `Application::decompress` (aggregator profile) | `decompress/prover.rs` |
| `Application::verify_uncompressed` | `verify.rs` |

## Reading order

1. `lib.rs`, `application.rs` and the entry points above.
2. `header/`, `step/` and `profile/`: what a proof claims and the shapes it
   takes.
3. `internal/`: each side's `mod.rs`, `claims.rs`, `unified.rs` and `stages/`,
   then the shared modules, then `circuits/`.
4. `verify.rs`: the plainest statement of what an accumulated proof must
   satisfy.
5. `compress/verifier.rs`, the `verifier.rs` files under it, and
   `ipa/verifier.rs`: the production decider.
6. The verifier side of `decompress/`.
7. `wire/`: decoding untrusted bytes.

## What soundness depends on

Everything except the prover and test-only code. The prover is `fuse/`,
`proof/builder.rs`, every `prover.rs` (under `compress/`, `ipa/`,
`decompress/` and `profile/online/`), `multicore.rs`, and the `impl
Application` blocks in `internal/{native,nested}/online.rs`, which run the
fuse's online batch phases beside the slots they fill. It matters for
completeness and zero knowledge, so a soundness review can set it aside.
`tests/prover_isolation.rs` checks that no other code names prover code, apart
from the public re-exports it lists. It checks paths, not calls: an inherent
method on `Application` that a prover file defines can be called from
anywhere.

## Following the fuse

Each phase commits the bridge stage it is named after, and the transcript
absorbs the bridge commitments in phase order:

| Phase | Absorbs | Then squeezes |
| --- | --- | --- |
| `_02_preamble.rs` | `bridge_preamble_commitment` | $w$ |
| `_03_s_prime.rs` | `bridge_s_prime_commitment` | $y$, $z$ |
| `_04_inner_error.rs` | `bridge_inner_error_commitment` | $\mu$ |
| `_05_outer_error.rs` | `bridge_outer_error_commitment` | $\mu'$ |
| `_06_ab.rs` | `bridge_ab_commitment` | $x$ |
| `_07_query.rs` | `bridge_query_commitment` | $\alpha$ |
| `_08_f.rs` | `bridge_f_commitment` | $u$ |
| `_09_eval.rs` | `bridge_eval_commitment` | $\beta$ |

`_01_application.rs` runs the step's circuit, in two phases around the
preamble; `_10_p.rs` accumulates $p(X)$; `_11_circuits.rs` traces the
internal circuits over the stage witnesses the earlier phases saved. The
prover's schedule, its rederivation in the `hashes_1` and `hashes_2` circuits,
and the native rederivations in `verify.rs` and `compress/verifier.rs` must
all agree.

What each circuit enforces, as its module documents:

| Circuit | Enforces |
| --- | --- |
| native `hashes_1`, `hashes_2` | The transcript above. `hashes_1` also checks the children's unified $k(y)$ and the step's circuit id. |
| native `collapse` | Both layers of the native revdot fold, and the step's own application $k(y)$. |
| native `compute_v` | The batch evaluation $v$, from the query and eval stages. |
| native `bind_challenges` | The nested challenge stage's commitment, up to $\beta$'s term. |
| native `bind_beta` | The children's walked nested commitments against their unified instances, completing the challenge bindings with $\beta$'s term. |
| native `bind_endoscalar`, `endoscaling_step` | The endoscaling walk over the nested batch's commitments into $P_n$. |
| nested `collapse` | Both layers of the nested fold, and the stage contracts the nested walk rests on. |
| nested `compute_v` | The nested batch evaluation $v_n$. |
| nested `loading` | The points stage against the bridge stages, mirroring `_10_p.rs`. |

To follow one obligation, go from its phase to its stage in
`internal/*/stages/`, the challenge after it, the circuit that enforces it,
the parent's binding, and the deciders' checks in `verify.rs` and
`compress/`.

## Tests

`Cargo.toml` turns off test discovery, and its `[[test]]` entries are the
integration tests. Most other files under `tests/` are unit tests mounted into
a `src` module with `#[path]`, so that they can reach private items; search
`src/` for a file's name to find the module it runs in.
