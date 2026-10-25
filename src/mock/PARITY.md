# Step API parity

Reference: `ea0bf839` (`poly-query-4-on-909`) in the read-only checkout
`/Users/yet/Developer/github.com/tachyon-zcash/ragu`. The older in-tree
`crates/ragu_pcd` is **not** the reference for this mock.

Paths prefixed `reference:` below are relative to that checkout. Other paths
are relative to this worktree. Line numbers identify the implementation at
the time of this change.

## Fixed divergences

| Surface | Mock | Reference |
| --- | --- | --- |
| `Header::Output` and allocator-/driver-generic gadget encoding replace native four-vector encoding | `src/mock/header.rs:100` | `reference:crates/ragu_pcd/src/header.rs:95` |
| `Step::witness` returns three `Encoded` gadgets, a `Bound<Shared>`, carried data, and aux; has `const HEADER_SIZE` | `src/mock/step.rs:185` | `reference:crates/ragu_pcd/src/step/mod.rs:133` |
| `Encoded::{new,from_gadget,as_gadget}`, cloning, fixed-width zero padding, suffix, streaming overflow refusal | `src/mock/step.rs:21` | `reference:crates/ragu_pcd/src/step/encoder.rs:55`, `reference:crates/ragu_pcd/src/step/internal/padded.rs:59` |
| Serialize returned left/right/output gadgets on the step's checked driver before extracting native bindings; output data never replaces the computed output gadget | `src/mock/application.rs:148` | `reference:crates/ragu_pcd/src/step/internal/adapter.rs:196` |
| Connect both returned input-header encodings to child proofs; mock compares its header hashes directly | `src/mock/application.rs:175` | `reference:crates/ragu_pcd/src/fuse/_01_application.rs:59`, `reference:crates/ragu_pcd/src/internal/native/stages/preamble.rs:370` |
| Verification encodes the carried header through the gadget API, with the application's width | `src/mock/application.rs:205` | `reference:crates/ragu_pcd/src/verify.rs:142`, `reference:crates/ragu_pcd/src/internal/native/stages/preamble.rs:370` |
| Full `Shared` trait, nested fixed-vector support, and checked sizing | `crates/ragu_primitives/src/shared.rs:28` | `reference:crates/ragu_primitives/src/shared.rs:34` |
| `Shared` derive, including rejection of skipped/raw/witness-only fields and unsupported shapes | `crates/ragu_macros/src/derive/shared.rs:14` | `reference:crates/ragu_macros/src/derive/shared.rs:14` |
| Builder takes parameters at `new(params)`, `register` retains the parameter lifetime bound, `finalize()` takes no arguments; application-wide const header width | `src/mock/application.rs:25` | `reference:crates/ragu_pcd/src/lib.rs:152` |
| Registration checks shared size arithmetic, reserved suffixes, and reference suffix-conflict error | `src/mock/application.rs:52` | `reference:crates/ragu_pcd/src/lib.rs:251`, `reference:crates/ragu_pcd/src/lib.rs:451` |
| `fuse` rejects an application step index outside the registered range | `src/mock/application.rs:130` | `reference:crates/ragu_pcd/src/fuse/_01_application.rs:52` |
| Public `header`/`step` modules, `step::StepCtx`, and `HANDLE_WIRES` | `src/mock/mod.rs:7`, `src/mock/poly_commitment.rs:16` | `reference:crates/ragu_pcd/src/lib.rs:40`, `reference:crates/ragu_pcd/src/lib.rs:57`, `reference:crates/ragu_pcd/src/step/mod.rs:7` |

`Suffix::new` and application `Index::new`, sequential registration,
`StepCtx.dr`, polynomial witness/evaluate/query signatures and errors,
two-limb commitment handles (including identity polynomial commitments),
`Pcd` accessors/clone, `Proof::carry`, and `seed`/`fuse`/`verify`/`rerandomize`
argument ordering already matched, modulo the specialization below.

## Deliberately retained differences

| Difference | Mock | Reference |
| --- | --- | --- |
| Pasta specialization: `Header` fixes `Fp`; `Step` fixes `Pasta`; context omits the cycle parameter, as documented in the original design | `src/mock/header.rs:100`, `src/mock/step.rs:185`, `src/mock/ctx.rs:21` | `reference:crates/ragu_pcd/src/header.rs:95`, `reference:crates/ragu_pcd/src/step/mod.rs:133`, `reference:crates/ragu_pcd/src/step/ctx.rs:16` |
| No application rank, hook-layout, or backend type parameters; no registry tags/backend selection or native registry accessor. Registration retains metadata rather than synthesizing/storing step circuits; no rank/gate/layout capacity checks or registry binding | `src/mock/application.rs:25`, `src/mock/application.rs:52` | `reference:crates/ragu_pcd/src/lib.rs:152`, `reference:crates/ragu_pcd/src/lib.rs:198`, `reference:crates/ragu_pcd/src/lib.rs:251`, `reference:crates/ragu_pcd/src/lib.rs:618` |
| Shared trait/derive and witness-count checks exist, but there is no separately committed application-stage polynomial or stage-wire equality binding | `src/mock/application.rs:142`, `src/mock/application.rs:157` | `reference:crates/ragu_pcd/src/step/internal/adapter.rs:196`, `reference:crates/ragu_pcd/src/fuse/_01_application.rs:72` |
| Polynomial hooks retain coefficients and check openings natively; no cryptographic opening proofs, parent recursive discharge, padding to hook capacities, or application-rank rewrapping | `src/mock/hooks.rs:47`, `src/mock/ctx.rs:52` | `reference:crates/ragu_pcd/src/framework_hooks.rs:143`, `reference:crates/ragu_pcd/src/step/ctx.rs:35` |
| `derive_challenge` is a mock-only hook absent from ea0bf839's `StepCtx`; it uses the supplied driver and variable-width Poseidon input. No promise of reference transcript values or recursive gate costs | `src/mock/ctx.rs:94`, `src/mock/hooks.rs:99` | `reference:crates/ragu_pcd/src/step/ctx.rs:26` (complete method set ends at line 92) |
| Mock proof hashes/23,000-byte serialization and deterministic rerandomization replace folding/recursion/decider/compression. `fuse` checks child header connections but not recursive child validity; verification is a local header/binding check | `src/mock/proof.rs:12`, `src/mock/application.rs:175`, `src/mock/application.rs:199`, `src/mock/application.rs:227` | `reference:crates/ragu_pcd/src/proof/mod.rs:182`, `reference:crates/ragu_pcd/src/fuse/mod.rs:196`, `reference:crates/ragu_pcd/src/verify.rs:88`, `reference:crates/ragu_pcd/src/lib.rs:597` |
| Bootstrap is synthesized mock machinery and publicly accessible as `Proof::bootstrap::<HEADER_SIZE>()`; real bootstrap is application-private. Mock convenience root re-exports/extra derives remain available | `src/mock/proof.rs:69`, `src/mock/mod.rs:7` | `reference:crates/ragu_pcd/src/lib.rs:548`, `reference:crates/ragu_pcd/src/step/mod.rs:45` |
| Internal uniform header encoding is unnecessary because mock rerandomization has no circuit | `src/mock/step.rs:21`, `src/mock/application.rs:227` | `reference:crates/ragu_pcd/src/step/encoder.rs:159` |
| Zero header width receives an explicit error rather than the reference padding arithmetic's invalid-width behavior | `src/mock/application.rs:73`, `src/mock/step.rs:56` | `reference:crates/ragu_pcd/src/step/internal/padded.rs:79` |

There is no unbounded header-width escape hatch. `HEADER_SIZE` is supplied
per application, exactly as a const parameter in the reference. Each header's
serialized payload must occupy at most `HEADER_SIZE - 1` `Fp` elements.
This enforces header width, not the deliberately omitted rank/staging limits.

## Tachyon migration

1. Change `Application<'static>` to `Application<'static, HEADER_SIZE>` and
   construct `ApplicationBuilder::<HEADER_SIZE>::new(params).register(...)
   .finalize()`. Choose the width on the Tachyon side; include the suffix slot.
2. Each `Header` declares `type Output: Write<Fp>` (usually a `Kind!` of an
   element, tuple, or named gadget) and implements:

   ```rust,ignore
   fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
       dr: &mut D,
       allocator: &mut A,
       witness: DriverValue<D, Self::Data>,
   ) -> Result<Bound<'dr, D, Self::Output>>;
   ```

   Pass the allocator to element allocations. Actual `Point` gadgets use
   circuit-curve affine points and serialize coordinates; host-curve polynomial
   commitments use the two-limb handle encoding, not native point coordinates.
3. Each step declares `type Shared = ();` or a `Kind!` of a gadget deriving
   `Gadget, Shared`, adds `const HEADER_SIZE: usize` to `witness`, and returns:

   ```rust,ignore
   (
       (left_encoded, right_encoded, output_encoded),
       shared_gadget,
       output_data,
       aux,
   )
   ```

   Return the actual computed gadget through `Encoded::from_gadget`; use
   `Encoded::new` to encode input witnesses and borrow with `as_gadget` when
   computing over their wires. Returning different native output data does not
   change the proof's output: that PCD fails verification.
4. Keep polynomial handle limbs bound to header gadget wires with circuit
   equality constraints. The native `Data` remains a prover-side carrier.
5. Keep the explicitly documented Pasta/cycle-arity specialization and
   mock-only challenge hook in mind when moving to the reference crate.
6. Existing mock proof bytes change because hashing now consumes padded gadget
   serialization. Regenerate mock fixtures; no real proof format is implied.

Regression coverage is in `src/mock/tests/parity.rs`: computed output versus
lying native data, both input substitutions, tampered child data, allocation
and serialization constraints on all three headers, clone/padding/overflow,
application width mismatch, and unregistered step refusal. Shared tests cover
nested generic layouts, wire order, zero-length vectors, overflow, and derive
rejection cases.
