//! # `ragu`
//!
//! Proof-carrying data (PCD) framework for Rust.
//!
//! Ragu is under heavy development and does not yet expose a stable API. Enable
//! the `mock` feature to instead expose an API-level mock of `ragu_pcd`
//! (re-exported at the crate root), used to integrate downstream consumers
//! (e.g. Zebra) against the eventual interface ahead of the real
//! implementation. See the [Ragu Book](https://tachyon.z.cash/ragu/) for more
//! information.
//!
//! ## Mock feature boundaries and migration
//!
//! The `mock` feature uses real `ragu_core` drivers and gadgets,
//! `ragu_primitives` gadgets, and the real polynomial APIs re-exported as
//! `ragu::polynomials`. Application steps run with `Simulator<Fp>`, which
//! checks assigned multiplication gates and linear constraints locally. This
//! is not proof soundness: registration does not synthesize circuit shape or
//! enforce rank and gate bounds, `fuse` checks child header bindings but does
//! not verify child proofs, and
//! hook-capacity checks are absent. Polynomial openings are checked natively
//! against retained coefficients rather than proved cryptographically. Proof
//! bytes, verification binding, rerandomization, and recursion remain mock
//! machinery.
//!
//! For migration, keep the `PastaParams` passed to `ApplicationBuilder::new`
//! alive for the application lifetime, and supply canonical generators
//! compatible with every polynomial rank and commitment. Construct an
//! `ApplicationBuilder::<HEADER_SIZE>::new(params)` and call `finalize()`;
//! the application width includes zero padding and the final suffix slot.
//! Oversized header encodings fail just as in the reference. Steps use
//! `StepCtx<'a, 'dr, D>` with public `ctx.dr`; unlike the recursive reference,
//! this Pasta-specialized context omits the cycle type parameter. Convert
//! headers to allocator-generic `Header::encode` implementations returning a
//! `Bound` gadget of `Header::Output: Write<Fp>`. `Step::witness` is generic
//! over `const HEADER_SIZE: usize` and returns the three `Encoded` headers,
//! the `Bound` shared gadget, carried output `DriverValue` data, and auxiliary
//! `DriverValue` data. Return computed wires through `Encoded::from_gadget`;
//! native carried data never substitutes for that output encoding. Declare
//! `Shared = ()` if no application-stage gadget is needed. The real `Shared`
//! trait and derive are available, but separate recursive stage commitments
//! and their wire-binding constraints are deliberately omitted by the mock.
//! Replace native polynomial commits and scalar queries
//! with `witness_polynomial`, then use its commitment-keyed handle with
//! `evaluate` for prover values and `enforce_poly_query` for locally checked
//! openings. `derive_challenge` accepts writable gadgets and returns an
//! `Element`; callers must pin the complete absorbed sequence. It is a mock
//! extension absent from the ea0bf839 reference's `StepCtx`; its variable-width
//! sponge does not promise reference transcript output or recursive cost parity.
//!
//! Legacy Pasta field, curve, rank, and arithmetic-trait imports must move to
//! matching real Ragu types and APIs. Native arithmetic and comparisons in
//! downstream relations need driver-generic gadgets that emit constraints.
//! Re-witnessing a polynomial does not bind it to a commitment stored in a
//! header: write the handle into a `Vec<Element>` with `GadgetExt::write` and
//! enforce element equality against the header's commitment elements. If
//! headers carry native points, their encoding, allocation, and binding must
//! also move to gadgets; native point comparison alone is insufficient.
//! Downstream dependency alignment is a separate change; static applications
//! need compatible parameters with a `'static` lifetime.
// The lints below apply to the `mock` surface, which mirrors an external API.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(feature = "mock"), deny(missing_docs))]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]
#![cfg_attr(
    feature = "mock",
    expect(clippy::pub_use, reason = "crate public API re-exports")
)]
#![cfg_attr(
    feature = "mock",
    expect(clippy::missing_const_for_fn, reason = "mirrors non-const ragu API")
)]
#![cfg_attr(
    feature = "mock",
    expect(
        clippy::missing_trait_methods,
        reason = "default impls are fine in a mock"
    )
)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "mock")]
extern crate alloc;
#[cfg(feature = "mock")]
extern crate self as ragu;

/// Real polynomial APIs available to mock steps.
#[cfg(feature = "mock")]
pub use ragu_circuits::polynomials;
#[cfg(feature = "mock")]
pub use ragu_core::*;

/// Real gadget APIs available to mock steps.
#[cfg(feature = "mock")]
pub mod primitives {
    pub use ragu_primitives::*;
}

#[cfg(feature = "mock")]
mod mock;
#[cfg(feature = "mock")]
pub use mock::*;
