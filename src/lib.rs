//! # `ragu`
//!
//! Proof-carrying data (PCD) framework for Rust.
//!
//! Ragu is under heavy development and does not yet expose a stable API. Enable
//! the `mock` feature to instead expose an API-level mock of `ragu_pcd`
//! (re-exported at the crate root), used to integrate downstream consumers
//! (e.g. Zebra) against the eventual interface ahead of the real
//! implementation. The mock is built against the legacy crypto stack, so it
//! requires `legacy-deps` and cannot be combined with the default
//! `modern-deps`. See the
//! [Ragu Book](https://tachyon.z.cash/ragu/) for more information.
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
    expect(clippy::module_name_repetitions, reason = "names mirror real ragu API")
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

// The mock uses the legacy crypto stack (ff 0.13 / pasta_curves 0.5 /
// rand_core 0.6) unconditionally, so it requires `legacy-deps` and cannot be
// built against the default `modern-deps`.
#[cfg(all(feature = "mock", not(feature = "legacy-deps")))]
compile_error!(
    "the `mock` feature requires the legacy crypto stack; build with \
     `--no-default-features --features \"mock legacy-deps\"`"
);

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "mock")]
extern crate alloc;

#[cfg(feature = "mock")]
mod mock;
#[cfg(feature = "mock")]
pub use mock::*;
