//! # `ragu`
//!
//! Proof-carrying data (PCD) framework for Rust.
//!
//! This crate is the single entry point to Ragu's crates:
//!
//! - The crate root re-exports [`ragu_core`]: drivers, gadgets, [`Result`],
//!   [`Error`] and the [`pasta`] cycle. The `Gadget`, `Write` and `Kind!`
//!   macros resolve their `ragu_core` paths here when a caller depends only on
//!   `ragu`.
//! - [`primitives`] is [`ragu_primitives`], where the `Write` and
//!   `Consistent` macros resolve their `ragu_primitives` paths.
//! - [`circuits`] is [`ragu_circuits`]: polynomials, registries and staging.
//! - [`pcd`] is [`ragu_pcd`]: the [`Application`](pcd::Application),
//!   [`Step`](pcd::step::Step) and [`Header`](pcd::header::Header) API and the
//!   [`Pcd`](pcd::Pcd) and [`Proof`](pcd::Proof) structures.
//! - [`acceleration`] is [`ragu_acceleration`]: the accelerated prover.
//!
//! Ragu is under heavy development and does not yet expose a stable API.
//! Please see the [Ragu Book](https://tachyon.z.cash/ragu/) for more
//! information.

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

pub use ragu_acceleration as acceleration;
pub use ragu_circuits as circuits;
pub use ragu_core::*;
pub use ragu_pcd as pcd;
pub use ragu_primitives as primitives;
