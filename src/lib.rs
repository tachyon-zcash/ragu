//! # `ragu`
//!
//! Proof-carrying data (PCD) framework for Rust.
//!
//! This crate is the single entry point to Ragu's crates. The crate root
//! carries what most callers name:
//!
//! - everything in [`ragu_core`]: drivers, gadgets, [`Result`], [`Error`], the
//!   [`pasta`] cycle and the [`udon`] arithmetic crate. The `Gadget`, `Write`
//!   and `Kind!` macros resolve their `ragu_core` and `udon` paths here when a
//!   caller depends only on `ragu`;
//! - the PCD API: [`ApplicationBuilder`], [`Application`], the [`step`] and
//!   [`header`] modules, and the [`Pcd`], [`Proof`], [`CompressedPcd`] and
//!   [`CompressedProof`] structures;
//! - the sparse [`Polynomial`], [`Rank`] and [`WalletRank`];
//! - the [`AcceleratedProver`].
//!
//! Each member crate stays reachable as a module for the rest of its API:
//! [`primitives`] ([`ragu_primitives`]: the gadget library, where the `Write`
//! and `Consistent` macros resolve their `ragu_primitives` paths), [`circuits`]
//! ([`ragu_circuits`]), [`pcd`] ([`ragu_pcd`], including its baked
//! generators under `pcd::pasta`) and [`acceleration`]
//! ([`ragu_acceleration`]).
//!
//! Ragu is under heavy development and does not yet expose a stable API.
//! Please see the [Ragu Book](https://tachyon.z.cash/ragu/) for more
//! information.

#![no_std]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

pub use ragu_acceleration::{self as acceleration, AcceleratedProver};
pub use ragu_circuits::{
    self as circuits,
    polynomials::{Rank, WalletRank, sparse::Polynomial},
};
pub use ragu_core::*;
pub use ragu_pcd::{
    self as pcd, Application, ApplicationBuilder, CompressedPcd, CompressedProof, Pcd, Proof,
    header, step,
};
pub use ragu_primitives as primitives;
