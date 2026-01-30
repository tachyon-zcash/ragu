//! # `ragu_core`
//!
//! This crate contains the fundamental traits and types for writing protocols
//! and arithmetic circuits for the Ragu project. This API is re-exported (as
//! necessary) in other crates and so this crate is only intended to be used
//! internally by Ragu.

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_core` requires the `alloc` feature to be enabled.");

extern crate alloc;

pub mod drivers;
mod errors;
pub mod floor_plan;
pub mod gadgets;
pub mod maybe;
pub mod routines;

pub use errors::{Error, Result};
