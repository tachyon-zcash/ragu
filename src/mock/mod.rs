//! API-level mock of `ragu_pcd`.
//!
//! Enabled by the `mock` feature. Mirrors the shape of the real `ragu_pcd` API
//! so downstream consumers (e.g. Zebra) can integrate against it ahead of the
//! real implementation. The contents are re-exported at the crate root.
//!
//! The mock is built against the legacy crypto stack only and is incompatible
//! with `modern-deps`.

pub use application::{Application, ApplicationBuilder};
pub use ctx::StepCtx;
pub use error::{Error, Result};
pub use header::{Header, Suffix};
pub use hooks::FrameworkHooks;
pub use polynomial::{Commitment, Polynomial, generators, poly_with_roots};
pub use proof::{Pcd, Proof};
pub use relations::{enforce_poly_concat, enforce_poly_product, enforce_poly_splice};
pub use step::{Index, Step};

pub mod application;
pub mod ctx;
pub mod error;
pub mod header;
pub mod hooks;
pub mod polynomial;
pub mod proof;
pub mod relations;
pub mod step;

#[cfg(test)]
mod tests;
