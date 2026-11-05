//! API-level mock of `ragu_pcd`.
//!
//! Enabled by the `mock` feature. Mirrors the shape of the real `ragu_pcd` API
//! so downstream consumers can integrate against it ahead of the real
//! implementation.

pub use application::{Application, ApplicationBuilder};
pub use proof::{CompressedPcd, CompressedProof, Pcd, Proof};

mod application;
pub mod header;
mod proof;
pub mod step;
pub mod wire;

#[cfg(test)]
mod tests;
