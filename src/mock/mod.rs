//! API-level mock of `ragu_pcd`.
//!
//! Enabled by the `mock` feature. Mirrors the shape of the real `ragu_pcd` API
//! so downstream consumers can integrate against it ahead of the real
//! implementation.

pub use application::{Application, ApplicationBuilder};
pub use ctx::StepCtx;
pub use header::{Header, Suffix};
pub use poly_commitment::{HANDLE_WIRES, PolyHandle};
pub use proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof};
pub use step::{Encoded, Index, Step};

mod application;
mod ctx;
pub mod header;
mod hooks;
mod poly_commitment;
mod proof;
pub mod step;

#[cfg(test)]
mod tests;
