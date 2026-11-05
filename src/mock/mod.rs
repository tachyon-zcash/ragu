//! API-level mock of `ragu_pcd`.
//!
//! Enabled by the `mock` feature. Mirrors the shape of the real `ragu_pcd` API
//! so downstream consumers can integrate against it ahead of the real
//! implementation.

pub use application::{Application, ApplicationBuilder};
pub use header::{HEADER_POLYNOMIALS, Header, Suffix};
pub use proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof};
pub use step::{Encoded, HeaderInput, Index, Oracles, Position, Slot, Step};

mod application;
pub mod header;
mod proof;
pub mod step;

#[cfg(test)]
mod tests;
