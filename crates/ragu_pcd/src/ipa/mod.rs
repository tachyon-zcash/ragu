//! Inner Product Argument (IPA) for polynomial commitments.

pub mod compress;
mod prover;
mod transcript;
mod verifier;

pub use compress::IpaProof;
