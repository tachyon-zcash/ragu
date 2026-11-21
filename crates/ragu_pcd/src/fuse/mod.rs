//! The fuse: the split-accumulation scheme that folds two child proofs into
//! one.
//!
//! [`prover`] constructs the proof: the fuse pipeline, the bootstrap, seed and
//! rerandomization entry points, and proof assembly. [`circuits`] are the
//! recursive verifier: the constraints that check the reduction of the
//! children's claims into the parent's accumulated obligations. `decider` is
//! the reference decider, a test oracle that checks the accumulated
//! obligations directly from the polynomials; `compress` restates its checks
//! over commitments. The definitions they share, from the canonical orders to
//! the stages a proof commits to, live in [`crate::protocol`].

pub(crate) mod circuits;
pub(crate) mod decider;
pub(crate) mod prover;
