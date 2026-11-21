//! Native registry restrictions and commitments for the fuse.
use ragu_core::Cycle;

use crate::fuse::prover::side::SPrime;
pub(in crate::fuse::prover) type NativeSPrime<C, R> = SPrime<<C as Cycle>::HostCurve, R>;
