//! Native registry restrictions and commitments for the fuse.
use ragu_core::Cycle;

use crate::prover::fuse::side::SPrime;
pub(in crate::prover::fuse) type NativeSPrime<C, R> = SPrime<<C as Cycle>::HostCurve, R>;
