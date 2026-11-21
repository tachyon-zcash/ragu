//! The bridge hash $H^{bridge}(P)$ of a host-curve point, computed outside
//! the circuit.
//!
//! A step's [`Oracles::bridge_hash`](crate::step::Oracles::bridge_hash) is the
//! bridge hash of its own last online commitment. An application that hashes
//! a polynomial commitment into state it also recomputes natively, such as an
//! anchor, recomputes the same value with [`digest`], without building an
//! [`Application`](crate::Application).
//!
//! [`digest`] is the commitment of the zero-alpha stage polynomial [`rx`] that
//! holds the point's two coordinates, so it depends on the rank and the
//! nested generators. It is the honest prover's encoding: an accepted bridge
//! digest binds the point but need not use this encoding or be fixed before
//! the step's challenge, so anchor applications must compare natively
//! recomputed advancement against canonical-chain anchors.
//!
//! Every backend computes the same [`digest`]. A caller outside Ragu passes
//! [`AcceleratedProver`](ragu_acceleration::AcceleratedProver) as its backend
//! `B`, or the backend its [`Application`](crate::Application) uses.

pub use crate::recursion::nested::stages::bridge_hash::{digest, rx};
