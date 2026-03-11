//! Test utilities for proof corruption, gated behind the `test-utils` feature.
//!
//! Provides controlled mutation of [`Proof`] internals for fuzz-testing the
//! verifier. Each [`Corruption`] variant targets a specific verification check.

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, registry::CircuitIndex};

use crate::{Application, Proof};

/// A targeted corruption of a proof field.
///
/// Each variant modifies a single field that a specific verification check
/// depends on, allowing fuzz targets to exercise every rejection path.
pub enum Corruption<F> {
    /// Overwrite `p.blind`, breaking the P commitment check.
    PBlind(F),
    /// Overwrite `p.v`, breaking the P evaluation check.
    PEval(F),
    /// Overwrite `ab.c`, breaking native revdot claims.
    AbC(F),
    /// Set `application.circuit_id` to an out-of-domain index.
    CircuitId(u32),
    /// Overwrite `challenges.u`, breaking the P evaluation check.
    ChallengeU(F),
    /// Overwrite `challenges.x`, breaking the registry xy check.
    ChallengeX(F),
    /// Overwrite `challenges.y`, breaking the registry xy check.
    ChallengeY(F),
    /// Resize `application.left_header` to the given length.
    LeftHeaderLen(usize),
    /// Resize `application.right_header` to the given length.
    RightHeaderLen(usize),
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Apply a [`Corruption`] to this proof.
    pub fn corrupt(&mut self, corruption: Corruption<C::CircuitField>) {
        match corruption {
            Corruption::PBlind(v) => self.p.blind = v,
            Corruption::PEval(v) => self.p.v = v,
            Corruption::AbC(v) => self.ab.c = v,
            Corruption::CircuitId(id) => {
                self.application.circuit_id = CircuitIndex::from_u32(id);
            }
            Corruption::ChallengeU(v) => self.challenges.u = v,
            Corruption::ChallengeX(v) => self.challenges.x = v,
            Corruption::ChallengeY(v) => self.challenges.y = v,
            Corruption::LeftHeaderLen(len) => {
                self.application
                    .left_header
                    .resize(len, C::CircuitField::ZERO);
            }
            Corruption::RightHeaderLen(len) => {
                self.application
                    .right_header
                    .resize(len, C::CircuitField::ZERO);
            }
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Create a trivial (all-zero) proof for testing.
    pub fn test_trivial_proof(&self) -> Proof<C, R> {
        self.trivial_proof()
    }
}
