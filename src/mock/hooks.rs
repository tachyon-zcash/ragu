//! Framework-side state surfaced to
//! [`Step::witness`](crate::step::Step::witness) impls — mirrors
//! `ragu_pcd::framework_hooks::FrameworkHooks`.
//!
//! Carries the polynomial-commitment opening-claim sink reached from a step
//! body through [`StepCtx`](crate::ctx::StepCtx).

use alloc::vec::Vec;

use pasta_curves::Fp;

use crate::{error::Result, polynomial::Commitment};

pub type PolyQueryClaim = (Commitment, Fp, Fp);

/// Container for framework-side state threaded through a
/// [`Step::witness`](crate::step::Step::witness) invocation.
#[derive(Clone, Debug, Default)]
pub struct FrameworkHooks {
    poly_query_claims: Vec<PolyQueryClaim>,
}

impl FrameworkHooks {
    #[must_use]
    pub fn new() -> Self {
        Self {
            poly_query_claims: Vec::new(),
        }
    }

    pub fn enforce_polynomial_query(&mut self, com: Commitment, x: Fp, y: Fp) -> Result<()> {
        self.poly_query_claims.push((com, x, y));
        Ok(())
    }

    #[must_use]
    pub fn into_outputs(self) -> Vec<PolyQueryClaim> {
        self.poly_query_claims
    }
}
