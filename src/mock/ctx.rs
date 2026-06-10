//! Context object threaded through
//! [`Step::witness`](crate::step::Step::witness)
//! — mirrors `ragu_pcd::step::StepCtx`.
//!
//! Real ragu's `StepCtx` bundles the circuit driver with the framework hooks.
//! The mock has no driver, so it carries only the [`FrameworkHooks`] claim sink
//! and exposes the two hooks a step body reaches for: recording
//! polynomial-query opening claims and deriving Fiat-Shamir challenges.

use blake2b_simd::Params;
use ff::FromUniformBytes as _;
use pasta_curves::Fp;

use crate::{error::Result, hooks::FrameworkHooks, polynomial::Commitment};

const CHALLENGE_LEN: usize = 64;

/// Framework-side state threaded through
/// [`Step::witness`](crate::step::Step::witness).
pub struct StepCtx<'a> {
    hooks: &'a mut FrameworkHooks,
}

impl<'a> StepCtx<'a> {
    pub(crate) fn new(hooks: &'a mut FrameworkHooks) -> Self {
        Self { hooks }
    }

    pub fn enforce_poly_query(&mut self, com: Commitment, x: Fp, y: Fp) -> Result<()> {
        self.hooks.enforce_polynomial_query(com, x, y)
    }

    pub fn derive_challenge(&mut self, commitments: &[Commitment]) -> Result<Fp> {
        let mut state = Params::new()
            .hash_length(CHALLENGE_LEN)
            .personal(b"MkRagu_Challng_\0")
            .to_state();
        for com in commitments {
            let bytes: [u8; 32] = (*com).into();
            state.update(&bytes);
        }
        let mut wide = [0u8; CHALLENGE_LEN];
        wide.copy_from_slice(state.finalize().as_bytes());
        Ok(Fp::from_uniform_bytes(&wide))
    }
}
