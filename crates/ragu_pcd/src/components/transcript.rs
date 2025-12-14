//! Transcript routines for computing Fiat-Shamir challenges.

use arithmetic::Cycle;
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// A long-lived transcript for Fiat-Shamir challenge derivation.
pub struct TranscriptEmulator<'dr, D: Driver<'dr>, C: Cycle>
where
    D: Driver<'dr, F = C::CircuitField>,
{
    sponge: Sponge<'dr, D, C::CircuitPoseidon>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle> TranscriptEmulator<'dr, D, C> {
    /// Create a new transcript emulator with an initialized sponge.
    pub fn new(dr: &mut D, params: &'dr C) -> Self {
        Self {
            sponge: Sponge::new(dr, params.circuit_poseidon()),
        }
    }

    /// Absorb a point commitment into the transcript.
    pub fn absorb_point(
        &mut self,
        dr: &mut D,
        point: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<()> {
        point.write(dr, &mut self.sponge)
    }

    /// Squeeze a single challenge from the transcript.
    pub fn squeeze(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        self.sponge.squeeze(dr)
    }

    /// Squeeze a pair of challenges from the transcript.
    pub fn squeeze_pair(&mut self, dr: &mut D) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        let first = self.sponge.squeeze(dr)?;
        let second = self.sponge.squeeze(dr)?;
        Ok((first, second))
    }

    /// Absorb nested_preamble_commitment and squeeze the w challenge.
    pub fn derive_w(
        &mut self,
        dr: &mut D,
        nested_preamble_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        self.absorb_point(dr, nested_preamble_commitment)?;
        self.squeeze(dr)
    }

    /// Absorb nested_s_prime_commitment and squeeze (y, z) challenges.
    pub fn derive_y_z(
        &mut self,
        dr: &mut D,
        nested_s_prime_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        self.absorb_point(dr, nested_s_prime_commitment)?;
        self.squeeze_pair(dr)
    }

    /// Absorb nested_error_commitment and squeeze (mu, nu) challenges.
    pub fn derive_mu_nu(
        &mut self,
        dr: &mut D,
        nested_error_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        self.absorb_point(dr, nested_error_commitment)?;
        self.squeeze_pair(dr)
    }

    /// Absorb nested_ab_commitment and squeeze the x challenge.
    pub fn derive_x(
        &mut self,
        dr: &mut D,
        nested_ab_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        self.absorb_point(dr, nested_ab_commitment)?;
        self.squeeze(dr)
    }

    /// Absorb nested_query_commitment and squeeze the alpha challenge.
    pub fn derive_alpha(
        &mut self,
        dr: &mut D,
        nested_query_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        self.absorb_point(dr, nested_query_commitment)?;
        self.squeeze(dr)
    }

    /// Absorb nested_f_commitment and squeeze the u challenge.
    pub fn derive_u(
        &mut self,
        dr: &mut D,
        nested_f_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        self.absorb_point(dr, nested_f_commitment)?;
        self.squeeze(dr)
    }

    /// Absorb nested_eval_commitment and squeeze the beta challenge.
    pub fn derive_beta(
        &mut self,
        dr: &mut D,
        nested_eval_commitment: &Point<'dr, D, C::NestedCurve>,
    ) -> Result<Element<'dr, D>> {
        self.absorb_point(dr, nested_eval_commitment)?;
        self.squeeze(dr)
    }
}
