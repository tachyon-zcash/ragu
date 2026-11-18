//! Prover state for the online batch's commitment deadlines.

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Layout, Phase};

/// Challenges available when preparing a phase of the enclosing step.
///
/// The quotient and evaluation challenges are not available during preparation.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreparationChallenges<F> {
    /// Available after the online input commitments.
    pub w: Option<F>,
    /// Available after the `BeforeY` auxiliary commitments.
    pub y: Option<F>,
    /// Available after the `BeforeX` auxiliary commitments.
    pub x: Option<F>,
}

/// An online batch under construction, with one assignment per polynomial.
///
/// This enforces the honest prover's lifecycle. The transcript absorption and
/// circuit bindings independently enforce these deadlines against a malicious
/// prover; a prover-side state machine is not a soundness boundary.
pub(crate) struct Prepared<F: Field, R: Rank> {
    layout: Layout,
    inputs: Vec<F>,
    polynomials: Vec<Option<sparse::Polynomial<F, R>>>,
    next: usize,
}

const PHASES: [Phase; 4] = Phase::ALL;

impl<F: Field, R: Rank> Prepared<F, R> {
    /// Starts preparation with the values to commit before `w`.
    ///
    /// # Errors
    ///
    /// Rejects a malformed layout or an incorrect number of input values.
    pub(crate) fn new(layout: Layout, inputs: Vec<F>) -> Result<Self> {
        layout.check()?;
        if inputs.len() != layout.inputs {
            return Err(Error::InvalidWitness(
                "online input length does not match its declaration".into(),
            ));
        }
        Ok(Self {
            layout,
            inputs,
            polynomials: vec![None; layout.polynomials.len()],
            next: 0,
        })
    }

    /// The immutable input values prepared before the first challenge.
    pub(crate) fn inputs(&self) -> &[F] {
        &self.inputs
    }

    /// Supplies the polynomials of the next phase, in declaration order.
    ///
    /// Even an empty phase must be supplied, so every transition follows the
    /// same schedule. Neither an earlier slot nor the early inputs can change.
    ///
    /// # Errors
    ///
    /// Rejects out-of-order or repeated phases, incorrect polynomial counts,
    /// and the zero polynomial, whose commitment the walk cannot take. A
    /// rejected call leaves the preparation unchanged.
    pub(crate) fn supply(
        &mut self,
        phase: Phase,
        polynomials: Vec<sparse::Polynomial<F, R>>,
    ) -> Result<()> {
        let count = self
            .layout
            .polynomials
            .iter()
            .filter(|&&p| p == phase)
            .count();
        if PHASES.get(self.next) != Some(&phase) || polynomials.len() != count {
            return Err(Error::InvalidWitness(
                "online polynomial preparation does not match its phase".into(),
            ));
        }
        if polynomials
            .iter()
            .any(|poly| poly.iter_coeffs().all(|c| c == F::ZERO))
        {
            return Err(Error::InvalidWitness(
                "an online polynomial must not be zero".into(),
            ));
        }
        let mut polynomials = polynomials.into_iter();
        for (slot, &deadline) in self.polynomials.iter_mut().zip(self.layout.polynomials) {
            if deadline == phase {
                *slot = Some(polynomials.next().expect("checked phase length"));
            }
        }
        self.next += 1;
        Ok(())
    }

    /// Returns the already prepared polynomials of one phase in slot order.
    ///
    /// # Errors
    ///
    /// Rejects access before that phase has been supplied.
    pub(crate) fn phase(&self, phase: Phase) -> Result<Vec<&sparse::Polynomial<F, R>>> {
        if !PHASES[..self.next].contains(&phase) {
            return Err(Error::InvalidWitness(
                "online polynomial phase has not been prepared".into(),
            ));
        }
        Ok(self
            .polynomials
            .iter()
            .zip(self.layout.polynomials)
            .filter(|(_, p)| **p == phase)
            .map(|(poly, _)| poly.as_ref().expect("completed phase"))
            .collect())
    }

    /// Finishes preparation after every commitment phase.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete preparation, including missing empty phases.
    pub(crate) fn finish(self) -> Result<Vec<sparse::Polynomial<F, R>>> {
        if self.next != PHASES.len() {
            return Err(Error::InvalidWitness(
                "online polynomial preparation is incomplete".into(),
            ));
        }
        Ok(self
            .polynomials
            .into_iter()
            .map(|p| p.expect("all phases completed"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::pasta::Fp;

    use super::*;
    use crate::profile::online::{Opening, Point};

    const LAYOUT: Layout = Layout {
        polynomials: &[Phase::BeforeW, Phase::BeforeX],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Input(0),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Constant(1),
                value: 1,
            },
        ],
        inputs: 1,
        points: 0,
        values: 2,
    };

    fn polynomial(value: u64) -> sparse::Polynomial<Fp, TestRank> {
        sparse::Polynomial::from_coeffs(vec![Fp::from(value)])
    }

    #[test]
    fn phases_are_once_only_and_rejected_calls_do_not_advance() -> Result<()> {
        let mut prepared = Prepared::<Fp, TestRank>::new(LAYOUT, vec![Fp::from(7)])?;
        assert!(prepared.phase(Phase::BeforeW).is_err());
        assert!(
            prepared
                .supply(Phase::BeforeX, vec![polynomial(2)])
                .is_err()
        );
        assert!(prepared.supply(Phase::BeforeW, vec![]).is_err());
        prepared.supply(Phase::BeforeW, vec![polynomial(1)])?;
        assert!(
            prepared
                .supply(Phase::BeforeW, vec![polynomial(3)])
                .is_err()
        );
        prepared.supply(Phase::BeforeY, vec![])?;
        prepared.supply(Phase::BeforeX, vec![polynomial(2)])?;
        prepared.supply(Phase::BeforeAlpha, vec![])?;
        assert_eq!(prepared.inputs(), &[Fp::from(7)]);
        assert_eq!(prepared.phase(Phase::BeforeW)?[0].eval(Fp::ZERO), Fp::ONE);
        let polynomials = prepared.finish()?;
        assert_eq!(polynomials[0].eval(Fp::ZERO), Fp::ONE);
        assert_eq!(polynomials[1].eval(Fp::ZERO), Fp::from(2));
        Ok(())
    }

    #[test]
    fn missing_inputs_or_phases_reject() -> Result<()> {
        assert!(Prepared::<Fp, TestRank>::new(LAYOUT, vec![]).is_err());
        let mut prepared = Prepared::<Fp, TestRank>::new(Layout::EMPTY, vec![])?;
        prepared.supply(Phase::BeforeW, vec![])?;
        assert!(prepared.finish().is_err());
        Ok(())
    }
}
