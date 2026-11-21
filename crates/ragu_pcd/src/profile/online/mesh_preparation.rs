//! Source-mesh witness preparation, with inherited polynomials preserved exactly.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Error, Result};
use udon::field::Field;

use super::{Layout, Phase, mesh::Mesh, prepared::PreparationChallenges, source::SourceRegistry};

/// Witnesses available at one declared mesh deadline.
pub(crate) struct PhaseWitness<'a, F: Field, R: Rank> {
    pub phase: Phase,
    pub inputs: &'a [F],
    pub challenges: PreparationChallenges<F>,
    pub inherited: Option<[&'a sparse::Polynomial<F, R>; 2]>,
    pub supplied: Vec<sparse::Polynomial<F, R>>,
}

impl Mesh {
    /// Whether a polynomial slot is supplied by the source mesh.
    pub fn owns(&self, index: usize) -> bool {
        self.restrictions().any(|r| r.polynomial == index)
            || self.helpers.iter().any(|h| h.polynomial == index)
            || self.u == index
            || self.outgoing == index
    }

    /// Positions of the two children's x,y coordinates, in child order.
    pub fn inherited_coordinates(&self) -> [usize; 4] {
        [
            self.inherited[0].x,
            self.inherited[0].y,
            self.inherited[1].x,
            self.inherited[1].y,
        ]
    }

    /// Fills the inherited coordinates from the actual child instances.
    ///
    /// The corresponding circuit exports must authenticate these same values.
    /// This helper alone is not a soundness boundary.
    pub(crate) fn carry_inputs<F: Field>(
        &self,
        layout: Layout,
        mut inputs: Vec<F>,
        children: [[F; 2]; 2],
    ) -> Result<Vec<F>> {
        self.check(layout)?;
        if inputs.len() != layout.inputs {
            return Err(Error::InvalidWitness(
                "source mesh input length does not match its declaration".into(),
            ));
        }
        for (index, value) in self
            .inherited_coordinates()
            .into_iter()
            .zip(children.into_iter().flatten())
        {
            inputs[index] = value;
        }
        Ok(inputs)
    }

    /// Merges user polynomial witnesses with the source mesh's reserved slots.
    ///
    /// Before w, inherited slots receive the children's retained polynomials,
    /// without replacing them by freshly computed restrictions. Later slots
    /// use only the enclosing challenges available at their deadlines.
    pub(crate) fn prepare<F: Field, R: Rank>(
        &self,
        layout: Layout,
        source: &SourceRegistry<'_, F>,
        witness: PhaseWitness<'_, F, R>,
    ) -> Result<Vec<sparse::Polynomial<F, R>>> {
        let PhaseWitness {
            phase,
            inputs,
            challenges,
            inherited,
            supplied,
        } = witness;
        self.check(layout)?;
        if inputs.len() != layout.inputs {
            return Err(Error::InvalidWitness(
                "source mesh input length does not match its declaration".into(),
            ));
        }
        let missing = || Error::InvalidWitness("source mesh is missing a deadline input".into());
        let mut supplied = supplied.into_iter();
        let mut polynomials = Vec::new();
        for index in layout.phase_range(phase) {
            let polynomial =
                if let Some(child) = self.inherited.iter().position(|r| r.polynomial == index) {
                    (*inherited.as_ref().ok_or_else(missing)?[child]).clone()
                } else if let Some(r) = self.introduced.iter().find(|r| r.polynomial == index) {
                    source.xy(inputs[r.x], inputs[r.y])?
                } else if let Some(h) = self.helpers.iter().find(|h| h.polynomial == index) {
                    source.wx(challenges.w.ok_or_else(missing)?, inputs[h.x])?
                } else if index == self.u {
                    source.wy(
                        challenges.w.ok_or_else(missing)?,
                        challenges.y.ok_or_else(missing)?,
                    )?
                } else if index == self.outgoing {
                    source.xy(
                        challenges.x.ok_or_else(missing)?,
                        challenges.y.ok_or_else(missing)?,
                    )?
                } else {
                    supplied.next().ok_or_else(|| {
                        Error::InvalidWitness("missing user polynomial outside source mesh".into())
                    })?
                };
            polynomials.push(polynomial);
        }
        if supplied.next().is_some() {
            return Err(Error::InvalidWitness(
                "extra user polynomial overlaps the source mesh".into(),
            ));
        }
        Ok(polynomials)
    }
}

impl Mesh {
    /// Valid setup-defined mesh restrictions for a synthetic base child.
    /// Unrelated online slots hold the padding polynomial, the constant one,
    /// as a synthetic child's online slots do.
    pub(crate) fn dummy_polynomials<F: Field, R: Rank>(
        &self,
        layout: Layout,
        source: &SourceRegistry<'_, F>,
        one: F,
    ) -> Result<Vec<sparse::Polynomial<F, R>>> {
        let inputs = alloc::vec![one;layout.inputs];
        let inherited = source.xy::<R>(one, one)?;
        let mut result = Vec::new();
        for phase in Phase::ALL {
            let challenges = PreparationChallenges {
                w: (phase >= Phase::BeforeY).then_some(one),
                y: (phase >= Phase::BeforeX).then_some(one),
                x: (phase >= Phase::BeforeAlpha).then_some(one),
            };
            let supplied = layout
                .phase_range(phase)
                .filter(|&i| !self.owns(i))
                .map(|_| crate::recursion::native::online::padding())
                .collect();
            result.extend(self.prepare(
                layout,
                source,
                PhaseWitness {
                    phase,
                    inputs: &inputs,
                    challenges,
                    inherited: Some([&inherited, &inherited]),
                    supplied,
                },
            )?);
        }
        Ok(result)
    }

    /// Checks that `source`'s restrictions at the synthetic base child's
    /// challenges are nonzero.
    ///
    /// The mesh's restrictions are the setup's polynomials, not the prover's,
    /// so a source registry whose restrictions vanish is rejected here: their
    /// commitments would be the identity, which the walk cannot take.
    ///
    /// # Errors
    ///
    /// Fails if a restriction is the zero polynomial, and propagates
    /// [`Self::dummy_polynomials`]'s errors.
    pub(crate) fn check_source<F: Field, R: Rank>(
        &self,
        layout: Layout,
        source: &SourceRegistry<'_, F>,
        one: F,
    ) -> Result<()> {
        let vanishes = self
            .dummy_polynomials::<F, R>(layout, source, one)?
            .iter()
            .any(|poly| poly.iter_coeffs().all(|c| c == F::ZERO));
        if vanishes {
            return Err(Error::Initialization(
                "the source registry's restrictions vanish, so their commitments are the identity"
                    .into(),
            ));
        }
        Ok(())
    }
}
