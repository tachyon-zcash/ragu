//! Ephemeral state shared by the fuse's private polynomial preparation phases.

use alloc::vec::Vec;

use ragu_backend::Backend;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
    staging::{MultiStage, StageExt},
};
use ragu_core::{Error, FixedGenerators, Result};
use ragu_primitives::vec::FixedVec;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::{
    Phase,
    batch::Challenges,
    circuit,
    prepared::{PreparationChallenges, Prepared},
    stages::{EvalStage, InputStage, InputWitness, PolynomialsLen, QueryStage, QueryWitness, Side},
};
use crate::profile::Profile;

/// A step's private polynomials and stages. Only stage polynomials survive in
/// the proof; the private polynomials are consumed by this step's PCS fold.
pub(crate) struct State<C: Affine, R: Rank, P: Profile, S: Side> {
    source_tag: Option<C::Scalar>,
    prepared: Option<Prepared<C::Scalar, R>>,
    polynomials: Vec<sparse::Polynomial<C::Scalar, R>>,
    commitments: Vec<C>,
    inputs: Option<InputWitness<C::Scalar, P, S>>,
    query: Option<QueryWitness<C::Scalar, P, S>>,
    eval: Option<FixedVec<C::Scalar, PolynomialsLen<P, S>>>,
    stages: [Option<sparse::Polynomial<C::Scalar, R>>; 3],
    stage_commitments: [Option<C>; 3],
}

impl<C: Affine, R: Rank, P: Profile, S: Side> State<C, R, P, S> {
    pub(crate) fn new(inputs: Vec<C::Scalar>) -> Result<Self> {
        Ok(Self {
            source_tag: None,
            prepared: Some(Prepared::new(S::layout::<P>(), inputs)?),
            polynomials: Vec::new(),
            commitments: Vec::new(),
            inputs: None,
            query: None,
            eval: None,
            stages: core::array::from_fn(|_| None),
            stage_commitments: [None; 3],
        })
    }

    pub(crate) fn with_source_tag(mut self, tag: Option<C::Scalar>) -> Result<Self> {
        circuit::Circuit::<C::Scalar, P, S>::with_source_tag(tag)?;
        self.source_tag = tag;
        Ok(self)
    }

    pub(crate) fn circuit(&self) -> circuit::Circuit<C::Scalar, P, S> {
        circuit::Circuit::with_source_tag(self.source_tag)
            .expect("source checked at initialization")
    }

    pub(crate) fn early_values(&self) -> &[C::Scalar] {
        match &self.inputs {
            Some(inputs) => &inputs.values,
            None => self
                .prepared
                .as_ref()
                .expect("preparation has not finished")
                .inputs(),
        }
    }

    /// Commits a phase once, preserving the profile's distinct-polynomial order.
    pub(crate) fn supply<B: Backend, G: FixedGenerators<C>>(
        &mut self,
        phase: Phase,
        polynomials: Vec<sparse::Polynomial<C::Scalar, R>>,
        generators: &G,
    ) -> Result<()> {
        if phase != Phase::BeforeW && self.inputs.is_none() {
            return Err(Error::InvalidWitness(
                "private inputs must be committed before the next phase".into(),
            ));
        }
        let prepared = self.prepared.as_mut().ok_or_else(|| {
            Error::InvalidWitness("private polynomial preparation already finished".into())
        })?;
        prepared.supply(phase, polynomials)?;
        self.commitments.extend(
            prepared
                .phase(phase)?
                .into_iter()
                .map(|poly| B::sparse_commit_to_affine(poly, generators)),
        );
        if phase == Phase::BeforeAlpha {
            self.polynomials = self
                .prepared
                .take()
                .expect("checked preparation")
                .finish()?;
        }
        Ok(())
    }

    pub(crate) fn commitments(&self) -> &[C] {
        &self.commitments
    }

    pub(crate) fn polynomials(&self) -> &[sparse::Polynomial<C::Scalar, R>] {
        &self.polynomials
    }

    /// Commits the immutable user data and the opposite field's pre-w points.
    pub(crate) fn commit_inputs<B: Backend, G: FixedGenerators<C>, RNG: CryptoRng>(
        &mut self,
        foreign: Vec<C::Scalar>,
        generators: &G,
        rng: &mut RNG,
    ) -> Result<()> {
        if self.inputs.is_some() {
            return Err(Error::InvalidWitness(
                "private inputs already committed".into(),
            ));
        }
        self.prepared
            .as_ref()
            .ok_or_else(|| Error::InvalidWitness("private preparation already finished".into()))?
            .phase(Phase::BeforeW)?;
        let inputs = InputWitness {
            source_tag: FixedVec::new(self.source_tag.into_iter().collect())?,
            values: FixedVec::new(self.early_values().to_vec())?,
            foreign: FixedVec::new(foreign)?,
        };
        let rx = <InputStage<P, S> as StageExt<C::Scalar, R>>::rx(
            C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
            &inputs,
        )?;
        self.set_stage::<B, G>(0, rx, generators);
        self.inputs = Some(inputs);
        Ok(())
    }

    /// Fixes all opening claims after the last auxiliary commitment.
    pub(crate) fn commit_query<B: Backend, G: FixedGenerators<C>, RNG: CryptoRng>(
        &mut self,
        points: Vec<C::Scalar>,
        challenges: PreparationChallenges<C::Scalar>,
        generators: &G,
        rng: &mut RNG,
    ) -> Result<()> {
        if self.prepared.is_some() || self.inputs.is_none() || self.query.is_some() {
            return Err(Error::InvalidWitness(
                "private query is out of phase".into(),
            ));
        }
        let missing = || Error::InvalidWitness("private query is missing a challenge".into());
        // Query points use only w, y and x. Later challenges are not sampled yet.
        let challenges = Challenges {
            w: challenges.w.ok_or_else(missing)?,
            y: challenges.y.ok_or_else(missing)?,
            x: challenges.x.ok_or_else(missing)?,
            alpha: C::Scalar::ZERO,
            u: C::Scalar::ZERO,
            beta: C::Scalar::ZERO,
        };
        #[cfg(test)]
        let challenges = crate::private_online_tests::mutate_query_challenges(challenges);
        let queries = S::layout::<P>().query::<_, R, B>(
            &self.polynomials,
            self.early_values().to_vec(),
            points,
            &challenges,
        )?;
        let query = QueryWitness {
            challenges: FixedVec::from_fn(|i| [challenges.w, challenges.y, challenges.x][i]),
            points: FixedVec::new(queries.points)?,
            values: FixedVec::new(queries.values)?,
        };
        let rx = <QueryStage<P, S> as StageExt<C::Scalar, R>>::rx(
            C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
            &query,
        )?;
        self.set_stage::<B, G>(1, rx, generators);
        self.query = Some(query);
        Ok(())
    }

    /// Fixes one evaluation at u per distinct polynomial before pre_beta.
    pub(crate) fn commit_eval<B: Backend, G: FixedGenerators<C>, RNG: CryptoRng>(
        &mut self,
        u: C::Scalar,
        generators: &G,
        rng: &mut RNG,
    ) -> Result<()> {
        if self.query.is_none() || self.eval.is_some() {
            return Err(Error::InvalidWitness(
                "private evaluation is out of phase".into(),
            ));
        }
        let eval = FixedVec::try_from_fn(|i| Ok(B::sparse_eval(&self.polynomials[i], u)))?;
        let rx = <EvalStage<P, S> as StageExt<C::Scalar, R>>::rx(
            C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
            &eval,
        )?;
        self.set_stage::<B, G>(2, rx, generators);
        self.eval = Some(eval);
        Ok(())
    }

    fn set_stage<B: Backend, G: FixedGenerators<C>>(
        &mut self,
        index: usize,
        rx: sparse::Polynomial<C::Scalar, R>,
        generators: &G,
    ) {
        self.stage_commitments[index] = Some(B::sparse_commit_to_affine(&rx, generators));
        self.stages[index] = Some(rx);
    }

    pub(crate) fn stage_commitment(&self, index: usize) -> C {
        self.stage_commitments[index].expect("private stage committed at its deadline")
    }

    pub(crate) fn query(&self) -> &QueryWitness<C::Scalar, P, S> {
        self.query.as_ref().expect("private query committed")
    }

    pub(crate) fn witness(
        &self,
        challenges: Challenges<C::Scalar>,
    ) -> circuit::Witness<'_, C::Scalar, P, S> {
        circuit::Witness {
            inputs: self.inputs.as_ref().expect("private inputs committed"),
            query: self.query(),
            eval: self.eval.as_ref().expect("private evaluations committed"),
            challenges,
        }
    }

    /// Traces the shared helper with exactly the stage witnesses already committed.
    pub(crate) fn trace<RNG: CryptoRng>(
        &self,
        challenges: Challenges<C::Scalar>,
        registry: &Registry<'_, C::Scalar, R>,
        index: CircuitIndex,
        rng: &mut RNG,
    ) -> Result<(sparse::Polynomial<C::Scalar, R>, [C::Scalar; 2])> {
        let circuit = MultiStage::<C::Scalar, R, _>::new(self.circuit());
        let (trace, sums) = circuit.trace(self.witness(challenges))?.into_parts();
        Ok((registry.assemble(&trace, index, rng)?, sums))
    }

    /// Common targets read from the already committed stage witnesses.
    pub(crate) fn mesh_claims(&self) -> Result<Vec<C::Scalar>> {
        S::mesh::<P>().map_or_else(
            || Ok(Vec::new()),
            |mesh| mesh.claim_values(S::layout::<P>(), self.early_values(), &self.query().values),
        )
    }

    pub(crate) fn take_stages(&mut self) -> Vec<sparse::Polynomial<C::Scalar, R>> {
        self.stages
            .iter_mut()
            .map(|stage| stage.take().expect("all private stages committed"))
            .collect()
    }
}
