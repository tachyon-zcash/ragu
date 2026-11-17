//! Ephemeral state shared by the fuse's online polynomial preparation phases.
//!
//! The fuse makes every call here for every profile. What a profile declares
//! is decided on this side of the calls: a side without a batch supplies
//! nothing, commits no stage and traces no helper, and a side without a mesh
//! carries and prepares no source polynomial.

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
    circuit, extension,
    mesh_preparation::PhaseWitness,
    prepared::{PreparationChallenges, Prepared},
    source::SourceRegistry,
    stages::{
        EvalStage, InputStage, InputWitness, PolynomialsLen, Present, QueryStage, QueryWitness,
        Side,
    },
};
use crate::profile::{ExtensionRxs, Profile};

/// A batch's fold, the helper's quotient and evaluation sums in that order:
/// empty for a side without a batch.
pub(crate) type Fold<F, P, S> = FixedVec<F, Present<P, S, 2>>;

/// A step's online polynomials and stages. Only stage polynomials survive in
/// the proof; the online polynomials are consumed by this step's PCS fold.
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
    helper: Option<sparse::Polynomial<C::Scalar, R>>,
    fold: Option<Fold<C::Scalar, P, S>>,
}

impl<C: Affine, R: Rank, P: Profile, S: Side> State<C, R, P, S> {
    /// Whether this side declares a batch, and so has stages and a helper.
    fn active() -> bool {
        !S::layout::<P>().is_empty()
    }

    /// Starts a step's batch from the inputs its profile supplied, with the
    /// children's coordinates in the slots a mesh inherits them at and the
    /// tag of the source registry setup captured.
    ///
    /// `children` is asked for the two children's $x$ and $y$ only when the
    /// side declares a mesh.
    pub(crate) fn begin(
        inputs: Vec<C::Scalar>,
        children: impl FnOnce() -> Result<[[C::Scalar; 2]; 2]>,
        source: Option<&SourceRegistry<'_, C::Scalar>>,
    ) -> Result<Self> {
        let inputs = match S::mesh::<P>() {
            Some(mesh) => mesh.carry_inputs(S::layout::<P>(), inputs, children()?)?,
            None => inputs,
        };
        Self::new(inputs)?.with_source_tag(source.map(|source| source.tag()))
    }

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
            helper: None,
            fold: None,
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

    /// Supplies `phase` with the polynomials the profile supplied for it,
    /// after a mesh fills the slots it owns from `source`, the challenges
    /// drawn so far and, before $w$, the polynomials the children handed up.
    pub(crate) fn prepare<B: Backend, G: FixedGenerators<C>>(
        &mut self,
        phase: Phase,
        supplied: Vec<sparse::Polynomial<C::Scalar, R>>,
        challenges: PreparationChallenges<C::Scalar>,
        source: Option<&SourceRegistry<'_, C::Scalar>>,
        inherited: Option<[&[sparse::Polynomial<C::Scalar, R>]; 2]>,
        generators: &G,
    ) -> Result<()> {
        let polynomials = match S::mesh::<P>() {
            Some(mesh) => mesh.prepare(
                S::layout::<P>(),
                source.ok_or_else(|| {
                    Error::Initialization("missing captured source registry".into())
                })?,
                PhaseWitness {
                    phase,
                    inputs: self.early_values(),
                    challenges,
                    inherited: inherited.map(|[left, right]| [&left[0], &right[0]]),
                    supplied,
                },
            )?,
            None => supplied,
        };
        self.supply::<B, G>(phase, polynomials, generators)
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
                "online inputs must be committed before the next phase".into(),
            ));
        }
        let prepared = self.prepared.as_mut().ok_or_else(|| {
            Error::InvalidWitness("online polynomial preparation already finished".into())
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

    /// The coordinates of the commitments so far, $x$ then $y$ in polynomial
    /// order: what the other field's input stage holds of them.
    pub(crate) fn coordinates(&self) -> Result<Vec<C::Base>> {
        let mut coordinates = Vec::with_capacity(2 * self.commitments.len());
        for point in &self.commitments {
            let (x, y) = point.coordinates().ok_or_else(|| {
                Error::InvalidWitness("an online polynomial commits to the identity".into())
            })?;
            coordinates.extend([x, y]);
        }
        Ok(coordinates)
    }

    /// The polynomial the step hands its parent: the mesh's outgoing
    /// restriction, and nothing without a mesh.
    pub(crate) fn source_out(&self) -> Vec<sparse::Polynomial<C::Scalar, R>> {
        S::mesh::<P>()
            .map(|mesh| self.polynomials[mesh.outgoing].clone())
            .into_iter()
            .collect()
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
                "online inputs already committed".into(),
            ));
        }
        self.prepared
            .as_ref()
            .ok_or_else(|| Error::InvalidWitness("online preparation already finished".into()))?
            .phase(Phase::BeforeW)?;
        let inputs = InputWitness {
            source_tag: FixedVec::new(self.source_tag.into_iter().collect())?,
            values: FixedVec::new(self.early_values().to_vec())?,
            foreign: FixedVec::new(foreign)?,
        };
        self.set_stage::<B, G>(
            0,
            || {
                <InputStage<P, S> as StageExt<C::Scalar, R>>::rx(
                    C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
                    &inputs,
                )
            },
            generators,
        )?;
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
            return Err(Error::InvalidWitness("online query is out of phase".into()));
        }
        let missing = || Error::InvalidWitness("online query is missing a challenge".into());
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
        let challenges = crate::online_batch_tests::mutate_query_challenges(challenges);
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
        self.set_stage::<B, G>(
            1,
            || {
                <QueryStage<P, S> as StageExt<C::Scalar, R>>::rx(
                    C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
                    &query,
                )
            },
            generators,
        )?;
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
                "online evaluation is out of phase".into(),
            ));
        }
        let eval = FixedVec::try_from_fn(|i| Ok(B::sparse_eval(&self.polynomials[i], u)))?;
        self.set_stage::<B, G>(
            2,
            || {
                <EvalStage<P, S> as StageExt<C::Scalar, R>>::rx(
                    C::Scalar::random(|bytes| rng.fill_bytes(bytes)),
                    &eval,
                )
            },
            generators,
        )?;
        self.eval = Some(eval);
        Ok(())
    }

    /// Commits stage `index` to the polynomial `rx` builds. A side without a
    /// batch registers no stage, so it builds and commits none.
    fn set_stage<B: Backend, G: FixedGenerators<C>>(
        &mut self,
        index: usize,
        rx: impl FnOnce() -> Result<sparse::Polynomial<C::Scalar, R>>,
        generators: &G,
    ) -> Result<()> {
        if Self::active() {
            let rx = rx()?;
            self.stage_commitments[index] = Some(B::sparse_commit_to_affine(&rx, generators));
            self.stages[index] = Some(rx);
        }
        Ok(())
    }

    pub(crate) fn stage_commitment(&self, index: usize) -> C {
        self.stage_commitments[index].expect("online stage committed at its deadline")
    }

    pub(crate) fn query(&self) -> &QueryWitness<C::Scalar, P, S> {
        self.query.as_ref().expect("online query committed")
    }

    /// Appends the batch's quotient to the step's: `poly` moves up one power
    /// of `alpha` per opening and the batch's quotients, in opening order,
    /// take the powers below. A side without a batch returns `poly` as it is.
    pub(crate) fn append_quotient(
        &self,
        mut poly: sparse::Polynomial<C::Scalar, R>,
        alpha: C::Scalar,
    ) -> Result<sparse::Polynomial<C::Scalar, R>> {
        if !Self::active() {
            return Ok(poly);
        }
        let layout = S::layout::<P>();
        let query = self.query();
        poly.scale(alpha.pow_u64(layout.openings.len() as u64));
        // Opening descriptors can use w, y and x; u and beta are not sampled
        // yet and are never read by quotient construction.
        poly += &layout.quotient(
            &self.polynomials,
            self.early_values(),
            &query.points,
            &Challenges {
                w: query.challenges[0],
                y: query.challenges[1],
                x: query.challenges[2],
                alpha,
                u: C::Scalar::ZERO,
                beta: C::Scalar::ZERO,
            },
        )?;
        Ok(poly)
    }

    /// The helper's witness over the stage witnesses already committed, which
    /// the profile's consumers trace over too: `None` for a side without a
    /// batch.
    pub(crate) fn witness(
        &self,
        challenges: Challenges<C::Scalar>,
    ) -> Option<circuit::Witness<'_, C::Scalar, P, S>> {
        Self::active().then(|| circuit::Witness {
            inputs: self.inputs.as_ref().expect("online inputs committed"),
            query: self.query(),
            eval: self.eval.as_ref().expect("online evaluations committed"),
            challenges,
        })
    }

    /// Traces the helper with exactly the stage witnesses already committed
    /// and assembles its polynomial at the registry index `index` gives the
    /// helper's place among the extension's circuits, keeping the polynomial
    /// for [`Self::extension_rxs`] and the fold for the proof. Returns the fold.
    ///
    /// A side without a batch traces nothing and its fold is empty.
    pub(crate) fn trace<RNG: CryptoRng>(
        &mut self,
        challenges: Challenges<C::Scalar>,
        registry: &Registry<'_, C::Scalar, R>,
        index: impl FnOnce(u32) -> CircuitIndex,
        rng: &mut RNG,
    ) -> Result<Fold<C::Scalar, P, S>> {
        let sums = match (self.witness(challenges), extension::helper::<P, S>()) {
            (Some(witness), Some(helper)) => {
                let circuit = MultiStage::<C::Scalar, R, _>::new(self.circuit());
                let (trace, sums) = circuit.trace(witness)?.into_parts();
                let rx = registry.assemble(&trace, index(helper), rng)?;
                self.helper = Some(rx);
                sums.to_vec()
            }
            _ => Vec::new(),
        };
        self.set_fold(sums)
    }

    /// The fold alone, for the patcher's execution, which assembles no
    /// polynomial.
    #[cfg(feature = "unstable-fuzzing")]
    pub(crate) fn trace_fold(
        &mut self,
        challenges: Challenges<C::Scalar>,
    ) -> Result<Fold<C::Scalar, P, S>> {
        let sums = match self.witness(challenges) {
            Some(witness) => {
                let circuit = MultiStage::<C::Scalar, R, _>::new(self.circuit());
                circuit.trace(witness)?.into_aux().to_vec()
            }
            None => Vec::new(),
        };
        self.set_fold(sums)
    }

    fn set_fold(&mut self, sums: Vec<C::Scalar>) -> Result<Fold<C::Scalar, P, S>> {
        let fold = Fold::<C::Scalar, P, S>::new(sums)?;
        self.fold = Some(fold.clone());
        Ok(fold)
    }

    /// The fold the helper's trace computed.
    pub(crate) fn fold(&self) -> Result<&[C::Scalar]> {
        self.fold
            .as_deref()
            .ok_or_else(|| Error::InvalidWitness("online helper has not been traced".into()))
    }

    /// Common targets read from the already committed stage witnesses.
    pub(crate) fn mesh_claims(&self) -> Result<Vec<C::Scalar>> {
        S::mesh::<P>().map_or_else(
            || Ok(Vec::new()),
            |mesh| mesh.claim_values(S::layout::<P>(), self.early_values(), &self.query().values),
        )
    }

    /// Completes the polynomials the profile's prover filled its own
    /// extension with into the registered extension's, in the order
    /// [`extension::layout`] declares: the helper after the profile's
    /// circuits, and the batch's stages before the profile's. A side without
    /// a batch adds nothing.
    pub(crate) fn extension_rxs(
        &mut self,
        mut rxs: ExtensionRxs<C::Scalar, R>,
    ) -> Result<ExtensionRxs<C::Scalar, R>> {
        if Self::active() {
            let missing = || Error::InvalidWitness("online batch is out of phase".into());
            rxs.circuits.push(self.helper.take().ok_or_else(missing)?);
            let stages = self
                .stages
                .iter_mut()
                .map(|stage| stage.take().ok_or_else(missing))
                .collect::<Result<Vec<_>>>()?;
            rxs.stages.splice(0..0, stages);
        }
        Ok(rxs)
    }
}
