//! Ephemeral state shared by the fuse's online polynomial preparation phases.
//!
//! The fuse makes every call here for every profile. What a profile declares
//! is decided on this side of the calls: a side without a batch supplies
//! nothing, commits no stage and traces no helper, and a side without a mesh
//! carries and prepares no source polynomial.
//!
//! The same state prepares the source meshes' witnesses, keeping inherited
//! polynomials exactly, and holds the batch to its commitment deadlines
//! ([`Prepared`]).

use alloc::{vec, vec::Vec};

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
    Layout, Phase, PreparationChallenges, SourceRegistry,
    circuit::{self, Challenges},
    mesh::Mesh,
    stages::{
        self, EvalStage, InputStage, InputWitness, PolynomialsLen, Present, QueryStage,
        QueryWitness, Side,
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
    source_domain: Option<u32>,
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
            Some(mesh) => {
                let children = children()?;
                // This runs on the thread that calls `fuse`, outside its
                // parallel jobs, as the hook's thread-local requires.
                #[cfg(test)]
                let children = crate::source_mesh_tests::mutate_inherited_coordinates(children);
                mesh.carry_inputs(S::layout::<P>(), inputs, children)?
            }
            None => inputs,
        };
        Self::new(inputs)?.with_source(
            source.map(|source| source.tag()),
            source.map(|source| source.domain_log2()),
        )
    }

    pub(crate) fn new(inputs: Vec<C::Scalar>) -> Result<Self> {
        Ok(Self {
            source_tag: None,
            source_domain: None,
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

    pub(crate) fn with_source(
        mut self,
        tag: Option<C::Scalar>,
        domain: Option<u32>,
    ) -> Result<Self> {
        circuit::Circuit::<C::Scalar, P, S>::with_source(tag, domain)?;
        self.source_tag = tag;
        self.source_domain = domain;
        Ok(self)
    }

    pub(crate) fn circuit(&self) -> circuit::Circuit<C::Scalar, P, S> {
        circuit::Circuit::with_source(self.source_tag, self.source_domain)
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
        mut rx: impl FnMut() -> Result<sparse::Polynomial<C::Scalar, R>>,
        generators: &G,
    ) -> Result<()> {
        if Self::active() {
            // The other field absorbs affine coordinates. Resample the stage's
            // alpha before publishing a commitment that has none.
            loop {
                let polynomial = rx()?;
                let commitment = B::sparse_commit_to_affine(&polynomial, generators);
                if !commitment.is_identity() {
                    self.stage_commitments[index] = Some(commitment);
                    self.stages[index] = Some(polynomial);
                    break;
                }
            }
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
        let sums = match (self.witness(challenges), stages::helper::<P, S>()) {
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
    /// [`stages::layout`] declares: the helper after the profile's
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
                .map(|_| crate::internal::native::online::padding())
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
mod prepared_tests {
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
