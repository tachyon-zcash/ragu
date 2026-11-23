//! The decompression's prover: the witness a compressed proof's sides are
//! prepared from, the stages it fills, and the extension's polynomials
//! for a proof.
//!
//! [`Witness::prepare`] runs the native verifier over a compressed proof,
//! keeping what both sides allocate; [`Prepared::new`] lays a side of it
//! out as the side's stages ([`Prepare`]) and runs the side's chunks
//! natively to fill the work, lifts, transcript and digits stages, which
//! the chunk circuits then hold their results to.
//!
//! Every proof of a profile carries every extension circuit's polynomial,
//! so every fuse runs the chunks over some compressed proof. A step that
//! decompresses a wallet's proof runs them over that one; any other runs
//! them over a canonical one, the wallet application's bootstrap proof
//! compressed, which [`Decompression`] prepares once and holds for the
//! aggregator application's lifetime. The chunk circuits' traces then
//! assemble against the aggregator's registry as the fuse's own circuits'
//! do, and the stages' polynomials come from the prepared sides' values.
//!
//! The context owns the wallet application: the aggregator application
//! holds the standard application whose proofs it decompresses, and hands
//! it back through [`Decompression::wallet`].

use alloc::{sync::Arc, vec, vec::Vec};
use core::marker::PhantomData;

use ragu_backend::Backend;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, WalletRank, sparse},
    registry::{CircuitIndex, Registry},
    staging::StageExt,
};
use ragu_core::{
    Cycle, Error, FixedGenerators, Result,
    drivers::{
        Driver,
        emulator::{Emulator, Wireless},
    },
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, Point, Uendo, extract_endoscalar, lift_endoscalar};
use rand::CryptoRng;
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{
    circuits::{self, Aux, Ctx, Loaded, Prepared, View, Write, execute, last},
    online::{self, input},
    program::{AbValue, Chunk, ElementSrc, Last, Schedule, squeezed},
    side::{Native, NativeExtra, Nested, NestedExtra, Side},
    stages::{
        self, DigitsStage, Front, LiftsStage, TranscriptStage, Values, WorkStage,
        message_points_of, message_scalars, num_runs,
    },
};
#[cfg(test)]
use super::{gadgets::derive::Fixed, program::ab_layout};
use crate::{
    Application, CompressedPcd, CompressedProof, Pcd, SelectableBackend,
    compress::{
        Lifted, Messages, Sampled,
        instance::Instance,
        revdot::{
            Openings,
            claims::{self, Kind},
            fold::Weights,
            native_position, nested_position,
        },
        transcript as compression_transcript,
    },
    header::{Header, NUM_ONLINE_FP_POLYS},
    internal::{ky, native, nested},
    ipa::{IpaCycle, IpaTranscript, MSM, Params},
    profile::{
        Aggregator, ExtensionRxs, Profile, Profiled, ProfiledCycle, ProverContext, Standard,
    },
    proof::bridge_alpha_power,
    step::internal::decompress::{DIGEST_SLOT, Decompress, S_SLOT},
};

/// A compressed proof prepared for decompression: both sides' stages
/// filled from the prover's native run of the chunks over it, which the
/// decompression step's fuse runs the chunk circuits over in place of the
/// canonical proof.
pub struct Decompressed<C: IpaCycle + ProfiledCycle<Profile = Standard>>(pub(crate) Sides<C>);

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Decompressed<C> {
    /// The round challenges of the host curve's IPA of the proof, in
    /// transcript order, as the circuit-field side's chunks hold them: the
    /// challenges of $s(X)$, which the decompression step commits.
    pub(crate) fn host_rounds(&self) -> Vec<C::CircuitField> {
        let native = &self.0.native;
        native.schedule.regions.lifts[squeezed::ROUNDS..]
            .iter()
            .map(|&slot| native.lifts.elements[slot])
            .collect()
    }

    /// The digest of the proof's compression transcript, as the
    /// circuit-field side's chunks squeeze it: the transcript's last
    /// squeeze, taken after every round message of both curves' IPAs,
    /// which the decompression step stages.
    pub(crate) fn transcript_digest(&self) -> C::CircuitField {
        let native = &self.0.native;
        let digest = native
            .schedule
            .regions
            .digest
            .expect("the circuit-field side squeezes the digest");
        native.work.elements[digest]
    }
}

/// The aggregator's prover context: the wallet application whose proofs
/// the aggregator decompresses and a canonical decompression, prepared
/// for chunk circuits at rank `R` with `HEADER_SIZE`-element headers.
///
/// The wallet application's registries are the source registries the
/// aggregator's meshes certify (see [`Aggregator`]'s *Soundness*), so an
/// aggregator's verifier is built over the same wallet application as its
/// prover.
pub struct Decompression<'params, C, R, const HEADER_SIZE: usize, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    B: SelectableBackend,
{
    wallet: Application<'params, C, WalletRank, HEADER_SIZE, B>,
    canonical: Sides<C>,
    _marker: PhantomData<fn() -> R>,
}

/// A decompression step supplies the compressed proof it decompresses.
impl<C, R, const HEADER_SIZE: usize, B> ProverContext for Decompression<'_, C, R, HEADER_SIZE, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    B: SelectableBackend,
{
    type Source = Decompressed<C>;
}

impl<'params, C, R, const HEADER_SIZE: usize, B> Decompression<'params, C, R, HEADER_SIZE, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    R: Rank,
    B: SelectableBackend,
{
    /// Prepares the canonical decompression of `wallet`'s proofs: its
    /// bootstrap proof, compressed and run through both sides' chunks.
    ///
    /// `wallet` must be the network's wallet application, built from the
    /// same steps as every wallet's and finalized over the aggregator's own
    /// parameters, whose tables reach rank `R`, such as
    /// `baked_aggregator()`: their prefix is the Standard tables, so its
    /// proofs are those of a wallet over `baked()`. `finalize_with` holds
    /// the aggregator's parameters and header types to its and refuses
    /// source registries other than the wallet's. The online meshes hold
    /// the decompression's registry evaluations to those registries. The
    /// caller must still select the network's intended wallet application.
    ///
    /// # Errors
    ///
    /// Fails if `wallet`'s tables stop short of rank `R`, whose stage
    /// generators the chunk circuits use, or if the compression or its
    /// verification fails, which a finalized application's bootstrap does
    /// not.
    pub fn new(
        wallet: Application<'params, C, WalletRank, HEADER_SIZE, B>,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let reach = R::num_coeffs();
        if C::host_generators(wallet.params).g().len() < reach
            || C::nested_generators(wallet.params).g().len() < reach
        {
            return Err(Error::Initialization(
                "the wallet application's tables stop short of the aggregator rank, whose stage generators the decompression's chunk circuits use: finalize it over the aggregator's parameters, such as `baked_aggregator()`"
                    .into(),
            ));
        }
        let bootstrap = wallet
            .bootstrap
            .clone()
            .expect("a finalized application holds its bootstrap proof")
            .carry::<()>(());
        let compressed = wallet.compress(&bootstrap, rng)?;
        let canonical = Sides::prepare::<WalletRank, R, HEADER_SIZE, B, ()>(&wallet, &compressed)?;
        Ok(Decompression {
            wallet,
            canonical,
            _marker: PhantomData,
        })
    }

    /// The wallet application whose proofs the aggregator decompresses.
    pub fn wallet(&self) -> &Application<'params, C, WalletRank, HEADER_SIZE, B> {
        &self.wallet
    }

    /// Prepares the decompression of `pcd`, a compressed proof of the
    /// wallet application, for the step that decompresses it.
    ///
    /// # Errors
    ///
    /// Fails if the wallet application's verifier would reject `pcd`.
    pub(crate) fn prepare<H: Header<C::CircuitField>>(
        &self,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Decompressed<C>> {
        Ok(Decompressed(Sides::prepare::<
            WalletRank,
            R,
            HEADER_SIZE,
            B,
            H,
        >(&self.wallet, pcd)?))
    }

    /// The step's online Fq polynomial: the challenge polynomial $s(X)$
    /// of the nested curve's IPA of the proof the step's chunks run over,
    /// whose commitment is that IPA's $G'$.
    pub(crate) fn online_fq_polynomials(
        &self,
        source: Option<&Decompressed<C>>,
    ) -> Vec<sparse::Polynomial<C::ScalarField, R>> {
        let nested = &self.sides(source).nested;
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut rounds: Vec<C::ScalarField> = nested.schedule.regions.lifts[squeezed::ROUNDS..]
            .iter()
            .map(|&slot| nested.lifts.elements[slot])
            .collect();
        // Test hook: this runs on the thread that calls `fuse`, outside its
        // parallel jobs, as the hook's thread-local requires.
        #[cfg(test)]
        super::support::mutate_fq_rounds(&mut rounds);
        alloc::vec![sparse::Polynomial::from_coeffs(
            crate::ipa::challenge_polynomial(&rounds)
        )]
    }

    /// The native online input stage's values for the proof the step's
    /// chunks run over: the coordinates of the wallet registry's
    /// restrictions its verification reads, and the points it reads them
    /// at, which the step commits before its challenge.
    pub(crate) fn native_online_inputs(
        &self,
        source: Option<&Decompressed<C>>,
    ) -> Vec<C::CircuitField> {
        self.sides(source).native.online_inputs().to_vec()
    }

    /// The nested online input stage's values, likewise.
    pub(crate) fn nested_online_inputs(
        &self,
        source: Option<&Decompressed<C>>,
    ) -> Vec<C::ScalarField> {
        self.sides(source).nested.online_inputs().to_vec()
    }

    /// The sides a fuse runs the chunks over: `source`'s, the proof the
    /// step decompresses, or the canonical proof's without.
    fn sides<'a>(&'a self, source: Option<&'a Decompressed<C>>) -> &'a Sides<C> {
        source.map_or(&self.canonical, |decompressed| &decompressed.0)
    }

    /// The native extension's polynomials for profile `P` over `source`,
    /// or over the canonical decompression without: every chunk circuit's
    /// trace, the statement circuit's and the binding circuit's assembled
    /// against `registry` at their index in `P`'s layout, and the six
    /// stages' polynomials, each with an alpha from `rng` but the digits
    /// stage's, which the scalar-field side recomputes.
    ///
    /// # Errors
    ///
    /// Fails if a circuit's trace or assembly fails, which the prepared
    /// sides of a verified proof do not.
    pub(crate) fn native_rxs<P: Profile>(
        &self,
        source: Option<&Decompressed<C>>,
        online_openings: &[[C::CircuitField; 2]; 3 * NUM_ONLINE_FP_POLYS],
        registry: &Registry<'_, C::CircuitField, R>,
        (online_input, online_query): (Vec<C::CircuitField>, Vec<C::CircuitField>),
        rng: &mut impl CryptoRng,
    ) -> Result<ExtensionRxs<C::CircuitField, R>> {
        let params = self.wallet.params;
        // The decompression step sets the step binding: its flag, the
        // opening of the slot it committed s(X) in and the digest it
        // staged, the point at which it opened its digest slot.
        let stepped;
        let prepared = match source {
            Some(decompressed) => {
                stepped = decompressed
                    .0
                    .native
                    .for_decompression::<WalletRank, HEADER_SIZE>(
                        params,
                        online_openings[2 * NUM_ONLINE_FP_POLYS + S_SLOT],
                        online_openings[DIGEST_SLOT][0],
                    )?;
                &stepped
            }
            None => &self.canonical.native,
        };
        // The chunks load the online stages the step's fuse committed.
        let prepared = &prepared.clone().with_online(online_input, online_query)?;
        let schedule = prepared.schedule.clone();
        let mut circuits = Vec::with_capacity(schedule.circuits.len() + 2);
        for index in 0..schedule.circuits.len() {
            let trace =
                chunk_trace::<C, Native, R, HEADER_SIZE>(&schedule, index, prepared, params)?;
            let circuit = native::InternalCircuitIndex::ExtensionCircuit(index as u32);
            circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
        }
        let trace = circuits::StatementCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(
            schedule.clone(),
        )
        .trace(prepared)?
        .into_parts()
        .0;
        let statement =
            native::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32);
        circuits.push(registry.assemble(&trace, statement.circuit_index::<P>(), rng)?);
        let trace = circuits::BindingCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(
            schedule.clone(),
        )
        .trace(prepared)?
        .into_parts()
        .0;
        let binding =
            native::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32 + 1);
        circuits.push(registry.assemble(&trace, binding.circuit_index::<P>(), rng)?);
        type Lifts<C, R, const H: usize> = LiftsStage<C, Native, WalletRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Native, WalletRank, R, H>;
        type Transcript<C, R, const H: usize> = TranscriptStage<C, Native, WalletRank, R, H>;
        type Digits<C, R, const H: usize> = DigitsStage<C, Native, WalletRank, R, H>;
        let mut stages = front_rxs::<C, Native, R, HEADER_SIZE>(prepared, rng)?;
        stages.extend([
            Lifts::<C, R, HEADER_SIZE>::rx(random_alpha::<C::CircuitField>(rng), &prepared.lifts)?,
            Work::<C, R, HEADER_SIZE>::rx(random_alpha::<C::CircuitField>(rng), &prepared.work)?,
            Transcript::<C, R, HEADER_SIZE>::rx(
                random_alpha::<C::CircuitField>(rng),
                &prepared.transcript,
            )?,
            Digits::<C, R, HEADER_SIZE>::rx(C::CircuitField::ZERO, &prepared.digits)?,
        ]);
        Ok(ExtensionRxs { circuits, stages })
    }

    /// The nested extension's polynomials for profile `P`, as
    /// [`native_rxs`](Self::native_rxs): every chunk circuit's, the
    /// binding circuit's and the stages', the run stages', whose
    /// commitments the compression's transcript absorbed, and the lifts
    /// and digits stages', which the circuit-field side recomputes, with
    /// a zero alpha.
    ///
    /// # Errors
    ///
    /// As [`native_rxs`](Self::native_rxs).
    pub(crate) fn nested_rxs<P: Profile>(
        &self,
        source: Option<&Decompressed<C>>,
        output_commitments: &[C::HostCurve; NUM_ONLINE_FP_POLYS],
        online_fq_openings: &[C::ScalarField],
        registry: &Registry<'_, C::ScalarField, R>,
        (online_input, online_query): (Vec<C::ScalarField>, Vec<C::ScalarField>),
        rng: &mut impl CryptoRng,
    ) -> Result<ExtensionRxs<C::ScalarField, R>> {
        let params = self.wallet.params;
        let &[x, y] = online_fq_openings else {
            return Err(Error::Initialization(
                "the aggregator's step exports the opening of its one online Fq polynomial".into(),
            ));
        };
        // Every step's binding circuit exposes the commitment of its own
        // output slot, which the decompression step's holds the host
        // IPA's G' to, and the opening of its online Fq polynomial, which
        // every step's chunks hold to the nested IPA's s(X).
        let prepared: Prepared<C, Nested> = self
            .sides(source)
            .nested
            .for_step::<WalletRank, HEADER_SIZE>(
                params,
                source.is_some(),
                output_commitments[S_SLOT],
                [x, y],
            )?
            .with_online(online_input, online_query)?;
        let prepared = &prepared;
        let schedule = prepared.schedule.clone();
        let mut circuits = Vec::with_capacity(schedule.circuits.len() + 1);
        for index in 0..schedule.circuits.len() {
            let trace =
                chunk_trace::<C, Nested, R, HEADER_SIZE>(&schedule, index, prepared, params)?;
            let circuit = nested::InternalCircuitIndex::ExtensionCircuit(index as u32);
            circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
        }
        let trace = circuits::BindingCircuit::<C, Nested, WalletRank, R, HEADER_SIZE>::new(
            schedule.clone(),
        )
        .trace(prepared)?
        .into_parts()
        .0;
        let binding =
            nested::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32);
        circuits.push(registry.assemble(&trace, binding.circuit_index::<P>(), rng)?);
        type Lifts<C, R, const H: usize> = LiftsStage<C, Nested, WalletRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Nested, WalletRank, R, H>;
        type Digits<C, R, const H: usize> = DigitsStage<C, Nested, WalletRank, R, H>;
        let zero = C::ScalarField::ZERO;
        let mut stages = front_rxs::<C, Nested, R, HEADER_SIZE>(prepared, rng)?;
        stages.extend([
            Lifts::<C, R, HEADER_SIZE>::rx(zero, &prepared.lifts)?,
            Work::<C, R, HEADER_SIZE>::rx(random_alpha::<C::ScalarField>(rng), &prepared.work)?,
            Digits::<C, R, HEADER_SIZE>::rx(zero, &prepared.digits)?,
        ]);
        Ok(ExtensionRxs { circuits, stages })
    }
}

/// The polynomials of side `S`'s front stages over `prepared`, in stage
/// order, each with an alpha from `rng` unless the other side holds a
/// value to its commitment.
fn front_rxs<C, S, R, const HEADER_SIZE: usize>(
    prepared: &Prepared<C, S>,
    rng: &mut impl CryptoRng,
) -> Result<Vec<sparse::Polynomial<S::F, R>>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, WalletRank, R, HEADER_SIZE>,
    R: Rank,
{
    (0..S::stages())
        .map(|index| {
            let alpha = if S::zero_alpha(index) {
                S::F::ZERO
            } else {
                random_alpha(rng)
            };
            S::rx(index, alpha, prepared)
        })
        .collect()
}

/// The trace of chunk circuit `index` of side `S` over `prepared`, by the
/// kind of chunks it runs.
fn chunk_trace<C, S, R, const HEADER_SIZE: usize>(
    schedule: &Arc<Schedule>,
    index: usize,
    prepared: &Prepared<C, S>,
    params: &C::Params,
) -> Result<ragu_circuits::Trace<S::F>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, WalletRank, R, HEADER_SIZE>,
    R: Rank,
{
    Ok(match last(schedule, index) {
        Last::Transcript => {
            circuits::TranscriptCircuit::<C, S, WalletRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0
        }
        Last::Digits => {
            circuits::DigitsCircuit::<C, S, WalletRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0
        }
        Last::Work => {
            circuits::Circuit::<C, S, WalletRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0
        }
    })
}

/// A random alpha for a stage polynomial.
fn random_alpha<F: Field>(rng: &mut impl CryptoRng) -> F {
    F::random(|bytes| rng.fill_bytes(bytes))
}

impl<'params, C, R, const HEADER_SIZE: usize, B>
    Application<'params, Profiled<C, Aggregator<HEADER_SIZE>>, R, HEADER_SIZE, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    R: Rank,
    B: SelectableBackend,
{
    /// Decompresses `pcd`, a compressed proof of the wallet application,
    /// into a proof of this application carrying the same header and data:
    /// the decompression step's, proved against the bootstrap proof with
    /// the chunks run over `pcd`.
    ///
    /// # Errors
    ///
    /// Fails if the wallet application's verifier would reject `pcd`,
    /// before any proving, or if proving fails.
    ///
    /// # Soundness
    ///
    /// See [`Aggregator`]'s *Soundness*: the profile is unaudited and
    /// behind the `unstable-aggregator` feature.
    pub fn decompress<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        rng: &mut RNG,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Pcd<Profiled<C, Aggregator<HEADER_SIZE>>, R, H>> {
        let decompressed = self.context.prepare(pcd)?;
        let (pcd, ()) = self.fuse_with_source(
            rng,
            Decompress::<H>::new(),
            (
                pcd.data().clone(),
                decompressed.host_rounds(),
                decompressed.transcript_digest(),
            ),
            self.bootstrap_pcd(),
            self.bootstrap_pcd(),
            Some(&decompressed),
        )?;
        Ok(pcd)
    }
}

/// One curve's challenges as the compression squeezes them, in order.
#[derive(Clone)]
pub(crate) struct Squeezed<F> {
    pub sampled: Sampled<F>,
    pub weights: Weights<F>,
    pub rho: F,
    pub r: F,
    pub alpha: F,
    pub u: F,
    pub beta: F,
    pub xi: F,
    pub ipa_z: F,
    pub rounds: Vec<F>,
}

impl<F: Field> Squeezed<F> {
    /// Every challenge in the compression's order.
    pub(crate) fn in_order(&self) -> Vec<F> {
        let Sampled { w, y, z, sigma } = self.sampled;
        let mut all = vec![
            w,
            y,
            z,
            sigma,
            self.weights.mu,
            self.weights.nu,
            self.weights.mu_prime,
            self.weights.nu_prime,
            self.rho,
            self.r,
            self.alpha,
            self.u,
            self.beta,
            self.xi,
            self.ipa_z,
        ];
        all.extend(self.rounds.iter().copied());
        all
    }

    /// Reads one curve's challenges off `t`, standing where the curve's
    /// reduction starts, with the curve's `sampled` challenges already
    /// read.
    fn read<P: Affine<Scalar = F>>(
        sampled: Sampled<F>,
        messages: &Messages<P>,
        t: &mut impl IpaTranscript<P>,
    ) -> Result<Self> {
        let reduction = &messages.reduction;
        let weights = reduction.fold.replay(t)?;
        let rho = t.squeeze_challenge()?;
        t.write_point(reduction.p)?;
        t.write_point(reduction.q)?;
        let r = t.squeeze_challenge()?;
        for &opened in &reduction.openings {
            t.write_scalar(opened)?;
        }
        t.write_scalar(reduction.p_at_inverse_r)?;
        t.write_scalar(reduction.q_at_r)?;

        let alpha = t.squeeze_challenge()?;
        t.write_point(messages.batch.f)?;
        let u = t.squeeze_challenge()?;
        for &value in &messages.batch.evaluations {
            t.write_scalar(value)?;
        }
        let beta = t.squeeze_challenge()?;

        t.write_point(messages.opening.s_commitment)?;
        let xi = t.squeeze_challenge()?;
        let ipa_z = t.squeeze_challenge()?;
        let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
        for &(l, r) in &messages.opening.rounds {
            t.write_point(l)?;
            t.write_point(r)?;
            rounds.push(t.squeeze_challenge()?);
        }
        t.write_scalar(messages.opening.c)?;

        Ok(Squeezed {
            sampled,
            weights,
            rho,
            r,
            alpha,
            u,
            beta,
            xi,
            ipa_z,
            rounds,
        })
    }
}

/// What one curve's side of the verifier needs beyond the proof: the
/// claims' kinds and public values, the IPA's witness points, and the
/// challenges raw, for their endoscalars.
#[derive(Clone)]
pub(crate) struct SideWitness<P: Affine> {
    #[cfg(test)]
    pub kinds: Vec<Kind>,
    /// Each named circuit's wiring restriction at the lifted $(r, y)$.
    pub restrictions: Vec<(CircuitIndex, P::Scalar)>,
    /// The wire bindings' stage polynomials, by component position, and
    /// their degrees and expected values.
    pub masked: Vec<(usize, Vec<usize>, Vec<P::Scalar>)>,
    /// The registry restriction at the compression's $w$, the instance's
    /// extra opening's value.
    pub restriction_at_w: P::Scalar,
    /// The IPA's witness points: each $u_j^{-1} L_j$, and $G'$.
    pub inverse_scaled: Vec<P>,
    pub g_prime: P,
    #[cfg(test)]
    pub fixed: Fixed<P>,
    pub raw: Squeezed<P::Scalar>,
    /// The batched claim's value and the IPA's $c b z$, the full-width
    /// scalars the other side scales by beside the proof's $c$.
    pub v: P::Scalar,
    pub cbz: P::Scalar,
}

/// Everything both sides allocate, prepared natively from a compressed
/// proof as the native verifier reads it.
pub(crate) struct Witness<C: Cycle> {
    pub proof: CompressedProof<C>,
    pub header: Vec<C::CircuitField>,
    /// The fuse's challenges, raw.
    pub fuse: nested::Challenges<C::CircuitField>,
    pub native: SideWitness<C::HostCurve>,
    pub nested: SideWitness<C::NestedCurve>,
    /// The `ab` bridge stage's nonzero coefficients, as [`ab_layout`] lays
    /// the stage out: the generator each lands on and the value it holds.
    /// The chunk circuits read the layout off the schedule; the whole-side
    /// circuits the tests run read it here.
    #[cfg(test)]
    pub ab_terms: Vec<(usize, AbValue)>,
    /// The transcript's run commitments, in [`Run`](super::stages::Run)
    /// order: what the circuit-field side absorbs for the scalar field's
    /// values and holds to the scalar-field side's run stages.
    pub runs: Vec<C::NestedCurve>,
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Witness<C> {
    /// Prepares the witness for `pcd` under `app`, running the native
    /// verifier's computations.
    ///
    /// # Errors
    ///
    /// Fails if the native verifier would reject the proof, or on an
    /// internal error.
    pub(crate) fn prepare<K: Rank, const HEADER_SIZE: usize, B: SelectableBackend, H>(
        app: &Application<'_, C, K, HEADER_SIZE, B>,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Self>
    where
        H: Header<C::CircuitField>,
    {
        type Verifier<B> = <B as SelectableBackend>::Verifier;
        let proof = pcd.proof().clone();
        let instance = &proof.instance;
        let header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;

        // The verifier's admission: the circuit id's domain, the messages'
        // shape, the fuse's challenges and the two nested stages the
        // decider recomputes. Nothing below repeats these checks
        // natively, and the chunk circuits' constraints on the recomputed
        // stages are not enforced when their traces are prepared, so a proof
        // the verifier rejects is refused here, before any proving.
        let fuse = app.admit_compressed(&proof)?;

        // The compression's transcript twice over: lifted, as the verifier
        // reads it, and raw, for the endoscalars.
        let mut lifted =
            compression_transcript::<C, Verifier<B>, K>(app.params, instance, &header)?;
        let mut raw = compression_transcript::<C, Verifier<B>, K>(app.params, instance, &header)?;
        let native_sampled = Sampled::squeeze(&mut Lifted(lifted.host()))?;
        let nested_sampled = Sampled::squeeze(&mut Lifted(lifted.nested()))?;
        let native_raw_sampled = Sampled::squeeze(&mut raw.host())?;
        let nested_raw_sampled = Sampled::squeeze(&mut raw.nested())?;
        let (native_targets, nested_targets) =
            instance.targets::<HEADER_SIZE>(&fuse, &header, native_sampled.y, nested_sampled.y)?;

        let native = {
            let registry = &app.native_registry;
            let masked = instance.native_bindings::<K, Verifier<B>, HEADER_SIZE>(
                &fuse,
                registry,
                native_sampled.sigma,
            )?;
            let shapes = claims::native_shapes::<Standard, _>(native_sampled.z, &masked)?;
            let kinds = shapes.iter().map(|shape| shape.kind).collect();
            let mut openings = crate::compress::revdot::verify_native::<C, K, Verifier<B>>(
                |component| instance.native_commitment(component),
                registry,
                native_sampled.y,
                native_sampled.z,
                &native_targets,
                &masked,
                &proof.native.reduction,
                &mut Lifted(lifted.host()),
            )?
            .ok_or_else(|| Error::InvalidWitness("the native reduction fails".into()))?;
            let (commitments, claims) = instance.native_openings::<K, Verifier<B>>(
                &fuse,
                registry,
                native_sampled.w,
                openings.commitments.len(),
            );
            // The registry restriction at w: the first instance claim's
            // value.
            let restriction_at_w = claims[0].value;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            side_witness::<C::HostCurve, K, Verifier<B>>(
                SideInputs {
                    sampled: native_sampled,
                    raw_sampled: native_raw_sampled,
                    messages: &proof.native,
                    openings: &openings,
                    registry,
                    masked: masked
                        .iter()
                        .map(|m| {
                            (
                                native_position::<Standard>(m.poly),
                                m.wires.iter().map(|&(degree, _)| degree).collect(),
                                m.wires.iter().map(|&(_, value)| value).collect(),
                            )
                        })
                        .collect(),
                    kinds,
                    restriction_at_w,
                    params: Params::with_k(
                        C::host_generators(app.params),
                        *C::host_u(app.params),
                        K::RANK,
                    ),
                },
                &mut Lifted(lifted.host()),
                &mut raw.host(),
            )?
        };

        let nested = {
            let registry = &app.nested_registry;
            let masked = instance.nested_bindings::<K, Verifier<B>>(
                &fuse,
                registry,
                nested_sampled.sigma,
            )?;
            let shapes = claims::nested_shapes::<Standard, _>(nested_sampled.z, &masked)?;
            let kinds = shapes.iter().map(|shape| shape.kind).collect();
            let mut openings = crate::compress::revdot::verify_nested::<C, K, Verifier<B>>(
                |component| instance.nested_commitment(component),
                registry,
                nested_sampled.y,
                nested_sampled.z,
                &nested_targets,
                &masked,
                &proof.nested.reduction,
                &mut Lifted(lifted.nested()),
            )?
            .ok_or_else(|| Error::InvalidWitness("the nested reduction fails".into()))?;
            let (commitments, claims) = instance.nested_openings::<K, Verifier<B>>(
                &fuse,
                registry,
                nested_sampled.w,
                openings.commitments.len(),
            )?;
            let restriction_at_w = claims[0].value;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            side_witness::<C::NestedCurve, K, Verifier<B>>(
                SideInputs {
                    sampled: nested_sampled,
                    raw_sampled: nested_raw_sampled,
                    messages: &proof.nested,
                    openings: &openings,
                    registry,
                    masked: masked
                        .iter()
                        .map(|m| {
                            (
                                nested_position::<Standard>(m.poly),
                                m.wires.iter().map(|&(degree, _)| degree).collect(),
                                m.wires.iter().map(|&(_, value)| value).collect(),
                            )
                        })
                        .collect(),
                    kinds,
                    restriction_at_w,
                    params: Params::with_k(
                        C::nested_generators(app.params),
                        *C::nested_u(app.params),
                        K::RANK,
                    ),
                },
                &mut Lifted(lifted.nested()),
                &mut raw.nested(),
            )?
        };

        #[cfg(test)]
        let ab_terms = ab_layout::<C, K>()?;
        let runs = lifted.runs().to_vec();
        if runs.len() != num_runs::<K>() {
            return Err(Error::InvalidWitness(
                "the transcript absorbed other runs than the proof has".into(),
            ));
        }

        Ok(Witness {
            proof,
            header,
            fuse,
            native,
            nested,
            #[cfg(test)]
            ab_terms,
            runs,
        })
    }
}

/// What [`side_witness`] takes for one curve.
struct SideInputs<'a, P: Affine, K: Rank> {
    sampled: Sampled<P::Scalar>,
    raw_sampled: Sampled<P::Scalar>,
    messages: &'a Messages<P>,
    openings: &'a Openings<P>,
    registry: &'a Registry<'a, P::Scalar, K>,
    masked: Vec<(usize, Vec<usize>, Vec<P::Scalar>)>,
    kinds: Vec<Kind>,
    restriction_at_w: P::Scalar,
    params: Params<P>,
}

/// One curve's side witness, with `lifted` standing after the curve's
/// reduction, as the verifier leaves it, and `raw` where the reduction
/// starts: the batch and the IPA run on the lifted view, the whole side on
/// the raw one.
fn side_witness<P: Affine, K: Rank, B: SelectableBackend + Backend>(
    inputs: SideInputs<'_, P, K>,
    lifted: &mut impl IpaTranscript<P>,
    raw: &mut impl IpaTranscript<P>,
) -> Result<SideWitness<P>> {
    let SideInputs {
        sampled,
        raw_sampled,
        messages,
        openings,
        registry,
        masked,
        kinds,
        restriction_at_w,
        params,
    } = inputs;
    let raw_squeezed = Squeezed::read(raw_sampled, messages, raw)?;

    let claim = crate::compress::batch::verifier::verify::<_, B, _>(
        &openings.commitments,
        &openings.claims,
        &messages.batch,
        lifted,
    )?;
    let mut msm = MSM::new(&params);
    msm.append_term(P::Scalar::ONE, claim.commitment);
    let guard = crate::ipa::verify_proof(
        &params,
        msm,
        lifted,
        &messages.opening,
        claim.point,
        claim.value,
    )?;
    let g_prime = guard.compute_g::<B>();
    if !guard.use_challenges().eval::<B>() {
        return Err(Error::InvalidWitness("the IPA fails".into()));
    }

    // The lifted challenges are the raw ones' lifts.
    let lift = |raw: P::Scalar| -> Result<P::Scalar> {
        Ok(ragu_primitives::lift_endoscalar(
            ragu_primitives::extract_endoscalar(raw)?,
        ))
    };
    let lifted_squeezed = Squeezed {
        sampled,
        weights: Weights {
            mu: lift(raw_squeezed.weights.mu)?,
            nu: lift(raw_squeezed.weights.nu)?,
            mu_prime: lift(raw_squeezed.weights.mu_prime)?,
            nu_prime: lift(raw_squeezed.weights.nu_prime)?,
        },
        rho: lift(raw_squeezed.rho)?,
        r: lift(raw_squeezed.r)?,
        alpha: lift(raw_squeezed.alpha)?,
        u: lift(raw_squeezed.u)?,
        beta: lift(raw_squeezed.beta)?,
        xi: lift(raw_squeezed.xi)?,
        ipa_z: lift(raw_squeezed.ipa_z)?,
        rounds: raw_squeezed
            .rounds
            .iter()
            .map(|&u_j| lift(u_j))
            .collect::<Result<_>>()?,
    };

    let mut restrictions: Vec<(CircuitIndex, P::Scalar)> = Vec::new();
    for kind in &kinds {
        if let Kind::Circuit(circuit) | Kind::Bonding(circuit) = *kind
            && !restrictions.iter().any(|(listed, _)| *listed == circuit)
        {
            let value = B::registry_wxy(
                registry,
                circuit.omega_j(),
                lifted_squeezed.r,
                lifted_squeezed.sampled.y,
            );
            restrictions.push((circuit, value));
        }
    }

    let mut b = P::Scalar::ONE;
    let mut cur = claim.point;
    for u_j in lifted_squeezed.rounds.iter().rev() {
        b *= P::Scalar::ONE + *u_j * cur;
        cur = cur.square();
    }
    let inverse_scaled = messages
        .opening
        .rounds
        .iter()
        .zip(&lifted_squeezed.rounds)
        .map(|(&(l, _), u_j)| {
            u_j.invert()
                .map(|inverse| (l * inverse).to_affine())
                .ok_or_else(|| Error::InvalidWitness("IPA round challenge is zero".into()))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(SideWitness {
        #[cfg(test)]
        kinds,
        restrictions,
        masked,
        restriction_at_w,
        inverse_scaled,
        g_prime,
        #[cfg(test)]
        fixed: Fixed {
            g_0: params.g[0],
            u: params.u,
            offset: params.g[1],
        },
        raw: raw_squeezed,
        cbz: messages.opening.c * b * lifted_squeezed.ipa_z,
        v: claim.value,
    })
}

/// The prover's half of a [`Side`]: what it reads off a prepared
/// [`Witness`] to fill the side's stages before its chunks run, and what
/// the side allocates beyond the stages.
pub(crate) trait Prepare<C: Cycle>: Side<C> {
    /// The side's online inputs for the proof `witness` was prepared from
    /// ([`online::input`]).
    ///
    /// # Errors
    ///
    /// Fails if a challenge has no lift, which the preparation refuses.
    fn online_inputs(witness: &Witness<C>) -> Result<Vec<Self::F>>;
    /// The transcript's run commitments the side's work stage carries,
    /// prover-supplied, in [`Regions::runs`](super::program::Regions::runs)
    /// order: the circuit-field side's; none on the scalar-field side.
    fn runs(witness: &Witness<C>) -> Vec<Self::P>;
    /// The instance stage's values.
    fn instance(
        params: &C::Params,
        instance: &Instance<C>,
        output_header: &[C::CircuitField],
    ) -> Values<Self::F, Self::P>;
    /// The messages stage's values.
    fn messages(params: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P>;
    /// The transcript stage's values before the prover's run fills the
    /// sponge states: none.
    fn transcript() -> Values<Self::F, Self::P> {
        Values {
            points: Vec::new(),
            elements: Vec::new(),
        }
    }
    /// The witness of the reduction the side checks in its field.
    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q>;
    /// The witness of the reduction whose points the side checks.
    fn other(witness: &Witness<C>) -> &SideWitness<Self::P>;
    /// The other field's full-width scalars the side scales by, in the
    /// schedule's [`ScalarRef::Bits`](super::program::ScalarRef::Bits) order.
    fn foreign(witness: &Witness<C>, schedule: &Schedule) -> Result<Vec<Self::Other>>;
    fn extra(witness: &Witness<C>) -> Result<Self::Extra>;
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Prepare<C> for Native {
    fn online_inputs(witness: &Witness<C>) -> Result<Vec<Self::F>> {
        native_inputs(witness)
    }

    fn runs(witness: &Witness<C>) -> Vec<Self::P> {
        witness.runs.clone()
    }

    fn instance(
        _: &C::Params,
        instance: &Instance<C>,
        output_header: &[C::CircuitField],
    ) -> Values<Self::F, Self::P> {
        let mut points = instance.nested.clone();
        points.extend([
            instance.nested_registry_xy,
            instance.nested_p,
            instance.nested_challenges_partial,
        ]);
        let (l, r) = (instance.left, instance.right);
        let mut elements = alloc::vec![
            instance.circuit_id.omega_j(),
            instance.c,
            instance.v,
            l.x,
            l.y,
            r.x,
            r.y,
            instance.a_at_u,
            instance.b_at_u,
        ];
        elements.extend_from_slice(output_header);
        // The step binding, which the step that proves the chunks sets:
        // zero outside the decompression step.
        elements.extend([C::CircuitField::ZERO; stages::step::LEN]);
        Values { points, elements }
    }

    fn messages(_: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P> {
        Values {
            points: message_points_of(&proof.nested),
            elements: message_scalars(&proof.native),
        }
    }

    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q> {
        &witness.native
    }

    fn other(witness: &Witness<C>) -> &SideWitness<Self::P> {
        &witness.nested
    }

    fn foreign(witness: &Witness<C>, schedule: &Schedule) -> Result<Vec<Self::Other>> {
        let instance = &witness.proof.instance;
        let other = Self::other(witness);
        let mut foreign = alloc::vec![other.v, witness.proof.nested.opening.c, other.cbz];
        let coordinates = |point: C::HostCurve| -> Result<[C::ScalarField; 2]> {
            let (x, y) = point.coordinates().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("a commitment is the identity".into())
            })?;
            Ok([x, y])
        };
        let a = coordinates(instance.native_commitment(native::RxComponent::AbA))?;
        let b = coordinates(instance.native_commitment(native::RxComponent::AbB))?;
        let points_ab = coordinates(
            instance.native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb)),
        )?;
        let alpha = bridge_alpha_power(instance.bridge_alpha, nested::RxIndex::BridgeAB);
        foreign.extend(schedule.ab_terms.iter().map(|&(_, which)| match which {
            AbValue::A(i) => a[i],
            AbValue::B(i) => b[i],
            AbValue::PointsAb(i) => points_ab[i],
            AbValue::Alpha => alpha,
        }));
        Ok(foreign)
    }

    fn extra(witness: &Witness<C>) -> Result<Self::Extra> {
        let instance = &witness.proof.instance;
        Ok(NativeExtra {
            unified: instance.unified(&witness.fuse),
            output_header: witness.header.clone(),
            omega_j: instance.circuit_id.omega_j(),
        })
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Prepare<C> for Nested {
    fn online_inputs(witness: &Witness<C>) -> Result<Vec<Self::F>> {
        nested_inputs(witness)
    }

    fn runs(_: &Witness<C>) -> Vec<Self::P> {
        Vec::new()
    }

    fn instance(
        _: &C::Params,
        instance: &Instance<C>,
        _: &[C::CircuitField],
    ) -> Values<Self::F, Self::P> {
        let mut points = instance.native.clone();
        points.extend([instance.native_registry_xy, instance.native_p]);
        points.extend(instance.online_commitments);
        let (l, r) = (instance.nested_left, instance.nested_right);
        let elements = alloc::vec![
            instance.bridge_alpha,
            instance.nested_c,
            instance.nested_v,
            l.x,
            l.y,
            r.x,
            r.y,
            instance.nested_a_at_u,
            instance.nested_b_at_u,
        ];
        assert_eq!(elements.len(), stages::NESTED_SCALARS);
        Values { points, elements }
    }

    fn messages(_: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P> {
        Values {
            points: message_points_of(&proof.native),
            elements: message_scalars(&proof.nested),
        }
    }

    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q> {
        &witness.nested
    }

    fn other(witness: &Witness<C>) -> &SideWitness<Self::P> {
        &witness.native
    }

    fn foreign(witness: &Witness<C>, _: &Schedule) -> Result<Vec<Self::Other>> {
        let other = Self::other(witness);
        Ok(alloc::vec![
            other.v,
            witness.proof.native.opening.c,
            other.cbz
        ])
    }

    fn extra(witness: &Witness<C>) -> Result<Self::Extra> {
        Ok(NestedExtra {
            unified: witness.proof.instance.nested_unified(&witness.fuse)?,
        })
    }
}

impl online::Values {
    /// The query stage's values a side's chunks read, as the native
    /// verifier computed them for the proof `own` was prepared from: the
    /// claims' restrictions, the instance's opening and the wire bindings'
    /// registry values. The step's challenges and the mesh's
    /// intersections, which only its fuse knows, are left zero.
    ///
    /// # Panics
    ///
    /// Panics if `own` does not hold the verifier's bindings in its order,
    /// the preamble's, the query's, then the eval's, or if a claim names
    /// another circuit than an internal one.
    pub(crate) fn evaluations<P: Affine>(self, own: &SideWitness<P>) -> Vec<P::Scalar> {
        let mut stage = alloc::vec![P::Scalar::ZERO; self.query_stage()];
        for &(circuit, value) in &own.restrictions {
            stage[Self::value_at(self.claim(usize::from(circuit)))] = value;
        }
        stage[Self::value_at(self.at_w_c())] = own.restriction_at_w;
        let (query, eval) = (&own.masked[1].2, &own.masked[2].2);
        let wires = self.query_binding();
        assert_eq!(query.len(), wires.len(), "the query binding's values");
        for (wire, &value) in wires.into_iter().zip(query) {
            stage[Self::value_at(wire)] = value;
        }
        assert_eq!(eval.len(), 6, "the eval binding's values");
        for (wire, &value) in self.eval_binding().into_iter().zip(eval) {
            if let Some(wire) = wire {
                stage[Self::value_at(wire)] = value;
            }
        }
        stage
    }
}

/// A raw compression challenge's lift, as the verifier's transcript
/// squeezes it.
fn lift<F: Field>(raw: F) -> Result<F> {
    Ok(lift_endoscalar(extract_endoscalar(raw)?))
}

/// The coordinates and points both sides share, after the inherited
/// wires, which the fuse fills: the compression's $r$ and $y$ of this
/// side's curve, the fuse's $x$ and $y$, the children's, the fuse's $u$
/// and $w$ and the compression's $w$.
fn shared<P: Affine>(
    own: &SideWitness<P>,
    [w, x, y, u]: [P::Scalar; 4],
    children: [[P::Scalar; 2]; 2],
) -> Result<Vec<P::Scalar>> {
    let mut inputs = alloc::vec![P::Scalar::ZERO; input::NESTED];
    inputs[input::R] = lift(own.raw.r)?;
    inputs[input::Y_C] = lift(own.raw.sampled.y)?;
    inputs[input::X] = x;
    inputs[input::Y] = y;
    [inputs[input::LEFT_X], inputs[input::LEFT_Y]] = children[0];
    [inputs[input::RIGHT_X], inputs[input::RIGHT_Y]] = children[1];
    inputs[input::U] = u;
    inputs[input::W] = w;
    inputs[input::W_C] = lift(own.raw.sampled.w)?;
    Ok(inputs)
}

/// The input stage's values as a side's chunks view them outside a fuse:
/// `inputs` at their wires, the tag, the inherited coordinates and the
/// other side's commitments, which only the step's fuse knows, left zero.
pub(crate) fn input_stage<F: Field>(values: online::Values, inputs: &[F]) -> Vec<F> {
    let mut stage = alloc::vec![F::ZERO; values.input_stage()];
    stage[online::Values::input_at(0)..online::Values::input_at(inputs.len())]
        .copy_from_slice(inputs);
    stage
}

/// The native input stage's values for the compressed proof `witness`
/// was prepared from, the inherited coordinates left for the fuse.
///
/// # Errors
///
/// Fails if a compression challenge is outside the endoscalar range,
/// which the proof's preparation has already refused.
pub(crate) fn native_inputs<C: Cycle>(witness: &Witness<C>) -> Result<Vec<C::CircuitField>> {
    let instance = &witness.proof.instance;
    let fuse = &witness.fuse;
    let (left, right) = (instance.left, instance.right);
    let mut inputs = shared(
        &witness.native,
        [fuse.w, fuse.x, fuse.y, fuse.u],
        [[left.x, left.y], [right.x, right.y]],
    )?;
    inputs.push(instance.circuit_id.omega_j());
    debug_assert_eq!(inputs.len(), input::NATIVE);
    Ok(inputs)
}

/// The nested input stage's values, as [`native_inputs`], at the nested
/// counterparts of the fuse's challenges.
///
/// # Errors
///
/// As [`native_inputs`], and if a fuse challenge has no nested
/// counterpart, which the preparation has refused too.
pub(crate) fn nested_inputs<C: Cycle>(witness: &Witness<C>) -> Result<Vec<C::ScalarField>> {
    let instance = &witness.proof.instance;
    let fuse = &witness.fuse;
    let (left, right) = (instance.nested_left, instance.nested_right);
    shared(
        &witness.nested,
        [
            nested::challenge::<C>(fuse.w)?,
            nested::challenge::<C>(fuse.x)?,
            nested::challenge::<C>(fuse.y)?,
            nested::challenge::<C>(fuse.u)?,
        ],
        [[left.x, left.y], [right.x, right.y]],
    )
}

/// The stages allocated as witnesses under a driver, for the prover's
/// native run.
struct Allocated<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    stages: [(Vec<Point<'dr, D, P>>, Vec<Element<'dr, D>>); 8],
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Allocated<'dr, D, P> {
    fn alloc(dr: &mut D, values: [&Values<D::F, P>; 8]) -> Result<Self> {
        let mut stages = Vec::with_capacity(8);
        for values in values {
            let points = values
                .points
                .iter()
                .map(|&point| Point::alloc(dr, D::just(|| point)))
                .collect::<Result<Vec<_>>>()?;
            let elements = values
                .elements
                .iter()
                .map(|&value| Element::alloc(dr, &mut (), D::just(|| value)))
                .collect::<Result<Vec<_>>>()?;
            stages.push((points, elements));
        }
        Ok(Allocated {
            stages: stages
                .try_into()
                .map_err(|_| Error::InvalidWitness("eight stages".into()))?,
        })
    }

    fn view(&self) -> Loaded<'_, 'dr, D, P> {
        let view = |i: usize| View {
            points: &self.stages[i].0[..],
            elements: &self.stages[i].1[..],
        };
        Loaded {
            instance: view(0),
            messages: view(1),
            lifts: view(2),
            work: view(3),
            transcript: view(4),
            digits: view(5),
            online_input: view(6),
            online_query: view(7),
        }
    }
}

/// Stores the prover-supplied slots of a side's work stage: the registry
/// values, the restrictions, the IPA's witness points and the transcript's
/// run commitments, `runs`.
fn supply<F: Field, P, Q>(
    schedule: &Schedule,
    own: &SideWitness<Q>,
    other: &SideWitness<P>,
    runs: &[P],
    work: &mut Values<F, P>,
) where
    P: Affine,
    Q: Affine<Scalar = F>,
{
    let regions = &schedule.regions;
    assert_eq!(
        regions.runs.len(),
        runs.len(),
        "one commitment per run the schedule absorbs"
    );
    for (slot, run) in regions.runs.iter().zip(runs) {
        work.points[*slot] = *run;
    }
    for (claim, slot) in schedule.claims.iter().zip(&regions.restrictions) {
        if let (Kind::Circuit(circuit) | Kind::Bonding(circuit), Some(slot)) = (claim.kind, slot) {
            let value = own
                .restrictions
                .iter()
                .find(|(listed, _)| *listed == circuit)
                .expect("every named circuit's restriction")
                .1;
            work.elements[*slot] = value;
        }
    }
    work.elements[regions.restriction_at_w] = own.restriction_at_w;
    for (plan, (_, _, values)) in schedule.bindings.iter().zip(&own.masked) {
        for (src, value) in plan.expected.iter().zip(values) {
            if let ElementSrc::Work(slot) = src {
                work.elements[*slot] = *value;
            }
        }
    }
    for (slot, point) in regions.inverse_scaled.iter().zip(&other.inverse_scaled) {
        work.points[*slot] = *point;
    }
    work.points[regions.g_prime] = other.g_prime;
    // Outside a step the opening is of s(X) at zero, which is one.
    if let Some([_, y]) = regions.fq_opening {
        work.elements[y] = F::ONE;
    }
}

type Executor<F> = Emulator<Wireless<Always<()>, F>>;

/// The endoscalars of raw challenges, as their bits.
fn bits<F: Field>(raw: &[F]) -> Result<Vec<Uendo>> {
    raw.iter().map(|&raw| extract_endoscalar(raw)).collect()
}

impl<C: Cycle, S: Prepare<C>> Prepared<C, S> {
    /// Prepares side `S` from the prepared `witness` for chunk circuits at
    /// rank `R` and runs its chunks natively to fill the work and
    /// transcript stages.
    pub(crate) fn new<K: Rank, R: Rank, const HEADER_SIZE: usize>(
        params: &C::Params,
        witness: &Witness<C>,
    ) -> Result<Self> {
        let instance = &witness.proof.instance;
        let schedule = super::program::schedule::<C, S, K, R, HEADER_SIZE>()?;
        let placeholder = S::generators(params)[0];
        let mut work = Values::blank(schedule.points, schedule.elements, placeholder);
        supply(
            &schedule,
            S::own(witness),
            S::other(witness),
            &S::runs(witness),
            &mut work,
        );
        let lifts = Values::blank(0, schedule.layout.lifts, placeholder);
        let digits = Values::blank(0, schedule.layout.digits, placeholder);
        let mut transcript = S::transcript();
        transcript.elements = alloc::vec![S::F::ZERO; schedule.states];
        let mut challenge_bits = bits(&S::own(witness).raw.in_order())?;
        // In `fuse::LIFTED` order.
        challenge_bits.extend(bits(&[
            witness.fuse.x,
            witness.fuse.y,
            witness.fuse.u,
            witness.fuse.w,
        ])?);
        challenge_bits.extend(bits(&S::other(witness).raw.in_order())?);
        let aux = Aux {
            challenge_bits,
            foreign: S::foreign(witness, &schedule)?,
            flags: alloc::vec![false; S::FLAGS],
        };
        let mut prepared = Prepared {
            instance: S::instance(params, instance, &witness.header),
            messages: S::messages(params, &witness.proof),
            online_input: Values {
                points: Vec::new(),
                elements: input_stage(S::ONLINE, &S::online_inputs(witness)?),
            },
            online_query: Values {
                points: Vec::new(),
                elements: S::ONLINE.evaluations(S::own(witness)),
            },
            extra: Arc::new(S::extra(witness)?),
            schedule,
            lifts,
            work,
            transcript,
            digits,
            aux,
        };
        prepared.run::<K, HEADER_SIZE>(params)?;
        Ok(prepared)
    }

    /// Runs every chunk natively, storing what each writes.
    pub(crate) fn run<K: Rank, const HEADER_SIZE: usize>(
        &mut self,
        params: &C::Params,
    ) -> Result<()> {
        self.rerun::<K, HEADER_SIZE>(params, |_| true)
    }

    /// Runs natively the chunks `select` picks, in schedule order, storing
    /// what each writes: every chunk for a fresh side, or the chunks that
    /// read what the step proving them set afterwards.
    fn rerun<K: Rank, const HEADER_SIZE: usize>(
        &mut self,
        params: &C::Params,
        select: impl Fn(&Chunk) -> bool,
    ) -> Result<()> {
        for k in 0..self.schedule.chunks.len() {
            if !select(&self.schedule.chunks[k]) {
                continue;
            }
            let mut dr = Executor::<S::F>::execute();
            let allocated = Allocated::alloc(
                &mut dr,
                [
                    &self.instance,
                    &self.messages,
                    &self.lifts,
                    &self.work,
                    &self.transcript,
                    &self.digits,
                    &self.online_input,
                    &self.online_query,
                ],
            )?;
            let writes = {
                let ctx = Ctx {
                    loaded: allocated.view(),
                    schedule: &self.schedule,
                    generators: S::generators(params),
                    u: S::u(params),
                    poseidon: S::poseidon(params),
                    witness: Executor::<S::F>::just(|| &*self),
                };
                execute::<_, C, S, K, HEADER_SIZE>(&mut dr, &self.schedule.chunks[k], &ctx)?
            };
            for write in writes {
                match write {
                    Write::Element(slot, element) => {
                        self.work.elements[slot] = *element.value().take();
                    }
                    Write::Point(slot, point) => {
                        self.work.points[slot] = point.value().take();
                    }
                    Write::Lift(slot, element) => {
                        self.lifts.elements[slot] = *element.value().take();
                    }
                    Write::State(slot, element) => {
                        self.transcript.elements[slot] = *element.value().take();
                    }
                    Write::Digit(slot, element) => {
                        self.digits.elements[slot] = *element.value().take();
                    }
                }
            }
        }
        Ok(())
    }
}

impl<C: Cycle, S: Side<C>> Prepared<C, S> {
    /// The proof's online inputs: the coordinates of the wallet registry's
    /// restrictions its verification reads and the points it reads them
    /// at, which the step that proves the chunks commits in its online
    /// input stage before its challenge.
    pub(crate) fn online_inputs(&self) -> &[S::F] {
        &self.online_input.elements[online::Values::input_at(0)..][..S::ONLINE.inputs()]
    }

    /// The side as the step proves it, with the online stages its fuse
    /// committed, `input` and `query`, each stage's values in order. The
    /// chunks hold the proof's inputs and the evaluations they read to
    /// these stages' wires, so a stage that does not hold what the side was
    /// prepared with leaves a chunk unsatisfied.
    ///
    /// # Errors
    ///
    /// Fails if a stage is not the side's size.
    pub(crate) fn with_online(mut self, input: Vec<S::F>, query: Vec<S::F>) -> Result<Self> {
        if input.len() != S::ONLINE.input_stage() || query.len() != S::ONLINE.query_stage() {
            return Err(Error::InvalidWitness(
                "the step's online stages are not the side's size".into(),
            ));
        }
        self.online_input.elements = input;
        self.online_query.elements = query;
        Ok(self)
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Prepared<C, Native> {
    /// The side as the decompression step proves it: the flag set and the
    /// step binding the step's own, `opening`, the point and value at
    /// which it opened the output slot holding $s(X)$, and `digest`, the
    /// transcript digest it staged. Any other step proves the side as
    /// prepared, the binding all zero.
    pub(crate) fn for_decompression<K: Rank, const HEADER_SIZE: usize>(
        &self,
        params: &C::Params,
        opening: [C::CircuitField; 2],
        digest: C::CircuitField,
    ) -> Result<Self> {
        let mut prepared = self.clone();
        let step = prepared.schedule.layout.instance.step;
        prepared.instance.elements[step.at(stages::step::FLAG)] = C::CircuitField::ONE;
        prepared.instance.elements[step.at(stages::step::X)] = opening[0];
        prepared.instance.elements[step.at(stages::step::Y)] = opening[1];
        prepared.instance.elements[step.at(stages::step::DIGEST)] = digest;
        prepared.rerun::<K, HEADER_SIZE>(
            params,
            |chunk| matches!(chunk, Chunk::Digits { flags, .. } if !flags.is_empty()),
        )?;
        Ok(prepared)
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Prepared<C, Nested> {
    /// The side as a step proves it: the commitment of the step's output
    /// slot the binding circuit exposes, `slot_commitment`, the flag, set
    /// in the decompression step, under which that commitment is the
    /// host IPA's $G'$, and `fq_opening`, the point and value at which the
    /// step opened its online Fq polynomial.
    pub(crate) fn for_step<K: Rank, const HEADER_SIZE: usize>(
        &self,
        params: &C::Params,
        decompression: bool,
        slot_commitment: C::HostCurve,
        fq_opening: [C::ScalarField; 2],
    ) -> Result<Self> {
        let mut prepared = self.clone();
        let [x, y] = prepared
            .schedule
            .regions
            .fq_opening
            .expect("the scalar-field side holds the online Fq opening");
        prepared.work.elements[x] = fq_opening[0];
        prepared.work.elements[y] = fq_opening[1];
        let (slot, digits_sum) = {
            let regions = &prepared.schedule.regions;
            (
                regions
                    .slot_commitment
                    .expect("the scalar-field side exposes the slot commitment"),
                regions.digits_sum,
            )
        };
        prepared.aux.flags[0] = decompression;
        prepared.work.points[slot] = slot_commitment;
        prepared.rerun::<K, HEADER_SIZE>(params, |chunk| match chunk {
            Chunk::EqualIf { .. } => true,
            Chunk::Sums { sums } => sums.iter().any(|(out, _)| *out == digits_sum),
            _ => false,
        })?;
        Ok(prepared)
    }
}

/// Both sides prepared for one compressed proof.
pub(crate) struct Sides<C: IpaCycle + ProfiledCycle<Profile = Standard>> {
    pub native: Prepared<C, Native>,
    pub nested: Prepared<C, Nested>,
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Sides<C> {
    /// Prepares both sides for `pcd` under `app`, for chunk circuits at
    /// rank `R`.
    ///
    /// # Errors
    ///
    /// Fails if the native verifier would reject the proof, or on an
    /// internal error.
    pub(crate) fn prepare<K: Rank, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend, H>(
        app: &Application<'_, C, K, HEADER_SIZE, B>,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Self>
    where
        H: Header<C::CircuitField>,
    {
        let witness = Witness::prepare(app, pcd)?;
        Ok(Sides {
            native: Prepared::new::<K, R, HEADER_SIZE>(app.params, &witness)?,
            nested: Prepared::new::<K, R, HEADER_SIZE>(app.params, &witness)?,
        })
    }
}
