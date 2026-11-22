//! The decompression as a profile's prover: the extension's polynomials
//! for a proof, from a compressed proof's prepared sides.
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

use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, WalletRank, sparse},
    registry::Registry,
    staging::StageExt,
};
use ragu_core::{Error, FixedGenerators, Result};
use rand::CryptoRng;
use udon::field::Field;

use super::{
    chunk::{self, last},
    program::{Last, squeezed},
    run::{Prepared, Sides},
    side::{Native, Nested},
    stages::{DigitsStage, Front, LiftsStage, TranscriptStage, WorkStage},
};
use crate::{
    Application, CompressedPcd, Pcd, SelectableBackend,
    header::{Header, NUM_ONLINE_FP_POLYS},
    internal::{native, nested},
    ipa::IpaCycle,
    profile::{
        Aggregator, ExtensionRxs, Profile, Profiled, ProfiledCycle, ProverContext, Standard,
    },
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
        let trace =
            chunk::StatementCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(schedule.clone())
                .trace(prepared)?
                .into_parts()
                .0;
        let statement =
            native::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32);
        circuits.push(registry.assemble(&trace, statement.circuit_index::<P>(), rng)?);
        let trace =
            chunk::BindingCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(schedule.clone())
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
        let trace =
            chunk::BindingCircuit::<C, Nested, WalletRank, R, HEADER_SIZE>::new(schedule.clone())
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
    schedule: &Arc<super::program::Schedule>,
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
            chunk::TranscriptCircuit::<C, S, WalletRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0
        }
        Last::Digits => {
            chunk::DigitsCircuit::<C, S, WalletRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0
        }
        Last::Work => {
            chunk::Circuit::<C, S, WalletRank, R, HEADER_SIZE>::new(index, schedule.clone(), params)
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
