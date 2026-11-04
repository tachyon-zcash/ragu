//! The decompression as a profile's prover: the extension's polynomials
//! for a proof, from a compressed proof's prepared sides.
//!
//! A decompression step traces the verifier over its incoming wallet proof
//! and assembles those traces against the aggregator's registry. Ordinary
//! aggregator steps instead use empty extension traces with fresh SYSTEM
//! blinding. The optional-extension relation derives activation from the
//! application's bound circuit ID on both sides.
//!
//! Profiles that retain the always-active relation can still use the
//! canonical bootstrap decompression and its cached circuit bodies. Actual
//! decompressions always trace and commit their input's circuits.
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
    program::Last,
    run::{Prepared, Sides},
    side::{Native, Nested},
    stages::{DigitsStage, Front, LiftsStage, TranscriptStage, WorkStage},
};
use crate::{
    Application, CompressedPcd, Pcd, SelectableBackend,
    header::Header,
    internal::{native, nested},
    ipa::IpaCycle,
    profile::{
        Aggregator, ExtensionRxs, Profile, Profiled, ProfiledCycle, ProverContext, Standard,
    },
    step::internal::decompress::Decompress,
};

/// A compressed proof prepared for decompression: both sides' stages
/// filled from the prover's native run of the chunks over it, which the
/// decompression step's fuse runs the chunk circuits over in place of the
/// canonical proof.
pub struct Decompressed<C: IpaCycle + ProfiledCycle<Profile = Standard>>(pub(crate) Sides<C>);

/// The aggregator's prover context: the wallet application whose proofs
/// the aggregator decompresses and a canonical decompression, prepared
/// for chunk circuits at rank `R` with `HEADER_SIZE`-element headers.
///
/// The aggregator profile is not yet sound against a dishonest prover; see
/// [`Aggregator`]'s *Soundness*.
pub struct Decompression<'params, C, R, const HEADER_SIZE: usize, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    R: Rank,
    B: SelectableBackend,
{
    wallet: Application<'params, C, WalletRank, HEADER_SIZE, B>,
    canonical: Sides<C>,
    // Owned by this context, which is moved into one finalized application:
    // the registry layout and generator tables cannot change underneath it.
    #[cfg(feature = "std")]
    native_cache: std::sync::OnceLock<CanonicalCircuits<C::HostCurve, R>>,
    #[cfg(feature = "std")]
    nested_cache: std::sync::OnceLock<CanonicalCircuits<C::NestedCurve, R>>,
    _marker: PhantomData<fn() -> R>,
}

/// A decompression step supplies the compressed proof it decompresses.
impl<C, R, const HEADER_SIZE: usize, B> ProverContext for Decompression<'_, C, R, HEADER_SIZE, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    R: Rank,
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
    /// the aggregator's parameters and header types to its, and the
    /// registry check the decompression module's *What remains* waits on
    /// will hold the proofs it decompresses to its registry.
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
            #[cfg(feature = "std")]
            native_cache: std::sync::OnceLock::new(),
            #[cfg(feature = "std")]
            nested_cache: std::sync::OnceLock::new(),
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

    pub(crate) fn native_cached_commitments(
        &self,
        source: Option<&Decompressed<C>>,
        circuits: &[sparse::Polynomial<C::CircuitField, R>],
    ) -> Option<Vec<C::HostCurve>> {
        #[cfg(feature = "std")]
        if source.is_none() {
            return self.native_cache.get().map(|cache| {
                cache.commitments::<B>(circuits, C::host_generators(self.wallet.params))
            });
        }
        let _ = (source, circuits);
        None
    }

    pub(crate) fn nested_cached_commitments(
        &self,
        source: Option<&Decompressed<C>>,
        circuits: &[sparse::Polynomial<C::ScalarField, R>],
    ) -> Option<Vec<C::NestedCurve>> {
        #[cfg(feature = "std")]
        if source.is_none() {
            return self.nested_cache.get().map(|cache| {
                cache.commitments::<B>(circuits, C::nested_generators(self.wallet.params))
            });
        }
        let _ = (source, circuits);
        None
    }

    /// The sides a fuse runs the chunks over: `source`'s, the proof the
    /// step decompresses, or the canonical proof's without.
    fn sides<'a>(&'a self, source: Option<&'a Decompressed<C>>) -> &'a Sides<C> {
        source.map_or(&self.canonical, |decompressed| &decompressed.0)
    }

    /// The native extension's polynomials for profile `P` over `source`,
    /// or a blinded empty witness for an inactive optional extension. An
    /// always-active profile uses the canonical proof without a source:
    /// every chunk circuit's
    /// trace, the statement circuit's and the binding circuit's assembled
    /// against `registry` at their index in `P`'s layout, and the six
    /// stages' polynomials, each blinded from `rng` but the digits
    /// stage's, which the scalar-field side recomputes.
    ///
    /// # Errors
    ///
    /// Fails if a circuit's trace or assembly fails, which the prepared
    /// sides of a verified proof do not.
    pub(crate) fn native_rxs<P: Profile>(
        &self,
        source: Option<&Decompressed<C>>,
        registry: &Registry<'_, C::CircuitField, R>,
        rng: &mut impl CryptoRng,
    ) -> Result<ExtensionRxs<C::CircuitField, R>> {
        if P::OPTIONAL_DECOMPRESSION && source.is_none() {
            return Ok(empty_extension(&P::native_extension(), rng));
        }
        let prepared = &self.sides(source).native;
        let schedule = Arc::new(prepared.schedule.clone());
        let params = self.wallet.params;
        #[cfg(feature = "std")]
        let cached = source
            .is_none()
            .then(|| self.native_cache.get())
            .flatten()
            .map(|cached| cached.rerandomize(rng));
        #[cfg(not(feature = "std"))]
        let cached: Option<Vec<sparse::Polynomial<C::CircuitField, R>>> = None;
        let circuits = if let Some(circuits) = cached {
            circuits
        } else {
            let mut circuits = Vec::with_capacity(schedule.circuits.len() + 2);
            for index in 0..schedule.circuits.len() {
                let trace =
                    chunk_trace::<C, Native, R, HEADER_SIZE>(&schedule, index, prepared, params)?;
                let circuit = native::InternalCircuitIndex::ExtensionCircuit(index as u32);
                circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
            }
            let trace = chunk::StatementCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(
                schedule.clone(),
            )
            .trace(prepared)?
            .into_parts()
            .0;
            let statement =
                native::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32);
            circuits.push(registry.assemble(&trace, statement.circuit_index::<P>(), rng)?);
            let trace = chunk::BindingCircuit::<C, Native, WalletRank, R, HEADER_SIZE>::new(
                schedule.clone(),
            )
            .trace(prepared)?
            .into_parts()
            .0;
            let binding =
                native::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32 + 1);
            circuits.push(registry.assemble(&trace, binding.circuit_index::<P>(), rng)?);
            #[cfg(feature = "std")]
            if source.is_none() {
                let _ = self.native_cache.set(CanonicalCircuits::new::<B>(
                    &circuits,
                    C::host_generators(params),
                ));
            }
            circuits
        };
        type Lifts<C, R, const H: usize> = LiftsStage<C, Native, WalletRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Native, WalletRank, R, H>;
        type Transcript<C, R, const H: usize> = TranscriptStage<C, Native, WalletRank, R, H>;
        type Digits<C, R, const H: usize> = DigitsStage<C, Native, WalletRank, R, H>;
        let mut stages = front_rxs::<C, Native, R, HEADER_SIZE>(prepared, rng)?;
        stages.extend([
            Lifts::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.lifts)?,
            Work::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.work)?,
            Transcript::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.transcript)?,
            Digits::<C, R, HEADER_SIZE>::rx(C::CircuitField::ZERO, &prepared.digits)?,
        ]);
        Ok(ExtensionRxs { circuits, stages })
    }

    /// The nested extension's polynomials for profile `P`, as
    /// [`native_rxs`](Self::native_rxs): every chunk circuit's, the
    /// binding circuit's and the stages', the run stages', whose
    /// commitments the compression's transcript absorbed, and the lifts
    /// and digits stages', which the circuit-field side recomputes,
    /// unblinded.
    ///
    /// # Errors
    ///
    /// As [`native_rxs`](Self::native_rxs).
    pub(crate) fn nested_rxs<P: Profile>(
        &self,
        source: Option<&Decompressed<C>>,
        registry: &Registry<'_, C::ScalarField, R>,
        rng: &mut impl CryptoRng,
    ) -> Result<ExtensionRxs<C::ScalarField, R>> {
        if P::OPTIONAL_DECOMPRESSION && source.is_none() {
            return Ok(empty_extension(&P::nested_extension(), rng));
        }
        let prepared: &Prepared<C, Nested> = &self.sides(source).nested;
        let schedule = Arc::new(prepared.schedule.clone());
        let params = self.wallet.params;
        #[cfg(feature = "std")]
        let cached = source
            .is_none()
            .then(|| self.nested_cache.get())
            .flatten()
            .map(|cached| cached.rerandomize(rng));
        #[cfg(not(feature = "std"))]
        let cached: Option<Vec<sparse::Polynomial<C::ScalarField, R>>> = None;
        let circuits = if let Some(circuits) = cached {
            circuits
        } else {
            let mut circuits = Vec::with_capacity(schedule.circuits.len() + 1);
            for index in 0..schedule.circuits.len() {
                let trace =
                    chunk_trace::<C, Nested, R, HEADER_SIZE>(&schedule, index, prepared, params)?;
                let circuit = nested::InternalCircuitIndex::ExtensionCircuit(index as u32);
                circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
            }
            let trace = chunk::BindingCircuit::<C, Nested, WalletRank, R, HEADER_SIZE>::new(
                schedule.clone(),
            )
            .trace(prepared)?
            .into_parts()
            .0;
            let binding =
                nested::InternalCircuitIndex::ExtensionCircuit(schedule.circuits.len() as u32);
            circuits.push(registry.assemble(&trace, binding.circuit_index::<P>(), rng)?);
            #[cfg(feature = "std")]
            if source.is_none() {
                let _ = self.nested_cache.set(CanonicalCircuits::new::<B>(
                    &circuits,
                    C::nested_generators(params),
                ));
            }
            circuits
        };
        type Lifts<C, R, const H: usize> = LiftsStage<C, Nested, WalletRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Nested, WalletRank, R, H>;
        type Digits<C, R, const H: usize> = DigitsStage<C, Nested, WalletRank, R, H>;
        let zero = C::ScalarField::ZERO;
        let mut stages = front_rxs::<C, Nested, R, HEADER_SIZE>(prepared, rng)?;
        stages.extend([
            Lifts::<C, R, HEADER_SIZE>::rx(zero, &prepared.lifts)?,
            Work::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.work)?,
            Digits::<C, R, HEADER_SIZE>::rx(zero, &prepared.digits)?,
        ]);
        Ok(ExtensionRxs { circuits, stages })
    }
}

/// The polynomials of side `S`'s front stages over `prepared`, in stage
/// order, each blinded from `rng` unless the other side holds a value to
/// its commitment.
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
            let alpha = if S::unblinded(index) {
                S::F::ZERO
            } else {
                blinding(rng)
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

/// A fixed canonical circuit body with its original SYSTEM-gate blinding.
/// Only this blinding changes between ordinary aggregator fuses. Actual
/// decompressions always trace their input-dependent circuits afresh.
#[cfg(feature = "std")]
struct CanonicalCircuits<C: udon::curve::Affine, R: Rank> {
    polynomials: Vec<sparse::Polynomial<C::Scalar, R>>,
    alphas: Vec<C::Scalar>,
    commitments: Vec<C>,
}

#[cfg(feature = "std")]
impl<C: udon::curve::Affine, R: Rank> CanonicalCircuits<C, R> {
    fn new<B: ragu_backend::Backend>(
        polynomials: &[sparse::Polynomial<C::Scalar, R>],
        generators: &impl FixedGenerators<C>,
    ) -> Self {
        Self {
            polynomials: polynomials.to_vec(),
            alphas: polynomials.iter().map(trace_alpha).collect(),
            commitments: B::sparse_commit_many_to_affine(polynomials, generators),
        }
    }

    fn rerandomize(&self, rng: &mut impl CryptoRng) -> Vec<sparse::Polynomial<C::Scalar, R>> {
        self.polynomials
            .iter()
            .zip(&self.alphas)
            .map(|(rx, &alpha)| {
                let mut rx = rx.clone();
                let mut delta = sparse::View::trace();
                delta.a.push(blinding::<C::Scalar>(rng) - alpha);
                rx.add_assign(&delta.build());
                rx
            })
            .collect()
    }

    fn commitments<B: ragu_backend::Backend>(
        &self,
        polynomials: &[sparse::Polynomial<C::Scalar, R>],
        generators: &impl FixedGenerators<C>,
    ) -> Vec<C> {
        assert_eq!(polynomials.len(), self.polynomials.len());
        let generator = generators.g()[2 * R::n() - 1];
        let projective: Vec<_> = polynomials
            .iter()
            .zip(&self.alphas)
            .zip(&self.commitments)
            .map(|((rx, &alpha), &commitment)| {
                let scalars = [C::Scalar::ONE, trace_alpha(rx) - alpha];
                let bases = [commitment, generator];
                B::msm(scalars.iter(), bases.iter())
            })
            .collect();
        let mut result = alloc::vec![C::identity(); projective.len()];
        C::batch_to_affine(&projective, &mut result);
        result
    }
}

#[cfg(feature = "std")]
fn trace_alpha<F: Field, R: Rank>(rx: &sparse::Polynomial<F, R>) -> F {
    rx.iter_stored_coeffs()
        .find_map(|(degree, &coefficient)| (degree == 2 * R::n() - 1).then_some(coefficient))
        .unwrap_or(F::ZERO)
}

/// An inactive extension still has nonidentity commitments. The SYSTEM
/// a-wire is unconstrained by circuit wiring and stage masks; b, c and d
/// remain zero, so every extension revdot target is zero.
fn empty_extension<F: Field, R: Rank>(
    extension: &crate::profile::Extension,
    rng: &mut impl CryptoRng,
) -> ExtensionRxs<F, R> {
    let mut empty = || {
        let mut alpha = F::ZERO;
        while alpha == F::ZERO {
            alpha = blinding(rng);
        }
        let mut view = sparse::View::trace();
        view.a.push(alpha);
        view.build()
    };
    ExtensionRxs {
        circuits: (0..extension.circuits.len()).map(|_| empty()).collect(),
        stages: (0..extension.stages).map(|_| empty()).collect(),
    }
}

/// A stage polynomial's blinding.
fn blinding<F: Field>(rng: &mut impl CryptoRng) -> F {
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
    /// Fails if the wallet application's verifier would reject `pcd`, or
    /// if proving fails.
    ///
    /// # Soundness
    ///
    /// The proof attests a decompression an honest prover ran: the
    /// aggregator profile is not yet sound against a dishonest one (see
    /// [`Aggregator`]'s *Soundness*).
    pub fn decompress<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        rng: &mut RNG,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Pcd<Profiled<C, Aggregator<HEADER_SIZE>>, R, H>> {
        let decompressed = self.context.prepare(pcd)?;
        let (pcd, ()) = self.fuse_with_source(
            rng,
            Decompress::<H>::new(),
            pcd.data().clone(),
            self.bootstrap_pcd(),
            self.bootstrap_pcd(),
            Some(&decompressed),
        )?;
        Ok(pcd)
    }
}

#[cfg(all(test, feature = "std"))]
mod canonical_cache_tests {
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_core::{Cycle, pasta::Pasta};
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use udon::curve::Affine;

    use super::*;

    fn check<C: Affine>(generators: &impl FixedGenerators<C>) {
        type R = ragu_circuits::polynomials::TestRank;
        let polynomials: Vec<sparse::Polynomial<C::Scalar, R>> = (0..3)
            .map(|i| {
                let mut view = sparse::View::trace();
                view.a.extend([C::Scalar::from(i), C::Scalar::from(5)]);
                view.b.extend([C::Scalar::ZERO, C::Scalar::from(7)]);
                view.c.extend([C::Scalar::ZERO, C::Scalar::from(35)]);
                view.d.push(C::Scalar::ONE);
                view.build()
            })
            .collect();
        let cache = CanonicalCircuits::new::<ReferenceBackend>(&polynomials, generators);
        let mut cached_rng = StdRng::seed_from_u64(51);
        let mut direct_rng = StdRng::seed_from_u64(51);
        for _ in 0..4 {
            let actual = cache.rerandomize(&mut cached_rng);
            let commitments = cache.commitments::<ReferenceBackend>(&actual, generators);
            for ((original, actual), commitment) in polynomials.iter().zip(&actual).zip(commitments)
            {
                let alpha = blinding::<C::Scalar>(&mut direct_rng);
                let expected: Vec<_> = original
                    .iter_coeffs()
                    .enumerate()
                    .map(|(degree, coefficient)| {
                        if degree == 2 * R::n() - 1 {
                            alpha
                        } else {
                            coefficient
                        }
                    })
                    .collect();
                assert!(actual.iter_coeffs().eq(expected));
                assert_eq!(
                    commitment,
                    ReferenceBackend::sparse_commit_to_affine(actual, generators)
                );
            }
        }
        assert_eq!(
            cached_rng.random::<u64>(),
            direct_rng.random::<u64>(),
            "cache preserves random draws"
        );
    }

    #[test]
    fn rerandomized_polynomials_and_commitments_match_direct_computation_on_both_curves() {
        let params = crate::pasta::baked_aggregator();
        check(Pasta::host_generators(params));
        check(Pasta::nested_generators(params));
    }
}
