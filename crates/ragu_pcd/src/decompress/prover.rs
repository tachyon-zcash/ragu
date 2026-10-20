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
    polynomials::{ProductionRank, Rank},
    registry::Registry,
    staging::StageExt,
};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use super::{
    chunk::{self, is_transcript},
    run::{Prepared, Sides},
    side::{Native, Nested},
    stages::{InstanceStage, MessagesStage, TranscriptStage, WorkStage},
};
use crate::{
    Application, CompressedPcd, Pcd, SelectableBackend,
    header::Header,
    internal::{native, nested},
    ipa::IpaCycle,
    profile::{Aggregator, ExtensionRxs, Profile, Profiled, ProfiledCycle, Standard},
    step::internal::decompress::Decompress,
};

/// A compressed proof prepared for decompression: both sides' stages
/// filled from the prover's native run of the chunks over it, which the
/// decompression step's fuse runs the chunk circuits over in place of the
/// canonical proof.
pub struct Decompressed<C: IpaCycle + ProfiledCycle<Profile = Standard>>(Sides<C>);

/// The aggregator's prover context: the wallet application whose proofs
/// the aggregator decompresses and a canonical decompression, prepared
/// for chunk circuits at rank `R` with `HEADER_SIZE`-element headers.
pub struct Decompression<'params, C, R, const HEADER_SIZE: usize, B>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    B: SelectableBackend,
{
    wallet: Application<'params, C, ProductionRank, HEADER_SIZE, B>,
    canonical: Sides<C>,
    _marker: PhantomData<fn() -> R>,
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
    /// same steps and parameters as every wallet's. Nothing checks this yet;
    /// see the decompression module's *What remains*.
    ///
    /// # Errors
    ///
    /// Fails if the compression or its verification fails, which a
    /// finalized application's bootstrap does not.
    pub fn new(
        wallet: Application<'params, C, ProductionRank, HEADER_SIZE, B>,
        rng: &mut impl CryptoRng,
    ) -> Result<Self> {
        let bootstrap = wallet
            .bootstrap
            .clone()
            .expect("a finalized application holds its bootstrap proof")
            .carry::<()>(());
        let compressed = wallet.compress(&bootstrap, rng)?;
        let canonical =
            Sides::prepare::<ProductionRank, R, HEADER_SIZE, B, ()>(&wallet, &compressed)?;
        Ok(Decompression {
            wallet,
            canonical,
            _marker: PhantomData,
        })
    }

    /// The wallet application whose proofs the aggregator decompresses.
    pub fn wallet(&self) -> &Application<'params, C, ProductionRank, HEADER_SIZE, B> {
        &self.wallet
    }

    /// Prepares the decompression of `pcd`, a compressed proof of the
    /// wallet application, for the step that decompresses it.
    ///
    /// # Errors
    ///
    /// Fails if the wallet application's verifier would reject `pcd`.
    pub fn prepare<H: Header<C::CircuitField>>(
        &self,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Decompressed<C>> {
        Ok(Decompressed(Sides::prepare::<
            ProductionRank,
            R,
            HEADER_SIZE,
            B,
            H,
        >(&self.wallet, pcd)?))
    }

    /// The sides a fuse runs the chunks over: `source`'s, the proof the
    /// step decompresses, or the canonical proof's without.
    fn sides<'a>(&'a self, source: Option<&'a Decompressed<C>>) -> &'a Sides<C> {
        source.map_or(&self.canonical, |decompressed| &decompressed.0)
    }

    /// The native extension's polynomials for profile `P` over `source`,
    /// or over the canonical decompression without: every chunk circuit's
    /// trace and the statement circuit's assembled against `registry` at
    /// their index in `P`'s layout, and the four stages' polynomials, each
    /// blinded from `rng`.
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
        let prepared = &self.sides(source).native;
        let schedule = Arc::new(prepared.schedule.clone());
        let params = self.wallet.params;
        let mut circuits = Vec::with_capacity(schedule.chunks.len() + 1);
        for index in 0..schedule.chunks.len() {
            let trace = if is_transcript(&schedule, index) {
                chunk::TranscriptCircuit::<C, Native, ProductionRank, R, HEADER_SIZE>::new(
                    index,
                    schedule.clone(),
                    params,
                )
                .trace(prepared)?
                .into_parts()
                .0
            } else {
                chunk::Circuit::<C, Native, ProductionRank, R, HEADER_SIZE>::new(
                    index,
                    schedule.clone(),
                    params,
                )
                .trace(prepared)?
                .into_parts()
                .0
            };
            let circuit = native::InternalCircuitIndex::ExtensionCircuit(index as u32);
            circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
        }
        let trace = chunk::StatementCircuit::<C, Native, ProductionRank, R, HEADER_SIZE>::new(
            schedule.clone(),
        )
        .trace(prepared)?
        .into_parts()
        .0;
        let statement =
            native::InternalCircuitIndex::ExtensionCircuit(schedule.chunks.len() as u32);
        circuits.push(registry.assemble(&trace, statement.circuit_index::<P>(), rng)?);
        type Instance<C, R, const H: usize> = InstanceStage<C, Native, ProductionRank, R, H>;
        type Messages<C, R, const H: usize> = MessagesStage<C, Native, ProductionRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Native, ProductionRank, R, H>;
        type Transcript<C, R, const H: usize> = TranscriptStage<C, Native, ProductionRank, R, H>;
        let stages = alloc::vec![
            Instance::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.instance)?,
            Messages::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.messages)?,
            Work::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.work)?,
            Transcript::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.transcript)?,
        ];
        Ok(ExtensionRxs { circuits, stages })
    }

    /// The nested extension's polynomials for profile `P`, as
    /// [`native_rxs`](Self::native_rxs): every chunk circuit's and the
    /// three stages'.
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
        let prepared: &Prepared<C, Nested> = &self.sides(source).nested;
        let schedule = Arc::new(prepared.schedule.clone());
        let params = self.wallet.params;
        let mut circuits = Vec::with_capacity(schedule.chunks.len());
        for index in 0..schedule.chunks.len() {
            let trace = chunk::Circuit::<C, Nested, ProductionRank, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            )
            .trace(prepared)?
            .into_parts()
            .0;
            let circuit = nested::InternalCircuitIndex::ExtensionCircuit(index as u32);
            circuits.push(registry.assemble(&trace, circuit.circuit_index::<P>(), rng)?);
        }
        type Instance<C, R, const H: usize> = InstanceStage<C, Nested, ProductionRank, R, H>;
        type Messages<C, R, const H: usize> = MessagesStage<C, Nested, ProductionRank, R, H>;
        type Work<C, R, const H: usize> = WorkStage<C, Nested, ProductionRank, R, H>;
        let stages = alloc::vec![
            Instance::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.instance)?,
            Messages::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.messages)?,
            Work::<C, R, HEADER_SIZE>::rx(blinding(rng), &prepared.work)?,
        ];
        Ok(ExtensionRxs { circuits, stages })
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
