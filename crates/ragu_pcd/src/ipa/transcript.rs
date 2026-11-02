//! The transcript the IPAs run on.
//!
//! [`IpaTranscript`] is what the prover and verifier need: halo2's transcript
//! operations with the proof carried as a struct rather than a byte stream.
//! [`CycleTranscript`] is the fuse's transcript opened for both curves: the
//! PCD transcript over the circuit field, executed at concrete values
//! through the [`Emulator`] driver. Nested-curve points and circuit-field
//! scalars are absorbed as the [`Point`] and [`Element`] gadgets write
//! them. Host-curve points and scalar-field values lie in the other field:
//! the transcript collects them as they come and, when anything else is
//! absorbed or a challenge is squeezed, first commits the run of them on
//! the nested curve and absorbs the commitment as a point, as the fuse's
//! bridge stages carry the other field's values. The commitment is over
//! the generators the run's stage of the proof's decompression lands the
//! values on, unblinded (the transcript is opened with them,
//! [`with_runs`](CycleTranscript::with_runs)), so that it is that stage's
//! commitment: a circuit over the circuit field absorbs it as a witness
//! point, and the proof's consumer holds the point to the stage, which
//! binds the run's values before the challenge that follows them (see
//! [`stages`](crate::decompress::stages)). A run that precedes no
//! challenge is never absorbed: no challenge depends on it. Challenges for
//! the host curve are the raw squeeze. Nested challenges preserve its
//! canonical integer in the scalar field, rejecting values outside the two
//! fields' common capacity (254 bits for Pasta). The compression reads both
//! through `Lifted`, which narrows each squeeze to a 143-bit endoscalar and
//! lifts it into the field of the curve the challenge serves, as the fuse's
//! challenges are read.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_backend::ReferenceBackend;
use ragu_core::{
    Cycle, Error, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, GadgetExt, Point};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use crate::{SelectableBackend, internal::transcript::Transcript};

/// Preserves the canonical integer on the common power-of-two range of the
/// two fields. Under an ideal uniform squeeze, accepted challenges are
/// uniform on that range; out-of-range draws fail without another squeeze.
pub(super) fn convert_challenge<F: Field, T: Field>(challenge: F) -> Result<T> {
    let capacity = F::CAPACITY.min(T::CAPACITY) as usize;
    if challenge.to_le_bits().as_ref()[capacity..]
        .iter()
        .any(|bit| *bit)
    {
        return Err(Error::InvalidWitness(
            "nested IPA challenge exceeds the common field capacity".into(),
        ));
    }

    // Both representations hold the common capacity; any bytes beyond the
    // shorter representation are zero after the range check.
    let source = challenge.to_bytes();
    let mut target = T::ZERO.to_bytes();
    let len = source.as_ref().len().min(target.as_ref().len());
    target.as_mut()[..len].copy_from_slice(&source.as_ref()[..len]);
    T::from_bytes(target).ok_or_else(|| {
        Error::InvalidWitness("nested IPA challenge is not a canonical scalar".into())
    })
}

/// What the IPA needs from a transcript: halo2's `TranscriptWrite`
/// operations, with the proof carried as a struct rather than written to a
/// byte stream, so the verifier writes what the prover wrote.
pub trait IpaTranscript<C: Affine> {
    /// Absorbs a point.
    fn write_point(&mut self, point: C) -> Result<()>;

    /// Absorbs a scalar.
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()>;

    /// Squeezes a challenge in the scalar field.
    fn squeeze_challenge(&mut self) -> Result<C::Scalar>;
}

type Executor<F> = Emulator<Wireless<Always<()>, F>>;

/// Where a transcript commits the scalar field's runs.
enum RunBases<C: Cycle> {
    /// Nowhere: the fuse's transcript takes no scalar-field value.
    None,
    /// Each run at its stage's generators, in absorption order: the
    /// compression's.
    Positioned(Vec<Vec<C::NestedCurve>>),
    /// Each run over the first nested generators, as the fuse's bridge
    /// stages commit: a test's transcript over part of the compression.
    #[cfg(test)]
    First(Vec<C::NestedCurve>),
}

/// The fuse's transcript, opened for the IPAs of both curves: one sponge over
/// the circuit field, executed at concrete values through the [`Emulator`]
/// driver, committing the scalar field's runs with the backend `B`.
pub struct CycleTranscript<'dr, C: Cycle, B: SelectableBackend = ReferenceBackend> {
    dr: Executor<C::CircuitField>,
    transcript: Transcript<'dr, Executor<C::CircuitField>, C::CircuitPoseidon>,
    /// The generators each run is committed at.
    bases: RunBases<C>,
    /// The scalar-field values absorbed since the last run's commitment,
    /// which the next covers.
    pending: Vec<C::ScalarField>,
    /// The runs' commitments absorbed so far, in order.
    runs: Vec<C::NestedCurve>,
    backend: PhantomData<B>,
}

impl<'dr, C: Cycle, B: SelectableBackend> CycleTranscript<'dr, C, B> {
    /// Creates a transcript over the cycle's circuit-field Poseidon,
    /// domain-separated by `tag`, which takes no scalar-field value: the
    /// fuse's.
    pub fn new(params: &'dr C::Params, tag: &[u8]) -> Result<Self> {
        let mut dr = Executor::<C::CircuitField>::execute();
        let transcript = Transcript::new(&mut dr, C::circuit_poseidon(params), tag)?;
        Ok(CycleTranscript {
            dr,
            transcript,
            bases: RunBases::None,
            pending: Vec::new(),
            runs: Vec::new(),
            backend: PhantomData,
        })
    }

    /// As [`new`](Self::new), committing each run of scalar-field values
    /// at the next of `bases`, in absorption order: the compression's.
    pub(crate) fn with_runs(
        params: &'dr C::Params,
        tag: &[u8],
        bases: Vec<Vec<C::NestedCurve>>,
    ) -> Result<Self> {
        let mut transcript = Self::new(params, tag)?;
        transcript.bases = RunBases::Positioned(bases);
        Ok(transcript)
    }

    /// As [`new`](Self::new), committing each run of scalar-field values
    /// over the first nested generators, for a test that runs part of the
    /// compression on a transcript of its own.
    #[cfg(test)]
    pub(crate) fn over_first_generators(params: &'dr C::Params, tag: &[u8]) -> Result<Self> {
        use ragu_core::FixedGenerators;
        let mut transcript = Self::new(params, tag)?;
        let generators = C::nested_generators(params).g();
        transcript.bases = RunBases::First(generators[..generators.len().min(256)].to_vec());
        Ok(transcript)
    }

    /// The transcript as the host-curve IPA sees it.
    pub fn host(&mut self) -> HostSide<'_, 'dr, C, B> {
        HostSide(self)
    }

    /// The transcript as the nested-curve IPA sees it.
    pub fn nested(&mut self) -> NestedSide<'_, 'dr, C, B> {
        NestedSide(self)
    }

    /// The runs' commitments absorbed so far, one per run of scalar-field
    /// values, in order.
    pub(crate) fn runs(&self) -> &[C::NestedCurve] {
        &self.runs
    }

    /// Absorbs a nested-curve point through the [`Point`] gadget, which
    /// rejects the identity as halo2's `common_point` does, after the
    /// commitment of the run before it, if any.
    fn absorb(&mut self, point: C::NestedCurve) -> Result<()> {
        self.flush()?;
        self.absorb_point(point)
    }

    fn absorb_point(&mut self, point: C::NestedCurve) -> Result<()> {
        super::fingerprint::record_point(&point);
        Point::constant(&mut self.dr, point)?.write(&mut self.dr, &mut self.transcript)
    }

    /// Absorbs a circuit-field scalar, after the commitment of the run
    /// before it, if any.
    fn absorb_scalar(&mut self, scalar: C::CircuitField) -> Result<()> {
        self.flush()?;
        super::fingerprint::record_scalar(&scalar);
        Element::constant(&mut self.dr, scalar).write(&mut self.dr, &mut self.transcript)
    }

    /// Collects a scalar-field value for the run's commitment.
    fn collect(&mut self, value: C::ScalarField) -> Result<()> {
        if matches!(self.bases, RunBases::None) {
            return Err(Error::Initialization(
                "the transcript was opened without run stages and takes no scalar-field value"
                    .into(),
            ));
        }
        self.pending.push(value);
        Ok(())
    }

    /// Absorbs the commitment of the scalar-field values collected since
    /// the last, if any, ending the run.
    ///
    /// A run committing to the identity, which a run of all zeros does, is
    /// rejected by [`absorb`](Self::absorb). This can reject
    /// otherwise-valid proofs.
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let run: &[C::NestedCurve] = match &self.bases {
            RunBases::None => unreachable!("values are collected only with run stages"),
            RunBases::Positioned(bases) => {
                let Some(run) = bases.get(self.runs.len()) else {
                    return Err(Error::Initialization(
                        "the transcript absorbs more runs of scalar-field values than the proof's decompression has stages for".into(),
                    ));
                };
                if run.len() != self.pending.len() {
                    return Err(Error::InvalidWitness(
                        "a run of scalar-field values is not the size of its stage".into(),
                    ));
                }
                run
            }
            #[cfg(test)]
            RunBases::First(generators) => &generators[..self.pending.len()],
        };
        let commitment = B::msm(self.pending.iter(), run.iter()).to_affine();
        self.pending.clear();
        self.absorb_point(commitment)?;
        self.runs.push(commitment);
        Ok(())
    }

    /// Squeezes a circuit-field challenge, after the commitment of the run
    /// before it, if any.
    fn squeeze(&mut self) -> Result<C::CircuitField> {
        self.flush()?;
        let challenge = *self.transcript.challenge(&mut self.dr)?.value().take();
        super::fingerprint::record_challenge(&challenge);
        Ok(challenge)
    }
}

/// A [`CycleTranscript`] as the host-curve IPA sees it: a point's
/// coordinates are in the scalar field, so they are collected for the run's
/// commitment; a scalar is in the circuit field, so it is absorbed directly;
/// and a challenge is the raw squeeze. The compression reads its challenges
/// through `Lifted`, as endoscalar lifts.
pub struct HostSide<'a, 'dr, C: Cycle, B: SelectableBackend>(&'a mut CycleTranscript<'dr, C, B>);

impl<C: Cycle, B: SelectableBackend> IpaTranscript<C::HostCurve> for HostSide<'_, '_, C, B> {
    fn write_point(&mut self, point: C::HostCurve) -> Result<()> {
        let Some((x, y)) = point.coordinates() else {
            return Err(Error::InvalidWitness(
                "point at infinity cannot be written to the transcript".into(),
            ));
        };
        self.0.collect(x)?;
        self.0.collect(y)
    }

    fn write_scalar(&mut self, scalar: C::CircuitField) -> Result<()> {
        self.0.absorb_scalar(scalar)
    }

    fn squeeze_challenge(&mut self) -> Result<C::CircuitField> {
        self.0.squeeze()
    }
}

/// A [`CycleTranscript`] as the nested-curve IPA sees it: a point's
/// coordinates are in the circuit field, so it is absorbed directly; a scalar
/// is in the scalar field, so it is collected for the run's commitment; and
/// a raw challenge keeps the squeeze's canonical integer within the two
/// fields' common capacity, 254 bits for Pasta. The compression reads its
/// challenges through `Lifted`, which narrows each squeeze to a 143-bit
/// endoscalar first, as the fuse's challenges are read; a recursive
/// verifier of the compression reproduces that lift.
pub struct NestedSide<'a, 'dr, C: Cycle, B: SelectableBackend>(&'a mut CycleTranscript<'dr, C, B>);

impl<C: Cycle, B: SelectableBackend> IpaTranscript<C::NestedCurve> for NestedSide<'_, '_, C, B> {
    fn write_point(&mut self, point: C::NestedCurve) -> Result<()> {
        self.0.absorb(point)
    }

    fn write_scalar(&mut self, scalar: C::ScalarField) -> Result<()> {
        self.0.collect(scalar)
    }

    fn squeeze_challenge(&mut self) -> Result<C::ScalarField> {
        convert_challenge(self.0.squeeze()?)
    }
}
