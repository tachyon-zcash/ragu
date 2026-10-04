//! The transcript the IPAs run on.
//!
//! [`IpaTranscript`] is what the prover and verifier need: halo2's transcript
//! operations with the proof carried as a struct rather than a byte stream.
//! [`CycleTranscript`] is the fuse's transcript opened for both curves: the
//! PCD transcript over the circuit field, executed at concrete values
//! through the [`Emulator`] driver. Nested-curve points are absorbed as the
//! [`Point`] gadget writes them; host-curve points and scalar-field values
//! are bridged the way the fuse's bridge stages bridge them, committed on the
//! nested curve and absorbed as that commitment. Challenges for the host
//! curve are the raw squeeze. Nested challenges preserve its canonical
//! integer in the scalar field, rejecting values outside the two fields'
//! common capacity (254 bits for Pasta).

use core::marker::PhantomData;

use ragu_backend::ReferenceBackend;
use ragu_core::{
    Cycle, Error, FixedGenerators, Result,
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

/// The fuse's transcript, opened for the IPAs of both curves: one sponge over
/// the circuit field, executed at concrete values through the [`Emulator`]
/// driver, with the cycle's parameters at hand for bridging. Bridge commitments
/// use the Ragu-owned backend `B`.
///
/// ```compile_fail,E0277
/// use ragu_backend::Backend;
/// use ragu_core::Cycle;
/// use ragu_pcd::ipa::{CycleTranscript, IPA_TAG};
///
/// #[derive(Clone, Copy, Debug, Default)]
/// struct CustomBackend;
/// impl Backend for CustomBackend {}
///
/// fn transcript<C: Cycle>(params: &C::Params) {
///     let _ = CycleTranscript::<C, CustomBackend>::new(params, IPA_TAG);
/// }
/// ```
pub struct CycleTranscript<'dr, C: Cycle, B: SelectableBackend = ReferenceBackend> {
    dr: Emulator<Wireless<Always<()>, C::CircuitField>>,
    transcript:
        Transcript<'dr, Emulator<Wireless<Always<()>, C::CircuitField>>, C::CircuitPoseidon>,
    params: &'dr C::Params,
    backend: PhantomData<B>,
}

impl<'dr, C: Cycle, B: SelectableBackend> CycleTranscript<'dr, C, B> {
    /// Creates a transcript over the cycle's circuit-field Poseidon,
    /// domain-separated by `tag`.
    pub fn new(params: &'dr C::Params, tag: &[u8]) -> Result<Self> {
        let mut dr = Emulator::execute();
        let transcript = Transcript::new(&mut dr, C::circuit_poseidon(params), tag)?;
        Ok(CycleTranscript {
            dr,
            transcript,
            params,
            backend: PhantomData,
        })
    }

    /// The transcript as the host-curve IPA sees it.
    pub fn host(&mut self) -> HostSide<'_, 'dr, C, B> {
        HostSide(self)
    }

    /// The transcript as the nested-curve IPA sees it.
    pub fn nested(&mut self) -> NestedSide<'_, 'dr, C, B> {
        NestedSide(self)
    }

    /// Absorbs a nested-curve point through the [`Point`] gadget, which
    /// rejects the identity as halo2's `common_point` does.
    fn absorb(&mut self, point: C::NestedCurve) -> Result<()> {
        Point::constant(&mut self.dr, point)?.write(&mut self.dr, &mut self.transcript)
    }

    /// Bridges scalar-field values into the transcript the way the fuse's
    /// bridge stages do: committed on the nested curve, then absorbed as that
    /// commitment.
    ///
    /// An identity bridge, including the encoding of a single zero scalar,
    /// is rejected by `absorb`. This can reject otherwise-valid proofs.
    fn bridge(&mut self, values: &[C::ScalarField]) -> Result<()> {
        let g = C::nested_generators(self.params).g();
        let commitment: C::NestedCurve = B::msm(values, &g[..values.len()]).to_affine();
        self.absorb(commitment)
    }

    /// Squeezes a circuit-field challenge.
    fn squeeze(&mut self) -> Result<C::CircuitField> {
        Ok(*self.transcript.challenge(&mut self.dr)?.value().take())
    }
}

/// A [`CycleTranscript`] as the host-curve IPA sees it: a point's
/// coordinates are in the scalar field, so it is bridged; a scalar is in the
/// circuit field, so it is absorbed directly; and a challenge is the raw
/// squeeze, as the fuse's native challenges are.
pub struct HostSide<'a, 'dr, C: Cycle, B: SelectableBackend = ReferenceBackend>(
    &'a mut CycleTranscript<'dr, C, B>,
);

impl<C: Cycle, B: SelectableBackend> IpaTranscript<C::HostCurve> for HostSide<'_, '_, C, B> {
    fn write_point(&mut self, point: C::HostCurve) -> Result<()> {
        let Some((x, y)) = point.coordinates() else {
            return Err(ragu_core::Error::InvalidWitness(
                "point at infinity cannot be written to the transcript".into(),
            ));
        };
        self.0.bridge(&[x, y])
    }

    fn write_scalar(&mut self, scalar: C::CircuitField) -> Result<()> {
        Element::constant(&mut self.0.dr, scalar).write(&mut self.0.dr, &mut self.0.transcript)
    }

    fn squeeze_challenge(&mut self) -> Result<C::CircuitField> {
        self.0.squeeze()
    }
}

/// A [`CycleTranscript`] as the nested-curve IPA sees it: a point's
/// coordinates are in the circuit field, so it is absorbed directly; a scalar
/// is in the scalar field, so it is bridged; and a challenge preserves the
/// squeeze's canonical integer within the two fields' common capacity.
/// For Pasta this gives a $2^{254}$-element challenge space. The fuse's
/// replayed challenges still use endoscalar lifts; a recursive verifier of
/// these fresh compression challenges must reproduce this conversion.
pub struct NestedSide<'a, 'dr, C: Cycle, B: SelectableBackend = ReferenceBackend>(
    &'a mut CycleTranscript<'dr, C, B>,
);

impl<C: Cycle, B: SelectableBackend> IpaTranscript<C::NestedCurve> for NestedSide<'_, '_, C, B> {
    fn write_point(&mut self, point: C::NestedCurve) -> Result<()> {
        self.0.absorb(point)
    }

    fn write_scalar(&mut self, scalar: C::ScalarField) -> Result<()> {
        self.0.bridge(&[scalar])
    }

    fn squeeze_challenge(&mut self) -> Result<C::ScalarField> {
        convert_challenge(self.0.squeeze()?)
    }
}
