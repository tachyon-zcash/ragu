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
//! curve are the raw squeeze, and challenges for the nested curve are its
//! lifts, as in the fuse.

use ragu_arithmetic::{CurveAffine, Cycle, FixedGenerators, group::Curve, msm};
use ragu_core::{
    Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, GadgetExt, Point};

use crate::internal::{nested, transcript::Transcript};

/// What the IPA needs from a transcript: halo2's `TranscriptWrite`
/// operations, with the proof carried as a struct rather than written to a
/// byte stream, so the verifier writes what the prover wrote.
pub trait IpaTranscript<C: CurveAffine> {
    /// Absorbs a point.
    fn write_point(&mut self, point: C) -> Result<()>;

    /// Absorbs a scalar.
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()>;

    /// Squeezes a challenge in the scalar field.
    fn squeeze_challenge(&mut self) -> Result<C::Scalar>;
}

/// The fuse's transcript, opened for the IPAs of both curves: one sponge over
/// the circuit field, executed at concrete values through the [`Emulator`]
/// driver, with the cycle's parameters at hand for bridging.
pub struct CycleTranscript<'dr, C: Cycle> {
    dr: Emulator<Wireless<Always<()>, C::CircuitField>>,
    transcript:
        Transcript<'dr, Emulator<Wireless<Always<()>, C::CircuitField>>, C::CircuitPoseidon>,
    params: &'dr C::Params,
}

impl<'dr, C: Cycle> CycleTranscript<'dr, C> {
    /// Creates a transcript over the cycle's circuit-field Poseidon,
    /// domain-separated by `tag`.
    pub fn new(params: &'dr C::Params, tag: &[u8]) -> Result<Self> {
        let mut dr = Emulator::execute();
        let transcript = Transcript::new(&mut dr, C::circuit_poseidon(params), tag)?;
        Ok(CycleTranscript {
            dr,
            transcript,
            params,
        })
    }

    /// The transcript as the host-curve IPA sees it.
    pub fn host(&mut self) -> HostSide<'_, 'dr, C> {
        HostSide(self)
    }

    /// The transcript as the nested-curve IPA sees it.
    pub fn nested(&mut self) -> NestedSide<'_, 'dr, C> {
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
    fn bridge(&mut self, values: &[C::ScalarField]) -> Result<()> {
        let g = C::nested_generators(self.params).g();
        let commitment: C::NestedCurve = msm(values, &g[..values.len()]).to_affine();
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
pub struct HostSide<'a, 'dr, C: Cycle>(&'a mut CycleTranscript<'dr, C>);

impl<C: Cycle> IpaTranscript<C::HostCurve> for HostSide<'_, '_, C> {
    fn write_point(&mut self, point: C::HostCurve) -> Result<()> {
        let Some(coordinates) = point.coordinates().into_option() else {
            return Err(ragu_core::Error::InvalidWitness(
                "point at infinity cannot be written to the transcript".into(),
            ));
        };
        self.0.bridge(&[*coordinates.x(), *coordinates.y()])
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
/// is in the scalar field, so it is bridged; and a challenge is the lift of
/// the squeeze, as the fuse's nested challenges are.
pub struct NestedSide<'a, 'dr, C: Cycle>(&'a mut CycleTranscript<'dr, C>);

impl<C: Cycle> IpaTranscript<C::NestedCurve> for NestedSide<'_, '_, C> {
    fn write_point(&mut self, point: C::NestedCurve) -> Result<()> {
        self.0.absorb(point)
    }

    fn write_scalar(&mut self, scalar: C::ScalarField) -> Result<()> {
        self.0.bridge(&[scalar])
    }

    fn squeeze_challenge(&mut self) -> Result<C::ScalarField> {
        nested::challenge::<C>(self.0.squeeze()?)
    }
}
