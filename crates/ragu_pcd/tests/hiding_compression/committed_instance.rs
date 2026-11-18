//! The two reductions share one committed instance. Each point has exactly
//! one ElGamal ciphertext, so the public fold can combine commitments by
//! the same coefficients as the unblinded fold.

use alloc::vec::Vec;

use ragu_core::{Cycle, Result};
use rand::CryptoRng;
use udon::curve::Affine;

use super::{Bases, HiddenPoint, Host, Instance, Nested, Pasta, Transcript, batch_proof::Opening};
use crate::{
    compress::revdot::{native_components, nested_components},
    internal::native::online::{NUM_ONLINE_FP_POLYS, NUM_ONLINE_FP_QUERIES},
    ipa::{IpaCycle, IpaTranscript},
    profile::Standard,
};

#[derive(Clone)]
pub(super) struct Side<C: Affine> {
    pub(super) points: Vec<HiddenPoint<C>>,
    pub(super) scalars: Vec<C>,
}

pub(super) struct Witness<F> {
    pub(super) point_blinds: Vec<F>,
    pub(super) scalars: Vec<Opening<F>>,
}

#[derive(Clone)]
pub(super) struct InstanceCommitments {
    pub(super) host: Side<Host>,
    pub(super) nested: Side<Nested>,
}

struct Commit<'a, C: Affine, R> {
    bases: Bases<C>,
    public: Side<C>,
    witness: Witness<C::Scalar>,
    rng: &'a mut R,
}

impl<'a, C: Affine, R> Commit<'a, C, R> {
    fn new(bases: Bases<C>, rng: &'a mut R) -> Self {
        Self {
            bases,
            public: Side {
                points: Vec::new(),
                scalars: Vec::new(),
            },
            witness: Witness {
                point_blinds: Vec::new(),
                scalars: Vec::new(),
            },
            rng,
        }
    }
}

impl<C: Affine, R: CryptoRng> IpaTranscript<C> for Commit<'_, C, R> {
    fn write_point(&mut self, point: C) -> Result<()> {
        let blind = super::random(self.rng);
        self.public.points.push(self.bases.hide_point(point, blind));
        self.witness.point_blinds.push(blind);
        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()> {
        let opening = Opening::fresh(scalar, self.rng);
        self.public
            .scalars
            .push(self.bases.commit(opening.value, opening.blind));
        self.witness.scalars.push(opening);
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        unreachable!("the instance walk only writes fields")
    }
}

impl InstanceCommitments {
    pub(super) fn commit(
        instance: &Instance<Pasta>,
        params: &<Pasta as Cycle>::Params,
        rng: &mut impl CryptoRng,
    ) -> Result<(
        Self,
        Witness<<Host as Affine>::Scalar>,
        Witness<<Nested as Affine>::Scalar>,
    )> {
        let mut host = Commit::new(
            Bases::new(Pasta::host_generators(params), *Pasta::host_u(params)),
            rng,
        );
        instance.absorb_native(&mut host)?;
        let Commit {
            public: host,
            witness: host_witness,
            ..
        } = host;
        let mut nested = Commit::new(
            Bases::new(Pasta::nested_generators(params), *Pasta::nested_u(params)),
            rng,
        );
        instance.absorb_nested(&mut nested)?;
        let Commit {
            public: nested,
            witness: nested_witness,
            ..
        } = nested;
        Ok((Self { host, nested }, host_witness, nested_witness))
    }

    pub(super) fn has_expected_shape(&self) -> bool {
        self.host.points.len() == native_components::<Standard>().count() + 2 + NUM_ONLINE_FP_POLYS
            && self.nested.points.len() == nested_components::<Standard>().count() + 3
            && self.host.scalars.len()
                == 1 + 2 * super::HEADER_SIZE + 2 * NUM_ONLINE_FP_QUERIES + 10
            && self.nested.scalars.len() == 9
    }

    pub(super) fn absorb(&self, transcript: &mut Transcript) {
        transcript.bytes(b"joint committed instance");
        self.host.absorb(transcript);
        self.nested.absorb(transcript);
    }
}

impl<C: Affine> Side<C> {
    fn absorb(&self, transcript: &mut Transcript) {
        transcript.bytes(&(self.points.len() as u64).to_le_bytes());
        for &ciphertext in &self.points {
            ciphertext.absorb(transcript);
        }
        transcript.bytes(&(self.scalars.len() as u64).to_le_bytes());
        for &commitment in &self.scalars {
            transcript.point(commitment);
        }
    }
}
