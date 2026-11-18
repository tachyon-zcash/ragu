//! Proves the original Fuse bridge transcript with Ragu's Point, Poseidon,
//! and endoscalar gadgets. The bridge coordinate commitments are fixed in
//! both curves' pre-alpha context. The Fp Fuse u is the very same committed
//! scalar used for the native accumulator, a, and b opening claims.

use alloc::{vec, vec::Vec};
use core::array;

use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    maybe::{Always, Empty, Maybe},
};
use ragu_primitives::{Element, EndoscalarChallenge, GadgetExt, Point};
use rand::CryptoRng;
use udon::curve::Affine;

use super::{
    App, Bases, Fp, HEADER_SIZE, HiddenPoint, Host, Instance, Nested, Pasta, RAGU_TAG, Transcript,
    batch_proof::Opening,
    circuit_proof::{CircuitProof, Recorder},
    committed_instance::{InstanceCommitments, Witness},
    context, nested, point_binding,
};
use crate::{
    compress::revdot::nested_position, internal::transcript::Transcript as RaguTranscript,
    ipa::IpaCycle, profile::Standard,
};

const POINTS: usize = 8;
const COORDS: usize = 2 * POINTS;
const CHALLENGES: usize = 9;
const FUSE_U: usize = 7;

fn bridge_indices() -> [nested::RxIndex; POINTS] {
    use nested::RxIndex::*;
    [
        BridgePreamble,
        BridgeSPrime,
        BridgeInnerError,
        BridgeOuterError,
        BridgeAB,
        BridgeQuery,
        BridgeF,
        BridgeEval,
    ]
}

fn bridge_slots() -> [usize; POINTS] {
    bridge_indices().map(|index| nested_position::<Standard>(nested::RxComponent::Rx(index)))
}

type Scalar = <Nested as Affine>::Scalar;

fn bridge_ciphertexts(instance: &InstanceCommitments) -> [HiddenPoint<Nested>; POINTS] {
    bridge_slots().map(|slot| instance.nested.points[slot])
}

fn synthesize<'dr, M: ragu_core::maybe::MaybeKind>(
    dr: &mut Recorder<Fp, M>,
    params: &'dr <Pasta as Cycle>::Params,
    bridges: DriverValue<Recorder<Fp, M>, [(Nested, Scalar); POINTS]>,
    ciphertexts: [HiddenPoint<Nested>; POINTS],
) -> Result<Vec<Element<'dr, Recorder<Fp, M>>>> {
    let mut transcript = RaguTranscript::new(dr, Pasta::circuit_poseidon(params), RAGU_TAG)?;
    let mut challenges = Vec::with_capacity(CHALLENGES);
    let bases = Bases::new(Pasta::nested_generators(params), *Pasta::nested_u(params));
    for (i, ciphertext) in ciphertexts.into_iter().enumerate() {
        let point = Point::alloc(dr, bridges.as_ref().map(|points| points[i].0))?;
        let blind = bridges.as_ref().map(|points| points[i].1);
        point_binding::enforce_opening(dr, &point, blind, ciphertext, bases)?;
        let mut coords = vec![];
        point.write(dr, &mut coords)?;
        assert_eq!(coords.len(), 2);
        for coord in &coords {
            dr.bind(coord.wire())?;
        }

        point.write(dr, &mut transcript)?;
        challenges.push(transcript.challenge(dr)?);
        if i == 1 {
            challenges.push(transcript.challenge(dr)?);
        }
    }

    EndoscalarChallenge::from_element(dr, &mut (), challenges[CHALLENGES - 1].clone())?;
    dr.bind(challenges[FUSE_U].wire())?;
    Ok(challenges)
}

#[derive(Clone)]
pub(super) struct FusePrefix {
    pub(super) bridges: [Host; COORDS],
    pub(super) native_u: Host,
    proof: CircuitProof<Host>,
}

impl FusePrefix {
    pub(super) fn prove(
        app: &App,
        header: &[Fp; HEADER_SIZE],
        instance: &Instance<Pasta>,
        committed: &InstanceCommitments,
        witness: &Witness<Scalar>,
        expected: [Fp; CHALLENGES],
        bases: Bases<Host>,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self, Opening<Fp>)> {
        let bridges = bridge_indices()
            .map(|index| instance.nested_commitment(nested::RxComponent::Rx(index)));
        let blinders = bridge_slots().map(|slot| witness.point_blinds[slot]);
        let coordinates = bridges.map(|point| point.coordinates().unwrap());
        let bound: [Opening<Fp>; COORDS + 1] = array::from_fn(|i| {
            let value = if i == COORDS {
                expected[FUSE_U]
            } else {
                let (x, y) = coordinates[i / 2];
                if i % 2 == 0 { x } else { y }
            };
            Opening::fresh(value, rng)
        });

        let mut recorder = Recorder::<Fp, Always<()>>::new();
        let values = synthesize(
            &mut recorder,
            app.params,
            Recorder::<Fp, Always<()>>::just(|| array::from_fn(|i| (bridges[i], blinders[i]))),
            bridge_ciphertexts(committed),
        )?;
        assert_eq!(
            values
                .iter()
                .map(|element| *element.value().take())
                .collect::<Vec<_>>(),
            expected,
        );

        let prefix = Self {
            bridges: array::from_fn(|i| bases.commit(bound[i].value, bound[i].blind)),
            native_u: bases.commit(bound[COORDS].value, bound[COORDS].blind),
            proof: recorder.prove(
                bases,
                circuit_transcript(app, header, committed),
                &bound,
                rng,
            ),
        };
        Ok((prefix, bound[COORDS]))
    }

    pub(super) fn verify(
        &self,
        app: &App,
        header: &[Fp; HEADER_SIZE],
        committed: &InstanceCommitments,
        bases: Bases<Host>,
    ) -> bool {
        if !committed.has_expected_shape() {
            return false;
        }
        let mut shape = Recorder::<Fp, Empty>::new();
        if synthesize(&mut shape, app.params, Empty, bridge_ciphertexts(committed)).is_err() {
            return false;
        }
        let bound: [Host; COORDS + 1] = array::from_fn(|i| {
            if i < COORDS {
                self.bridges[i]
            } else {
                self.native_u
            }
        });
        self.proof.verify(
            &shape,
            bases,
            circuit_transcript(app, header, committed),
            &bound,
        )
    }

    pub(super) fn bind(&self, transcript: &mut Transcript) {
        for &point in &self.bridges {
            transcript.point(point);
        }
        transcript.point(self.native_u);
    }

    pub(super) fn proof_elements(&self) -> usize {
        self.proof.elements()
    }
}

fn circuit_transcript(
    app: &App,
    header: &[Fp; HEADER_SIZE],
    committed: &InstanceCommitments,
) -> Transcript {
    let mut transcript = context(app, header);
    transcript.bytes(b"private Fuse bridge transcript");
    committed.absorb(&mut transcript);
    transcript
}
