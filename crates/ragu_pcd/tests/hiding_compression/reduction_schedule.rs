//! The existing revdot prover runs on a message schedule over fresh hiding
//! commitments. The verifier replays that schedule and computes the batch's
//! input ciphertexts from the public weights without decrypting them.

use alloc::vec::Vec;
use core::array;

use ragu_core::Result;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::{
    Bases, HiddenPoint, POLYS, Sampled, Transcript, batch_proof::Opening, committed_instance::Side,
};
use crate::{
    compress::revdot::{
        claims::Shape,
        fold::{self, Weights},
    },
    ipa::IpaTranscript,
};

#[derive(Clone, Copy)]
enum Step {
    Challenge(&'static [u8]),
    Point(usize),
    Scalar(usize),
}

use Step::{Challenge as Draw, Point, Scalar};

const SCHEDULE: &[Step] = &[
    Draw(b"registry w"),
    Draw(b"target y"),
    Draw(b"revdot z"),
    Draw(b"wire sigma"),
    Point(0),
    Draw(b"inner mu"),
    Draw(b"inner nu"),
    Point(1),
    Draw(b"outer mu"),
    Draw(b"outer nu"),
    Scalar(0),
    Scalar(1),
    Draw(b"split rho"),
    Point(2),
    Point(3),
    Draw(b"split r"),
    Scalar(2),
    Scalar(3),
    Scalar(4),
    Scalar(5),
    Scalar(6),
    Scalar(7),
    Scalar(8),
];

#[derive(Clone)]
pub(super) struct Messages<C: Affine> {
    pub(super) points: [HiddenPoint<C>; 4],
    pub(super) scalars: [C; 9],
}

pub(super) struct Challenges<F> {
    pub(super) sampled: Sampled<F>,
    pub(super) weights: Weights<F>,
    pub(super) rho: F,
    pub(super) r: F,
}

impl<C: Affine> Messages<C> {
    pub(super) fn replay(&self, mut transcript: Transcript) -> (Challenges<C::Scalar>, Transcript) {
        let mut values = [C::Scalar::ZERO; 10];
        let mut draws = values.iter_mut();
        for &step in SCHEDULE {
            match step {
                Draw(label) => *draws.next().unwrap() = transcript.challenge(label),
                Point(index) => self.points[index].absorb(&mut transcript),
                Scalar(index) => transcript.point(self.scalars[index]),
            }
        }
        let [w, y, z, sigma, mu, nu, mu_prime, nu_prime, rho, r] = values;
        (
            Challenges {
                sampled: Sampled { w, y, z, sigma },
                weights: Weights {
                    mu,
                    nu,
                    mu_prime,
                    nu_prime,
                },
                rho,
                r,
            },
            transcript,
        )
    }
}

/// Feeds the same schedule to the native verifier during witness generation.
pub(super) struct DiagnosticReplay<'a, C: Affine> {
    pub(super) transcript: Transcript,
    pub(super) messages: &'a Messages<C>,
    pub(super) at: usize,
}

impl<C: Affine> IpaTranscript<C> for DiagnosticReplay<'_, C> {
    fn write_point(&mut self, _: C) -> Result<()> {
        let Point(i) = SCHEDULE[self.at] else {
            unreachable!()
        };
        self.at += 1;
        self.messages.points[i].absorb(&mut self.transcript);
        Ok(())
    }

    fn write_scalar(&mut self, _: C::Scalar) -> Result<()> {
        let Scalar(i) = SCHEDULE[self.at] else {
            unreachable!()
        };
        self.at += 1;
        self.transcript.point(self.messages.scalars[i]);
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        let Draw(label) = SCHEDULE[self.at] else {
            unreachable!()
        };
        self.at += 1;
        Ok(self.transcript.challenge(label))
    }
}

pub(super) struct Witness<F> {
    pub(super) blinders: [F; 4],
    pub(super) scalars: [Opening<F>; 9],
}

pub(super) struct Prover<'a, C: Affine, R> {
    bases: Bases<C>,
    transcript: Transcript,
    rng: &'a mut R,
    at: usize,
    points: Vec<HiddenPoint<C>>,
    scalars: Vec<C>,
    blinders: Vec<C::Scalar>,
    openings: Vec<Opening<C::Scalar>>,
}

impl<'a, C: Affine, R: CryptoRng> Prover<'a, C, R> {
    pub(super) fn new(bases: Bases<C>, transcript: Transcript, rng: &'a mut R) -> Self {
        Self {
            bases,
            transcript,
            rng,
            at: 0,
            points: Vec::new(),
            scalars: Vec::new(),
            blinders: Vec::new(),
            openings: Vec::new(),
        }
    }

    fn take_step(&mut self) -> Step {
        let step = SCHEDULE[self.at];
        self.at += 1;
        step
    }

    pub(super) fn finish(self) -> (Messages<C>, Witness<C::Scalar>, Transcript) {
        assert_eq!(self.at, SCHEDULE.len());
        (
            Messages {
                points: self.points.try_into().ok().unwrap(),
                scalars: self.scalars.try_into().ok().unwrap(),
            },
            Witness {
                blinders: self.blinders.try_into().ok().unwrap(),
                scalars: self.openings.try_into().ok().unwrap(),
            },
            self.transcript,
        )
    }
}

impl<C: Affine, R: CryptoRng> IpaTranscript<C> for Prover<'_, C, R> {
    fn write_point(&mut self, point: C) -> Result<()> {
        assert!(matches!(self.take_step(), Point(i) if i == self.points.len()));
        let blind = super::random(self.rng);
        let point = self.bases.hide_point(point, blind);
        point.absorb(&mut self.transcript);
        self.points.push(point);
        self.blinders.push(blind);
        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<()> {
        assert!(matches!(self.take_step(), Scalar(i) if i == self.scalars.len()));
        let opening = Opening::fresh(scalar, self.rng);
        let commitment = self.bases.commit(opening.value, opening.blind);
        self.transcript.point(commitment);
        self.scalars.push(commitment);
        self.openings.push(opening);
        Ok(())
    }

    fn squeeze_challenge(&mut self) -> Result<C::Scalar> {
        let Draw(label) = self.take_step() else {
            unreachable!("unexpected revdot squeeze")
        };
        Ok(self.transcript.challenge(label))
    }
}

/// The first three inputs come from the regular fold's component weights.
/// The next four are the two errors and split commitments. The last four
/// are the registry restriction, accumulator and A/B of the focused instance.
pub(super) fn inputs<C: Affine, Id: Copy>(
    instance: &Side<C>,
    reduction: &Messages<C>,
    shapes: &[Shape<Id, C::Scalar>],
    weights: &Weights<C::Scalar>,
    position: impl Fn(Id) -> usize,
    remaining: [usize; 4],
) -> [HiddenPoint<C>; POLYS] {
    let derived = fold::component_terms(shapes, weights).map(|terms| {
        let (scalars, points): (Vec<_>, Vec<_>) = terms
            .into_iter()
            .map(|(weight, id)| (weight, instance.points[position(id)]))
            .unzip();
        let first: Vec<_> = points.iter().map(|ciphertext| ciphertext.first).collect();
        let second: Vec<_> = points.iter().map(|ciphertext| ciphertext.second).collect();
        HiddenPoint {
            first: C::msm(&scalars, &first).into(),
            second: C::msm(&scalars, &second).into(),
        }
    });
    array::from_fn(|i| match i {
        0..3 => derived[i],
        3..7 => reduction.points[i - 3],
        _ => instance.points[remaining[i - 7]],
    })
}

pub(super) fn input_blinders<F: Field, Id: Copy>(
    instance: &[F],
    reduction: &Witness<F>,
    shapes: &[Shape<Id, F>],
    weights: &Weights<F>,
    position: impl Fn(Id) -> usize,
    remaining: [usize; 4],
) -> [F; POLYS] {
    let derived = fold::component_terms(shapes, weights).map(|terms| {
        terms.into_iter().fold(F::ZERO, |total, (weight, id)| {
            total + weight * instance[position(id)]
        })
    });
    array::from_fn(|i| match i {
        0..3 => derived[i],
        3..7 => reduction.blinders[i - 3],
        _ => instance[remaining[i - 7]],
    })
}
