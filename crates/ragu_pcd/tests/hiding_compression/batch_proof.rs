//! Fiat-Shamir proofs of knowledge of representations for the terminal batch.
//! Each multiplication uses Pedersen commitments A, B, C to a, b, c.
//! Prove A = aG + sH and C = aB + dH with the same a. Binding then
//! gives c = ab. One challenge binds all gates and the mask relation.

use alloc::vec::Vec;
use core::array;

use rand::CryptoRng;
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use super::{Bases, CLAIMS, HiddenPoint, POLYS, Transcript, random};

#[derive(Clone, Copy)]
pub(super) struct BatchPublic<C: Affine> {
    pub prefix: C,
    pub inputs: [HiddenPoint<C>; POLYS],
    pub split: [C; super::split_proof::AUX],
    pub queries: [(C, C); CLAIMS],
    pub quotient: HiddenPoint<C>,
    pub evaluations: [C; POLYS],
}

impl<C: Affine> BatchPublic<C> {
    pub(super) fn absorb_prefix(
        transcript: &mut Transcript,
        prefix: C,
        inputs: &[HiddenPoint<C>; POLYS],
        split: &[C; super::split_proof::AUX],
        queries: &[(C, C); CLAIMS],
    ) {
        transcript.point(prefix);
        for input in inputs {
            input.absorb(transcript);
        }
        absorb_points(transcript, split);
        for &(point, value) in queries {
            transcript.point(point);
            transcript.point(value);
        }
    }

    pub(super) fn replay(
        &self,
        mut transcript: Transcript,
    ) -> (C::Scalar, C::Scalar, C::Scalar, Transcript) {
        Self::absorb_prefix(
            &mut transcript,
            self.prefix,
            &self.inputs,
            &self.split,
            &self.queries,
        );
        let alpha = transcript.challenge(b"alpha");
        self.quotient.absorb(&mut transcript);
        let u = transcript.challenge(b"u");
        for &evaluation in &self.evaluations {
            transcript.point(evaluation);
        }
        let beta = transcript.challenge(b"beta");
        (alpha, u, beta, transcript)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Opening<F> {
    pub value: F,
    pub blind: F,
}

impl<F: Field> Opening<F> {
    pub fn fresh(value: F, rng: &mut impl CryptoRng) -> Self {
        Self {
            value,
            blind: random(rng),
        }
    }

    fn horner(self, weight: F, next: Self) -> Self {
        Self {
            value: self.value * weight + next.value,
            blind: self.blind * weight + next.blind,
        }
    }
}

#[derive(Clone)]
struct Sigma<C: Affine, const N: usize, const M: usize> {
    announcements: [C; M],
    responses: [C::Scalar; N],
}

struct Pending<C: Affine, const N: usize, const M: usize> {
    announcements: [C; M],
    nonce: [C::Scalar; N],
    witness: [C::Scalar; N],
}

type Equations<C, const N: usize, const M: usize> = [[C; N]; M];

fn linear<C: Affine, const N: usize>(bases: &[C; N], scalars: &[C::Scalar; N]) -> C::Projective {
    bases
        .iter()
        .zip(scalars)
        .fold(C::Projective::identity(), |acc, (&base, &scalar)| {
            acc + base * scalar
        })
}

impl<C: Affine, const N: usize, const M: usize> Pending<C, N, M> {
    fn start(
        bases: &Equations<C, N, M>,
        witness: [C::Scalar; N],
        rng: &mut impl CryptoRng,
    ) -> Self {
        let nonce = array::from_fn(|_| random(rng));
        let announcements = bases.each_ref().map(|row| linear(row, &nonce).to_affine());
        Self {
            announcements,
            nonce,
            witness,
        }
    }

    fn finish(self, challenge: C::Scalar) -> Sigma<C, N, M> {
        Sigma {
            announcements: self.announcements,
            responses: array::from_fn(|i| self.nonce[i] + challenge * self.witness[i]),
        }
    }
}

impl<C: Affine, const N: usize, const M: usize> Sigma<C, N, M> {
    fn verifies(&self, bases: &Equations<C, N, M>, targets: [C; M], challenge: C::Scalar) -> bool {
        bases
            .iter()
            .zip(targets)
            .zip(self.announcements)
            .all(|((row, target), announcement)| {
                linear(row, &self.responses) == announcement.to_projective() + target * challenge
            })
    }
}

#[derive(Clone)]
struct Division<C: Affine> {
    inverse: C,
    term: C,
    inverse_check: Sigma<C, 3, 2>,
    term_check: Sigma<C, 3, 2>,
}

#[derive(Clone)]
pub(super) struct BatchProof<C: Affine> {
    divisions: Vec<Division<C>>,
    mask: Sigma<C, 4, 3>,
}

/// The unblinded claim points/values and evaluations. Commitment openings for
/// the points of the polynomial commitments need only their blinders here.
pub(super) struct BatchWitness<F> {
    pub input_blinds: [F; POLYS],
    pub quotient_blind: F,
    pub queries: [(Opening<F>, Opening<F>); CLAIMS],
    pub evaluations: [Opening<F>; POLYS],
    pub mask: F,
}

#[derive(Clone, Copy)]
pub(super) struct BatchRelation<'a, C: Affine> {
    pub bases: Bases<C>,
    pub alpha: C::Scalar,
    pub u: C::Scalar,
    pub beta: C::Scalar,
    pub public: &'a BatchPublic<C>,
    pub d: C,
}

fn absorb_points<C: Affine>(transcript: &mut Transcript, points: &[C]) {
    for &point in points {
        transcript.point(point);
    }
}

impl<C: Affine> BatchRelation<'_, C> {
    fn product_bases(&self, b: C) -> Equations<C, 3, 2> {
        [
            [self.bases.g0, self.bases.h, C::identity()],
            [b, C::identity(), self.bases.h],
        ]
    }

    fn mask_bases(&self) -> Equations<C, 4, 3> {
        let Bases { g0, g1, h, j } = self.bases;
        let zero = C::identity();
        let mask = (g0 * self.u + (-g1).to_projective()).to_affine();
        // Witness order is the point blinder, v, its blinder, and r.
        [
            [j, zero, zero, zero],
            [zero, g0, h, zero],
            [h, g0, zero, mask],
        ]
    }

    fn mask_targets(&self, divisions: &[Division<C>]) -> [C; 3] {
        let mut v = C::Projective::identity();
        for division in divisions {
            v = v.to_affine() * self.alpha + division.term.to_projective();
        }

        let mut c = self.public.quotient;
        for (i, &input) in self.public.inputs.iter().enumerate() {
            c = c.horner(self.beta, input);
            v = v.to_affine() * self.beta + self.public.evaluations[i].to_projective();
        }
        [
            c.first,
            v.to_affine(),
            (c.second.to_projective() + (-self.d).to_projective()).to_affine(),
        ]
    }

    pub(super) fn prove(
        &self,
        transcript: &mut Transcript,
        witness: &BatchWitness<C::Scalar>,
        rng: &mut impl CryptoRng,
    ) -> Option<BatchProof<C>> {
        let mut divisions = Vec::with_capacity(CLAIMS);
        let mut v = Opening {
            value: C::Scalar::ZERO,
            blind: C::Scalar::ZERO,
        };
        for (&poly, &(point, value)) in super::QUERY_POLYS.iter().zip(&witness.queries) {
            let evaluation = witness.evaluations[poly];
            let difference = self.u - point.value;
            let inverse = Opening::fresh(difference.invert()?, rng);
            let term = Opening::fresh((evaluation.value - value.value) * inverse.value, rng);
            let inverse_commitment = self.bases.commit(inverse.value, inverse.blind);
            let term_commitment = self.bases.commit(term.value, term.blind);
            let inverse_check = Pending::start(
                &self.product_bases(inverse_commitment),
                [difference, -point.blind, -difference * inverse.blind],
                rng,
            );
            let term_check = Pending::start(
                &self.product_bases(term_commitment),
                [
                    difference,
                    -point.blind,
                    evaluation.blind - value.blind - difference * term.blind,
                ],
                rng,
            );
            v = v.horner(self.alpha, term);
            absorb_points(transcript, &[inverse_commitment, term_commitment]);
            absorb_points(transcript, &inverse_check.announcements);
            absorb_points(transcript, &term_check.announcements);
            divisions.push((
                inverse_commitment,
                term_commitment,
                inverse_check,
                term_check,
            ));
        }
        let mut c_blind = witness.quotient_blind;
        for (blind, evaluation) in witness.input_blinds.into_iter().zip(witness.evaluations) {
            v = v.horner(self.beta, evaluation);
            c_blind = c_blind * self.beta + blind;
        }
        let mask = Pending::start(
            &self.mask_bases(),
            [c_blind, v.value, v.blind, witness.mask],
            rng,
        );
        absorb_points(transcript, &mask.announcements);

        let challenge = transcript.challenge(b"batch-proof-challenge");
        Some(BatchProof {
            divisions: divisions
                .into_iter()
                .map(|(inverse, term, inverse_check, term_check)| Division {
                    inverse,
                    term,
                    inverse_check: inverse_check.finish(challenge),
                    term_check: term_check.finish(challenge),
                })
                .collect(),
            mask: mask.finish(challenge),
        })
    }

    pub(super) fn verify(&self, transcript: &mut Transcript, proof: &BatchProof<C>) -> bool {
        if proof.divisions.len() != CLAIMS {
            return false;
        }
        for division in &proof.divisions {
            absorb_points(transcript, &[division.inverse, division.term]);
            absorb_points(transcript, &division.inverse_check.announcements);
            absorb_points(transcript, &division.term_check.announcements);
        }
        absorb_points(transcript, &proof.mask.announcements);
        let challenge = transcript.challenge(b"batch-proof-challenge");

        let g = self.bases.g0;
        for (i, division) in proof.divisions.iter().enumerate() {
            let (point, value) = self.public.queries[i];
            let difference = (g * self.u + (-point).to_projective()).to_affine();
            let evaluation = self.public.evaluations[super::QUERY_POLYS[i]];
            let numerator = (evaluation.to_projective() + (-value).to_projective()).to_affine();
            if !division.inverse_check.verifies(
                &self.product_bases(division.inverse),
                [difference, g],
                challenge,
            ) || !division.term_check.verifies(
                &self.product_bases(division.term),
                [difference, numerator],
                challenge,
            ) {
                return false;
            }
        }
        proof.mask.verifies(
            &self.mask_bases(),
            self.mask_targets(&proof.divisions),
            challenge,
        )
    }
}

// Packed canonical group/field elements, with fixed counts and no framing.
pub(super) fn proof_elements() -> usize {
    // Per division: inverse and term commitments, plus two Sigma proofs with
    // two announcements and three responses each. Mask: three + four.
    CLAIMS * (2 + 2 * (2 + 3)) + 3 + 4
}
