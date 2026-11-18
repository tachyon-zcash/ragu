//! Experimental proof of a Ragu driver's two multiplication relations and
//! linear constraints. Each wire is Pedersen committed on its scalar curve.
//! The verifier synthesizes the fixed wiring with an empty witness.
//!
//! For committed values A, B, C with blinders a, b, c, the multiplication
//! equation proves that C's commitment is the commitment to B scaled by A,
//! plus a blinding term of c - A*b. The same response for A appears in this
//! equation and the opening proof of A's commitment. The linear checks use
//! an independently weighted sum of rows and prove that the corresponding
//! sum of commitments is a multiple of the blinding generator.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverTypes, LinearExpression},
    maybe::{Always, MaybeKind},
};
use rand::CryptoRng;
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use super::{Bases, Transcript, batch_proof::Opening, random};

#[derive(Clone)]
pub(super) enum Wire<F> {
    Atom(usize),
    Sum(BTreeMap<usize, F>),
}

pub(super) struct Linear<F> {
    terms: BTreeMap<usize, F>,
    gain: F,
}

impl<F: Field> Default for Linear<F> {
    fn default() -> Self {
        Self {
            terms: BTreeMap::new(),
            gain: F::ONE,
        }
    }
}

impl<F: Field> LinearExpression<Wire<F>, F> for Linear<F> {
    fn add_term(mut self, wire: &Wire<F>, coeff: Coeff<F>) -> Self {
        let coeff = self.gain * coeff.value();
        match wire {
            Wire::Atom(i) => *self.terms.entry(*i).or_insert(F::ZERO) += coeff,
            Wire::Sum(terms) => {
                for (&i, &value) in terms {
                    *self.terms.entry(i).or_insert(F::ZERO) += coeff * value;
                }
            }
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain *= coeff.value();
        self
    }
}

pub(super) struct Recorder<F, M> {
    size: usize,
    values: Vec<F>,
    gates: Vec<[usize; 3]>,
    constraints: Vec<BTreeMap<usize, F>>,
    bound: Vec<usize>,
    marker: PhantomData<M>,
}

impl<F: Field, M: MaybeKind> Recorder<F, M> {
    pub fn new() -> Self {
        let mut values = Vec::new();
        M::maybe_just(|| values.extend([F::ONE, F::ZERO]));
        Self {
            size: 2,
            values,
            gates: Vec::new(),
            constraints: Vec::new(),
            bound: Vec::new(),
            marker: PhantomData,
        }
    }

    /// Ties this circuit expression to a separately committed scalar.
    /// The verifier places the public commitment at the allocated wire.
    pub fn bind(&mut self, source: &Wire<F>) -> Result<()> {
        let i = self.size;
        self.size += 1;
        M::maybe_just(|| {
            let value = match source {
                Wire::Atom(i) => self.values[*i],
                Wire::Sum(terms) => terms.iter().fold(F::ZERO, |value, (&i, &coeff)| {
                    value + self.values[i] * coeff
                }),
            };
            self.values.push(value);
        });
        self.enforce_equal(source, &Wire::Atom(i))?;
        self.bound.push(i);
        Ok(())
    }
}

impl<F: Field, M: MaybeKind> DriverTypes for Recorder<F, M> {
    type ImplField = F;
    type ImplWire = Wire<F>;
    type MaybeKind = M;
    type LCadd = Linear<F>;
    type LCenforce = Linear<F>;
    type Extra = usize;

    fn gate(
        &mut self,
        values: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Wire<F>, Wire<F>, Wire<F>, usize)> {
        let [a, b, c] = [self.size, self.size + 1, self.size + 2];
        self.size += 3;
        M::maybe_try_just(|| {
            let (a, b, c) = values()?;
            self.values.extend([a.value(), b.value(), c.value()]);
            Ok::<(), ragu_core::Error>(())
        })?;
        self.gates.push([a, b, c]);
        Ok((Wire::Atom(a), Wire::Atom(b), Wire::Atom(c), c))
    }

    fn assign_extra(&mut self, c: usize, value: impl Fn() -> Result<Coeff<F>>) -> Result<Wire<F>> {
        let d = self.size;
        self.size += 1;
        M::maybe_try_just(|| {
            self.values.push(value()?.value());
            Ok::<(), ragu_core::Error>(())
        })?;
        self.gates.push([c, d, 1]);
        Ok(Wire::Atom(d))
    }
}

impl<'dr, F: Field, M: MaybeKind> Driver<'dr> for Recorder<F, M> {
    type F = F;
    type Wire = Wire<F>;
    const ONE: Wire<F> = Wire::Atom(0);

    fn add(&mut self, lc: impl Fn(Linear<F>) -> Linear<F>) -> Wire<F> {
        Wire::Sum(lc(Linear::default()).terms)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Linear<F>) -> Linear<F>) -> Result<()> {
        self.constraints.push(lc(Linear::default()).terms);
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct CircuitProof<C: Affine> {
    commitments: Vec<C>,
    wire_announcements: Vec<C>,
    gate_announcements: Vec<C>,
    linear_announcement: C,
    wire_responses: Vec<[C::Scalar; 2]>,
    gate_responses: Vec<C::Scalar>,
    linear_response: C::Scalar,
}

fn absorb<C: Affine>(transcript: &mut Transcript, points: &[C]) {
    for &point in points {
        transcript.point(point);
    }
}

impl<F: Field, M> Recorder<F, M> {
    fn linear_weights(&self, alpha: F) -> Vec<F> {
        let mut weights = vec![F::ZERO; self.size];
        let mut power = F::ONE;
        for linear in &self.constraints {
            for (&i, &value) in linear {
                weights[i] += power * value;
            }
            power *= alpha;
        }
        weights
    }
}

impl<F: Field> Recorder<F, Always<()>> {
    pub(super) fn prove<C: Affine<Scalar = F>>(
        &self,
        bases: Bases<C>,
        mut transcript: Transcript,
        bound: &[Opening<F>],
        rng: &mut impl CryptoRng,
    ) -> CircuitProof<C> {
        assert_eq!(self.bound.len(), bound.len());
        let mut blinds = self.values.iter().map(|_| random(rng)).collect::<Vec<F>>();
        blinds[0] = F::ZERO;
        blinds[1] = F::ZERO;
        for (&i, bound) in self.bound.iter().zip(bound) {
            blinds[i] = bound.blind;
        }
        let commitments = self
            .values
            .iter()
            .zip(&blinds)
            .map(|(&value, &blind)| bases.commit(value, blind))
            .collect::<Vec<_>>();
        absorb(&mut transcript, &commitments);
        let linear_weights = self.linear_weights(transcript.challenge(b"linear weights"));

        let wire_nonces = (0..self.size)
            .map(|_| [random(rng), random(rng)])
            .collect::<Vec<[F; 2]>>();
        let wire_announcements = wire_nonces
            .iter()
            .map(|&[a, b]| bases.commit(a, b))
            .collect::<Vec<_>>();
        let gate_nonces = self.gates.iter().map(|_| random(rng)).collect::<Vec<F>>();
        let gate_announcements = self
            .gates
            .iter()
            .zip(&gate_nonces)
            .map(|(&[a, b, _], &nonce)| {
                (commitments[b] * wire_nonces[a][0] + bases.h * nonce).to_affine()
            })
            .collect::<Vec<_>>();
        let linear_nonce: F = random(rng);
        let linear_announcement = (bases.h * linear_nonce).to_affine();
        absorb(&mut transcript, &wire_announcements);
        absorb(&mut transcript, &gate_announcements);
        transcript.point(linear_announcement);
        let challenge: F = transcript.challenge(b"circuit proof challenge");

        let wire_responses = (0..self.size)
            .map(|i| {
                [
                    wire_nonces[i][0] + challenge * self.values[i],
                    wire_nonces[i][1] + challenge * blinds[i],
                ]
            })
            .collect();
        let gate_responses = self
            .gates
            .iter()
            .zip(&gate_nonces)
            .map(|(&[a, b, c], &nonce)| {
                nonce + challenge * (blinds[c] - self.values[a] * blinds[b])
            })
            .collect();
        let linear_blind = F::sum_of_products_slice(&linear_weights, &blinds);
        let linear_response = linear_nonce + challenge * linear_blind;
        CircuitProof {
            commitments,
            wire_announcements,
            gate_announcements,
            linear_announcement,
            wire_responses,
            gate_responses,
            linear_response,
        }
    }
}

impl<C: Affine> CircuitProof<C> {
    pub(super) fn verify<M>(
        &self,
        shape: &Recorder<C::Scalar, M>,
        bases: Bases<C>,
        mut transcript: Transcript,
        bound: &[C],
    ) -> bool {
        if self.commitments.len() != shape.size
            || self.wire_announcements.len() != shape.size
            || self.wire_responses.len() != shape.size
            || self.gate_announcements.len() != shape.gates.len()
            || self.gate_responses.len() != shape.gates.len()
            || bound.len() != shape.bound.len()
            || self.commitments[0] != bases.g0
            || !self.commitments[1].is_identity()
            || !shape
                .bound
                .iter()
                .zip(bound)
                .all(|(&i, &point)| self.commitments[i] == point)
        {
            return false;
        }

        absorb(&mut transcript, &self.commitments);
        let linear_weights = shape.linear_weights(transcript.challenge(b"linear weights"));
        absorb(&mut transcript, &self.wire_announcements);
        absorb(&mut transcript, &self.gate_announcements);
        transcript.point(self.linear_announcement);
        let challenge: C::Scalar = transcript.challenge(b"circuit proof challenge");

        for i in 0..shape.size {
            let [a, b] = self.wire_responses[i];
            if bases.commit(a, b).to_projective()
                != self.wire_announcements[i].to_projective() + self.commitments[i] * challenge
            {
                return false;
            }
        }
        for (i, &[a, b, c]) in shape.gates.iter().enumerate() {
            if self.commitments[b] * self.wire_responses[a][0] + bases.h * self.gate_responses[i]
                != self.gate_announcements[i].to_projective() + self.commitments[c] * challenge
            {
                return false;
            }
        }

        let linear_target = C::msm(&linear_weights, &self.commitments).to_affine();
        bases.h * self.linear_response
            == self.linear_announcement.to_projective() + linear_target * challenge
    }

    pub(super) fn elements(&self) -> usize {
        4 * self.commitments.len() + 2 * self.gate_announcements.len() + 2
    }
}

#[test]
fn rejects_fresh_proofs_for_unsatisfied_ragu_constraints() {
    use ragu_core::{Cycle, maybe::Empty};
    use rand::{SeedableRng, rngs::StdRng};

    use super::{Fp, Pasta};
    use crate::ipa::IpaCycle;

    fn synthesize<M: MaybeKind>(dr: &mut Recorder<Fp, M>, values: [u64; 4]) {
        let [a, b, c, d] = values.map(|value| Coeff::Arbitrary(Fp::from(value)));
        let (wire_a, _, _, extra) = dr.gate(|| Ok((a, b, c))).unwrap();
        dr.assign_extra(extra, || Ok(d)).unwrap();
        let two = dr.constant(Coeff::Two);
        dr.enforce_equal(&wire_a, &two).unwrap();
    }

    let params = crate::pasta::baked();
    let bases = Bases::new(Pasta::host_generators(params), *Pasta::host_u(params));
    let mut shape = Recorder::<Fp, Empty>::new();
    synthesize(&mut shape, [0; 4]);

    let mut rng = StdRng::seed_from_u64(9);
    for (values, valid) in [
        ([2, 3, 6, 0], true),
        ([2, 3, 7, 0], false), // A*B = C
        ([2, 3, 6, 1], false), // C*D = 0
        ([3, 2, 6, 0], false), // A = 2
    ] {
        let mut recorder = Recorder::<Fp, Always<()>>::new();
        synthesize(&mut recorder, values);
        let transcript = Transcript::new(b"Ragu gate constraints");
        let proof = recorder.prove(bases, transcript.clone(), &[], &mut rng);
        assert_eq!(proof.verify(&shape, bases, transcript, &[]), valid);
    }
}
