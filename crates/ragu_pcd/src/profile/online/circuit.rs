//! The independent online opening fold, with explicit public challenge inputs,
//! and the arithmetic online batches share on either field, which the
//! `compute_v` circuits and the fuse use too.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_backend::Backend;
use ragu_circuits::{
    WithAux,
    horner::Horner,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt,
    io::Write,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field;

use super::{
    Challenge, Layout, Point,
    stages::{
        EvalStage, ForeignLen, InputStage, InputWitness, PolynomialsLen, QueryStage, QueryWitness,
        Side,
    },
};
use crate::profile::Profile;

/// Public values shared by the batch helper and the fuse's `compute_v` target.
#[derive(Clone)]
pub(crate) struct Instance<F, P: Profile, S: Side> {
    /// The authenticated enclosing-step challenges. On the native side `beta`
    /// carries raw `pre_beta`; on the nested side it is the effective lift.
    pub challenges: Challenges<F>,
    /// The quotient and polynomial-evaluation sums, in that order.
    pub sums: [F; 2],
    /// The opposite field's pre-w polynomial commitments, as canonical coordinates.
    pub foreign: FixedVec<F, ForeignLen<P, S>>,
    /// Early coordinates and shared edge values, in the mesh's fixed order.
    pub mesh: FixedVec<F, super::stages::MeshClaimsLen<P, S>>,
}

/// The helper's public output, before the extension's zero suffix.
#[derive(Gadget, Write)]
pub(crate) struct Output<'dr, D: Driver<'dr>, P: Profile, S: Side> {
    /// `w`, `y`, `x`, `alpha`, `u`, and the side's `beta` input, in order.
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<6>>,
    /// The quotient and evaluation sums.
    #[ragu(gadget)]
    pub sums: FixedVec<Element<'dr, D>, ConstLen<2>>,
    /// The same commitment coordinates that online consumers read before w.
    #[ragu(gadget)]
    pub foreign: FixedVec<Element<'dr, D>, ForeignLen<P, S>>,
    /// The same early coordinates and intersection wires used by consumers.
    #[ragu(gadget)]
    pub mesh: FixedVec<Element<'dr, D>, super::stages::MeshClaimsLen<P, S>>,
}

/// The three committed stage witnesses and the authenticated challenge inputs.
pub struct Witness<'a, F: Field, P: Profile, S: Side> {
    /// Input values committed before `w`.
    pub inputs: &'a InputWitness<F, P, S>,
    /// Opening points and claims committed before `alpha`.
    pub query: &'a QueryWitness<F, P, S>,
    /// One value at `u` per polynomial, committed before `pre_beta`.
    pub eval: &'a FixedVec<F, PolynomialsLen<P, S>>,
    /// Public challenge inputs fixed by the parent or terminal verifier.
    pub challenges: Challenges<F>,
}

/// Computes the two online-batch sums without loading the fuse preamble.
pub(crate) struct Circuit<F: Field, P: Profile, S: Side> {
    source_tag: Option<F>,
    /// The base-two logarithm of the source registry's domain, for a
    /// profile that holds inputs to it.
    source_domain: Option<u32>,
    marker: PhantomData<(P, S)>,
}
impl<F: Field, P: Profile, S: Side> Default for Circuit<F, P, S> {
    fn default() -> Self {
        Self {
            source_tag: None,
            source_domain: None,
            marker: PhantomData,
        }
    }
}
impl<F: Field, P: Profile, S: Side> Circuit<F, P, S> {
    /// Uses a source tag alone, for a profile that holds no input to the
    /// source registry's domain.
    ///
    /// # Errors
    ///
    /// Rejects a missing or undeclared source identity.
    #[cfg(test)]
    pub(crate) fn with_source_tag(source_tag: Option<F>) -> Result<Self> {
        Self::with_source(source_tag, None)
    }

    /// Uses the tag and the domain of the source registry captured when
    /// the enclosing application was set up: `source_domain` is the
    /// base-two logarithm of the domain's size, which the helper holds the
    /// profile's domain inputs to.
    ///
    /// # Errors
    ///
    /// Rejects a missing or undeclared source identity, and a profile with
    /// domain inputs given no domain.
    pub(crate) fn with_source(source_tag: Option<F>, source_domain: Option<u32>) -> Result<Self> {
        if source_tag.is_some() != S::mesh::<P>().is_some() {
            return Err(Error::Initialization(
                "source registry does not match the mesh declaration".into(),
            ));
        }
        if source_domain.is_none() && !S::domain_inputs::<P>().is_empty() {
            return Err(Error::Initialization(
                "the profile holds inputs to a source registry's domain it was not given".into(),
            ));
        }
        Ok(Self {
            source_tag,
            source_domain,
            marker: PhantomData,
        })
    }
}

impl<F: Field, R: Rank, P: Profile, S: Side> MultiStageCircuit<F, R> for Circuit<F, P, S> {
    type Last = EvalStage<P, S>;
    type Instance<'source> = &'source Instance<F, P, S>;
    type Witness<'source> = Witness<'source, F, P, S>;
    type Output = Kind![F; Output<'_, _, P, S>];
    type Aux<'source> = [F; 2];

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let challenges = allocate_challenges(dr, instance.as_ref().map(|i| &i.challenges))?;
        let sums = FixedVec::try_from_fn(|j| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|i| i.sums[j]))
        })?;
        let foreign = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|v| v.foreign[i]))
        })?;
        let mesh = FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), instance.as_ref().map(|v| v.mesh[i]))
        })?;
        Ok(Output {
            challenges,
            sums,
            foreign,
            mesh,
        })
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (inputs, builder) = builder.add_stage::<InputStage<P, S>>()?;
        let (query, builder) = builder.add_stage::<QueryStage<P, S>>()?;
        let (eval, builder) = builder.add_stage::<EvalStage<P, S>>()?;
        let dr = builder.finish();
        let inputs = inputs.unenforced(dr, witness.as_ref().map(|w| w.inputs))?;
        if self.source_tag.is_some() != S::mesh::<P>().is_some() {
            return Err(Error::Initialization(
                "online helper is missing its captured source".into(),
            ));
        }
        if let Some(tag) = self.source_tag {
            let expected = Element::constant(dr, tag);
            inputs.source_tag[0].enforce_equal(dr, &expected)?;
        }
        // A domain input is a point of the source registry's domain: a
        // root of unity of the domain's order, which is a power of two.
        for &input in S::domain_inputs::<P>() {
            let log2 = self.source_domain.ok_or_else(|| {
                Error::Initialization("online helper is missing its source's domain".into())
            })?;
            let mut power = inputs.values[input].clone();
            for _ in 0..log2 {
                power = power.square(dr)?;
            }
            let one = Element::constant(dr, F::ONE);
            power.enforce_equal(dr, &one)?;
        }
        let query = query.unenforced(dr, witness.as_ref().map(|w| w.query))?;
        let eval = eval.unenforced(dr, witness.as_ref().map(|w| w.eval))?;
        // Consumers use these very same staged wires. Their authenticity is
        // supplied by the helper's public claim target, not a prover copy.
        let public = FixedVec::<_, ConstLen<6>>::try_from_fn(|i| {
            if i < query.challenges.len() {
                Ok(query.challenges[i].clone())
            } else {
                Element::alloc(
                    dr,
                    &mut (),
                    witness.as_ref().map(|w| {
                        let c = &w.challenges;
                        [c.w, c.y, c.x, c.alpha, c.u, c.beta][i]
                    }),
                )
            }
        })?;
        let beta = if S::NATIVE {
            let challenge = EndoscalarChallenge::from_element(dr, &mut (), public[5].clone())?;
            Endoscalar::extract(challenge).lift(dr)?
        } else {
            public[5].clone()
        };
        let challenges = Challenges {
            w: public[0].clone(),
            y: public[1].clone(),
            x: public[2].clone(),
            alpha: public[3].clone(),
            u: public[4].clone(),
            beta,
        };
        let mesh = if let Some(mesh) = S::mesh::<P>() {
            mesh.claim_values(S::layout::<P>(), &inputs.values, &query.values)?
        } else {
            alloc::vec::Vec::new()
        }
        .try_into()?;
        let query = Queries {
            inputs: inputs.values.to_vec(),
            points: query.points.to_vec(),
            values: query.values.to_vec(),
        };
        let (f, e) = S::layout::<P>().fold(dr, &query, &eval, &challenges)?;
        let sums = FixedVec::new(alloc::vec![f, e])?;
        let values = D::just(|| [*sums[0].value().take(), *sums[1].value().take()]);
        Ok(WithAux::new(
            Output {
                challenges: public,
                sums,
                foreign: inputs.foreign,
                mesh,
            },
            values,
        ))
    }
}

fn allocate_challenges<'dr, D: Driver<'dr>>(
    dr: &mut D,
    challenges: DriverValue<D, &Challenges<D::F>>,
) -> Result<FixedVec<Element<'dr, D>, ConstLen<6>>> {
    FixedVec::try_from_fn(|i| {
        Element::alloc(
            dr,
            &mut (),
            challenges
                .as_ref()
                .map(|c| [c.w, c.y, c.x, c.alpha, c.u, c.beta][i]),
        )
    })
}

/// The enclosing step's authenticated challenges on one field.
///
/// What `beta` holds depends on the side. The batch fold takes the
/// effective endoscalar lift that the commitment walk uses. The helper
/// circuit's witness carries raw `pre_beta` on the native side, which the
/// circuit lifts, and the lift itself on the nested side.
#[derive(Clone, Debug)]
pub struct Challenges<T> {
    /// Challenge sampled after the online commitments.
    pub w: T,
    /// Challenge sampled after the first auxiliary commitments.
    pub y: T,
    /// Challenge sampled after the second auxiliary commitments.
    pub x: T,
    /// Quotient batching challenge.
    pub alpha: T,
    /// Fresh evaluation point for the quotient and all polynomials.
    pub u: T,
    /// The commitment-fold scalar, raw or lifted by side (see above).
    pub beta: T,
}

impl<T> Challenges<T> {
    fn opening(&self, challenge: Challenge) -> &T {
        match challenge {
            Challenge::W => &self.w,
            Challenge::Y => &self.y,
            Challenge::X => &self.x,
        }
    }
}

impl Point {
    /// Resolves an opening point from setup and the staged witness points.
    ///
    /// # Errors
    ///
    /// Rejects an out-of-range witness or circuit domain index.
    pub(crate) fn resolve<F: Field>(
        &self,
        challenges: &Challenges<F>,
        inputs: &[F],
        points: &[F],
    ) -> Result<F> {
        match *self {
            Self::Challenge(challenge) => Ok(*challenges.opening(challenge)),
            Self::Constant(value) => Ok(F::from(value)),
            Self::Circuit(index) => circuit_point(index),
            Self::Input(index) => inputs
                .get(index)
                .copied()
                .ok_or_else(|| Error::InvalidWitness("missing online input point".into())),
            Self::Witness(index) => points
                .get(index)
                .copied()
                .ok_or_else(|| Error::InvalidWitness("missing online opening point".into())),
        }
    }
}

/// Whether a registry index lies in a $2^{\text{two-adicity}}$ domain, so its
/// bit-reversed root of unity does not alias another index's.
fn in_domain(index: u32, two_adicity: u32) -> bool {
    u64::from(index) < 1u64.checked_shl(two_adicity).unwrap_or(u64::MAX)
}

/// Resolves a setup-fixed registry index without allowing bit-reversal aliases.
fn circuit_point<F: Field>(index: u32) -> Result<F> {
    if !in_domain(index, F::TWO_ADICITY) {
        return Err(Error::Initialization(
            "online opening circuit index exceeds the field domain".into(),
        ));
    }
    Ok(CircuitIndex::from_u32(index).omega_j())
}

/// Claimed query wires, committed before `alpha`.
#[derive(Clone, Debug)]
pub(crate) struct Queries<F> {
    /// Input values from the stage committed before `w`.
    pub inputs: Vec<F>,
    /// Arbitrary points, indexed by [`Point::Witness`].
    pub points: Vec<F>,
    /// Claimed values, indexed by [`super::Opening::value`].
    pub values: Vec<F>,
}

impl Layout {
    /// Checks that every [`Point::Circuit`] index lies in field `F`'s domain.
    ///
    /// [`Self::check`] does not know the field; setup runs this for each side
    /// so that an out-of-domain index fails before any proof is made.
    ///
    /// # Errors
    ///
    /// Rejects a circuit index whose root of unity would alias another's.
    pub(crate) fn check_circuit_points<F: Field>(&self) -> Result<()> {
        for opening in self.openings {
            if let Point::Circuit(index) = opening.point {
                circuit_point::<F>(index)?;
            }
        }
        Ok(())
    }

    /// Evaluates every opening and fills its shared claimed-value slot.
    ///
    /// # Errors
    ///
    /// Rejects malformed declarations, wrong witness lengths, and shared
    /// values that disagree. This is a prover helper; circuit binding still
    /// comes from opening every claim in [`Self::fold`].
    pub(crate) fn query<F: Field, R: Rank, B: Backend>(
        &self,
        polynomials: &[sparse::Polynomial<F, R>],
        inputs: Vec<F>,
        points: Vec<F>,
        challenges: &Challenges<F>,
    ) -> Result<Queries<F>> {
        self.check()?;
        if polynomials.len() != self.polynomials.len()
            || inputs.len() != self.inputs
            || points.len() != self.points
        {
            return Err(Error::InvalidWitness(
                "online batch has the wrong witness lengths".into(),
            ));
        }
        let mut values = alloc::vec![None; self.values];
        for opening in self.openings {
            let point = opening.point.resolve(challenges, &inputs, &points)?;
            let value = B::sparse_eval(&polynomials[opening.polynomial], point);
            if values[opening.value].is_some_and(|prior| prior != value) {
                return Err(Error::InvalidWitness(
                    "online openings disagree on a shared value".into(),
                ));
            }
            values[opening.value] = Some(value);
        }
        Ok(Queries {
            inputs,
            points,
            values: values
                .into_iter()
                .map(|v| v.expect("layout checks value coverage"))
                .collect(),
        })
    }

    /// Builds the appended quotient in opening order.
    ///
    /// Repeated polynomial indices contribute separate quotient terms.
    ///
    /// # Errors
    ///
    /// Rejects malformed layouts, witness lengths or point indices.
    pub(crate) fn quotient<F: Field, R: Rank>(
        &self,
        polynomials: &[sparse::Polynomial<F, R>],
        inputs: &[F],
        points: &[F],
        challenges: &Challenges<F>,
    ) -> Result<sparse::Polynomial<F, R>> {
        self.check()?;
        if polynomials.len() != self.polynomials.len()
            || inputs.len() != self.inputs
            || points.len() != self.points
        {
            return Err(Error::InvalidWitness(
                "online batch has the wrong witness lengths".into(),
            ));
        }
        let quotients = self
            .openings
            .iter()
            .map(|opening| {
                let point = opening.point.resolve(challenges, inputs, points)?;
                Ok(udon::polynomial::divide_linear_rev(
                    polynomials[opening.polynomial].iter_coeffs(),
                    point,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(quotient_sum(quotients, challenges.alpha))
    }

    /// Constrains the online quotient and evaluation sums.
    ///
    /// `queries` must be the shared `OnlineQuery` wires, `evaluations` the
    /// `OnlineEval` wires, and `challenges` authenticated by the containing
    /// circuit's instance. The caller binds both returned sums to `compute_v`.
    ///
    /// # Errors
    ///
    /// Rejects wrong lengths and enforces every denominator nonzero, including
    /// when the opening's numerator is zero.
    pub(crate) fn fold<'dr, D: Driver<'dr>>(
        &self,
        dr: &mut D,
        queries: &Queries<Element<'dr, D>>,
        evaluations: &[Element<'dr, D>],
        challenges: &Challenges<Element<'dr, D>>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        self.check()?;
        if queries.inputs.len() != self.inputs
            || queries.points.len() != self.points
            || queries.values.len() != self.values
            || evaluations.len() != self.polynomials.len()
        {
            return Err(Error::Initialization(
                "online batch wires do not match the layout".into(),
            ));
        }
        let mut inverter = crate::internal::inverter::Inverter::with_base(challenges.u.clone());
        let mut denominators = Vec::with_capacity(self.openings.len());
        for opening in self.openings {
            let point = match opening.point {
                Point::Challenge(challenge) => challenges.opening(challenge).clone(),
                Point::Constant(value) => Element::constant(dr, D::F::from(value)),
                Point::Circuit(index) => Element::constant(dr, circuit_point::<D::F>(index)?),
                Point::Input(index) => queries.inputs[index].clone(),
                Point::Witness(index) => queries.points[index].clone(),
            };
            denominators.push(inverter.add(dr, &point)?);
        }
        let inverses = inverter.invert(dr)?;
        let mut quotient = Horner::new(&challenges.alpha);
        append_quotients(
            dr,
            &mut quotient,
            self.openings
                .iter()
                .zip(denominators)
                .map(|(opening, denominator)| {
                    (
                        &evaluations[opening.polynomial],
                        &queries.values[opening.value],
                        &inverses[denominator],
                    )
                }),
        )?;
        let mut evaluated = Horner::new(&challenges.beta);
        for value in evaluations {
            value.write(dr, &mut evaluated)?;
        }
        Ok((quotient.finish(dr), evaluated.finish(dr)))
    }
}

/// Horner-batches quotient coefficient streams with $\alpha$: the first
/// stream receives the highest power.
pub(crate) fn quotient_sum<F: Field, R: Rank>(
    mut iters: Vec<impl Iterator<Item = F>>,
    alpha: F,
) -> sparse::Polynomial<F, R> {
    let mut coeffs = Vec::with_capacity(R::num_coeffs());
    let Some((first, rest)) = iters.split_first_mut() else {
        return sparse::Polynomial::new();
    };
    for val in first.by_ref() {
        let c = rest
            .iter_mut()
            .fold(val, |acc, iter| acc.mul_add(&alpha, &iter.next().unwrap()));
        coeffs.push(c);
    }
    coeffs.reverse();

    sparse::Polynomial::from_coeffs(coeffs)
}

/// Multiplies `value` by `base` raised to a setup-fixed `exponent`.
///
/// Square-and-multiply costs about $\log_2$ of the exponent in
/// multiplications, rather than one per power. `compute_v` uses it to shift
/// its existing folds below the online batch's terms.
pub(crate) fn mul_pow<'dr, D: Driver<'dr>>(
    dr: &mut D,
    value: &Element<'dr, D>,
    base: &Element<'dr, D>,
    exponent: usize,
) -> Result<Element<'dr, D>> {
    if exponent == 0 {
        return Ok(value.clone());
    }
    let mut power = base.clone();
    for bit in (0..usize::BITS - 1 - exponent.leading_zeros()).rev() {
        power = power.square(dr)?;
        if (exponent >> bit) & 1 == 1 {
            power = power.mul(dr, base)?;
        }
    }
    value.mul(dr, &power)
}

/// Appends opening terms to a quotient fold in descriptor order.
/// Used by both online helpers and the compatibility placement in compute-v.
pub(crate) fn append_quotients<'a, 'dr: 'a, D: Driver<'dr> + 'a>(
    dr: &mut D,
    horner: &mut Horner<'_, 'dr, D>,
    terms: impl IntoIterator<
        Item = (
            &'a Element<'dr, D>,
            &'a Element<'dr, D>,
            &'a Element<'dr, D>,
        ),
    >,
) -> Result<()> {
    for (evaluated, value, inverse) in terms {
        evaluated
            .sub(dr, value)
            .mul(dr, inverse)?
            .write(dr, horner)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ragu_backend::ReferenceBackend;
    use ragu_circuits::polynomials::TestRank;
    use ragu_core::{
        maybe::Maybe,
        pasta::{Fp, Fq},
    };
    use ragu_primitives::Simulator;

    use super::*;
    use crate::profile::online::{Opening, Phase};

    const LAYOUT: Layout = Layout {
        polynomials: &[Phase::BeforeW, Phase::BeforeW],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Witness(0),
                value: 1,
            },
            Opening {
                polynomial: 1,
                point: Point::Constant(0),
                value: 2,
            },
            Opening {
                polynomial: 0,
                point: Point::Constant(0),
                value: 2,
            },
            Opening {
                polynomial: 1,
                point: Point::Circuit(3),
                value: 3,
            },
        ],
        inputs: 0,
        points: 1,
        values: 4,
    };

    fn check<F: Field>() -> Result<()> {
        let polynomials: [sparse::Polynomial<F, TestRank>; 2] = [
            sparse::Polynomial::from_coeffs(vec![F::ONE, F::from(2), F::from(3)]),
            sparse::Polynomial::from_coeffs(vec![F::ONE, F::from(5)]),
        ];
        let challenges = Challenges {
            w: F::from(2),
            y: F::from(3),
            x: F::from(5),
            alpha: F::from(11),
            u: F::from(17),
            beta: F::from(13),
        };
        let queries = LAYOUT.query::<_, _, ReferenceBackend>(
            &polynomials,
            vec![],
            vec![F::from(7)],
            &challenges,
        )?;
        let omega = CircuitIndex::from_u32(3).omega_j::<F>();
        assert_eq!(
            queries.values,
            vec![
                F::from(17),
                F::from(162),
                F::ONE,
                F::ONE + F::from(5) * omega
            ]
        );
        let quotient =
            LAYOUT.quotient(&polynomials, &queries.inputs, &queries.points, &challenges)?;
        let u = challenges.u;
        let a = challenges.alpha;
        // The circuit-point opening of 1 + 5X is last, so it takes alpha^0
        // and its quotient is the constant 5.
        let expected_f = a.pow_u64(4) * (F::from(2) + F::from(3) * (u + F::from(2)))
            + a.pow_u64(3) * (F::from(2) + F::from(3) * (u + F::from(7)))
            + a.square() * F::from(5)
            + a * (F::from(2) + F::from(3) * u)
            + F::from(5);
        let expected_e = challenges.beta * (F::ONE + F::from(2) * u + F::from(3) * u.square())
            + F::ONE
            + F::from(5) * u;
        assert_eq!(quotient.eval(u), expected_f);
        let evaluations = polynomials.iter().map(|p| p.eval(u)).collect::<Vec<_>>();
        for mutation in 0..6 {
            let result =
                Simulator::<F>::simulate((queries.clone(), evaluations.clone()), |dr, witness| {
                    let mut query = witness.as_ref().map(|w| w.0.clone()).take();
                    let mut evaluations = witness.as_ref().map(|w| w.1.clone()).take();
                    let mut challenges = challenges.clone();
                    match mutation {
                        1 => query.values[1] += F::ONE,
                        2 => query.points[0] += F::ONE,
                        3 => evaluations[0] += F::ONE,
                        4 => challenges.u = challenges.w,
                        5 => query.values[3] += F::ONE,
                        _ => {}
                    }
                    let query = Queries {
                        inputs: vec![],
                        points: query
                            .points
                            .into_iter()
                            .map(|v| Element::constant(dr, v))
                            .collect(),
                        values: query
                            .values
                            .into_iter()
                            .map(|v| Element::constant(dr, v))
                            .collect(),
                    };
                    let evaluations = evaluations
                        .into_iter()
                        .map(|v| Element::constant(dr, v))
                        .collect::<Vec<_>>();
                    let challenges = Challenges {
                        w: Element::constant(dr, challenges.w),
                        y: Element::constant(dr, challenges.y),
                        x: Element::constant(dr, challenges.x),
                        alpha: Element::constant(dr, challenges.alpha),
                        u: Element::constant(dr, challenges.u),
                        beta: Element::constant(dr, challenges.beta),
                    };
                    let (f, e) = LAYOUT.fold(dr, &query, &evaluations, &challenges)?;
                    let expected_f = Element::constant(dr, expected_f);
                    let expected_e = Element::constant(dr, expected_e);
                    f.enforce_equal(dr, &expected_f)?;
                    e.enforce_equal(dr, &expected_e)
                });
            assert_eq!(result.is_ok(), mutation == 0, "mutation {mutation}");
        }
        Ok(())
    }

    #[test]
    fn repeated_openings_match_direct_polynomial_algebra() -> Result<()> {
        check::<Fp>()?;
        check::<Fq>()
    }

    #[test]
    fn mul_pow_matches_repeated_multiplication() -> Result<()> {
        let (value, base) = (Fp::from(3), Fp::from(7));
        for exponent in 0..=41 {
            Simulator::<Fp>::simulate((), |dr, _| {
                let v = Element::constant(dr, value);
                let b = Element::constant(dr, base);
                let expected = Element::constant(dr, value * base.pow_u64(exponent as u64));
                mul_pow(dr, &v, &b, exponent)?.enforce_equal(dr, &expected)
            })?;
        }
        Ok(())
    }

    #[test]
    fn circuit_points_outside_the_field_domain_reject() {
        assert!(in_domain(15, 4));
        assert!(!in_domain(16, 4));
        assert!(in_domain(u32::MAX, 32));
        assert!(LAYOUT.check_circuit_points::<Fp>().is_ok());
        assert!(LAYOUT.check_circuit_points::<Fq>().is_ok());
    }

    #[test]
    fn shared_values_and_witness_lengths_are_checked() {
        let polynomials = [
            sparse::Polynomial::<Fp, TestRank>::from_coeffs(vec![Fp::ONE]),
            sparse::Polynomial::from_coeffs(vec![Fp::from(2)]),
        ];
        let challenges = Challenges {
            w: Fp::ONE,
            y: Fp::ONE,
            x: Fp::ONE,
            alpha: Fp::ONE,
            u: Fp::from(3),
            beta: Fp::ONE,
        };
        assert!(
            LAYOUT
                .query::<_, _, ReferenceBackend>(&polynomials, vec![], vec![Fp::ONE], &challenges)
                .is_err()
        );
        assert!(
            LAYOUT
                .quotient(&polynomials[..1], &[], &[Fp::ONE], &challenges)
                .is_err()
        );
        assert!(
            LAYOUT
                .quotient(&polynomials, &[], &[], &challenges)
                .is_err()
        );
    }

    #[test]
    fn empty_and_zero_batches_are_zero() -> Result<()> {
        let challenges = Challenges {
            w: Fp::from(2),
            y: Fp::from(3),
            x: Fp::from(5),
            alpha: Fp::from(7),
            u: Fp::from(11),
            beta: Fp::from(13),
        };
        for layout in [Layout::EMPTY, LAYOUT] {
            let polynomials =
                vec![sparse::Polynomial::<Fp, TestRank>::new(); layout.polynomials.len()];
            let points = vec![Fp::ZERO; layout.points];
            let queries = layout.query::<_, _, ReferenceBackend>(
                &polynomials,
                vec![],
                points,
                &challenges,
            )?;
            assert!(queries.values.iter().all(|v| *v == Fp::ZERO));
            assert_eq!(
                layout
                    .quotient(&polynomials, &queries.inputs, &queries.points, &challenges)?
                    .eval(challenges.u),
                Fp::ZERO
            );
        }
        Ok(())
    }
}
