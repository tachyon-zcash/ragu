//! The compressed verifier assembled from the gadgets, split between the
//! two fields of the cycle: what the native verifier checks in the circuit
//! field runs on one side, what it checks in the scalar field on the
//! other, and what passes between them is what a stage of the
//! decompression proof would carry.
//!
//! The circuit-field side replays the fuse's transcript for the proof's
//! challenges and the compression's for its own, derives the claims'
//! targets through [`ProofInputs`], runs the host curve's field checks,
//! derives the nested curve's commitments and checks its IPA, and
//! recomputes the two nested stages the native verifier recomputes. The
//! scalar-field side lifts the challenges from their endoscalars, derives
//! the nested targets, runs the nested curve's field checks, derives the
//! host curve's commitments and checks its IPA.
//!
//! Between the sides pass the endoscalars of every challenge, the digits
//! of the full-width scalars each side's IPA check needs the other to
//! scale by, and the scalar field's values the circuit-field transcript
//! absorbs through bridges. In the decompression proof each is a stage:
//! the side that computes the value holds it as wires, and the other
//! side's view is bound by the stage's commitment, as the fuse binds its
//! challenge stage. Here the [`Witness`] carries them, and the two sides
//! allocate them from it; the registry's evaluations likewise arrive as
//! wires the decider checks.

use alloc::{vec, vec::Vec};
use core::iter::once;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, Registry},
    staging::StageExt,
};
use ragu_core::{Cycle, Error, FixedGenerators, Result, drivers::Driver};
use ragu_primitives::{Element, Endoscalar, GadgetExt, NonzeroBank, Point};
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{
    batch, derive,
    derive::{Digits, Fixed},
    ipa, revdot, transcript,
    transcript::{Absorb, Challenge, RawChallenge},
};
use crate::{
    Application, CompressedPcd, CompressedProof, RAGU_TAG, SelectableBackend,
    compress::{
        Lifted, Messages, Sampled,
        instance::Instance,
        revdot::{
            OpeningClaim, Openings,
            claims::{self, Kind},
            fold::{Derived, Weights},
            native_components, native_position, nested_components, nested_position,
        },
        transcript as compression_transcript,
    },
    header::{Header, Suffix},
    internal::{
        ky,
        native::{
            self,
            claims::KySource as NativeKySource,
            stages::{eval::generator_index, preamble::ProofInputs},
        },
        nested::{
            self, claims::KySource as NestedKySource, stages::challenges as challenge_stage,
            unified as nested_unified,
        },
        transcript::Transcript,
    },
    ipa::{CycleTranscript, IpaCycle, IpaTranscript, MSM, Params},
    proof::bridge_alpha_power,
};

/// One curve's challenges as the compression squeezes them, in order.
#[derive(Clone)]
pub(crate) struct Squeezed<F> {
    pub sampled: Sampled<F>,
    pub weights: Weights<F>,
    pub rho: F,
    pub r: F,
    pub alpha: F,
    pub u: F,
    pub beta: F,
    pub xi: F,
    pub ipa_z: F,
    pub rounds: Vec<F>,
}

impl<F: Field> Squeezed<F> {
    /// Reads one curve's challenges off `t`, standing where the curve's
    /// reduction starts, with the curve's `sampled` challenges already
    /// read.
    fn read<P: Affine<Scalar = F>>(
        sampled: Sampled<F>,
        messages: &Messages<P>,
        t: &mut impl IpaTranscript<P>,
    ) -> Result<Self> {
        let reduction = &messages.reduction;
        let weights = reduction.fold.replay(t)?;
        let rho = t.squeeze_challenge()?;
        t.write_point(reduction.p)?;
        t.write_point(reduction.q)?;
        let r = t.squeeze_challenge()?;
        for &opened in &reduction.openings {
            t.write_scalar(opened)?;
        }
        t.write_scalar(reduction.p_at_inverse_r)?;
        t.write_scalar(reduction.q_at_r)?;

        let alpha = t.squeeze_challenge()?;
        t.write_point(messages.batch.f)?;
        let u = t.squeeze_challenge()?;
        for &value in &messages.batch.evaluations {
            t.write_scalar(value)?;
        }
        let beta = t.squeeze_challenge()?;

        t.write_point(messages.opening.s_commitment)?;
        let xi = t.squeeze_challenge()?;
        let ipa_z = t.squeeze_challenge()?;
        let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
        for &(l, r) in &messages.opening.rounds {
            t.write_point(l)?;
            t.write_point(r)?;
            rounds.push(t.squeeze_challenge()?);
        }
        t.write_scalar(messages.opening.c)?;

        Ok(Squeezed {
            sampled,
            weights,
            rho,
            r,
            alpha,
            u,
            beta,
            xi,
            ipa_z,
            rounds,
        })
    }
}

/// What one curve's side of the verifier needs beyond the proof: the
/// claims' kinds and public values, the IPA's witness points, and the
/// challenges raw, for their endoscalars, and lifted, as the side uses
/// them.
#[derive(Clone)]
pub(crate) struct SideWitness<P: Affine> {
    pub kinds: Vec<Kind>,
    /// Each named circuit's wiring restriction at the lifted $(r, y)$.
    pub restrictions: Vec<(CircuitIndex, P::Scalar)>,
    /// The wire bindings' stage polynomials, by component position, and
    /// their degrees and expected values.
    pub masked: Vec<(usize, Vec<usize>, Vec<P::Scalar>)>,
    /// The registry restriction at the compression's $w$, the instance's
    /// extra opening's value.
    pub restriction_at_w: P::Scalar,
    /// The IPA's witness points: each $u_j^{-1} L_j$, and $G'$.
    pub inverse_scaled: Vec<P>,
    pub g_prime: P,
    pub fixed: Fixed<P>,
    pub raw: Squeezed<P::Scalar>,
    pub lifted: Squeezed<P::Scalar>,
    /// The batched claim's value and the IPA's $c b z$, the full-width
    /// scalars the other side scales by beside the proof's $c$.
    pub v: P::Scalar,
    pub cbz: P::Scalar,
}

/// A coefficient of the `ab` bridge stage: which of its values it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbValue {
    /// A coordinate of the native $A$ commitment, $x$ then $y$.
    A(usize),
    /// A coordinate of the native $B$ commitment.
    B(usize),
    /// A coordinate of the native points stage's commitment.
    PointsAb(usize),
    /// The blinding, `bridge_alpha` squared.
    Alpha,
}

/// Everything both sides allocate, prepared natively from a compressed
/// proof as the native verifier reads it.
pub(crate) struct Witness<C: Cycle> {
    pub proof: CompressedProof<C>,
    pub header: Vec<C::CircuitField>,
    /// The fuse's challenges, raw.
    pub fuse: nested::Challenges<C::CircuitField>,
    pub native: SideWitness<C::HostCurve>,
    pub nested: SideWitness<C::NestedCurve>,
    /// The `ab` bridge stage's nonzero coefficients: the generator each
    /// lands on and the value it holds.
    pub ab_terms: Vec<(usize, AbValue)>,
}

impl<C: IpaCycle> Witness<C> {
    /// Prepares the witness for `pcd` under `app`, running the native
    /// verifier's computations.
    ///
    /// # Errors
    ///
    /// Fails if the native verifier would reject the proof, or on an
    /// internal error.
    pub(crate) fn prepare<R: Rank, const HEADER_SIZE: usize, B: SelectableBackend, H>(
        app: &Application<'_, C, R, HEADER_SIZE, B>,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<Self>
    where
        H: Header<C::CircuitField>,
    {
        type Verifier<B> = <B as SelectableBackend>::Verifier;
        let proof = pcd.proof().clone();
        let instance = &proof.instance;
        let header = ky::output_header::<C, H, HEADER_SIZE>(pcd.data().clone())?;

        let mut fuse_transcript = CycleTranscript::<C, Verifier<B>>::new(app.params, RAGU_TAG)?;
        let fuse = instance
            .challenges(&mut fuse_transcript)?
            .ok_or_else(|| Error::InvalidWitness("pre_beta is out of range".into()))?;

        // The compression's transcript twice over: lifted, as the verifier
        // reads it, and raw, for the endoscalars.
        let mut lifted = compression_transcript::<C, Verifier<B>>(app.params, instance, &header)?;
        let mut raw = compression_transcript::<C, Verifier<B>>(app.params, instance, &header)?;
        let native_sampled = Sampled::squeeze(&mut Lifted(lifted.host()))?;
        let nested_sampled = Sampled::squeeze(&mut Lifted(lifted.nested()))?;
        let native_raw_sampled = Sampled::squeeze(&mut raw.host())?;
        let nested_raw_sampled = Sampled::squeeze(&mut raw.nested())?;
        let (native_targets, nested_targets) =
            instance.targets::<HEADER_SIZE>(&fuse, &header, native_sampled.y, nested_sampled.y)?;

        let native = {
            let registry = &app.native_registry;
            let masked = instance.native_bindings::<R, Verifier<B>, HEADER_SIZE>(
                &fuse,
                registry,
                native_sampled.sigma,
            )?;
            let shapes = claims::native_shapes(instance.circuit_id, native_sampled.z, &masked)?;
            let kinds = shapes.iter().map(|shape| shape.kind).collect();
            let mut openings = crate::compress::revdot::verify_native::<C, R, Verifier<B>>(
                instance.circuit_id,
                |component| instance.native_commitment(component),
                registry,
                native_sampled.y,
                native_sampled.z,
                &native_targets,
                &masked,
                &proof.native.reduction,
                &mut Lifted(lifted.host()),
            )?
            .ok_or_else(|| Error::InvalidWitness("the native reduction fails".into()))?;
            let (commitments, claims) = instance.native_openings::<R, Verifier<B>>(
                &fuse,
                registry,
                native_sampled.w,
                openings.commitments.len(),
            );
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            let restriction_at_w = openings.claims[Derived::ALL.len() + 2].value;
            side_witness::<C::HostCurve, R, Verifier<B>>(
                SideInputs {
                    sampled: native_sampled,
                    raw_sampled: native_raw_sampled,
                    messages: &proof.native,
                    openings: &openings,
                    registry,
                    masked: masked
                        .iter()
                        .map(|m| {
                            (
                                native_position(m.poly),
                                m.wires.iter().map(|&(degree, _)| degree).collect(),
                                m.wires.iter().map(|&(_, value)| value).collect(),
                            )
                        })
                        .collect(),
                    kinds,
                    restriction_at_w,
                    params: Params::with_k(
                        C::host_generators(app.params),
                        *C::host_u(app.params),
                        R::RANK,
                    ),
                },
                &mut Lifted(lifted.host()),
                &mut raw.host(),
            )?
        };

        let nested = {
            let registry = &app.nested_registry;
            let masked = instance.nested_bindings::<R, Verifier<B>>(
                &fuse,
                registry,
                nested_sampled.sigma,
            )?;
            let shapes = claims::nested_shapes(nested_sampled.z, &masked)?;
            let kinds = shapes.iter().map(|shape| shape.kind).collect();
            let mut openings = crate::compress::revdot::verify_nested::<C, R, Verifier<B>>(
                |component| instance.nested_commitment(component),
                registry,
                nested_sampled.y,
                nested_sampled.z,
                &nested_targets,
                &masked,
                &proof.nested.reduction,
                &mut Lifted(lifted.nested()),
            )?
            .ok_or_else(|| Error::InvalidWitness("the nested reduction fails".into()))?;
            let (commitments, claims) = instance.nested_openings::<R, Verifier<B>>(
                &fuse,
                registry,
                nested_sampled.w,
                openings.commitments.len(),
            )?;
            openings.commitments.extend(commitments);
            openings.claims.extend(claims);
            let restriction_at_w = openings.claims[Derived::ALL.len() + 2].value;
            side_witness::<C::NestedCurve, R, Verifier<B>>(
                SideInputs {
                    sampled: nested_sampled,
                    raw_sampled: nested_raw_sampled,
                    messages: &proof.nested,
                    openings: &openings,
                    registry,
                    masked: masked
                        .iter()
                        .map(|m| {
                            (
                                nested_position(m.poly),
                                m.wires.iter().map(|&(degree, _)| degree).collect(),
                                m.wires.iter().map(|&(_, value)| value).collect(),
                            )
                        })
                        .collect(),
                    kinds,
                    restriction_at_w,
                    params: Params::with_k(
                        C::nested_generators(app.params),
                        *C::nested_u(app.params),
                        R::RANK,
                    ),
                },
                &mut Lifted(lifted.nested()),
                &mut raw.nested(),
            )?
        };

        let ab_terms = ab_terms::<C, R>(instance)?;

        Ok(Witness {
            proof,
            header,
            fuse,
            native,
            nested,
            ab_terms,
        })
    }
}

/// What [`side_witness`] takes for one curve.
struct SideInputs<'a, P: Affine, R: Rank> {
    sampled: Sampled<P::Scalar>,
    raw_sampled: Sampled<P::Scalar>,
    messages: &'a Messages<P>,
    openings: &'a Openings<P>,
    registry: &'a Registry<'a, P::Scalar, R>,
    masked: Vec<(usize, Vec<usize>, Vec<P::Scalar>)>,
    kinds: Vec<Kind>,
    restriction_at_w: P::Scalar,
    params: Params<P>,
}

/// One curve's side witness, with `lifted` standing after the curve's
/// reduction, as the verifier leaves it, and `raw` where the reduction
/// starts: the batch and the IPA run on the lifted view, the whole side on
/// the raw one.
fn side_witness<P: Affine, R: Rank, B: SelectableBackend + Backend>(
    inputs: SideInputs<'_, P, R>,
    lifted: &mut impl IpaTranscript<P>,
    raw: &mut impl IpaTranscript<P>,
) -> Result<SideWitness<P>> {
    let SideInputs {
        sampled,
        raw_sampled,
        messages,
        openings,
        registry,
        masked,
        kinds,
        restriction_at_w,
        params,
    } = inputs;
    let raw_squeezed = Squeezed::read(raw_sampled, messages, raw)?;

    let claim = crate::compress::batch::verify::<_, B, _>(
        &openings.commitments,
        &openings.claims,
        &messages.batch,
        lifted,
    )?;
    let mut msm = MSM::new(&params);
    msm.append_term(P::Scalar::ONE, claim.commitment);
    let guard = crate::ipa::verify_proof(
        &params,
        msm,
        lifted,
        &messages.opening,
        claim.point,
        claim.value,
    )?;
    let g_prime = guard.compute_g::<B>();
    if !guard.use_challenges().eval::<B>() {
        return Err(Error::InvalidWitness("the IPA fails".into()));
    }

    // The lifted challenges are the raw ones' lifts.
    let lift = |raw: P::Scalar| -> Result<P::Scalar> {
        Ok(ragu_primitives::lift_endoscalar(
            ragu_primitives::extract_endoscalar(raw)?,
        ))
    };
    let lifted_squeezed = Squeezed {
        sampled,
        weights: Weights {
            mu: lift(raw_squeezed.weights.mu)?,
            nu: lift(raw_squeezed.weights.nu)?,
            mu_prime: lift(raw_squeezed.weights.mu_prime)?,
            nu_prime: lift(raw_squeezed.weights.nu_prime)?,
        },
        rho: lift(raw_squeezed.rho)?,
        r: lift(raw_squeezed.r)?,
        alpha: lift(raw_squeezed.alpha)?,
        u: lift(raw_squeezed.u)?,
        beta: lift(raw_squeezed.beta)?,
        xi: lift(raw_squeezed.xi)?,
        ipa_z: lift(raw_squeezed.ipa_z)?,
        rounds: raw_squeezed
            .rounds
            .iter()
            .map(|&u_j| lift(u_j))
            .collect::<Result<_>>()?,
    };

    let mut restrictions: Vec<(CircuitIndex, P::Scalar)> = Vec::new();
    for kind in &kinds {
        if let Kind::Circuit(circuit) | Kind::Bonding(circuit) = *kind
            && !restrictions.iter().any(|(listed, _)| *listed == circuit)
        {
            let value = B::registry_wxy(
                registry,
                circuit.omega_j(),
                lifted_squeezed.r,
                lifted_squeezed.sampled.y,
            );
            restrictions.push((circuit, value));
        }
    }

    let mut b = P::Scalar::ONE;
    let mut cur = claim.point;
    for u_j in lifted_squeezed.rounds.iter().rev() {
        b *= P::Scalar::ONE + *u_j * cur;
        cur = cur.square();
    }
    let inverse_scaled = messages
        .opening
        .rounds
        .iter()
        .zip(&lifted_squeezed.rounds)
        .map(|(&(l, _), u_j)| {
            u_j.invert()
                .map(|inverse| (l * inverse).to_affine())
                .ok_or_else(|| Error::InvalidWitness("IPA round challenge is zero".into()))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(SideWitness {
        kinds,
        restrictions,
        masked,
        restriction_at_w,
        inverse_scaled,
        g_prime,
        fixed: Fixed {
            g_0: params.g[0],
            u: params.u,
            offset: params.g[1],
        },
        raw: raw_squeezed,
        cbz: messages.opening.c * b * lifted_squeezed.ipa_z,
        lifted: lifted_squeezed,
        v: claim.value,
    })
}

/// The `ab` bridge stage's nonzero coefficients, read off the stage
/// polynomial the native verifier recomputes: its layout is the stage's,
/// so the circuit learns it from the polynomial rather than restating it.
fn ab_terms<C: Cycle, R: Rank>(instance: &Instance<C>) -> Result<Vec<(usize, AbValue)>> {
    let a = instance.native_commitment(native::RxComponent::AbA);
    let b = instance.native_commitment(native::RxComponent::AbB);
    let points_ab = instance.native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb));
    let alpha = bridge_alpha_power(instance.bridge_alpha, nested::RxIndex::BridgeAB);
    let stage = nested::stages::ab::Stage::<C::HostCurve, R>::rx(
        alpha,
        &nested::stages::ab::Witness {
            a,
            b,
            native_points_ab: points_ab,
        },
    )?;
    let coordinates = |point: C::HostCurve| -> Result<[C::ScalarField; 2]> {
        let (x, y) = point
            .coordinates()
            .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
        Ok([x, y])
    };
    let values = [
        (AbValue::A(0), coordinates(a)?[0]),
        (AbValue::A(1), coordinates(a)?[1]),
        (AbValue::B(0), coordinates(b)?[0]),
        (AbValue::B(1), coordinates(b)?[1]),
        (AbValue::PointsAb(0), coordinates(points_ab)?[0]),
        (AbValue::PointsAb(1), coordinates(points_ab)?[1]),
        (AbValue::Alpha, alpha),
    ];
    let mut terms = Vec::new();
    for (index, coefficient) in stage.iter_coeffs().enumerate() {
        if coefficient == C::ScalarField::ZERO {
            continue;
        }
        let (which, _) = values
            .iter()
            .find(|(_, value)| *value == coefficient)
            .ok_or_else(|| {
                Error::InvalidWitness("the ab bridge stage holds an unexpected coefficient".into())
            })?;
        terms.push((index, *which));
    }
    Ok(terms)
}

/// The native targets as elements, for
/// [`ky_values`](native::claims::ky_values).
struct NativeTargets<'dr, D: Driver<'dr>> {
    c: Element<'dr, D>,
    application: Element<'dr, D>,
    unified_bridge: Element<'dr, D>,
    unified: Element<'dr, D>,
    one: Element<'dr, D>,
    zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> NativeKySource for NativeTargets<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.c.clone())
    }

    fn application_ky(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.application.clone())
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.unified_bridge.clone())
    }

    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.unified.clone())
    }

    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.one.clone())
    }

    fn zero(&self) -> Self::Ky {
        self.zero.clone()
    }
}

/// The nested targets as elements.
struct NestedTargets<'dr, D: Driver<'dr>> {
    c: Element<'dr, D>,
    unified: Element<'dr, D>,
    one: Element<'dr, D>,
    zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> NestedKySource for NestedTargets<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.c.clone())
    }

    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.one.clone())
    }

    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.unified.clone())
    }

    fn zero(&self) -> Self::Ky {
        self.zero.clone()
    }
}

fn elements<'dr, D: Driver<'dr>>(
    dr: &mut D,
    values: impl IntoIterator<Item = D::F>,
) -> Result<Vec<Element<'dr, D>>> {
    values
        .into_iter()
        .map(|value| Element::alloc(dr, &mut (), D::just(|| value)))
        .collect()
}

fn element<'dr, D: Driver<'dr>>(dr: &mut D, value: D::F) -> Result<Element<'dr, D>> {
    Element::alloc(dr, &mut (), D::just(|| value))
}

fn points<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    values: impl IntoIterator<Item = P>,
) -> Result<Vec<Point<'dr, D, P>>> {
    values
        .into_iter()
        .map(|value| Point::alloc(dr, D::just(|| value)))
        .collect()
}

fn point<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    value: P,
) -> Result<Point<'dr, D, P>> {
    Point::alloc(dr, D::just(|| value))
}

/// The endoscalar of a raw challenge, allocated from its bits on the side
/// that did not squeeze it.
fn endoscalar<'dr, D: Driver<'dr>, F: Field>(dr: &mut D, raw: F) -> Result<Endoscalar<'dr, D>> {
    let endo = ragu_primitives::extract_endoscalar(raw)?;
    Endoscalar::alloc(dr, D::just(|| endo))
}

/// A point's coordinates as elements.
fn coordinates<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    point: &Point<'dr, D, P>,
) -> Result<[Element<'dr, D>; 2]> {
    let mut written = Vec::with_capacity(2);
    GadgetExt::write(point, dr, &mut written)?;
    let [x, y]: [Element<'dr, D>; 2] = written
        .try_into()
        .map_err(|_| Error::InvalidWitness("a point has two coordinates".into()))?;
    Ok([x, y])
}

/// The wire bindings as the revdot gadget takes them, from the side
/// witness's masked lists.
fn bindings<'dr, D: Driver<'dr>>(
    dr: &mut D,
    masked: &[(usize, Vec<usize>, Vec<D::F>)],
) -> Result<Vec<revdot::Binding<'dr, D>>> {
    masked
        .iter()
        .map(|(_, degrees, expected)| {
            Ok(revdot::Binding {
                degrees: degrees.clone(),
                expected: elements(dr, expected.iter().copied())?,
            })
        })
        .collect()
}

/// Binds the elements at `positions` of `binding`'s expected values to
/// `gadgets`: the values the instance supplies rather than the registry.
fn bind_expected<'dr, D: Driver<'dr>>(
    dr: &mut D,
    binding: &revdot::Binding<'dr, D>,
    positions: impl IntoIterator<Item = usize>,
    gadgets: &[Element<'dr, D>],
) -> Result<()> {
    for (position, gadget) in positions.into_iter().zip(gadgets) {
        binding.expected[position].enforce_equal(dr, gadget)?;
    }
    Ok(())
}

/// The opening claims of one side after the reduction's: the registry
/// restriction at the compression's $w$, the batch polynomial at the
/// fuse's $u$ and the accumulator's $a$ and $b$ there, with the values the
/// side holds.
fn instance_claims<'dr, D: Driver<'dr>>(
    base: usize,
    w: &Element<'dr, D>,
    restriction_at_w: Element<'dr, D>,
    u: &Element<'dr, D>,
    v: &Element<'dr, D>,
    a_at_u: &Element<'dr, D>,
    b_at_u: &Element<'dr, D>,
) -> Vec<OpeningClaim<Element<'dr, D>>> {
    let claim = |poly, point: &Element<'dr, D>, value: &Element<'dr, D>| OpeningClaim {
        poly,
        point: point.clone(),
        value: value.clone(),
    };
    vec![
        claim(base, w, &restriction_at_w),
        claim(base + 1, u, v),
        claim(base + 2, u, a_at_u),
        claim(base + 3, u, b_at_u),
    ]
}

/// What one side's scalar checks leave: the batched claim's value, the
/// prover's $c$ and the IPA's $c b z$, the full-width scalars the other
/// side scales by.
struct ScalarChecks<'dr, D: Driver<'dr>> {
    v: Element<'dr, D>,
    c: Element<'dr, D>,
    cbz: Element<'dr, D>,
}

/// One side's scalar checks: the reduction, the instance's openings, the
/// batch and the IPA's scalars, over the challenges' lifts.
fn scalar_checks<'dr, D: Driver<'dr>, R: Rank>(
    dr: &mut D,
    public: &revdot::Public<'dr, D>,
    challenges: &transcript::Challenges<'dr, D>,
    reduction: &revdot::Messages<'dr, D>,
    extra: Vec<OpeningClaim<Element<'dr, D>>>,
    evaluations: &[Element<'dr, D>],
    c: &Element<'dr, D>,
) -> Result<ScalarChecks<'dr, D>> {
    let lifts = revdot::Challenges {
        z: challenges.sampled.z.lift.clone(),
        weights: Weights {
            mu: challenges.weights.mu.lift.clone(),
            nu: challenges.weights.nu.lift.clone(),
            mu_prime: challenges.weights.mu_prime.lift.clone(),
            nu_prime: challenges.weights.nu_prime.lift.clone(),
        },
        rho: challenges.rho.lift.clone(),
        r: challenges.r.lift.clone(),
    };
    let mut claims = revdot::verify::<_, R>(dr, public, &lifts, reduction)?;
    claims.extend(extra);
    let polys = Derived::ALL.len() + 2 + crate::compress::instance::OPENED;
    let batched = batch::verify(
        dr,
        &claims,
        polys,
        &batch::Challenges {
            alpha: challenges.alpha.lift.clone(),
            u: challenges.u.lift.clone(),
            beta: challenges.beta.lift.clone(),
        },
        &batch::Messages {
            evaluations: evaluations.to_vec(),
        },
    )?;
    let scalars = ipa::verify(
        dr,
        &batched.point,
        &batched.value,
        &ipa::Challenges {
            xi: challenges.xi.lift.clone(),
            z: challenges.z.lift.clone(),
            rounds: challenges
                .rounds
                .iter()
                .map(|round| round.lift.clone())
                .collect(),
        },
        &ipa::Messages { c: c.clone() },
    )?;
    Ok(ScalarChecks {
        v: batched.value,
        c: c.clone(),
        cbz: scalars.u.negate(dr),
    })
}

/// One side's point checks for the other curve: the derived commitments,
/// the batched commitment and the IPA's final check, over the challenges'
/// endoscalars, with `reduction` the fold's two error commitments and $p$
/// and $q$, and `extra` the instance's four opened commitments.
#[allow(clippy::too_many_arguments)]
fn point_checks<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    claims: Vec<derive::Claim<'dr, D, P>>,
    weights: &Weights<Endoscalar<'dr, D>>,
    reduction: [&Point<'dr, D, P>; 4],
    extra: [&Point<'dr, D, P>; 4],
    f: &Point<'dr, D, P>,
    beta: &Endoscalar<'dr, D>,
    opening: &derive::Opening<'dr, D, P>,
    xi: &Endoscalar<'dr, D>,
    rounds: &[Endoscalar<'dr, D>],
    scalars: &derive::Scalars<'dr, D>,
    fixed: Fixed<P>,
    bank: &mut NonzeroBank<'dr, D>,
) -> Result<()> {
    let [a, dilated, raw] = derive::fold(dr, &claims, weights, bank)?;
    let [inner, outer, p, q] = reduction;
    let commitments: Vec<Point<'dr, D, P>> = [&a, &dilated, &raw, inner, outer, p, q]
        .into_iter()
        .chain(extra)
        .cloned()
        .collect();
    let h = derive::batched(dr, f, &commitments, beta, bank)?;
    derive::enforce_opening(dr, &h, opening, xi, rounds, scalars, fixed, bank)
}

/// The circuit-field side of the decompressed verifier.
pub(crate) fn circuit_field_side<'dr, D, C, R, const HEADER_SIZE: usize>(
    dr: &mut D,
    params: &'dr C::Params,
    witness: &Witness<C>,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: IpaCycle,
    R: Rank,
{
    let poseidon = C::circuit_poseidon(params);
    let instance = &witness.proof.instance;
    let nested_generators = C::nested_generators(params);

    // The instance, allocated as the transcript absorbs it: the scalar
    // field's values through the bridges the native transcript forms.
    let bridge = |dr: &mut D, point: C::HostCurve| -> Result<Point<'dr, D, C::NestedCurve>> {
        let (x, y) = point
            .coordinates()
            .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
        let g = nested_generators.g();
        let commitment: C::NestedCurve = (g[0] * x + (g[1] * y)).to_affine();
        Point::alloc(dr, D::just(|| commitment))
    };
    let bridged = |dr: &mut D, scalar: C::ScalarField| -> Result<Point<'dr, D, C::NestedCurve>> {
        let g = nested_generators.g();
        let commitment: C::NestedCurve = (g[0] * scalar).to_affine();
        Point::alloc(dr, D::just(|| commitment))
    };
    let mut native_bridges = Vec::with_capacity(instance.native.len());
    for &commitment in &instance.native {
        native_bridges.push(bridge(dr, commitment)?);
    }
    let nested_points = points(dr, instance.nested.iter().copied())?;
    let allocated = transcript::Instance {
        circuit_id: element(dr, instance.circuit_id.omega_j())?,
        left_header: elements(dr, instance.left_header.iter().copied())?,
        right_header: elements(dr, instance.right_header.iter().copied())?,
        native: native_bridges,
        native_registry_xy: bridge(dr, instance.native_registry_xy)?,
        native_p: bridge(dr, instance.native_p)?,
        nested: nested_points,
        nested_registry_xy: point(dr, instance.nested_registry_xy)?,
        nested_p: point(dr, instance.nested_p)?,
        nested_challenges_partial: point(dr, instance.nested_challenges_partial)?,
        bridge_alpha: bridged(dr, instance.bridge_alpha)?,
        c: element(dr, instance.c)?,
        v: element(dr, instance.v)?,
        nested_c: bridged(dr, instance.nested_c)?,
        nested_v: bridged(dr, instance.nested_v)?,
        left: transcript::Child {
            x: element(dr, instance.left.x)?,
            y: element(dr, instance.left.y)?,
            id: element(dr, instance.left.id)?,
        },
        right: transcript::Child {
            x: element(dr, instance.right.x)?,
            y: element(dr, instance.right.y)?,
            id: element(dr, instance.right.id)?,
        },
        a_at_u: element(dr, instance.a_at_u)?,
        b_at_u: element(dr, instance.b_at_u)?,
        nested_left: transcript::NestedChild {
            x: bridged(dr, instance.nested_left.x)?,
            y: bridged(dr, instance.nested_left.y)?,
        },
        nested_right: transcript::NestedChild {
            x: bridged(dr, instance.nested_right.x)?,
            y: bridged(dr, instance.nested_right.y)?,
        },
        nested_a_at_u: bridged(dr, instance.nested_a_at_u)?,
        nested_b_at_u: bridged(dr, instance.nested_b_at_u)?,
    };
    let header = elements(dr, witness.header.iter().copied())?;
    let nested_at = |component| &allocated.nested[nested_position(component)];
    let bridge_at = |index| nested_at(nested::RxComponent::Rx(index));

    // The fuse's challenges, replayed from the bridge commitments under the
    // fuse's tag, each read as an endoscalar as the fuse's circuits read
    // them.
    let fuse = {
        use nested::RxIndex::*;
        let mut t = Transcript::new(dr, poseidon, RAGU_TAG)?;
        let squeeze = RawChallenge::squeeze;
        bridge_at(BridgePreamble).absorb(dr, &mut t)?;
        let w = squeeze(dr, &mut t)?;
        bridge_at(BridgeSPrime).absorb(dr, &mut t)?;
        let y = squeeze(dr, &mut t)?;
        let z = squeeze(dr, &mut t)?;
        bridge_at(BridgeInnerError).absorb(dr, &mut t)?;
        let mu = squeeze(dr, &mut t)?;
        let nu = squeeze(dr, &mut t)?;
        bridge_at(BridgeOuterError).absorb(dr, &mut t)?;
        let mu_prime = squeeze(dr, &mut t)?;
        let nu_prime = squeeze(dr, &mut t)?;
        bridge_at(BridgeAB).absorb(dr, &mut t)?;
        let x = squeeze(dr, &mut t)?;
        bridge_at(BridgeQuery).absorb(dr, &mut t)?;
        let alpha = squeeze(dr, &mut t)?;
        bridge_at(BridgeF).absorb(dr, &mut t)?;
        let u = squeeze(dr, &mut t)?;
        bridge_at(BridgeEval).absorb(dr, &mut t)?;
        let pre_beta = squeeze(dr, &mut t)?;
        [w, y, z, mu, nu, mu_prime, nu_prime, x, alpha, u, pre_beta]
    };

    // The targets, through the proof inputs the fuse derives them with,
    // bound to the instance and the replayed challenges.
    let unified = instance.unified(&witness.fuse);
    let proof_inputs = ProofInputs::<D, C, HEADER_SIZE>::alloc_from_parts(
        dr,
        D::just(|| instance.left_header.as_slice()),
        D::just(|| instance.right_header.as_slice()),
        D::just(|| witness.header.as_slice()),
        D::just(|| instance.circuit_id.omega_j()),
        D::just(|| &unified),
    )?;
    {
        use nested::RxIndex::*;
        let out = &proof_inputs.unified;
        for (ours, theirs) in [
            (bridge_at(BridgePreamble), &out.bridge_preamble_commitment),
            (bridge_at(BridgeSPrime), &out.bridge_s_prime_commitment),
            (
                bridge_at(BridgeInnerError),
                &out.bridge_inner_error_commitment,
            ),
            (
                bridge_at(BridgeOuterError),
                &out.bridge_outer_error_commitment,
            ),
            (bridge_at(BridgeAB), &out.bridge_ab_commitment),
            (bridge_at(BridgeQuery), &out.bridge_query_commitment),
            (bridge_at(BridgeF), &out.bridge_f_commitment),
            (bridge_at(BridgeEval), &out.bridge_eval_commitment),
            (
                &allocated.nested_challenges_partial,
                &out.nested_challenges_partial,
            ),
            (&allocated.nested_p, &out.nested_p_commitment),
            (
                nested_at(nested::RxComponent::AbA),
                &out.nested_a_commitment,
            ),
            (
                nested_at(nested::RxComponent::AbB),
                &out.nested_b_commitment,
            ),
            (
                &allocated.nested_registry_xy,
                &out.nested_registry_xy_commitment,
            ),
        ] {
            ours.enforce_equal(dr, theirs)?;
        }
        for (ours, theirs) in fuse.iter().zip([
            &out.w,
            &out.y,
            &out.z,
            &out.mu,
            &out.nu,
            &out.mu_prime,
            &out.nu_prime,
            &out.x,
            &out.alpha,
            &out.u,
            &out.pre_beta,
        ]) {
            ours.raw.enforce_equal(dr, theirs)?;
        }
        allocated.c.enforce_equal(dr, &out.c)?;
        allocated.v.enforce_equal(dr, &out.v)?;
        allocated
            .circuit_id
            .enforce_equal(dr, &proof_inputs.circuit_id)?;
        for (ours, theirs) in allocated
            .left_header
            .iter()
            .zip(proof_inputs.children.left.iter())
            .chain(
                allocated
                    .right_header
                    .iter()
                    .zip(proof_inputs.children.right.iter()),
            )
            .chain(header.iter().zip(proof_inputs.output_header.iter()))
        {
            ours.enforce_equal(dr, theirs)?;
        }
    }

    // The compression's transcript over the statement and both curves'
    // messages.
    let native_messages = {
        let m = &witness.proof.native;
        let mut rounds = Vec::with_capacity(m.opening.rounds.len());
        for &(l, r) in &m.opening.rounds {
            rounds.push((bridge(dr, l)?, bridge(dr, r)?));
        }
        transcript::Messages {
            inner: bridge(dr, m.reduction.fold.inner)?,
            outer: bridge(dr, m.reduction.fold.outer)?,
            inner_epsilon: element(dr, m.reduction.fold.inner_epsilon)?,
            outer_epsilon: element(dr, m.reduction.fold.outer_epsilon)?,
            p: bridge(dr, m.reduction.p)?,
            q: bridge(dr, m.reduction.q)?,
            openings: elements(dr, m.reduction.openings.iter().copied())?,
            p_at_inverse_r: element(dr, m.reduction.p_at_inverse_r)?,
            q_at_r: element(dr, m.reduction.q_at_r)?,
            f: bridge(dr, m.batch.f)?,
            evaluations: elements(dr, m.batch.evaluations.iter().copied())?,
            s_commitment: bridge(dr, m.opening.s_commitment)?,
            rounds,
            c: element(dr, m.opening.c)?,
        }
    };
    let nested_messages = {
        let m = &witness.proof.nested;
        let mut rounds = Vec::with_capacity(m.opening.rounds.len());
        for &(l, r) in &m.opening.rounds {
            rounds.push((point(dr, l)?, point(dr, r)?));
        }
        let mut openings = Vec::with_capacity(m.reduction.openings.len());
        for &opened in &m.reduction.openings {
            openings.push(bridged(dr, opened)?);
        }
        let mut evaluations = Vec::with_capacity(m.batch.evaluations.len());
        for &value in &m.batch.evaluations {
            evaluations.push(bridged(dr, value)?);
        }
        transcript::Messages {
            inner: point(dr, m.reduction.fold.inner)?,
            outer: point(dr, m.reduction.fold.outer)?,
            inner_epsilon: bridged(dr, m.reduction.fold.inner_epsilon)?,
            outer_epsilon: bridged(dr, m.reduction.fold.outer_epsilon)?,
            p: point(dr, m.reduction.p)?,
            q: point(dr, m.reduction.q)?,
            openings,
            p_at_inverse_r: bridged(dr, m.reduction.p_at_inverse_r)?,
            q_at_r: bridged(dr, m.reduction.q_at_r)?,
            f: point(dr, m.batch.f)?,
            evaluations,
            s_commitment: point(dr, m.opening.s_commitment)?,
            rounds,
            c: bridged(dr, m.opening.c)?,
        }
    };
    let (native_challenges, nested_challenges) = transcript::replay(
        dr,
        poseidon,
        &allocated,
        &header,
        &native_messages,
        &nested_messages,
    )?;

    // The host curve's field checks.
    {
        let side = &witness.native;
        let y = &native_challenges.sampled.y.lift;
        let (unified_target, unified_bridge) = proof_inputs.unified_ky_values(dr, y)?;
        let application = proof_inputs.application_ky(dr, y)?;
        let targets = NativeTargets {
            c: allocated.c.clone(),
            application,
            unified_bridge,
            unified: unified_target,
            one: Element::one(),
            zero: Element::zero(dr),
        };
        let targets: Vec<_> = native::claims::ky_values(&targets)
            .take(side.kinds.len())
            .collect();
        let restrictions = side
            .restrictions
            .iter()
            .map(|&(circuit, value)| Ok((circuit, element(dr, value)?)))
            .collect::<Result<Vec<_>>>()?;
        let bindings = bindings(dr, &side.masked)?;
        // The bindings' values the instance supplies: the preamble's
        // children, the eval stage's a(u) and b(u), and the points
        // stages' coordinates of the nested commitments.
        let (l, r) = (&allocated.left, &allocated.right);
        bind_expected(
            dr,
            &bindings[0],
            0..6,
            &[
                l.x.clone(),
                l.y.clone(),
                l.id.clone(),
                r.x.clone(),
                r.y.clone(),
                r.id.clone(),
            ],
        )?;
        bind_expected(
            dr,
            &bindings[2],
            [3, 4],
            &[allocated.a_at_u.clone(), allocated.b_at_u.clone()],
        )?;
        let [ax, ay] = coordinates(dr, nested_at(nested::RxComponent::AbA))?;
        let [bx, by] = coordinates(dr, nested_at(nested::RxComponent::AbB))?;
        bind_expected(dr, &bindings[3], 0..4, &[ax, ay, bx, by])?;
        let [gx, gy] = coordinates(dr, &allocated.nested_registry_xy)?;
        bind_expected(dr, &bindings[4], 0..2, &[gx, gy])?;

        let public = revdot::Public {
            kinds: side.kinds.clone(),
            targets,
            restrictions,
            bindings,
            sigma: native_challenges.sampled.sigma.lift.clone(),
        };
        let reduction = revdot::Messages {
            inner_epsilon: native_messages.inner_epsilon.clone(),
            outer_epsilon: native_messages.outer_epsilon.clone(),
            openings: native_messages.openings.clone(),
            p_at_inverse_r: native_messages.p_at_inverse_r.clone(),
            q_at_r: native_messages.q_at_r.clone(),
        };
        let restriction_at_w = element(dr, side.restriction_at_w)?;
        let extra = instance_claims(
            Derived::ALL.len() + 2,
            &native_challenges.sampled.w.lift,
            restriction_at_w,
            &fuse[9].raw,
            &allocated.v,
            &allocated.a_at_u,
            &allocated.b_at_u,
        );
        let checks = scalar_checks::<_, R>(
            dr,
            &public,
            &native_challenges,
            &reduction,
            extra,
            &native_messages.evaluations,
            &native_messages.c,
        )?;
        // The digits the scalar-field side scales by, bound here to the
        // values this side computed.
        Digits::alloc_bound(dr, &checks.v)?;
        Digits::alloc_bound(dr, &checks.c)?;
        Digits::alloc_bound(dr, &checks.cbz)?;
    }

    // The nested curve's point checks, under its challenges' endoscalars.
    NonzeroBank::scope(dr, |dr, bank| {
        let side = &witness.nested;
        let claims = derive::nested_claims(
            dr,
            &allocated.nested,
            &nested_challenges.sampled.z.endoscalar,
            side.masked.iter().map(|&(position, _, _)| {
                nested_components()
                    .nth(position)
                    .expect("a nested component")
            }),
            bank,
        )?;
        let weights = Weights {
            mu: nested_challenges.weights.mu.endoscalar.clone(),
            nu: nested_challenges.weights.nu.endoscalar.clone(),
            mu_prime: nested_challenges.weights.mu_prime.endoscalar.clone(),
            nu_prime: nested_challenges.weights.nu_prime.endoscalar.clone(),
        };
        let opening = derive::Opening {
            s_commitment: nested_messages.s_commitment.clone(),
            rounds: nested_messages.rounds.clone(),
            inverse_scaled: points(dr, side.inverse_scaled.iter().copied())?,
            g_prime: point(dr, side.g_prime)?,
        };
        let scalars = derive::Scalars {
            v: Digits::alloc(dr, D::just(|| side.v))?,
            c: Digits::alloc(dr, D::just(|| witness.proof.nested.opening.c))?,
            cbz: Digits::alloc(dr, D::just(|| side.cbz))?,
        };
        point_checks(
            dr,
            claims,
            &weights,
            [
                &nested_messages.inner,
                &nested_messages.outer,
                &nested_messages.p,
                &nested_messages.q,
            ],
            [
                &allocated.nested_registry_xy,
                &allocated.nested_p,
                nested_at(nested::RxComponent::AbA),
                nested_at(nested::RxComponent::AbB),
            ],
            &nested_messages.f,
            &nested_challenges.beta.endoscalar,
            &opening,
            &nested_challenges.xi.endoscalar,
            &nested_challenges
                .rounds
                .iter()
                .map(|round| round.endoscalar.clone())
                .collect::<Vec<_>>(),
            &scalars,
            side.fixed,
            bank,
        )
    })?;

    // The nested stages the native verifier recomputes: the challenge
    // stage from the challenges' endoscalars and the base-case sign, and
    // the ab bridge from its coordinates' digits.
    NonzeroBank::scope(dr, |dr, bank| {
        let g = nested_generators.g();
        let generator = |dr: &mut D, i: usize| Point::constant(dr, g[generator_index::<C, R>(i)]);
        let mut acc: Option<Point<'dr, D, C::NestedCurve>> = None;
        for (i, challenge) in fuse.iter().take(challenge_stage::NUM).enumerate() {
            let base = generator(dr, i)?;
            let term = challenge.endoscalar.group_scale(dr, &base)?;
            acc = Some(match acc {
                None => term,
                Some(acc) => acc.add_incomplete(dr, &term, bank)?,
            });
        }
        let dummy = Element::constant(dr, C::CircuitField::from(Suffix::internal(2).get()));
        let left_dummy = allocated.left_header[HEADER_SIZE - 1].is_equal(dr, &mut (), &dummy)?;
        let right_dummy = allocated.right_header[HEADER_SIZE - 1].is_equal(dr, &mut (), &dummy)?;
        let base_case = left_dummy.and(dr, &right_dummy)?;
        let sign = generator(dr, challenge_stage::SIGN_INDEX)?;
        let negate = base_case.not(dr);
        let sign = sign.conditional_negate(dr, &negate)?;
        let acc = acc.expect("the stage has challenges");
        let acc = acc.add_incomplete(dr, &sign, bank)?;
        let beta = generator(dr, challenge_stage::BETA_INDEX)?;
        let beta = fuse[10].endoscalar.group_scale(dr, &beta)?;
        let acc = acc.add_incomplete(dr, &beta, bank)?;
        acc.enforce_equal(dr, bridge_at(nested::RxIndex::ChallengeStage))?;

        let ab = {
            let a = instance.native_commitment(native::RxComponent::AbA);
            let b = instance.native_commitment(native::RxComponent::AbB);
            let points_ab =
                instance.native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb));
            let coordinates = |point: C::HostCurve| -> Result<[C::ScalarField; 2]> {
                let (x, y) = point
                    .coordinates()
                    .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
                Ok([x, y])
            };
            let value = |which: AbValue| -> Result<C::ScalarField> {
                Ok(match which {
                    AbValue::A(i) => coordinates(a)?[i],
                    AbValue::B(i) => coordinates(b)?[i],
                    AbValue::PointsAb(i) => coordinates(points_ab)?[i],
                    AbValue::Alpha => {
                        bridge_alpha_power(instance.bridge_alpha, nested::RxIndex::BridgeAB)
                    }
                })
            };
            let mut acc: Option<Point<'dr, D, C::NestedCurve>> = None;
            for &(index, which) in &witness.ab_terms {
                let base = Point::constant(dr, g[index])?;
                let digits = Digits::alloc(dr, D::try_just(|| value(which))?)?;
                let term = derive::scale(dr, &base, &digits, *C::nested_u(params), bank)?;
                acc = Some(match acc {
                    None => term,
                    Some(acc) => acc.add_incomplete(dr, &term, bank)?,
                });
            }
            acc.expect("the ab bridge has coefficients")
        };
        ab.enforce_equal(dr, bridge_at(nested::RxIndex::BridgeAB))
    })?;

    Ok(())
}

/// The scalar-field side of the decompressed verifier.
pub(crate) fn scalar_field_side<'dr, D, C, R>(dr: &mut D, witness: &Witness<C>) -> Result<()>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle,
    R: Rank,
{
    let instance = &witness.proof.instance;
    let side = &witness.nested;

    // The fuse's challenges' lifts, from their endoscalars.
    let fuse_lift = |dr: &mut D, raw: C::CircuitField| -> Result<Element<'dr, D>> {
        endoscalar(dr, raw)?.lift(dr)
    };
    let fuse_x = fuse_lift(dr, witness.fuse.x)?;
    let fuse_y = fuse_lift(dr, witness.fuse.y)?;
    let fuse_u = fuse_lift(dr, witness.fuse.u)?;

    // The nested unified output, bound to the lifts, and the host curve's
    // commitments it exports.
    let nested_unified = instance.nested_unified(&witness.fuse)?;
    let output =
        nested_unified::Output::<D, C::HostCurve>::alloc(dr, &mut (), D::just(|| &nested_unified))?;
    output.x.enforce_equal(dr, &fuse_x)?;
    output.y.enforce_equal(dr, &fuse_y)?;
    output.u.enforce_equal(dr, &fuse_u)?;
    let exported_components = {
        use native::{RxComponent::*, RxIndex::*};
        [
            Rx(Preamble),
            Rx(InnerError),
            Rx(OuterError),
            Rx(Query),
            Rx(Eval),
            AbA,
            AbB,
        ]
    };
    let mut native_points: Vec<Option<Point<'dr, D, C::HostCurve>>> =
        vec![None; instance.native.len()];
    for (component, exported) in exported_components.iter().zip(output.exported.iter()) {
        native_points[native_position(*component)] = Some(exported.clone());
    }
    let native_registry_xy = output.exported[7].clone();
    let native_p = output.exported[8].clone();
    {
        use native::{RxComponent::Rx, RxIndex::*};
        for (i, index) in [
            PointsBinding,
            PointsChildren,
            PointsRegistryWx,
            PointsAb,
            PointsF,
        ]
        .into_iter()
        .enumerate()
        {
            native_points[native_position(Rx(index))] = Some(output.exported[9 + i].clone());
        }
    }
    let mut commitments = Vec::with_capacity(native_points.len());
    for (position, allocated) in native_points.into_iter().enumerate() {
        commitments.push(match allocated {
            Some(point) => point,
            None => point(dr, instance.native[position])?,
        });
    }

    // The compression's challenges for this curve, lifted from their
    // endoscalars, as the transcript gadget on the other side yields them.
    let challenge = |dr: &mut D, raw: C::ScalarField| -> Result<Challenge<'dr, D>> {
        let endoscalar = endoscalar(dr, raw)?;
        let lift = endoscalar.lift(dr)?;
        Ok(Challenge { endoscalar, lift })
    };
    let challenges = {
        let raw = &side.raw;
        let mut rounds = Vec::with_capacity(raw.rounds.len());
        for &u_j in &raw.rounds {
            rounds.push(challenge(dr, u_j)?);
        }
        transcript::Challenges {
            sampled: Sampled {
                w: challenge(dr, raw.sampled.w)?,
                y: challenge(dr, raw.sampled.y)?,
                z: challenge(dr, raw.sampled.z)?,
                sigma: challenge(dr, raw.sampled.sigma)?,
            },
            weights: Weights {
                mu: challenge(dr, raw.weights.mu)?,
                nu: challenge(dr, raw.weights.nu)?,
                mu_prime: challenge(dr, raw.weights.mu_prime)?,
                nu_prime: challenge(dr, raw.weights.nu_prime)?,
            },
            rho: challenge(dr, raw.rho)?,
            r: challenge(dr, raw.r)?,
            alpha: challenge(dr, raw.alpha)?,
            u: challenge(dr, raw.u)?,
            beta: challenge(dr, raw.beta)?,
            xi: challenge(dr, raw.xi)?,
            z: challenge(dr, raw.ipa_z)?,
            rounds,
        }
    };

    // The nested curve's field checks.
    {
        let targets = NestedTargets {
            c: output.c.clone(),
            unified: output.ky(dr, &challenges.sampled.y.lift)?,
            one: Element::one(),
            zero: Element::zero(dr),
        };
        let targets: Vec<_> = nested::claims::ky_values(&targets)
            .take(side.kinds.len())
            .collect();
        let restrictions = side
            .restrictions
            .iter()
            .map(|&(circuit, value)| Ok((circuit, element(dr, value)?)))
            .collect::<Result<Vec<_>>>()?;
        let bindings = bindings(dr, &side.masked)?;
        let (l, r) = (instance.nested_left, instance.nested_right);
        let children = elements(dr, [l.x, l.y, r.x, r.y])?;
        bind_expected(dr, &bindings[0], 0..4, &children)?;
        let at_u = elements(dr, [instance.nested_a_at_u, instance.nested_b_at_u])?;
        bind_expected(dr, &bindings[2], [3, 4], &at_u)?;

        let m = &witness.proof.nested;
        let public = revdot::Public {
            kinds: side.kinds.clone(),
            targets,
            restrictions,
            bindings,
            sigma: challenges.sampled.sigma.lift.clone(),
        };
        let reduction = revdot::Messages {
            inner_epsilon: element(dr, m.reduction.fold.inner_epsilon)?,
            outer_epsilon: element(dr, m.reduction.fold.outer_epsilon)?,
            openings: elements(dr, m.reduction.openings.iter().copied())?,
            p_at_inverse_r: element(dr, m.reduction.p_at_inverse_r)?,
            q_at_r: element(dr, m.reduction.q_at_r)?,
        };
        let restriction_at_w = element(dr, side.restriction_at_w)?;
        let extra = instance_claims(
            Derived::ALL.len() + 2,
            &challenges.sampled.w.lift,
            restriction_at_w,
            &fuse_u,
            &output.v,
            &at_u[0],
            &at_u[1],
        );
        let evaluations = elements(dr, m.batch.evaluations.iter().copied())?;
        let c = element(dr, m.opening.c)?;
        let checks = scalar_checks::<_, R>(
            dr,
            &public,
            &challenges,
            &reduction,
            extra,
            &evaluations,
            &c,
        )?;
        Digits::alloc_bound(dr, &checks.v)?;
        Digits::alloc_bound(dr, &checks.c)?;
        Digits::alloc_bound(dr, &checks.cbz)?;

        // The ab bridge's coordinates and blinding, whose digits the other
        // side scales generators by, bound here to the exported points and
        // the instance's bridge_alpha.
        let [ax, ay] = coordinates(dr, &commitments[native_position(native::RxComponent::AbA)])?;
        let [bx, by] = coordinates(dr, &commitments[native_position(native::RxComponent::AbB)])?;
        let [px, py] = coordinates(
            dr,
            &commitments[native_position(native::RxComponent::Rx(native::RxIndex::PointsAb))],
        )?;
        let bridge_alpha = element(dr, instance.bridge_alpha)?;
        let alpha = bridge_alpha.square(dr)?;
        for (_, which) in &witness.ab_terms {
            let value = match which {
                AbValue::A(0) => &ax,
                AbValue::A(_) => &ay,
                AbValue::B(0) => &bx,
                AbValue::B(_) => &by,
                AbValue::PointsAb(0) => &px,
                AbValue::PointsAb(_) => &py,
                AbValue::Alpha => &alpha,
            };
            Digits::alloc_bound(dr, value)?;
        }
    }

    // The host curve's point checks, under the native challenges'
    // endoscalars.
    let native = &witness.native;
    let (z, weights, beta, xi, rounds) = {
        let raw = &native.raw;
        let mut rounds = Vec::with_capacity(raw.rounds.len());
        for &u_j in &raw.rounds {
            rounds.push(endoscalar(dr, u_j)?);
        }
        (
            endoscalar(dr, raw.sampled.z)?,
            Weights {
                mu: endoscalar(dr, raw.weights.mu)?,
                nu: endoscalar(dr, raw.weights.nu)?,
                mu_prime: endoscalar(dr, raw.weights.mu_prime)?,
                nu_prime: endoscalar(dr, raw.weights.nu_prime)?,
            },
            endoscalar(dr, raw.beta)?,
            endoscalar(dr, raw.xi)?,
            rounds,
        )
    };
    NonzeroBank::scope(dr, |dr, bank| {
        let m = &witness.proof.native;
        let claims = derive::native_claims(
            dr,
            &commitments,
            instance.circuit_id,
            &z,
            native.masked.iter().map(|&(position, _, _)| {
                native_components()
                    .nth(position)
                    .expect("a native component")
            }),
            bank,
        )?;
        let mut round_points = Vec::with_capacity(m.opening.rounds.len());
        for &(l, r) in &m.opening.rounds {
            round_points.push((point(dr, l)?, point(dr, r)?));
        }
        let opening = derive::Opening {
            s_commitment: point(dr, m.opening.s_commitment)?,
            rounds: round_points,
            inverse_scaled: points(dr, native.inverse_scaled.iter().copied())?,
            g_prime: point(dr, native.g_prime)?,
        };
        let scalars = derive::Scalars {
            v: Digits::alloc(dr, D::just(|| native.v))?,
            c: Digits::alloc(dr, D::just(|| m.opening.c))?,
            cbz: Digits::alloc(dr, D::just(|| native.cbz))?,
        };
        let inner = point(dr, m.reduction.fold.inner)?;
        let outer = point(dr, m.reduction.fold.outer)?;
        let p = point(dr, m.reduction.p)?;
        let q = point(dr, m.reduction.q)?;
        let f = point(dr, m.batch.f)?;
        point_checks(
            dr,
            claims,
            &weights,
            [&inner, &outer, &p, &q],
            [
                &native_registry_xy,
                &native_p,
                &commitments[native_position(native::RxComponent::AbA)],
                &commitments[native_position(native::RxComponent::AbB)],
            ],
            &f,
            &beta,
            &opening,
            &xi,
            &rounds,
            &scalars,
            native.fixed,
            bank,
        )
    })?;

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/decompress_circuit.rs"]
mod tests;
