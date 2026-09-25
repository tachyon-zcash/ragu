//! Reduction 1: from revdot claims to polynomial openings.
//!
//! The prover forms $t(X) = \sum_i \rho^i a_i(X) b_i(X)$ over the claims,
//! splits it as $t(X) = X^{n-1} p(1/X) + X^n q(X)$, so that $p(0) = \sum_i
//! \rho^i \operatorname{revdot}(a_i, b_i)$, and commits to $p$ and $q$. The
//! verifier squeezes $r$ and checks $\sum_i \rho^i a_i(r) b_i(r) = r^{n-1}
//! p(1/r) + r^n q(r)$ from the claimed openings, then hands every opening it
//! relied on to the batch: each committed polynomial at $r$ and $rz$, $p$ at
//! $1/r$ and at $0$, where it must equal $\sum_i \rho^i k_i(y)$, and $q$ at
//! $r$.
//!
//! Combining products rather than folding vectors leaves no cross terms, so
//! nothing but the two commitments and the claimed openings travels. Both
//! sides take the claims in the decider's order, the prover through
//! [`claims::Builder`](crate::internal::claims::Builder) and the verifier
//! through [`claims::native`] and [`claims::nested`].
//!
//! The transcript is assumed to have seen the commitments the claims are
//! over, and $y$ and $z$ to have been squeezed from it.

use alloc::{borrow::Cow, vec, vec::Vec};

use ragu_arithmetic::{
    CurveAffine, Cycle, FixedGenerators, decomp_poly, eval, ff::Field, poly_mul,
};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use ragu_core::{Error, Result};

use super::claims::{self, Evaluated, Masked, NativePolys, NestedPolys, Opened};
use crate::{
    Proof,
    internal::{
        claims::Builder,
        ky::{NativeKy, NestedKy},
        native, nested,
    },
    ipa::IpaTranscript,
};

/// An opening claim: the polynomial at `poly` in an [`Openings`]' list takes
/// `value` at `point`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpeningClaim<F> {
    pub poly: usize,
    pub point: F,
    pub value: F,
}

/// The opening claims a reduction leaves for the batch, over the committed
/// polynomials they refer to: the components in order, then $p$, then $q$.
#[derive(Clone, Debug)]
pub(crate) struct Openings<C: CurveAffine> {
    pub commitments: Vec<C>,
    pub claims: Vec<OpeningClaim<C::Scalar>>,
}

/// The prover's messages of the reduction on one curve.
#[derive(Clone, Debug)]
pub(crate) struct Reduction<C: CurveAffine> {
    /// The commitment to $p$.
    pub p: C,
    /// The commitment to $q$.
    pub q: C,
    /// Each committed polynomial's claimed openings at $r$ and $rz$, in
    /// component order.
    pub openings: Vec<Opened<C::Scalar>>,
    /// The claimed $p(1/r)$.
    pub p_at_inverse_r: C::Scalar,
    /// The claimed $q(r)$.
    pub q_at_r: C::Scalar,
}

/// What the prover keeps to open $p$ and $q$ in the batch.
pub(crate) struct Witness<F> {
    /// The point the claims were opened at.
    pub r: F,
    /// $p$, with $n$ coefficients.
    pub p: Vec<F>,
    /// $q$, padded to $n$ coefficients.
    pub q: Vec<F>,
}

impl<F: Field> Witness<F> {
    /// The openings the verifier will require of `reduction` over
    /// `commitments`, the components' in order, as [`verify`] lists them,
    /// with $p(0)$ read off $p$.
    pub(crate) fn openings<C: CurveAffine<ScalarExt = F>>(
        &self,
        commitments: Vec<C>,
        reduction: &Reduction<C>,
        z: F,
    ) -> Result<Openings<C>> {
        let inverse_r = invert(self.r)?;
        Ok(openings(
            commitments,
            reduction,
            self.r,
            z,
            inverse_r,
            self.p[0],
        ))
    }

    /// The polynomials behind an [`Openings`]' commitments, in its order:
    /// `committed` in component order, then $p$, then $q$.
    pub(crate) fn polys<'a, R: Rank>(
        &'a self,
        committed: impl IntoIterator<Item = &'a sparse::Polynomial<F, R>>,
    ) -> Vec<Cow<'a, sparse::Polynomial<F, R>>> {
        committed
            .into_iter()
            .map(Cow::Borrowed)
            .chain([
                Cow::Owned(sparse::Polynomial::from_coeffs(self.p.clone())),
                Cow::Owned(sparse::Polynomial::from_coeffs(self.q.clone())),
            ])
            .collect()
    }
}

/// The native components in the order their openings are listed.
pub(crate) fn native_components() -> impl Iterator<Item = native::RxComponent> {
    [native::RxComponent::AbA, native::RxComponent::AbB]
        .into_iter()
        .chain(
            native::RxIndex::ALL
                .into_iter()
                .map(native::RxComponent::Rx),
        )
}

/// The position of a native component in [`native_components`].
pub(crate) fn native_position(component: native::RxComponent) -> usize {
    match component {
        native::RxComponent::AbA => 0,
        native::RxComponent::AbB => 1,
        native::RxComponent::Rx(index) => {
            2 + native::RxIndex::ALL
                .iter()
                .position(|&listed| listed == index)
                .expect("every native index is listed")
        }
    }
}

/// The nested components in the order their openings are listed.
pub(crate) fn nested_components() -> impl Iterator<Item = nested::RxComponent> {
    [nested::RxComponent::AbA, nested::RxComponent::AbB]
        .into_iter()
        .chain(
            nested::RxIndex::ALL
                .into_iter()
                .map(nested::RxComponent::Rx),
        )
}

/// The position of a nested component in [`nested_components`].
pub(crate) fn nested_position(component: nested::RxComponent) -> usize {
    match component {
        nested::RxComponent::AbA => 0,
        nested::RxComponent::AbB => 1,
        nested::RxComponent::Rx(index) => {
            2 + nested::RxIndex::ALL
                .iter()
                .position(|&listed| listed == index)
                .expect("every nested index is listed")
        }
    }
}

/// The prover's reduction on one curve: `claims` are the $(a_i, b_i)$
/// coefficient vectors in claim order, and `committed` the polynomials to
/// open, in component order.
fn reduce<C: CurveAffine, R: Rank, T: IpaTranscript<C>>(
    claims: impl Iterator<Item = (Vec<C::Scalar>, Vec<C::Scalar>)>,
    committed: &[&sparse::Polynomial<C::Scalar, R>],
    generators: &impl FixedGenerators<C>,
    z: C::Scalar,
    transcript: &mut T,
) -> Result<(Reduction<C>, Witness<C::Scalar>)> {
    let n = R::num_coeffs();
    let rho = transcript.squeeze_challenge()?;

    // t = \sum_i \rho^i a_i b_i
    let mut t = vec![C::Scalar::ZERO; 2 * n - 1];
    let mut product = Vec::new();
    let mut weight = C::Scalar::ONE;
    for (a, b) in claims {
        poly_mul(&a, &b, &mut product);
        for (t, c) in t.iter_mut().zip(&product) {
            *t += weight * c;
        }
        weight *= rho;
    }

    let (p, mut q) = decomp_poly(t, n);
    q.resize(n, C::Scalar::ZERO);
    let commit = |coeffs: &[C::Scalar]| {
        sparse::Polynomial::<_, R>::from_coeffs(coeffs.to_vec()).commit_to_affine(generators)
    };
    let p_commitment = commit(&p);
    let q_commitment = commit(&q);
    transcript.write_point(p_commitment)?;
    transcript.write_point(q_commitment)?;

    let r = transcript.squeeze_challenge()?;
    let inverse_r = invert(r)?;
    let mut openings = Vec::with_capacity(committed.len());
    for poly in committed {
        let opened = Opened {
            at_r: poly.eval(r),
            at_rz: poly.eval(r * z),
        };
        transcript.write_scalar(opened.at_r)?;
        transcript.write_scalar(opened.at_rz)?;
        openings.push(opened);
    }
    let p_at_inverse_r = eval(&p, inverse_r);
    let q_at_r = eval(&q, r);
    transcript.write_scalar(p_at_inverse_r)?;
    transcript.write_scalar(q_at_r)?;

    Ok((
        Reduction {
            p: p_commitment,
            q: q_commitment,
            openings,
            p_at_inverse_r,
            q_at_r,
        },
        Witness { r, p, q },
    ))
}

/// The verifier's side on one curve: `evaluate` gives the claims at $r$ from
/// the claimed openings, and `commitments` are the committed polynomials in
/// component order. Returns the opening claims the batch must prove, or
/// `None` if the reduction does not hold.
fn verify<C: CurveAffine, R: Rank, T: IpaTranscript<C>>(
    evaluate: impl FnOnce(C::Scalar, &[Opened<C::Scalar>]) -> Result<Vec<Evaluated<C::Scalar>>>,
    commitments: Vec<C>,
    reduction: &Reduction<C>,
    z: C::Scalar,
    transcript: &mut T,
) -> Result<Option<Openings<C>>> {
    let n = R::num_coeffs();
    if reduction.openings.len() != commitments.len() {
        return Err(Error::InvalidWitness(
            "one pair of openings per committed polynomial".into(),
        ));
    }

    let rho = transcript.squeeze_challenge()?;
    transcript.write_point(reduction.p)?;
    transcript.write_point(reduction.q)?;
    let r = transcript.squeeze_challenge()?;
    let inverse_r = invert(r)?;
    for opened in &reduction.openings {
        transcript.write_scalar(opened.at_r)?;
        transcript.write_scalar(opened.at_rz)?;
    }
    transcript.write_scalar(reduction.p_at_inverse_r)?;
    transcript.write_scalar(reduction.q_at_r)?;

    // \sum_i \rho^i a_i(r) b_i(r) against the split, and the target p(0)
    // must take.
    let evaluated = evaluate(r, &reduction.openings)?;
    let (mut combined, mut target, mut weight) = (C::Scalar::ZERO, C::Scalar::ZERO, C::Scalar::ONE);
    for claim in &evaluated {
        combined += weight * claim.a * claim.b;
        target += weight * claim.k;
        weight *= rho;
    }
    let split = r.pow_vartime([(n - 1) as u64]) * reduction.p_at_inverse_r
        + r.pow_vartime([n as u64]) * reduction.q_at_r;
    if combined != split {
        return Ok(None);
    }

    Ok(Some(openings(
        commitments,
        reduction,
        r,
        z,
        inverse_r,
        target,
    )))
}

/// The opening claims a reduction leaves over `commitments`, the
/// components' in order: each committed polynomial at $r$ and $rz$, $p$ at
/// $1/r$, $q$ at $r$, and $p$ at $0$, where it must equal `target`.
fn openings<C: CurveAffine>(
    mut commitments: Vec<C>,
    reduction: &Reduction<C>,
    r: C::Scalar,
    z: C::Scalar,
    inverse_r: C::Scalar,
    target: C::Scalar,
) -> Openings<C> {
    let rz = r * z;
    let (p, q) = (commitments.len(), commitments.len() + 1);
    let mut claims = Vec::with_capacity(2 * commitments.len() + 3);
    for (poly, opened) in reduction.openings.iter().enumerate() {
        claims.push(OpeningClaim {
            poly,
            point: r,
            value: opened.at_r,
        });
        claims.push(OpeningClaim {
            poly,
            point: rz,
            value: opened.at_rz,
        });
    }
    claims.push(OpeningClaim {
        poly: p,
        point: inverse_r,
        value: reduction.p_at_inverse_r,
    });
    claims.push(OpeningClaim {
        poly: q,
        point: r,
        value: reduction.q_at_r,
    });
    claims.push(OpeningClaim {
        poly: p,
        point: C::Scalar::ZERO,
        value: target,
    });
    commitments.push(reduction.p);
    commitments.push(reduction.q);
    Openings {
        commitments,
        claims,
    }
}

/// The inverse of a challenge, which is zero with negligible probability.
fn invert<F: Field>(value: F) -> Result<F> {
    Option::from(value.invert())
        .ok_or_else(|| Error::InvalidWitness("a zero challenge cannot be inverted".into()))
}

/// The prover's native reduction of `proof`'s claims at `y` and `z`.
pub(crate) fn reduce_native<C: Cycle, R: Rank, B: Backend, T: IpaTranscript<C::HostCurve>>(
    proof: &Proof<C, R>,
    registry: &Registry<'_, C::CircuitField, R>,
    generators: &C::HostGenerators,
    y: C::CircuitField,
    z: C::CircuitField,
    masked: &[Masked<native::RxComponent, C::CircuitField>],
    transcript: &mut T,
) -> Result<(Reduction<C::HostCurve>, Witness<C::CircuitField>)> {
    let mut builder = Builder::<_, C::CircuitField, R, B>::new(registry, y, z);
    native::claims::build(&NativePolys(proof), &mut builder)?;
    let committed: Vec<_> = native_components()
        .map(|component| &proof[component])
        .collect();
    let claims = builder
        .a
        .iter()
        .zip(&builder.b)
        .map(|(a, b)| (a.iter_coeffs().collect(), b.iter_coeffs().collect()))
        .chain(masked.iter().map(|masked| {
            let mut a = proof[masked.poly].clone();
            a.sub_assign(&masked.expected::<R>());
            (
                a.iter_coeffs().collect(),
                masked.mask::<R>().iter_coeffs().collect(),
            )
        }));
    reduce::<_, R, _>(claims, &committed, generators, z, transcript)
}

/// The verifier's native side: `commitment` gives each component's
/// commitment, `registry` the native registry, and `targets` the claims'
/// $k(y)$ values.
pub(crate) fn verify_native<C: Cycle, R: Rank, T: IpaTranscript<C::HostCurve>>(
    circuit_id: CircuitIndex,
    commitment: impl Fn(native::RxComponent) -> C::HostCurve,
    registry: &Registry<'_, C::CircuitField, R>,
    y: C::CircuitField,
    z: C::CircuitField,
    targets: &NativeKy<C::CircuitField>,
    masked: &[Masked<native::RxComponent, C::CircuitField>],
    reduction: &Reduction<C::HostCurve>,
    transcript: &mut T,
) -> Result<Option<Openings<C::HostCurve>>> {
    let commitments: Vec<_> = native_components().map(commitment).collect();
    verify::<_, R, _>(
        |r, openings| {
            claims::native::<R, _>(
                circuit_id,
                r,
                z,
                |component| openings[native_position(component)],
                |circuit| registry.circuit_y(circuit, y).eval(r),
                targets,
                masked,
            )
        },
        commitments,
        reduction,
        z,
        transcript,
    )
}

/// The prover's nested reduction of `proof`'s claims at the nested `y` and
/// `z`.
pub(crate) fn reduce_nested<C: Cycle, R: Rank, B: Backend, T: IpaTranscript<C::NestedCurve>>(
    proof: &Proof<C, R>,
    registry: &Registry<'_, C::ScalarField, R>,
    generators: &C::NestedGenerators,
    y: C::ScalarField,
    z: C::ScalarField,
    masked: &[Masked<nested::RxComponent, C::ScalarField>],
    transcript: &mut T,
) -> Result<(Reduction<C::NestedCurve>, Witness<C::ScalarField>)> {
    let mut builder = Builder::<_, C::ScalarField, R, B>::new(registry, y, z);
    nested::claims::build(&NestedPolys(proof), &mut builder)?;
    let committed: Vec<_> = nested_components()
        .map(|component| &proof[component])
        .collect();
    let claims = builder
        .a
        .iter()
        .zip(&builder.b)
        .map(|(a, b)| (a.iter_coeffs().collect(), b.iter_coeffs().collect()))
        .chain(masked.iter().map(|masked| {
            let mut a = proof[masked.poly].clone();
            a.sub_assign(&masked.expected::<R>());
            (
                a.iter_coeffs().collect(),
                masked.mask::<R>().iter_coeffs().collect(),
            )
        }));
    reduce::<_, R, _>(claims, &committed, generators, z, transcript)
}

/// The verifier's nested side, as [`verify_native`] takes its inputs.
pub(crate) fn verify_nested<C: Cycle, R: Rank, T: IpaTranscript<C::NestedCurve>>(
    commitment: impl Fn(nested::RxComponent) -> C::NestedCurve,
    registry: &Registry<'_, C::ScalarField, R>,
    y: C::ScalarField,
    z: C::ScalarField,
    targets: &NestedKy<C::ScalarField>,
    masked: &[Masked<nested::RxComponent, C::ScalarField>],
    reduction: &Reduction<C::NestedCurve>,
    transcript: &mut T,
) -> Result<Option<Openings<C::NestedCurve>>> {
    let commitments: Vec<_> = nested_components().map(commitment).collect();
    verify::<_, R, _>(
        |r, openings| {
            claims::nested::<R, _>(
                r,
                z,
                |component| openings[nested_position(component)],
                |circuit| registry.circuit_y(circuit, y).eval(r),
                targets,
                masked,
            )
        },
        commitments,
        reduction,
        z,
        transcript,
    )
}

#[cfg(test)]
#[path = "../../tests/compress_revdot.rs"]
mod tests;
