//! The verifier's side of the reduction.

use alloc::vec::Vec;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, Registry},
};
use ragu_core::{Cycle, Error, Result};
use udon::{curve::Affine, field::Field};

use super::{
    Openings, Reduction,
    fold::{self, Derived, Layout},
    invert, openings,
};
use crate::{
    compress::revdot::claims::{self, Kind, Masked, Shape},
    internal::{
        ky::{NativeKy, NestedKy},
        native, nested,
    },
    ipa::IpaTranscript,
};

/// One claim evaluated at $r$: $a(r)$, $b(r)$ and the target $k(y)$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Evaluated<F> {
    /// $a(r)$.
    pub a: F,
    /// $b(r)$.
    pub b: F,
    /// The target $k(y)$.
    pub k: F,
}

/// The verifier's side on one curve: `shapes` are the claims' shapes and
/// `targets` their $k(y)$, one per claim in claim order; `commitment` gives each
/// component's commitment and `public` each kind of claim's public parts
/// of $a$ and $b$ at a point. Returns the opening claims the batch must
/// prove, or `None` if the reduction does not hold.
fn verify<C: Affine, R: Rank, B: Backend, Id: Copy, T: IpaTranscript<C>>(
    shapes: &[Shape<Id, C::Scalar>],
    targets: impl Iterator<Item = C::Scalar>,
    commitment: impl Fn(Id) -> C,
    public: impl Fn(Kind, C::Scalar) -> (C::Scalar, C::Scalar),
    reduction: &Reduction<C>,
    z: C::Scalar,
    transcript: &mut T,
) -> Result<Option<Openings<C>>> {
    let n = R::num_coeffs();
    if reduction.openings.len() != Derived::ALL.len() {
        return Err(Error::InvalidWitness(
            "one opening per derived polynomial".into(),
        ));
    }

    // The fold: its messages, weights and the commitments it derives.
    let layout = Layout::new(shapes.len());
    let weights = reduction.fold.replay(transcript)?;
    let commitments = fold::commitments::<_, B, _>(shapes, &weights, commitment, &reduction.fold);

    let rho = transcript.squeeze_challenge()?;
    transcript.write_point(reduction.p)?;
    transcript.write_point(reduction.q)?;
    let r = transcript.squeeze_challenge()?;
    let inverse_r = invert(r)?;
    for &opened in &reduction.openings {
        transcript.write_scalar(opened)?;
    }
    transcript.write_scalar(reduction.p_at_inverse_r)?;
    transcript.write_scalar(reduction.q_at_r)?;

    // The folded claims at r: (A, B) from the derived openings and the
    // public parts, and each layer's (E, W) from its opening, the weights
    // and the sent epsilon.
    let opened = |which: Derived| reduction.openings[which as usize];
    // One target per claim, materialized: a target stream that ran short
    // would otherwise end the loop early and drop the trailing claims'
    // public parts and targets without a word.
    let targets: Vec<_> = targets.take(shapes.len()).collect();
    if targets.len() != shapes.len() {
        return Err(Error::VectorLengthMismatch {
            expected: shapes.len(),
            actual: targets.len(),
        });
    }
    let (mut a_public, mut b_public, mut target) =
        (C::Scalar::ZERO, C::Scalar::ZERO, C::Scalar::ZERO);
    for (i, shape) in shapes.iter().enumerate() {
        let (a, b) = public(shape.kind, r);
        a_public += weights.a(i) * a;
        b_public += weights.b(i) * b;
        target += weights.a(i) * weights.b(i) * targets[i];
    }
    let messages = &reduction.fold;
    let evaluated = [
        Evaluated {
            a: opened(Derived::A) + a_public,
            b: opened(Derived::B) + opened(Derived::Dilated) + b_public,
            k: target + messages.inner_epsilon + messages.outer_epsilon,
        },
        Evaluated {
            a: opened(Derived::Inner),
            b: weights.inner::<R>(&layout).eval(r),
            k: messages.inner_epsilon,
        },
        Evaluated {
            a: opened(Derived::Outer),
            b: weights.outer::<R>(&layout).eval(r),
            k: messages.outer_epsilon,
        },
    ];

    // \sum_i \rho^i a_i(r) b_i(r) against the split, and the target p(0)
    // must take.
    let (mut combined, mut target, mut weight) = (C::Scalar::ZERO, C::Scalar::ZERO, C::Scalar::ONE);
    for claim in &evaluated {
        combined += weight * claim.a * claim.b;
        target += weight * claim.k;
        weight *= rho;
    }
    let split = r.pow_u64((n - 1) as u64) * reduction.p_at_inverse_r
        + r.pow_u64(n as u64) * reduction.q_at_r;
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

/// A claim's public parts of $a$ and $b$ at `r`, by kind: a wire binding
/// subtracts its expected values from $a$ and has its mask for $b$, a
/// circuit claim's $b$ holds the restriction and $t(z, X)$, a bonding
/// claim's the restriction alone.
fn public<F: Field, R: Rank, Id>(
    kind: Kind,
    r: F,
    z: F,
    restriction: &impl Fn(CircuitIndex) -> F,
    masked: &[Masked<Id, F>],
) -> (F, F) {
    match kind {
        Kind::Raw => (F::ZERO, F::ZERO),
        Kind::Circuit(circuit) => (F::ZERO, restriction(circuit) + R::tz(z).eval(r)),
        Kind::Bonding(circuit) => (F::ZERO, restriction(circuit)),
        Kind::Masked(m) => (-masked[m].expected_at(r), masked[m].mask_at::<R>(r)),
    }
}

/// A circuit's wiring restriction $s_i(r, y)$, read off the registry as the
/// point $m(\omega^i, r, y)$: the restriction's value at $r$, without
/// materializing $s_i(X, y)$ as the decider's claim builder must.
fn restriction_at<F: Field, R: Rank, B: Backend>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    r: F,
    y: F,
) -> F {
    B::registry_wxy(registry, circuit.omega_j(), r, y)
}

/// The verifier's native side: `commitment` gives each component's
/// commitment, `registry` the native registry, and `targets` the claims'
/// $k(y)$ values; the registry is read through the backend `B`.
pub(crate) fn verify_native<C: Cycle, R: Rank, B: Backend, T: IpaTranscript<C::HostCurve>>(
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
    let shapes = claims::native_shapes(circuit_id, z, masked)?;
    let restriction = |circuit, r| restriction_at::<_, R, B>(registry, circuit, r, y);
    verify::<_, R, B, _, _>(
        &shapes,
        native::claims::ky_values(targets),
        commitment,
        |kind, r| public::<_, R, _>(kind, r, z, &|circuit| restriction(circuit, r), masked),
        reduction,
        z,
        transcript,
    )
}

/// The verifier's nested side, as [`verify_native`] takes its inputs.
pub(crate) fn verify_nested<C: Cycle, R: Rank, B: Backend, T: IpaTranscript<C::NestedCurve>>(
    commitment: impl Fn(nested::RxComponent) -> C::NestedCurve,
    registry: &Registry<'_, C::ScalarField, R>,
    y: C::ScalarField,
    z: C::ScalarField,
    targets: &NestedKy<C::ScalarField>,
    masked: &[Masked<nested::RxComponent, C::ScalarField>],
    reduction: &Reduction<C::NestedCurve>,
    transcript: &mut T,
) -> Result<Option<Openings<C::NestedCurve>>> {
    let shapes = claims::nested_shapes(z, masked)?;
    let restriction = |circuit, r| restriction_at::<_, R, B>(registry, circuit, r, y);
    verify::<_, R, B, _, _>(
        &shapes,
        nested::claims::ky_values(targets),
        commitment,
        |kind, r| public::<_, R, _>(kind, r, z, &|circuit| restriction(circuit, r), masked),
        reduction,
        z,
        transcript,
    )
}
