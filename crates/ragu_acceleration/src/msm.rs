//! Accelerated multiscalar multiplication dispatch.

use ragu_arithmetic::CurveAffine;

/// Computes the MSM with Zakura's signed-Booth multiexp.
///
/// `zakura-halo2-proofs` depends on the same `zakura-pasta-curves` package as
/// Ragu, so the curve types (and the [`CurveAffine`] trait itself) unify and
/// the call needs no conversion. The implementation is variable-time and uses
/// threads only when `maybe-rayon` threading is enabled (via the `multicore`
/// feature) and beneficial.
///
/// Unequal input lengths violate [`Backend::msm`](ragu_backend::Backend::msm)'s
/// contract; this panics where the reference implementation truncates.
pub(crate) fn accelerated_msm<C: CurveAffine>(coeffs: &[C::Scalar], bases: &[C]) -> C::Curve {
    assert_eq!(
        coeffs.len(),
        bases.len(),
        "MSM coefficients and bases must have equal length"
    );

    halo2_proofs::arithmetic::best_multiexp(coeffs, bases)
}
