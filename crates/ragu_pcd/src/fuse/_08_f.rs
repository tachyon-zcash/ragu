//! Construct and commit to $f(X)$.
//!
//! This computes the multi-quotient polynomial $f(X)$ that acts as a witness
//! for the claimed evaluations in the `query` stage. This also constructs the
//! bridge for committing to the polynomial.
//!
//! Each `factor_iter` call below produces the coefficients of $(p\_i(X) - v\_i)
//! / (X - x\_i)$ for a single query. The terms must match `poly_queries` in the
//! `compute_v` circuit exactly.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::{CryptoRngCore, Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use super::{NativeF, NativeSPrime, RegistryWy};
use crate::{
    Application, Proof,
    internal::{
        native,
        native::{RxComponent, RxIndex},
        nested,
    },
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_f<'dr, D, RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NativeF<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let native = self.compute_native_f(
            w,
            y,
            z,
            x,
            alpha,
            s_prime,
            registry_wy,
            builder,
            left,
            right,
        )?;
        self.compute_bridge_f(rng, &native, builder)?;
        Ok(native)
    }

    /// Manually commits the bridge for $f$, rather than having the
    /// [`ProofBuilder`] retain the native copy that derives it, since the `f`
    /// polynomial is not retained after the fuse step and so does not appear in
    /// the proof.
    fn compute_bridge_f<RNG: CryptoRngCore>(
        &self,
        rng: &mut RNG,
        native: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::f::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::f::Witness {
                native_f: native.commitment,
            },
        )?;
        let bridge_commitment = bridge_rx.commit_to_affine(C::nested_generators(self.params));
        builder.set_bridge_f_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    fn compute_native_f<'dr, D>(
        &self,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        builder: &ProofBuilder<'_, C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<NativeF<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        use ragu_arithmetic::factor_iter;

        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;
        let alpha = *alpha.value().take();

        let omega_j = |idx: native::InternalCircuitIndex| -> C::CircuitField {
            idx.circuit_index().omega_j()
        };

        // This must exactly match the ordering of the `poly_queries` function
        // in the `compute_v` circuit.
        let mut iters: Vec<_> = vec![
            // Child proof p(u)=v checks
            factor_iter(left.native_p_poly().iter_coeffs(), left.u()),
            factor_iter(right.native_p_poly().iter_coeffs(), right.u()),
            // Registry transitions
            factor_iter(left.native_registry_xy_poly().iter_coeffs(), w),
            factor_iter(right.native_registry_xy_poly().iter_coeffs(), w),
            factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), left.y()),
            factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), right.y()),
            factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), y),
            factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), y),
            factor_iter(registry_wy.poly.iter_coeffs(), left.x()),
            factor_iter(registry_wy.poly.iter_coeffs(), right.x()),
            factor_iter(registry_wy.poly.iter_coeffs(), x),
            factor_iter(builder.native_registry_xy_poly().iter_coeffs(), w),
            // App circuit registry evals
            factor_iter(
                builder.native_registry_xy_poly().iter_coeffs(),
                left.circuit_id().omega_j(),
            ),
            factor_iter(
                builder.native_registry_xy_poly().iter_coeffs(),
                right.circuit_id().omega_j(),
            ),
            // A/B polynomial queries:
            // a_poly at xz, b_poly at x for left child, right child, current
            factor_iter(left[RxComponent::AbA].iter_coeffs(), xz),
            factor_iter(left[RxComponent::AbB].iter_coeffs(), x),
            factor_iter(right[RxComponent::AbA].iter_coeffs(), xz),
            factor_iter(right[RxComponent::AbB].iter_coeffs(), x),
            factor_iter(builder.native_a_poly().iter_coeffs(), xz),
            factor_iter(builder.native_b_poly().iter_coeffs(), x),
        ];
        // Per-rx evaluations at xz only. The same r_i(xz) values feed
        // into both A(xz) (undilated) and B(x) (Z-dilated).
        for proof in [left, right] {
            for &id in &RxIndex::ALL {
                iters.push(factor_iter(proof[id].iter_coeffs(), xz));
            }
        }

        // m(\omega^j, x, y) evaluations for each internal index j
        for &id in &native::InternalCircuitIndex::ALL {
            iters.push(factor_iter(
                builder.native_registry_xy_poly().iter_coeffs(),
                omega_j(id),
            ));
        }

        let mut coeffs = Vec::with_capacity(R::num_coeffs());
        let (first, rest) = iters.split_first_mut().unwrap();
        for val in first.by_ref() {
            let c = rest
                .iter_mut()
                .fold(val, |acc, iter| alpha * acc + iter.next().unwrap());
            coeffs.push(c);
        }
        coeffs.reverse();

        let poly = sparse::Polynomial::from_coeffs(coeffs);
        let commitment = poly.commit_to_affine(C::host_generators(self.params));

        Ok(NativeF { poly, commitment })
    }
}
