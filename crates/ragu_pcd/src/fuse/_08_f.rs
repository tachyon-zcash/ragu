//! Construct and commit to $f(X)$.
//!
//! This computes the multi-quotient polynomial $f(X)$ that acts as a witness
//! for the claimed evaluations in the `query` stage. This also constructs the
//! bridge for committing to the polynomial.
//!
//! Each `factor_iter` call below produces the coefficients of $(p\_i(X) - v\_i)
//! / (X - x\_i)$ for a single query. The static query prefix is defined by
//! [`STATIC_F_QUERIES`] and consumed by both this prover path and the
//! `compute_v` circuit.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field, rand::CryptoRng};
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
        native::{RxComponent, RxIndex, STATIC_F_QUERIES, StaticFQuery},
        nested,
    },
    proof::ProofBuilder,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_f<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        alpha: &Element<'dr, D>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
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
    fn compute_bridge_f<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::f::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::random(&mut *rng),
            &nested::stages::f::Witness {
                native_f: native.commitment,
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
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
        builder: &ProofBuilder<'_, C, R, B>,
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

        let mut iters: Vec<_> = STATIC_F_QUERIES
            .into_iter()
            .map(|query| match query {
                StaticFQuery::LeftP => factor_iter(left.native_p_poly().iter_coeffs(), left.u()),
                StaticFQuery::RightP => factor_iter(right.native_p_poly().iter_coeffs(), right.u()),
                StaticFQuery::LeftRegistryXyAtW => {
                    factor_iter(left.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RightRegistryXyAtW => {
                    factor_iter(right.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RegistryWx0AtLeftY => {
                    factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), left.y())
                }
                StaticFQuery::RegistryWx1AtRightY => {
                    factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), right.y())
                }
                StaticFQuery::RegistryWx0AtY => {
                    factor_iter(s_prime.registry_wx0_poly.iter_coeffs(), y)
                }
                StaticFQuery::RegistryWx1AtY => {
                    factor_iter(s_prime.registry_wx1_poly.iter_coeffs(), y)
                }
                StaticFQuery::RegistryWyAtLeftX => {
                    factor_iter(registry_wy.poly.iter_coeffs(), left.x())
                }
                StaticFQuery::RegistryWyAtRightX => {
                    factor_iter(registry_wy.poly.iter_coeffs(), right.x())
                }
                StaticFQuery::RegistryWyAtX => factor_iter(registry_wy.poly.iter_coeffs(), x),
                StaticFQuery::RegistryXyAtW => {
                    factor_iter(builder.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RegistryXyAtLeftCircuitId => factor_iter(
                    builder.native_registry_xy_poly().iter_coeffs(),
                    left.circuit_id().omega_j(),
                ),
                StaticFQuery::RegistryXyAtRightCircuitId => factor_iter(
                    builder.native_registry_xy_poly().iter_coeffs(),
                    right.circuit_id().omega_j(),
                ),
                StaticFQuery::LeftAbAAtXz => factor_iter(left[RxComponent::AbA].iter_coeffs(), xz),
                StaticFQuery::LeftAbBAtX => factor_iter(left[RxComponent::AbB].iter_coeffs(), x),
                StaticFQuery::RightAbAAtXz => {
                    factor_iter(right[RxComponent::AbA].iter_coeffs(), xz)
                }
                StaticFQuery::RightAbBAtX => factor_iter(right[RxComponent::AbB].iter_coeffs(), x),
                StaticFQuery::CurrentAAtXz => {
                    factor_iter(builder.native_a_poly().iter_coeffs(), xz)
                }
                StaticFQuery::CurrentBAtX => factor_iter(builder.native_b_poly().iter_coeffs(), x),
            })
            .collect();
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
        let commitment = B::sparse_commit_to_affine(&poly, C::host_generators(self.params));

        Ok(NativeF { poly, commitment })
    }
}
