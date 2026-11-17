//! Native f prover phase.
use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::{
        native,
        native::{RxComponent, RxIndex, STATIC_F_QUERIES, StaticFQuery, online},
    },
    prover::{
        fuse::native::{inner_error::RegistryWy, s_prime::NativeSPrime},
        proof_builder::ProofBuilder,
    },
};

/// Ephemeral native-field data for $f(X)$, used only during the fuse step.
pub(in crate::prover::fuse) struct NativeF<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(in crate::prover::fuse) commitment: C::HostCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_f<'dr, D>(
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
        use udon::polynomial::divide_linear_rev;

        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;
        let alpha = *alpha.value().take();

        let omega_j = |idx: native::InternalCircuitIndex| -> C::CircuitField {
            idx.circuit_index::<C::Profile>().omega_j()
        };

        let mut iters: Vec<_> = STATIC_F_QUERIES
            .into_iter()
            .map(|query| match query {
                StaticFQuery::LeftP => {
                    divide_linear_rev(left.native_p_poly().iter_coeffs(), left.u())
                }
                StaticFQuery::RightP => {
                    divide_linear_rev(right.native_p_poly().iter_coeffs(), right.u())
                }
                StaticFQuery::LeftRegistryXyAtW => {
                    divide_linear_rev(left.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RightRegistryXyAtW => {
                    divide_linear_rev(right.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RegistryWx0AtLeftY => {
                    divide_linear_rev(s_prime.registry_wx0_poly.iter_coeffs(), left.y())
                }
                StaticFQuery::RegistryWx1AtRightY => {
                    divide_linear_rev(s_prime.registry_wx1_poly.iter_coeffs(), right.y())
                }
                StaticFQuery::RegistryWx0AtY => {
                    divide_linear_rev(s_prime.registry_wx0_poly.iter_coeffs(), y)
                }
                StaticFQuery::RegistryWx1AtY => {
                    divide_linear_rev(s_prime.registry_wx1_poly.iter_coeffs(), y)
                }
                StaticFQuery::RegistryWyAtLeftX => {
                    divide_linear_rev(registry_wy.poly.iter_coeffs(), left.x())
                }
                StaticFQuery::RegistryWyAtRightX => {
                    divide_linear_rev(registry_wy.poly.iter_coeffs(), right.x())
                }
                StaticFQuery::RegistryWyAtX => divide_linear_rev(registry_wy.poly.iter_coeffs(), x),
                StaticFQuery::RegistryXyAtW => {
                    divide_linear_rev(builder.native_registry_xy_poly().iter_coeffs(), w)
                }
                StaticFQuery::RegistryXyAtLeftCircuitId => divide_linear_rev(
                    builder.native_registry_xy_poly().iter_coeffs(),
                    left.circuit_id().omega_j(),
                ),
                StaticFQuery::RegistryXyAtRightCircuitId => divide_linear_rev(
                    builder.native_registry_xy_poly().iter_coeffs(),
                    right.circuit_id().omega_j(),
                ),
                StaticFQuery::LeftAbAAtXz => {
                    divide_linear_rev(left[RxComponent::AbA].iter_coeffs(), xz)
                }
                StaticFQuery::LeftAbBAtX => {
                    divide_linear_rev(left[RxComponent::AbB].iter_coeffs(), x)
                }
                StaticFQuery::RightAbAAtXz => {
                    divide_linear_rev(right[RxComponent::AbA].iter_coeffs(), xz)
                }
                StaticFQuery::RightAbBAtX => {
                    divide_linear_rev(right[RxComponent::AbB].iter_coeffs(), x)
                }
                StaticFQuery::CurrentAAtXz => {
                    divide_linear_rev(builder.native_a_poly().iter_coeffs(), xz)
                }
                StaticFQuery::CurrentBAtX => {
                    divide_linear_rev(builder.native_b_poly().iter_coeffs(), x)
                }
            })
            .collect();
        // Per-rx evaluations at xz only. The same r_i(xz) values feed
        // into both A(xz) (undilated) and B(x) (Z-dilated).
        for proof in [left, right] {
            for id in RxIndex::all::<C::Profile>() {
                iters.push(divide_linear_rev(proof[id].iter_coeffs(), xz));
            }
        }

        // m(\omega^j, x, y) evaluations for each internal index j
        for id in native::InternalCircuitIndex::all::<C::Profile>() {
            iters.push(divide_linear_rev(
                builder.native_registry_xy_poly().iter_coeffs(),
                omega_j(id),
            ));
        }

        // The online openings, in slot order, each at its own point.
        let polys = online::polys(left, right, builder.online_polynomials());
        for (poly, query) in polys.into_iter().zip(builder.online_openings()) {
            iters.push(divide_linear_rev(poly.iter_coeffs(), query.x));
        }

        let poly = alpha_batched_quotients::<_, R>(iters, alpha);
        let commitment = B::sparse_commit_to_affine(&poly, C::host_generators(self.params));

        Ok(NativeF { poly, commitment })
    }
}

use crate::prover::fuse::quotient::alpha_batched_quotients;
