//! Construct and commit to $f(X)$.
//!
//! This computes the multi-quotient polynomial $f(X)$ that acts as a witness
//! for the claimed evaluations in the `query` stage. This also constructs the
//! `f` bridge stage, which carries the polynomial's commitment.
//!
//! Each `udon::polynomial::divide_linear_rev` call below produces the
//! coefficients of $(p\_i(X) - v\_i) / (X - x\_i)$ for a single query. The
//! static query prefix is defined by
//! [`STATIC_F_QUERIES`] and consumed by both this prover path and the
//! `compute_v` circuit.
//!
//! The nested quotient polynomial $f_n(X)$ is built the same way over the
//! nested batch ([`pcs::Batch::queries`]), with $\alpha_n$ derived from
//! $\alpha$. Its nested-curve commitment, the initial point of the native
//! endoscaling walk, is committed with the nested $m_n(W, x_n, y_n)$
//! restriction's in the native points stage the walk reads them from, whose
//! commitment the `f` bridge carries, so they are fixed before $u$ is
//! squeezed.

use alloc::vec::Vec;

use ragu_circuits::{
    Blind,
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;

use super::{
    _01_application::NativeApplication,
    _03_s_prime::{NativeSPrime, NestedSPrime},
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    randomizer::{NativeRandomizer, NestedRandomizer, Randomizers},
};
use crate::{
    Application, Proof,
    internal::{
        native,
        native::{
            RxComponent, RxIndex, online,
            pcs::{STATIC_F_QUERIES, StaticFQuery},
            stages::points as native_points,
        },
        nested::{self, pcs},
    },
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

/// Ephemeral native-field data for $f(X)$, used only during the fuse step.
pub(super) struct NativeF<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::CircuitField, R>,
    pub(super) commitment: C::HostCurve,
}

/// Ephemeral nested-field data for $f_n(X)$, used only during the fuse step.
pub(super) struct NestedF<C: Cycle, R: Rank> {
    pub(super) poly: sparse::Polynomial<C::ScalarField, R>,
    pub(super) commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
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
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        application: &NativeApplication<C, R>,
        randomizers: &Randomizers<C, R>,
    ) -> Result<(NativeF<C, R>, NestedF<C, R>)>
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
            application,
            &randomizers.native,
        )?;
        let nested = {
            let batch = self.nested_batch(
                builder,
                nested_s_prime,
                nested_registry_wy,
                left,
                right,
                &randomizers.nested,
            );
            let challenges = self.nested_challenges(w, x, y, z, left, right)?;
            let alpha = nested::challenge::<C>(*alpha.value().take())?;
            self.compute_nested_f(&batch, challenges, alpha, builder)?
        };
        // The batch randomizers are fixed here with the quotients, each
        // side's commitment in the other side's stage.
        self.commit_native_points_f(
            rng,
            builder.nested_registry_xy_commitment(),
            nested.commitment,
            randomizers.nested.mask_commitment,
            builder,
        )?;
        self.compute_bridge_f(rng, &native, &randomizers.native, builder)?;
        Ok((native, nested))
    }

    /// Manually commits the bridge for $f$, rather than having the
    /// [`ProofBuilder`] retain the native copy that derives it, since the `f`
    /// polynomial is not retained after the fuse step and so does not appear in
    /// the proof.
    fn compute_bridge_f<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        native: &NativeF<C, R>,
        randomizer: &NativeRandomizer<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::f::Stage::<C::HostCurve, R, C::Profile>::rx(
            Blind::random(rng),
            &nested::stages::f::Witness {
                native_f: native.commitment,
                native_points_f: builder.native_points_f_commitment(),
                native_mask: randomizer.mask_commitment,
            },
        )?;
        let bridge_commitment = self.nested().commit(&bridge_rx);
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
        application: &NativeApplication<C, R>,
        randomizer: &NativeRandomizer<C, R>,
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
                StaticFQuery::RegistryXyAtCircuitId => divide_linear_rev(
                    builder.native_registry_xy_poly().iter_coeffs(),
                    application.circuit_id.omega_j(),
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
                StaticFQuery::CurrentApplicationAtXz => {
                    divide_linear_rev(application.rx.iter_coeffs(), xz)
                }
                StaticFQuery::CurrentApplicationStageAtXz => {
                    divide_linear_rev(application.stage.rx.iter_coeffs(), xz)
                }
                StaticFQuery::RandomizerAAtXz => divide_linear_rev(randomizer.a.iter_coeffs(), xz),
                StaticFQuery::RandomizerBAtX => divide_linear_rev(randomizer.b.iter_coeffs(), x),
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

        let poly = crate::profile::online::circuit::quotient_sum::<_, R>(iters, alpha);
        let poly = builder.native_online().append_quotient(poly, alpha)?;
        let commitment = B::sparse_commit_to_affine(&poly, C::host_generators(self.params));

        Ok(NativeF { poly, commitment })
    }

    /// Builds $f_n(X)$: the $\alpha_n$-batched quotients of every opening
    /// in the nested batch, in [`pcs::Batch::queries`] order.
    fn compute_nested_f(
        &self,
        batch: &pcs::Batch<'_, C, R>,
        challenges: pcs::Challenges<C::ScalarField>,
        alpha: C::ScalarField,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> Result<NestedF<C, R>> {
        use udon::polynomial::divide_linear_rev;

        let iters: Vec<_> = batch
            .queries(challenges)
            .map(|(poly, point)| divide_linear_rev(poly.iter_coeffs(), point))
            .collect();

        let poly = crate::profile::online::circuit::quotient_sum::<_, R>(iters, alpha);
        let poly = builder.nested_online().append_quotient(poly, alpha)?;
        let commitment = B::sparse_commit_to_affine(&poly, C::nested_generators(self.params));

        Ok(NestedF { poly, commitment })
    }

    /// The nested batch this step opens, over the nested polynomials the
    /// builder has committed so far.
    pub(super) fn nested_batch<'a>(
        &self,
        builder: &'a ProofBuilder<'_, C, R, B>,
        nested_s_prime: &'a NestedSPrime<C, R>,
        nested_registry_wy: &'a NestedRegistryWy<C, R>,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        randomizer: &'a NestedRandomizer<C, R>,
    ) -> pcs::Batch<'a, C, R> {
        pcs::Batch {
            left,
            right,
            registry_wx0: &nested_s_prime.registry_wx0_poly,
            registry_wx1: &nested_s_prime.registry_wx1_poly,
            registry_wy: &nested_registry_wy.poly,
            registry_xy: builder.nested_registry_xy_poly(),
            a: builder.nested_a_poly(),
            b: builder.nested_b_poly(),
            randomizer_a: &randomizer.a,
            randomizer_b: &randomizer.b,
            mask: &randomizer.mask,
            online_fq: builder.online_fq_polynomials(),
        }
    }

    /// The nested challenges this step's openings are at, derived from the
    /// native ones (see [`nested::challenge`]).
    fn nested_challenges<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<pcs::Challenges<C::ScalarField>> {
        Ok(pcs::Challenges {
            w: nested::challenge::<C>(*w.value().take())?,
            x: nested::challenge::<C>(*x.value().take())?,
            y: nested::challenge::<C>(*y.value().take())?,
            z: nested::challenge::<C>(*z.value().take())?,
            left: pcs::ChildChallenges::of(left)?,
            right: pcs::ChildChallenges::of(right)?,
        })
    }

    /// Commits the native points stage holding the nested `registry_xy`
    /// commitment, $F_n$ and the nested batch randomizer's commitment,
    /// before $u$ is squeezed; the `f` bridge carries its commitment.
    pub(crate) fn commit_native_points_f<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_xy: C::NestedCurve,
        f: C::NestedCurve,
        mask: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::FWitness {
            registry_xy,
            f,
            mask,
            online_points: builder.nested_online_phase::<3>(),
        };
        builder.set_native_points_f_rx(<native_points::FStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            Blind::random(rng),
            &witness,
        )?);
        Ok(())
    }
}
