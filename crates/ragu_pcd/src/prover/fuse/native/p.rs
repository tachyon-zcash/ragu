//! Native p prover phase.
use alloc::vec::Vec;
use core::ops::AddAssign;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::Always,
};
use ragu_primitives::{Uendo, lift_endoscalar, vec::Len};
use udon::field::Field;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::{
        native::{RxComponent, RxIndex, online},
        nested::{PointsWitness, pcs},
    },
    prover::{
        fuse::{
            native::{f::NativeF, inner_error::RegistryWy, s_prime::NativeSPrime},
            nested::{f::NestedF, inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        },
        proof_builder::ProofBuilder,
    },
    verifier::recursive::native::stages::points::{Inputs, WalkWitness},
};

/// The native points stages' witnesses: the nested batch's commitments.
pub(in crate::prover::fuse) type NativeInputs<C> =
    Inputs<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The native walk stage's witness: the endoscalar and the walk's outputs.
pub(in crate::prover::fuse) type NativeWalk<C> =
    WalkWitness<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The wireless emulator the fuse step's transcript runs in, which `pre_beta`
/// is sampled from.
pub(in crate::prover::fuse) type NativeFuseEmulator<C> =
    Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;

/// Accumulates polynomials with their commitments.
pub(in crate::prover::fuse) struct Accumulator<'a, C: Cycle, R: Rank> {
    poly: &'a mut sparse::Polynomial<C::CircuitField, R>,
    commitments: &'a mut Vec<C::HostCurve>,
    beta: C::CircuitField,
}

impl<C: Cycle, R: Rank> Accumulator<'_, C, R> {
    pub(in crate::prover::fuse) fn acc<P>(&mut self, poly: &P, commitment: C::HostCurve)
    where
        for<'p> sparse::Polynomial<C::CircuitField, R>: AddAssign<&'p P>,
    {
        self.poly.scale(self.beta);
        *self.poly += poly;
        self.commitments.push(commitment);
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The nested batch's commitments, $f_n$'s first, in
    /// [`pcs::Batch::evaluated`] order, as the native points stages the
    /// earlier phases committed hold them.
    pub(in crate::prover::fuse) fn native_inputs(
        &self,
        nested_f: &NestedF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> NativeInputs<C> {
        let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
        let current = pcs::CurrentCommitments {
            registry_wx0: nested_s_prime.registry_wx0_commitment,
            registry_wx1: nested_s_prime.registry_wx1_commitment,
            registry_wy: nested_registry_wy.commitment,
            a: builder.nested_a_commitment(),
            b: builder.nested_b_commitment(),
            registry_xy: builder.nested_registry_xy_commitment(),
        };
        let points: Vec<C::NestedCurve> = core::iter::once(nested_f.commitment)
            .chain(batch.commitments(current, builder.online_fq_commitments()))
            .collect();
        assert_eq!(
            points.len(),
            crate::protocol::native::NumPoints::<C::Profile>::len()
        );
        Inputs::from_walk(&points)
    }

    pub(in crate::prover::fuse) fn compute_native_p<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<PointsWitness<C::HostCurve, C::Profile>> {
        let mut poly = f.poly.clone();

        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `crate::verifier::recursive::native::stages::eval::Output`.
        //
        // We accumulate polynomials while collecting MSM terms for the
        // commitment computation.
        let effective_beta = lift_endoscalar(beta_endo);

        {
            let mut acc: Accumulator<'_, C, R> = Accumulator {
                poly: &mut poly,
                commitments: &mut commitments,
                beta: effective_beta,
            };

            for proof in [left, right] {
                for id in RxIndex::all::<C::Profile>() {
                    acc.acc(&proof[id], proof.native_rx_commitment(id));
                }
                acc.acc(
                    &proof[RxComponent::AbA],
                    proof.native_commitment(RxComponent::AbA),
                );
                acc.acc(
                    &proof[RxComponent::AbB],
                    proof.native_commitment(RxComponent::AbB),
                );
                acc.acc(
                    proof.native_registry_xy_poly(),
                    proof.native_registry_xy_commitment(),
                );
                acc.acc(proof.native_p_poly(), proof.native_p_commitment());
            }

            acc.acc(&s_prime.registry_wx0_poly, s_prime.registry_wx0_commitment);
            acc.acc(&s_prime.registry_wx1_poly, s_prime.registry_wx1_commitment);
            acc.acc(&registry_wy.poly, registry_wy.commitment);
            acc.acc(builder.native_a_poly(), builder.native_a_commitment());
            acc.acc(builder.native_b_poly(), builder.native_b_commitment());
            acc.acc(
                builder.native_registry_xy_poly(),
                builder.native_registry_xy_commitment(),
            );

            // The online slots, in slot order, whose commitments the nested
            // `loading` circuit walks off the preamble bridge stage.
            let polys = online::polys(left, right, builder.online_polynomials());
            let commitments = online::commitments(left, right, builder.online_commitments());
            for (poly, commitment) in polys.into_iter().zip(commitments) {
                acc.acc(poly, commitment);
            }
        }

        // Build the PointsStage input vector ([f.commitment, commitments..])
        // and delegate to the shared endoscaling helper, which also
        // sets `nested_endoscalar_rx`, `nested_points_rx`, and
        // `nested_endoscaling_step_rxs` on the builder.
        let mut points =
            Vec::with_capacity(crate::protocol::native::NumPoints::<C::Profile>::len().max(1));
        points.push(f.commitment);
        points.extend_from_slice(&commitments);

        let endoscalar_alpha = C::ScalarField::random(|bytes| rng.fill_bytes(bytes));
        let points_alpha = C::ScalarField::random(|bytes| rng.fill_bytes(bytes));
        let (p_commitment, points) = self.compute_endoscaling(
            rng,
            beta_endo,
            &points,
            endoscalar_alpha,
            points_alpha,
            builder,
        )?;

        builder.set_native_p_poly(poly, p_commitment);

        Ok(points)
    }
}
