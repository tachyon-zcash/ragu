//! Prover native points construction.
use alloc::vec::Vec;

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::Result;
use udon::field::Field;

use crate::{
    fuse::prover::proof_builder::ProofBuilder,
    profile::{Profile, ProfiledCycle},
    protocol::{
        native::stages::{points as native_points, points::Inputs},
        nested,
    },
};

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'params, C, R, HEADER_SIZE, B>
{
    /// Commits the native points binding and preamble stages over the
    /// children's nested commitments and the step's own online Fq
    /// commitments, before $w$ is squeezed; the preamble bridge carries
    /// their commitments.
    pub(crate) fn commit_native_points_preamble<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        // TODO(decompression): the profile's prover supplies these
        // polynomials. Until then each slot holds the placeholder.
        builder.set_online_fq_polynomials(
            (0..C::Profile::ONLINE_FQ_POLYS)
                .map(|_| online_fq::placeholder())
                .collect(),
        );

        // The step's own online Fq commitments, which the preamble stage
        // holds.
        let online_fq = builder.online_fq_commitments();

        // Test hook: this runs on the thread that calls `fuse`, outside its
        // parallel jobs, as the hook's thread-local requires.
        #[cfg(test)]
        let online_fq = &crate::online_fq_oracles_tests::mutate_stage_commitments(online_fq);

        let (binding, preamble) = native_points::preamble_witnesses::<_, C::Profile>(
            &nested::pcs::child_commitments(left).collect::<Vec<_>>(),
            &nested::pcs::child_commitments(right).collect::<Vec<_>>(),
            online_fq,
        );
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &binding,
        )?);
        builder.set_native_points_preamble_rx(<native_points::PreambleStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &preamble,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wx`
    /// commitments, before $y$ is squeezed; the `s_prime` bridge carries its
    /// commitment.
    pub(crate) fn commit_native_points_registry_wx<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wx0: C::NestedCurve,
        registry_wx1: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::RegistryWxWitness {
            registry_wx0,
            registry_wx1,
        };
        builder.set_native_points_registry_wx_rx(<native_points::RegistryWxStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wy`
    /// commitment, $A_n$ and $B_n$, before $x$ is squeezed; the `ab` bridge
    /// carries its commitment.
    pub(crate) fn commit_native_points_ab<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wy: C::NestedCurve,
        a: C::NestedCurve,
        b: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::AbWitness { registry_wy, a, b };
        builder.set_native_points_ab_rx(<native_points::AbStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_xy`
    /// commitment and $F_n$, before $u$ is squeezed; the `f` bridge carries
    /// its commitment.
    pub(crate) fn commit_native_points_f<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_xy: C::NestedCurve,
        f: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::FWitness { registry_xy, f };
        builder.set_native_points_f_rx(<native_points::FStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits every native points input stage at once, for a proof whose
    /// walk needs no transcript schedule: the dummy proof.
    pub(in crate::fuse::prover) fn commit_native_points_stages<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.binding,
        )?);
        builder.set_native_points_preamble_rx(<native_points::PreambleStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.preamble,
        )?);
        self.commit_native_points_registry_wx(
            rng,
            inputs.registry_wx.registry_wx0,
            inputs.registry_wx.registry_wx1,
            builder,
        )?;
        self.commit_native_points_ab(
            rng,
            inputs.ab.registry_wy,
            inputs.ab.a,
            inputs.ab.b,
            builder,
        )?;
        self.commit_native_points_f(rng, inputs.f.registry_xy, inputs.f.f, builder)
    }
}

use crate::{Proof, protocol::nested::online as online_fq};
