//! Accumulate $p(X)$.
//!
//! This sets the $p(X)$ polynomial field on the [`ProofBuilder`], containing
//! the accumulated polynomial and its claimed evaluation $p(u) = v$.
//!
//! The commitment is derived as a linear combination of all constituent
//! polynomial commitments using additive homomorphism:
//! $\text{commit}(\sum\_j \beta^j \cdot p\_j) = \sum\_j \beta^j \cdot C\_j$.
//!
//! The commitment is computed via
//! [`PointsWitness`]
//! Horner evaluation.
//!
//! The nested batch is accumulated the same way into $p_n(X)$, with
//! $\beta_n$ the scalar-field lift of the same endoscalar bits. Its
//! nested-curve commitment $P_n$ is the Horner walk over the batch's
//! nested-curve commitments, performed by the native endoscaling steps over
//! the points stages the earlier phases committed (see
//! [`native::stages::points`]).

use alloc::vec::Vec;

use ragu_circuits::{
    Blind, CircuitExt,
    polynomials::{Rank, sparse},
    staging::{MultiStage, StageExt},
};
use ragu_core::{
    Cycle, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::Always,
};
use ragu_primitives::{
    EndoscalarChallenge, Uendo, lift_endoscalar,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use super::{
    _01_application::NativeApplication,
    _03_s_prime::{NativeSPrime, NestedSPrime},
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    _08_f::{NativeF, NestedF},
    randomizer::{NativeRandomizer, NestedRandomizer, Randomizers},
};
use crate::{
    Application, Proof,
    internal::{
        endoscalar::EndoscalarStage,
        native::{
            self, RxComponent, RxIndex, online,
            stages::points::{self as native_points, Inputs, WalkWitness},
        },
        nested::{
            self, EndoscalingStep, EndoscalingStepWitness, NumPoints, NumSteps, PointsStage,
            PointsWitness, pcs,
        },
    },
    profile::{Profile, ProfiledCycle, paging},
    proof::ProofBuilder,
};

/// The native points stages' witnesses: the nested batch's commitments.
pub(super) type NativeInputs<C> = Inputs<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The native walk stage's witness: the endoscalar and the walk's outputs.
pub(super) type NativeWalk<C> =
    WalkWitness<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The wireless emulator the fuse step's transcript runs in, which `pre_beta`
/// is sampled from.
type NativeFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;

/// Collects the polynomials of an accumulation with their commitments.
struct Accumulator<'a, 'c, C: Cycle, R: Rank> {
    polys: Vec<&'a sparse::Polynomial<C::CircuitField, R>>,
    commitments: &'c mut Vec<C::HostCurve>,
}

impl<'a, C: Cycle, R: Rank> Accumulator<'a, '_, C, R> {
    fn acc(&mut self, poly: &'a sparse::Polynomial<C::CircuitField, R>, commitment: C::HostCurve) {
        self.polys.push(poly);
        self.commitments.push(commitment);
    }
}

/// The polynomial Horner's rule accumulates from `first` and then each of
/// `rest` in order: $\beta^k \cdot \text{first} + \sum\_i \beta^{k-1-i} \cdot
/// \text{rest}\_i$ for the $k$ polynomials of `rest`.
///
/// It is formed as one linear combination under those powers, so that the
/// running sum is never rescaled and the backend can split the work.
fn accumulate<B: ragu_backend::Backend, F: Field, R: Rank>(
    first: &sparse::Polynomial<F, R>,
    rest: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    B::sparse_linear_combination(&sparse::Polynomial::fold_terms(
        core::iter::once(first).chain(rest.iter().copied()),
        beta,
    ))
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// The nested batch's commitments, $f_n$'s first, in
    /// [`pcs::Batch::evaluated`] order, as the native points stages the
    /// earlier phases committed hold them.
    fn native_inputs(
        &self,
        nested_f: &NestedF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        randomizer: &NestedRandomizer<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
    ) -> NativeInputs<C> {
        let batch = self.nested_batch(
            builder,
            nested_s_prime,
            nested_registry_wy,
            left,
            right,
            randomizer,
        );
        let current = pcs::CurrentCommitments {
            registry_wx0: nested_s_prime.registry_wx0_commitment,
            registry_wx1: nested_s_prime.registry_wx1_commitment,
            registry_wy: nested_registry_wy.commitment,
            a: builder.nested_a_commitment(),
            b: builder.nested_b_commitment(),
            registry_xy: builder.nested_registry_xy_commitment(),
            randomizer_a: randomizer.a_commitment,
            randomizer_b: randomizer.b_commitment,
            mask: randomizer.mask_commitment,
        };
        let points: Vec<C::NestedCurve> = core::iter::once(nested_f.commitment)
            .chain(batch.commitments(current))
            .chain(builder.nested_online().commitments().iter().copied())
            .collect();
        assert_eq!(
            points.len(),
            crate::internal::native::NumPoints::<C::Profile>::len()
        );
        Inputs::from_walk(
            &points,
            FixedVec::from_fn(|_| builder.nested_online_stage_commitment(0)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_p<'dr, RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        pre_beta: &EndoscalarChallenge<'dr, NativeFuseEmulator<C>>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        application: &NativeApplication<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        randomizers: &Randomizers<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        PointsWitness<C::HostCurve, C::Profile>,
        NativeInputs<C>,
        NativeWalk<C>,
    )> {
        // Extract endoscalar from pre_beta and compute effective beta. Going
        // through the validated `EndoscalarChallenge` makes the
        // `value < 2^CAPACITY` precondition a type invariant rather than an
        // unchecked argument to `extract_endoscalar`.
        let beta_endo = pre_beta.extract_native();

        let points = self.compute_native_p(
            rng,
            beta_endo,
            left,
            right,
            application,
            s_prime,
            registry_wy,
            f,
            &randomizers.native,
            builder,
        )?;
        let native_points = self.native_inputs(
            nested_f,
            nested_s_prime,
            nested_registry_wy,
            left,
            right,
            &randomizers.nested,
            builder,
        );
        let native_walk = self.compute_nested_p(
            rng,
            beta_endo,
            left,
            right,
            nested_s_prime,
            nested_registry_wy,
            nested_f,
            &randomizers.nested,
            &native_points,
            builder,
        )?;

        Ok((points, native_points, native_walk))
    }

    fn compute_native_p<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        application: &NativeApplication<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        randomizer: &NativeRandomizer<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<PointsWitness<C::HostCurve, C::Profile>> {
        // Collect commitments for PointsWitness construction.
        let mut commitments: Vec<C::HostCurve> = Vec::new();

        // The orderings in this code must match the `Write` serialization
        // order of `native::stages::eval::Output`.
        //
        // We accumulate polynomials while collecting MSM terms for the
        // commitment computation.
        let effective_beta = lift_endoscalar(beta_endo);

        let poly = {
            let mut acc: Accumulator<'_, '_, C, R> = Accumulator {
                polys: Vec::new(),
                commitments: &mut commitments,
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
            acc.acc(&application.rx, application.commitment);
            acc.acc(&application.stage.rx, application.stage.commitment);
            acc.acc(&registry_wy.poly, registry_wy.commitment);
            acc.acc(builder.native_a_poly(), builder.native_a_commitment());
            acc.acc(builder.native_b_poly(), builder.native_b_commitment());
            acc.acc(
                builder.native_registry_xy_poly(),
                builder.native_registry_xy_commitment(),
            );
            // The step's own randomizers: the fold's two, which the batch
            // opens, and the batch's own, which makes $p$ uniform.
            acc.acc(&randomizer.a, randomizer.a_commitment);
            acc.acc(&randomizer.b, randomizer.b_commitment);
            acc.acc(&randomizer.mask, randomizer.mask_commitment);

            // The online slots, in slot order, whose commitments the nested
            // `collapse` circuit walks off the preamble bridge stage.
            let polys = online::polys(left, right, builder.online_polynomials());
            let commitments = online::commitments(left, right, builder.online_commitments());
            for (poly, commitment) in polys.into_iter().zip(commitments) {
                acc.acc(poly, commitment);
            }
            // Each distinct online polynomial enters the commitment fold
            // once, independently of how many openings the quotient checks.
            let online = builder.native_online();
            for (poly, &point) in online.polynomials().iter().zip(online.commitments()) {
                acc.acc(poly, point);
            }
            accumulate::<B, _, _>(&f.poly, &acc.polys, effective_beta)
        };

        // Build the PointsStage input vector ([f.commitment, commitments..])
        // and delegate to the shared endoscaling helper, which also
        // sets `nested_endoscalar_rx`, `nested_points_rx`, and
        // `nested_endoscaling_step_rxs` on the builder.
        let mut points =
            Vec::with_capacity(crate::internal::native::NumPoints::<C::Profile>::len().max(1));
        points.push(f.commitment);
        points.extend_from_slice(&commitments);

        let endoscalar_alpha = Blind::random(rng);
        let points_alpha = Blind::random(rng);
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

    /// Accumulates the nested batch into $p_n(X)$, in [`pcs::Batch::evaluated`]
    /// order after $f_n$, and runs the native endoscaling over the committed
    /// points: $P_n$ is the walk's last interstitial, which the native steps
    /// enforce and `bind_endoscalar` pins to the unified instance.
    #[allow(clippy::too_many_arguments)]
    fn compute_nested_p<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        randomizer: &NestedRandomizer<C, R>,
        native_points: &NativeInputs<C>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<NativeWalk<C>> {
        let beta: C::ScalarField = lift_endoscalar(beta_endo);
        let batch = self.nested_batch(
            builder,
            nested_s_prime,
            nested_registry_wy,
            left,
            right,
            randomizer,
        );

        let poly = {
            let rest: Vec<&sparse::Polynomial<C::ScalarField, R>> = batch
                .evaluated()
                .chain(builder.nested_online().polynomials())
                .collect();
            accumulate::<B, _, _>(&nested_f.poly, &rest, beta)
        };
        let (p_commitment, walk) =
            self.compute_native_endoscaling(rng, beta_endo, native_points, builder)?;
        // A child can carry a polynomial inconsistent with its cached point.
        // Keep the debug consistency check fallible for such witnesses.
        #[cfg(debug_assertions)]
        if self.nested().commit::<R>(&poly) != p_commitment {
            return Err(ragu_core::Error::InvalidWitness(
                "nested P does not match its accumulated polynomial".into(),
            ));
        }
        builder.set_nested_p_poly(poly, p_commitment);

        Ok(walk)
    }

    /// Runs endoscaling over the host-curve commitments that feed
    /// `PointsStage`, in the order `compute_p` (`_10_p.rs`)
    /// accumulates them. Writes `nested_endoscalar_rx`,
    /// `nested_points_rx`, and `nested_endoscaling_step_rxs` onto
    /// `builder`, and returns the accumulated `p` commitment (last
    /// `PointsStage` interstitial) together with the points witness the
    /// nested circuits load.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and by
    /// [`dummy_proof`](Self::dummy_proof), so the nested
    /// endoscaling setup lives in one place.
    pub(crate) fn compute_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        points: &[C::HostCurve],
        endoscalar_alpha: Blind<C::ScalarField>,
        points_alpha: Blind<C::ScalarField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(C::HostCurve, PointsWitness<C::HostCurve, C::Profile>)> {
        assert_eq!(points.len(), NumPoints::<C::Profile>::len());

        let witness = PointsWitness::<C::HostCurve, C::Profile>::new(beta_endo, points);

        let endoscalar_rx =
            <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(endoscalar_alpha, beta_endo)?;
        let points_rx = <PointsStage<C::HostCurve, C::Profile> as StageExt<C::ScalarField, R>>::rx(
            points_alpha,
            &witness,
        )?;

        let num_steps = NumSteps::<C::Profile>::len();
        let mut step_rxs = Vec::with_capacity(num_steps);
        let (registry, points) = (&self.nested_registry, &witness);
        // A paged step is traced once for each of its pages that hold
        // gates. What they read of the walk's stages without loading them
        // comes off the stages' polynomials; the bridge-hash stage a step
        // reserves between the two is nothing it reads.
        if C::Profile::PAGES.nested_endoscaling_step.pages > 1 {
            let mut pages = builder.take_nested_pages(&self.nested_plans);
            let gap = sparse::Polynomial::<C::ScalarField, R>::default();
            let stages = [&endoscalar_rx, &gap, &points_rx];
            for step in 0..num_steps {
                let (step_rx, _) = C::Profile::prove_internal(
                    &mut pages,
                    paging::Circuit::NestedEndoscalingStep(step as u32),
                    MultiStage::new(EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step)),
                    registry,
                    nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index::<C::Profile>(),
                    |circuit| {
                        nested::InternalCircuitIndex::ExtensionCircuit(circuit)
                            .circuit_index::<C::Profile>()
                    },
                    &stages,
                    || EndoscalingStepWitness {
                        endoscalar: beta_endo,
                        points,
                    },
                    &mut *rng,
                )?;
                step_rxs.push(step_rx);
            }
            builder.set_nested_pages(pages);
        }
        // The steps' traces are independent work for the backend. Each
        // step's blinding factor is drawn first, in step order, so that no
        // job touches the RNG.
        let blinds: Vec<Blind<C::ScalarField>> = (step_rxs.len()..num_steps)
            .map(|_| Blind::random(rng))
            .collect();
        for step_rx in B::map(blinds.into_iter().enumerate(), |(step, blind)| {
            let staged = MultiStage::new(EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step));
            let step_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points,
                })?
                .into_output();
            registry.assemble_with_alpha(
                &step_trace,
                nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                    .circuit_index::<C::Profile>(),
                blind,
            )
        }) {
            step_rxs.push(step_rx?);
        }

        builder.set_nested_endoscaling_step_rxs(step_rxs);
        builder.set_nested_endoscalar_rx(endoscalar_rx);
        builder.set_nested_points_rx(points_rx);

        let p_commitment = *witness
            .interstitials
            .last()
            .expect("every walk has at least one interstitial");
        Ok((p_commitment, witness))
    }

    /// Runs the native endoscaling over the committed inputs: walks them
    /// under `beta_endo`, commits the walk stage, traces the steps, and
    /// writes all of it onto `builder`. Returns $P_n$ (the last
    /// interstitial) with the walk stage's witness.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and
    /// [`dummy_proof`](Self::dummy_proof), like
    /// [`compute_endoscaling`](Self::compute_endoscaling) on the nested side.
    pub(crate) fn compute_native_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        C::NestedCurve,
        native_points::WalkWitness<C::NestedCurve, C::Profile>,
    )> {
        use native_points::{WalkStage, WalkWitness};

        let walk = WalkWitness::new(
            beta_endo,
            crate::internal::endoscalar::PointsWitness::<
                C::NestedCurve,
                native::NumPoints<C::Profile>,
                native::Endoscalings<C::Profile>,
            >::new(beta_endo, &inputs.walk()),
        );

        let walk_rx = <WalkStage<C::NestedCurve, C::Profile> as StageExt<C::CircuitField, R>>::rx(
            Blind::random(rng),
            &walk,
        )?;

        let num_steps = native::NumSteps::<C::Profile>::len();
        let mut step_rxs = Vec::with_capacity(num_steps);
        let (registry, walk_ref) = (&self.native_registry, &walk);
        // As for the nested steps: a paged step's pages read what they do
        // not load of the points stages off the stages' polynomials.
        if C::Profile::PAGES.endoscaling_step.pages > 1 {
            let mut pages = builder.take_native_pages(&self.native_plans);
            let [binding, preamble, registry_wx, ab, f] = builder.native_points_input_rxs();
            let stages = [binding, preamble, registry_wx, ab, f, &walk_rx];
            for step in 0..num_steps {
                let (step_rx, _) = C::Profile::prove_internal(
                    &mut pages,
                    paging::Circuit::EndoscalingStep(step as u32),
                    native::circuits::endoscaling_step::Circuit::<C, R>::new(step),
                    registry,
                    native::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index::<C::Profile>(),
                    |circuit| {
                        native::InternalCircuitIndex::ExtensionCircuit(circuit)
                            .circuit_index::<C::Profile>()
                    },
                    &stages,
                    || native::circuits::endoscaling_step::Witness {
                        inputs,
                        walk: walk_ref,
                    },
                    &mut *rng,
                )?;
                step_rxs.push(step_rx);
            }
            builder.set_native_pages(pages);
        }
        // As for the nested steps: independent work, with each step's
        // blinding factor drawn first, in step order.
        let blinds: Vec<Blind<C::CircuitField>> = (step_rxs.len()..num_steps)
            .map(|_| Blind::random(rng))
            .collect();
        for step_rx in B::map(blinds.into_iter().enumerate(), |(step, blind)| {
            let trace = native::circuits::endoscaling_step::Circuit::<C, R>::new(step)
                .trace(native::circuits::endoscaling_step::Witness {
                    inputs,
                    walk: walk_ref,
                })?
                .into_output();
            registry.assemble_with_alpha(
                &trace,
                native::InternalCircuitIndex::EndoscalingStep(step as u32)
                    .circuit_index::<C::Profile>(),
                blind,
            )
        }) {
            step_rxs.push(step_rx?);
        }

        builder.set_native_points_walk_rx(walk_rx);
        builder.set_native_endoscaling_step_rxs(step_rxs);

        let p_commitment = walk.p();
        Ok((p_commitment, walk))
    }
}
