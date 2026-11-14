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
//! [`native::stages::points`](crate::internal::native::stages::points)).

use alloc::{sync::Arc, vec::Vec};

use ragu_backend::{Backend, PolyDevice, Slot, StartedCommitments};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, FixedGenerators, Result,
    drivers::emulator::{Emulator, Wireless},
    maybe::Always,
};
use ragu_primitives::{EndoscalarChallenge, lift_endoscalar, vec::Len};
use udon::{curve::Affine, field::Field};

use super::{
    _03_s_prime::{NativeSPrime, NestedSPrime},
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    _08_f::{NativeF, NestedF},
    device::{Devices, Held},
};
use crate::{
    Application, Proof,
    internal::{
        native::{
            RxComponent, RxIndex,
            stages::points::{Inputs, WalkWitness},
        },
        nested::{PointsWitness, pcs},
        online,
    },
    multicore::{Background, Batches, Handle, current_num_threads, par_join},
    profile::ProfiledCycle,
    proof::{ProofBuilder, commit_all, commit_all_beside},
    timing::span,
};

/// A walk's step polynomials, in step order, each shared with the task that
/// commits to it.
type StepRxs<F, R> = Vec<Arc<sparse::Polynomial<F, R>>>;

/// The two walks' step polynomials, which
/// [`compute_p`](Application::compute_p) returns before they are all
/// committed to.
pub(super) struct StepPolys<C: Cycle, R: Rank> {
    native: StepRxs<C::CircuitField, R>,
    nested: StepRxs<C::ScalarField, R>,
}

/// The commitments to the two walks' steps, which
/// [`compute_p`](Application::compute_p) starts and does not wait for: each
/// step is handed over as soon as it is assembled, and committed to with the
/// others that are ready by the time the device is free for them. The device
/// is idle while the walks are traced and in the stages after them, so the
/// commitments, the longest wait of the step, go on behind both.
pub(super) struct StepCommitments<C: Cycle, R: Rank> {
    native: StepBatches<C::HostCurve, R>,
    nested: StepBatches<C::NestedCurve, R>,
}

/// A walk's step polynomials on their way to being committed to: handed over
/// one at a time and committed to in batches.
type StepBatches<P, R> = Batches<
    Arc<sparse::Polynomial<<P as Affine>::Scalar, R>>,
    P,
    alloc::boxed::Box<dyn StartedCommitments<<P as Affine>::Projective>>,
>;

/// Commits to a batch of step polynomials, each as it would be alone.
fn commit_steps<B: Backend, P: Affine, R: Rank, G: FixedGenerators<P>>(
    rxs: &[Arc<sparse::Polynomial<P::Scalar, R>>],
    generators: &G,
) -> Vec<P> {
    span("p.steps.commit", || {
        commit_all::<B, P, R, G>(&rxs.iter().map(|rx| &**rx).collect::<Vec<_>>(), generators)
    })
}

/// How a walk's step polynomials are committed to over the generators it
/// holds: through the backend `B`, begun without waiting where `B` can.
struct CommitSteps<'a, B, G>(&'a G, core::marker::PhantomData<fn() -> B>);

impl<B, G> Clone for CommitSteps<'_, B, G> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B, G> Copy for CommitSteps<'_, B, G> {}

impl<B: Backend, P: Affine, R: Rank, G: FixedGenerators<P> + Sync>
    Handle<Arc<sparse::Polynomial<P::Scalar, R>>, P> for CommitSteps<'_, B, G>
{
    type Started = alloc::boxed::Box<dyn StartedCommitments<P::Projective>>;

    fn start(self, rxs: &[Arc<sparse::Polynomial<P::Scalar, R>>]) -> Option<Self::Started> {
        span("p.steps.start", || {
            B::sparse_commit_many_start(&rxs.iter().map(|rx| &**rx).collect::<Vec<_>>(), self.0)
        })
    }

    fn ready(self, started: &mut Self::Started) -> bool {
        started.ready()
    }

    fn wait(self, started: Self::Started, rxs: &[Arc<sparse::Polynomial<P::Scalar, R>>]) -> Vec<P> {
        // A thread that waits here does the pool's other work meanwhile.
        let mut started = started;
        crate::multicore::wait_until(|| started.ready());
        span("p.steps.wait", || match started.finish() {
            Some(projective) => {
                let mut affine = alloc::vec![P::identity(); projective.len()];
                P::batch_to_affine(&projective, &mut affine);
                affine
            }
            None => commit_steps::<B, P, R, G>(rxs, self.0),
        })
    }

    fn run(self, rxs: &[Arc<sparse::Polynomial<P::Scalar, R>>]) -> Vec<P> {
        commit_steps::<B, P, R, G>(rxs, self.0)
    }
}

/// The polynomial `rx` shares with nobody any more.
fn unshared<F: Field, R: Rank>(rx: Arc<sparse::Polynomial<F, R>>) -> sparse::Polynomial<F, R> {
    Arc::try_unwrap(rx).unwrap_or_else(|rx| (*rx).clone())
}

impl<C: ProfiledCycle, R: Rank> StepCommitments<C, R> {
    /// No step yet.
    pub(super) fn new() -> Self {
        Self {
            native: Batches::new(),
            nested: Batches::new(),
        }
    }

    /// Sets the walks' steps on `builder`, each with its commitment. To be
    /// called once the scope `compute_p` started the commitments in has
    /// ended; the steps of a walk whose commitments did not all get started
    /// are committed to here.
    pub(super) fn finish<B: Backend>(
        self,
        polys: StepPolys<C, R>,
        params: &C::Params,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) {
        let commitments = self.native.finish(&polys.native, |rxs| {
            commit_steps::<B, C::HostCurve, R, _>(rxs, C::host_generators(params))
        });
        builder.set_native_endoscaling_steps(
            polys.native.into_iter().map(unshared).collect(),
            commitments,
        );
        let commitments = self.nested.finish(&polys.nested, |rxs| {
            commit_steps::<B, C::NestedCurve, R, _>(rxs, C::nested_generators(params))
        });
        builder.set_nested_endoscaling_steps(
            polys.nested.into_iter().map(unshared).collect(),
            commitments,
        );
    }
}

/// The native points stages' witnesses: the nested batch's commitments.
pub(super) type NativeInputs<C> = Inputs<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The native walk stage's witness: the endoscalar and the walk's outputs.
pub(super) type NativeWalk<C> =
    WalkWitness<<C as Cycle>::NestedCurve, <C as ProfiledCycle>::Profile>;

/// The wireless emulator the fuse step's transcript runs in, which `pre_beta`
/// is sampled from.
type NativeFuseEmulator<C> = Emulator<Wireless<Always<()>, <C as Cycle>::CircuitField>>;

/// Accumulates `polys` onto `first` by Horner's rule in `beta`: each
/// polynomial in turn replaces the running sum `p` with `beta * p + poly`.
///
/// The polynomials are split into consecutive groups, each accumulated from
/// zero through [`Backend::map`], and the groups
/// are then accumulated in the same order. A group of $s$ polynomials scales
/// everything before it by $\beta^s$, which is the single pass over all of
/// them with its multiplications regrouped: the coefficients are the same
/// field elements for every grouping.
fn horner_accumulate<B: ragu_backend::Backend, F: Field, R: Rank>(
    first: sparse::Polynomial<F, R>,
    polys: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    let per_group = polys.len().div_ceil(current_num_threads()).max(1);
    let partials = B::map(polys.chunks(per_group), |group| {
        let mut shift = F::ONE;
        let mut partial = sparse::Polynomial::<F, R>::new();
        for poly in group {
            shift *= beta;
            partial.scale(beta);
            partial.add_assign(poly);
        }
        (shift, partial)
    });

    let mut acc = first;
    for (shift, partial) in partials {
        acc.scale(shift);
        acc.add_assign(&partial);
    }
    acc
}

/// [`horner_accumulate`] on `device`, which holds the polynomials: the same
/// sum, each polynomial with the power of `beta` the passes give it.
fn device_accumulate<F: Field, R: Rank>(
    device: &mut dyn PolyDevice<F, R>,
    held: &mut Held<'_, F, R>,
    first: &sparse::Polynomial<F, R>,
    current: &[&sparse::Polynomial<F, R>],
    polys: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    let slots = held.slots(device, current, polys);
    let first = match held.f {
        Some(slot) => slot,
        None => device.upload(&[first])[0],
    };
    // The last polynomial has weight one, and `first` the highest power.
    let mut weight = F::ONE;
    let mut job: Vec<(F, Slot)> = Vec::with_capacity(slots.len() + 1);
    for slot in slots.into_iter().rev() {
        job.push((weight, slot));
        weight *= beta;
    }
    job.push((weight, first));
    let sum = device.lincomb(&[job]);
    device
        .download(&sum)
        .pop()
        .expect("one polynomial per slot")
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
            .chain(batch.commitments(current))
            .collect();
        assert_eq!(
            points.len(),
            crate::internal::native::NumPoints::<C::Profile>::len()
        );
        Inputs::from_walk(&points)
    }

    /// Accumulates $p$ and $p_n$, walks the two batches' commitments and
    /// sets the walks' stages on `builder`.
    ///
    /// The walks' step polynomials are not set on `builder`: they are
    /// returned, and committed to on `background` through `steps`, which
    /// holds every commitment by the time the scope ends. The caller then
    /// sets both with [`StepCommitments::finish`].
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_p<'dr, 'scope, RNG: rand::CryptoRng>(
        &'scope self,
        rng: &mut RNG,
        pre_beta: &EndoscalarChallenge<'dr, NativeFuseEmulator<C>>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        f: &NativeF<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
        devices: &mut Devices<'_, C, R>,
        background: &Background<'_, 'scope>,
        steps: &'scope StepCommitments<C, R>,
    ) -> Result<(
        PointsWitness<C::HostCurve, C::Profile>,
        NativeInputs<C>,
        NativeWalk<C>,
        StepPolys<C, R>,
    )> {
        // Extract endoscalar from pre_beta and compute effective beta. Going
        // through the validated `EndoscalarChallenge` makes the
        // `value < 2^CAPACITY` precondition a type invariant rather than an
        // unchecked argument to `extract_endoscalar`.
        let beta_endo = pre_beta.extract_native();

        // The nested batch's commitments, which the native walk runs over.
        let native_points = self.native_inputs(
            nested_f,
            nested_s_prime,
            nested_registry_wy,
            left,
            right,
            builder,
        );

        // The blindings of the walks' stages and steps, drawn here in the
        // order building them one after another draws them: the nested
        // endoscalar and points stages and each nested step, then the native
        // walk stage and each native step. The walks below then read no
        // randomness, and each assembles its own steps.
        let endoscalar_alpha = C::ScalarField::random(|bytes| rng.fill_bytes(bytes));
        let points_alpha = C::ScalarField::random(|bytes| rng.fill_bytes(bytes));
        let nested_step_alphas: Vec<_> =
            (0..crate::internal::nested::NumSteps::<C::Profile>::len())
                .map(|_| C::ScalarField::random(|bytes| rng.fill_bytes(bytes)))
                .collect();
        let native_walk_alpha = C::CircuitField::random(|bytes| rng.fill_bytes(bytes));
        let native_step_alphas: Vec<_> =
            (0..crate::internal::native::NumSteps::<C::Profile>::len())
                .map(|_| C::CircuitField::random(|bytes| rng.fill_bytes(bytes)))
                .collect();
        let (host_generators, nested_generators) = (
            C::host_generators(self.params),
            C::nested_generators(self.params),
        );
        let (native_registry, nested_registry) = (&self.native_registry, &self.nested_registry);
        let commit_native = CommitSteps::<B, _>(host_generators, core::marker::PhantomData);
        let commit_nested = CommitSteps::<B, _>(nested_generators, core::marker::PhantomData);

        // The two accumulations and the two endoscaling walks read only
        // values that are already fixed, so the four run together. Each
        // walk hands its steps over to be committed to as they are ready.
        //
        // The commitments no stage has asked for yet are computed beside
        // them: the device has nothing else to do until the first step is
        // assembled, and from then to the end of the fuse it is the steps'
        // commitments that are waited for. A failure to list the nested
        // ones is left for `build` to report.
        let (native_poly, nested_poly, walk, native_walk) = {
            let pending_native = builder.pending_native();
            let pending_nested = builder.pending_nested().ok();
            let (native_pending, nested_pending) = (
                &pending_native.polys,
                pending_nested.as_ref().map(|pending| &pending.polys),
            );

            let (native_polys, commitments) =
                self.native_p_terms(left, right, s_prime, registry_wy, builder);
            let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
            let nested_polys: Vec<_> = batch.evaluated().collect();

            // The points stage's inputs: f's commitment, then the batch's.
            let mut points =
                Vec::with_capacity(crate::internal::native::NumPoints::<C::Profile>::len().max(1));
            points.push(f.commitment);
            points.extend_from_slice(&commitments);

            // A side with a device accumulates there, from the polynomials
            // it holds.
            let native_current = self.native_current_polys(s_prime, registry_wy, builder);
            let nested_current = batch.current();
            let (native_device, nested_device) =
                (devices.native.as_deref_mut(), devices.nested.as_deref_mut());
            let (native_held, nested_held) = (&mut devices.native_held, &mut devices.nested_held);

            let (walked, (native_commitments, nested_commitments)) = par_join!(
                || span("p.parallel", || {
                    par_join!(
                        || span("p.horner", || {
                            let beta = lift_endoscalar(beta_endo);
                            match native_device {
                                Some(device) => device_accumulate(
                                    device,
                                    native_held,
                                    &f.poly,
                                    &native_current,
                                    &native_polys,
                                    beta,
                                ),
                                None => horner_accumulate::<B, _, R>(
                                    f.poly.clone(),
                                    &native_polys,
                                    beta,
                                ),
                            }
                        }),
                        || span("p.horner", || {
                            let beta = lift_endoscalar(beta_endo);
                            match nested_device {
                                Some(device) => device_accumulate(
                                    device,
                                    nested_held,
                                    &nested_f.poly,
                                    &nested_current,
                                    &nested_polys,
                                    beta,
                                ),
                                None => horner_accumulate::<B, _, R>(
                                    nested_f.poly.clone(),
                                    &nested_polys,
                                    beta,
                                ),
                            }
                        }),
                        || span("p.walk", || Self::endoscaling_steps(
                            nested_registry,
                            beta_endo,
                            &points,
                            &nested_step_alphas,
                            |ready| match ready {
                                Some((step, rx)) => {
                                    steps.nested.push(step, Arc::clone(rx), commit_nested)
                                }
                                None => steps.nested.look_in(commit_nested),
                            },
                        )),
                        || span("p.walk", || Self::native_endoscaling_steps(
                            native_registry,
                            beta_endo,
                            &native_points,
                            &native_step_alphas,
                            |ready| match ready {
                                Some((step, rx)) => {
                                    steps.native.push(step, Arc::clone(rx), commit_native)
                                }
                                None => steps.native.look_in(commit_native),
                            },
                        )),
                    )
                }),
                || span("p.pending", || par_join!(
                    || commit_all_beside::<B, C::HostCurve, R, _>(native_pending, host_generators),
                    || nested_pending.map(|polys| {
                        commit_all_beside::<B, C::NestedCurve, R, _>(polys, nested_generators)
                    }),
                )),
            );
            pending_native.fill(native_commitments);
            if let (Some(pending), Some(commitments)) = (pending_nested, nested_commitments) {
                pending.fill(commitments);
            }
            walked
        };
        // The steps not committed to yet are, behind the stages after this
        // one.
        steps.nested.close(background, commit_nested);
        steps.native.close(background, commit_native);
        let (points, nested_step_rxs) = walk?;
        let (native_walk, native_step_rxs) = native_walk?;

        // The nested stages over the host-curve points, and then the native
        // walk stage.
        let p_commitment = Self::set_endoscaling_stages(
            beta_endo,
            &points,
            endoscalar_alpha,
            points_alpha,
            builder,
        )?;
        builder.set_native_p_poly(native_poly, p_commitment);

        let nested_p_commitment =
            Self::set_native_walk_stage(native_walk_alpha, &native_walk, builder)?;
        debug_assert_eq!(
            B::sparse_commit_to_affine(&nested_poly, C::nested_generators(self.params)),
            nested_p_commitment,
            "nested P must be the Horner walk over the batch's commitments"
        );
        builder.set_nested_p_poly(nested_poly, nested_p_commitment);

        Ok((
            points,
            native_points,
            native_walk,
            StepPolys {
                native: native_step_rxs,
                nested: nested_step_rxs,
            },
        ))
    }

    /// The current step's polynomials among
    /// [`native_p_terms`](Self::native_p_terms), in its order.
    pub(super) fn native_current_polys<'a>(
        &self,
        s_prime: &'a NativeSPrime<C, R>,
        registry_wy: &'a RegistryWy<C, R>,
        builder: &'a ProofBuilder<'_, C, R, B>,
    ) -> Vec<&'a sparse::Polynomial<C::CircuitField, R>> {
        [
            &s_prime.registry_wx0_poly,
            &s_prime.registry_wx1_poly,
            &registry_wy.poly,
            builder.native_a_poly(),
            builder.native_b_poly(),
            builder.native_registry_xy_poly(),
        ]
        .into_iter()
        .chain(builder.online_polynomials())
        .collect()
    }

    /// The polynomials $p(X)$ accumulates after $f$, with their
    /// commitments, in the `Write` serialization order of
    /// `native::stages::eval::Output`.
    pub(super) fn native_p_terms<'a>(
        &self,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        s_prime: &'a NativeSPrime<C, R>,
        registry_wy: &'a RegistryWy<C, R>,
        builder: &'a ProofBuilder<'_, C, R, B>,
    ) -> (
        Vec<&'a sparse::Polynomial<C::CircuitField, R>>,
        Vec<C::HostCurve>,
    ) {
        let mut polys = Vec::new();
        let mut commitments = Vec::new();
        let mut acc = |poly: &'a sparse::Polynomial<C::CircuitField, R>, commitment| {
            polys.push(poly);
            commitments.push(commitment);
        };

        for proof in [left, right] {
            for id in RxIndex::all::<C::Profile>() {
                acc(&proof[id], proof.native_rx_commitment(id));
            }
            acc(
                &proof[RxComponent::AbA],
                proof.native_commitment(RxComponent::AbA),
            );
            acc(
                &proof[RxComponent::AbB],
                proof.native_commitment(RxComponent::AbB),
            );
            acc(
                proof.native_registry_xy_poly(),
                proof.native_registry_xy_commitment(),
            );
            acc(proof.native_p_poly(), proof.native_p_commitment());
        }

        acc(&s_prime.registry_wx0_poly, s_prime.registry_wx0_commitment);
        acc(&s_prime.registry_wx1_poly, s_prime.registry_wx1_commitment);
        acc(&registry_wy.poly, registry_wy.commitment);
        acc(builder.native_a_poly(), builder.native_a_commitment());
        acc(builder.native_b_poly(), builder.native_b_commitment());
        acc(
            builder.native_registry_xy_poly(),
            builder.native_registry_xy_commitment(),
        );

        // The online slots, in slot order, whose commitments the nested
        // `loading` circuit walks off the preamble bridge stage.
        let online_polys = online::polys(left, right, builder.online_polynomials());
        let online_commitments = online::commitments(left, right, builder.online_commitments());
        for (poly, commitment) in online_polys.into_iter().zip(online_commitments) {
            acc(poly, commitment);
        }

        (polys, commitments)
    }
}
