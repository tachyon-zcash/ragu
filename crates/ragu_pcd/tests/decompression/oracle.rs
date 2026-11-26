//! A test oracle for the chunk circuits: the compressed verifier
//! assembled from the gadgets, split between the
//! two fields of the cycle: what the native verifier checks in the circuit
//! field runs on one side, what it checks in the scalar field on the
//! other, and what passes between them is what a stage of the
//! decompression proof would carry.
//!
//! The circuit-field side replays the fuse's transcript for the proof's
//! challenges and the compression's for its own, derives the claims'
//! targets through [`ProofInputs`], runs the host curve's field checks,
//! derives the nested curve's commitments and checks its IPA, and
//! recomputes the two nested stages the native verifier recomputes. The
//! scalar-field side lifts the challenges from their endoscalars, derives
//! the nested targets, runs the nested curve's field checks, derives the
//! host curve's commitments and checks its IPA.
//!
//! Between the sides pass the endoscalars of every challenge, the digits
//! of the full-width scalars each side's IPA check needs the other to
//! scale by, and the commitments of the runs of the scalar field's values
//! the circuit-field transcript absorbs. The chunk circuits make each a
//! stage the other side recomputes or absorbs (see [`stages`]); here, in
//! the whole-side circuits the tests run, the [`Witness`] carries them and
//! the two sides allocate them from it, with each side's own $v$ and
//! $c b z$ held to the witness's. Here the registry's evaluations arrive
//! as wires nothing checks, and each side's IPA takes its $G'$ as a
//! witness point these circuits do not bind: the chunk circuits hold the
//! evaluations to the step's online batches and bind $G'$ through the step
//! binding (see the module's *Registry evaluations* and *The step
//! binding*).
//!
//! [`ProofInputs`]: crate::internal::native::stages::preamble::ProofInputs
//! [`stages`]: crate::decompress::stages

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, FixedGenerators, Result, drivers::Driver};
use ragu_primitives::{Element, Endoscalar, GadgetExt, NonzeroBank, Point};
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine},
    field::Field,
};

use self::transcript::{Absorb, Challenge, RawChallenge};
use crate::{
    RAGU_TAG,
    compress::{
        Sampled,
        revdot::{
            OpeningClaim,
            fold::{Derived, Weights},
            native_components, native_position, nested_components, nested_position,
        },
    },
    decompress::{
        gadgets::{
            batch,
            derive::{self, Digits, Fixed},
            ipa, revdot,
        },
        program::AbValue,
        prover::Witness,
        side::{NativeTargets, NestedTargets},
    },
    internal::{
        native::{
            self,
            stages::{eval::generator_index, preamble::ProofInputs},
        },
        nested::{self, stages::challenges as challenge_stage, unified as nested_unified},
        transcript::Transcript,
    },
    ipa::IpaCycle,
    profile::{ProfiledCycle, Standard},
    proof::bridge_alpha_power,
};

pub(crate) mod transcript {
    //! The compression's transcript as a gadget: the schedule of
    //! [`verify_compressed`](crate::Application::verify_compressed) over an
    //! allocated instance and allocated messages, squeezing the challenges
    //! the native verifier squeezes.
    //!
    //! The native transcript is a Poseidon sponge over the circuit field. It
    //! absorbs the host curve's scalars directly and the nested curve's points
    //! by their coordinates; what lives in the other field, the host curve's
    //! points and the nested curve's scalars, it commits by the run before
    //! each challenge and absorbs as the commitment, a nested-curve point (see
    //! [`CycleTranscript`](crate::ipa::CycleTranscript)). In the circuit over
    //! the circuit field the same sponge runs over allocated elements and
    //! points, each run's commitment an allocated point: what the commitment
    //! covers is bound elsewhere, by the proof's consumer holding the point to
    //! the run's stage on the other side (see [`stages`](crate::decompress::stages)). Each
    //! challenge is read as the
    //! compression reads it: the squeezed element constrained into the
    //! endoscalar range, its endoscalar, which scales points, and the
    //! endoscalar's lift into the circuit field, which the field checks over
    //! this field use. The nested curve's field checks use the same
    //! endoscalar's lift into the scalar field, which the circuit over that
    //! field must receive bound to these bits.

    use alloc::vec::Vec;

    use ragu_core::{PoseidonPermutation, Result, drivers::Driver};
    use ragu_primitives::{Element, Endoscalar, EndoscalarChallenge, GadgetExt, Point, io::Buffer};
    use udon::curve::EndomorphismAffine as Affine;

    use crate::{
        compress::{Sampled, revdot::fold::Weights},
        internal::transcript::Transcript,
        ipa::IPA_TAG,
    };

    /// What the transcript absorbs: an element by value, a point by its
    /// coordinates.
    pub(crate) trait Absorb<'dr, D: Driver<'dr>> {
        fn absorb<P: PoseidonPermutation<D::F>>(
            &self,
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<()>;
    }

    impl<'dr, D: Driver<'dr>> Absorb<'dr, D> for Element<'dr, D> {
        fn absorb<P: PoseidonPermutation<D::F>>(
            &self,
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<()> {
            transcript.write(dr, self)
        }
    }

    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Absorb<'dr, D> for Point<'dr, D, C> {
        fn absorb<P: PoseidonPermutation<D::F>>(
            &self,
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<()> {
            GadgetExt::write(self, dr, transcript)
        }
    }

    /// A child's values as the preamble stage holds them, allocated.
    pub(crate) struct Child<'dr, D: Driver<'dr>> {
        pub x: Element<'dr, D>,
        pub y: Element<'dr, D>,
    }

    /// The instance as the transcript absorbs it, with the fields of
    /// [`Instance`](crate::compress::instance::Instance) that lie in the
    /// circuit field, as elements, and on the nested curve, as points. Its
    /// scalar-field values, the host commitments and the nested curve's
    /// instance values, are the instance's two runs
    /// ([`Run::Commitments`](crate::decompress::stages::Run::Commitments) and
    /// [`Run::Scalars`](crate::decompress::stages::Run::Scalars)).
    pub(crate) struct Instance<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        /// $\omega^j$ of the circuit id.
        pub circuit_id: Element<'dr, D>,

        /// The nested commitments, in
        /// [`nested_components`](crate::compress::revdot::nested_components)
        /// order.
        pub nested: Vec<Point<'dr, D, C>>,
        pub nested_registry_xy: Point<'dr, D, C>,
        pub nested_p: Point<'dr, D, C>,
        pub nested_challenges_partial: Point<'dr, D, C>,

        pub c: Element<'dr, D>,
        pub v: Element<'dr, D>,

        pub left: Child<'dr, D>,
        pub right: Child<'dr, D>,
        pub a_at_u: Element<'dr, D>,
        pub b_at_u: Element<'dr, D>,
    }

    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Instance<'dr, D, C> {
        /// Absorbs the instance in the native verifier's order: the circuit
        /// id, the host commitments' run, the host curve's scalars, the nested
        /// commitments, then the run of the scalar field's instance values.
        fn absorb<P: PoseidonPermutation<D::F>>(
            &self,
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
            runs: &mut Runs<'_, 'dr, D, C>,
        ) -> Result<()> {
            self.circuit_id.absorb(dr, transcript)?;
            runs.absorb(dr, transcript)?; // the host commitments
            let (l, r) = (&self.left, &self.right);
            for element in [
                &self.c,
                &self.v,
                &l.x,
                &l.y,
                &r.x,
                &r.y,
                &self.a_at_u,
                &self.b_at_u,
            ] {
                element.absorb(dr, transcript)?;
            }
            for point in self.nested.iter().chain([
                &self.nested_registry_xy,
                &self.nested_p,
                &self.nested_challenges_partial,
            ]) {
                point.absorb(dr, transcript)?;
            }
            runs.absorb(dr, transcript)?; // the scalar field's instance values
            Ok(())
        }
    }

    /// A challenge as the compression uses it: the endoscalar read from the
    /// squeezed element, which scales points, and its lift, the scalar the
    /// field checks over this field use.
    pub(crate) struct Challenge<'dr, D: Driver<'dr>> {
        pub endoscalar: Endoscalar<'dr, D>,
        pub lift: Element<'dr, D>,
    }

    impl<'dr, D: Driver<'dr>> Challenge<'dr, D> {
        /// Squeezes a challenge, constraining the element into the endoscalar
        /// range as the native transcript requires of it.
        fn squeeze<P: PoseidonPermutation<D::F>>(
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<Self> {
            let element = transcript.challenge(dr)?;
            let endoscalar = Endoscalar::extract(EndoscalarChallenge::from_element(dr, element)?);
            let lift = endoscalar.lift(dr)?;
            Ok(Challenge { endoscalar, lift })
        }
    }

    /// A challenge of the fuse's transcript as the compressed verifier
    /// replays it: the squeezed element, which the native side uses as it is,
    /// and its endoscalar, whose lift the nested side uses and whose bits
    /// scale the challenge stage's generator.
    pub(crate) struct RawChallenge<'dr, D: Driver<'dr>> {
        pub raw: Element<'dr, D>,
        pub endoscalar: Endoscalar<'dr, D>,
    }

    impl<'dr, D: Driver<'dr>> RawChallenge<'dr, D> {
        /// Squeezes a challenge, constraining it into the endoscalar range as
        /// the fuse's circuits do.
        pub(crate) fn squeeze<P: PoseidonPermutation<D::F>>(
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<Self> {
            let raw = transcript.challenge(dr)?;
            let endoscalar =
                Endoscalar::extract(EndoscalarChallenge::from_element(dr, raw.clone())?);
            Ok(RawChallenge { raw, endoscalar })
        }
    }

    /// The host curve's messages as the transcript absorbs them: its scalars,
    /// which lie in the circuit field, as elements. Its points are in the
    /// runs.
    pub(crate) struct NativeMessages<'dr, D: Driver<'dr>> {
        pub inner_epsilon: Element<'dr, D>,
        pub outer_epsilon: Element<'dr, D>,
        pub openings: Vec<Element<'dr, D>>,
        pub p_at_inverse_r: Element<'dr, D>,
        pub q_at_r: Element<'dr, D>,
        pub evaluations: Vec<Element<'dr, D>>,
        pub c: Element<'dr, D>,
    }

    /// The nested curve's messages as the transcript absorbs them: its points.
    /// Its scalars are in the runs.
    pub(crate) struct NestedMessages<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        pub inner: Point<'dr, D, C>,
        pub outer: Point<'dr, D, C>,
        pub p: Point<'dr, D, C>,
        pub q: Point<'dr, D, C>,
        pub f: Point<'dr, D, C>,
        pub s_commitment: Point<'dr, D, C>,
        pub rounds: Vec<(Point<'dr, D, C>, Point<'dr, D, C>)>,
    }

    /// The challenges the transcript squeezes for one curve, in the order
    /// the native verifier squeezes them.
    pub(crate) struct Challenges<'dr, D: Driver<'dr>> {
        pub sampled: Sampled<Challenge<'dr, D>>,
        pub weights: Weights<Challenge<'dr, D>>,
        pub rho: Challenge<'dr, D>,
        pub r: Challenge<'dr, D>,
        pub alpha: Challenge<'dr, D>,
        pub u: Challenge<'dr, D>,
        pub beta: Challenge<'dr, D>,
        pub xi: Challenge<'dr, D>,
        pub z: Challenge<'dr, D>,
        pub rounds: Vec<Challenge<'dr, D>>,
    }

    /// The runs' commitments in [`Run`](crate::decompress::stages::Run) order, absorbed
    /// one per run as the native transcript absorbs them: witness points,
    /// which the chunk circuits' consumer holds to the run stages.
    pub(crate) struct Runs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
        points: core::slice::Iter<'a, Point<'dr, D, C>>,
    }

    impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> Runs<'_, 'dr, D, C> {
        /// Absorbs the next run's commitment.
        fn absorb<P: PoseidonPermutation<D::F>>(
            &mut self,
            dr: &mut D,
            transcript: &mut Transcript<'dr, D, P>,
        ) -> Result<()> {
            self.points
                .next()
                .expect("a commitment per run")
                .absorb(dr, transcript)
        }
    }

    /// Replays the compression's transcript over the allocated statement,
    /// both curves' messages and `runs`, the commitments of the scalar field's
    /// runs in [`Run`](crate::decompress::stages::Run) order, returning each curve's
    /// challenges: the statement is absorbed, both curves' challenges are
    /// sampled, then the host curve's messages run, then the nested curve's.
    ///
    /// # Panics
    ///
    /// Panics unless `runs` holds one commitment per run.
    pub(crate) fn replay<'dr, D, P, C>(
        dr: &mut D,
        params: &'dr P,
        instance: &Instance<'dr, D, C>,
        output_header: &[Element<'dr, D>],
        native: &NativeMessages<'dr, D>,
        nested: &NestedMessages<'dr, D, C>,
        runs: &[Point<'dr, D, C>],
    ) -> Result<(Challenges<'dr, D>, Challenges<'dr, D>)>
    where
        D: Driver<'dr>,
        P: PoseidonPermutation<D::F>,
        C: Affine<Base = D::F>,
    {
        let mut runs = Runs {
            points: runs.iter(),
        };
        let mut transcript = Transcript::new(dr, params, IPA_TAG)?;
        instance.absorb(dr, &mut transcript, &mut runs)?;
        for element in output_header {
            element.absorb(dr, &mut transcript)?;
        }
        let native_sampled = sample(dr, &mut transcript)?;
        let nested_sampled = sample(dr, &mut transcript)?;
        let native = native_side(
            dr,
            &mut transcript,
            native_sampled,
            native,
            nested.rounds.len(),
            &mut runs,
        )?;
        let nested = nested_side(dr, &mut transcript, nested_sampled, nested, &mut runs)?;
        assert!(runs.points.next().is_none(), "every run is absorbed");
        Ok((native, nested))
    }

    /// The challenges sampled for one curve once the statement is absorbed.
    fn sample<'dr, D: Driver<'dr>, P: PoseidonPermutation<D::F>>(
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
    ) -> Result<Sampled<Challenge<'dr, D>>> {
        Ok(Sampled {
            w: Challenge::squeeze(dr, transcript)?,
            y: Challenge::squeeze(dr, transcript)?,
            z: Challenge::squeeze(dr, transcript)?,
            sigma: Challenge::squeeze(dr, transcript)?,
        })
    }

    /// The host curve's reduction, batch and IPA of `rounds` rounds on the
    /// transcript: its points come as runs, one before each challenge a point
    /// precedes.
    fn native_side<'dr, D, P, C>(
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
        sampled: Sampled<Challenge<'dr, D>>,
        messages: &NativeMessages<'dr, D>,
        rounds: usize,
        runs: &mut Runs<'_, 'dr, D, C>,
    ) -> Result<Challenges<'dr, D>>
    where
        D: Driver<'dr>,
        P: PoseidonPermutation<D::F>,
        C: Affine<Base = D::F>,
    {
        let squeeze = Challenge::squeeze;

        runs.absorb(dr, transcript)?; // the inner error commitment
        let mu = squeeze(dr, transcript)?;
        let nu = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // the outer error commitment
        let mu_prime = squeeze(dr, transcript)?;
        let nu_prime = squeeze(dr, transcript)?;
        messages.inner_epsilon.absorb(dr, transcript)?;
        messages.outer_epsilon.absorb(dr, transcript)?;
        let rho = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // p and q
        let r = squeeze(dr, transcript)?;
        for opened in &messages.openings {
            opened.absorb(dr, transcript)?;
        }
        messages.p_at_inverse_r.absorb(dr, transcript)?;
        messages.q_at_r.absorb(dr, transcript)?;

        let alpha = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // f
        let u = squeeze(dr, transcript)?;
        for evaluation in &messages.evaluations {
            evaluation.absorb(dr, transcript)?;
        }
        let beta = squeeze(dr, transcript)?;

        runs.absorb(dr, transcript)?; // the masking commitment
        let xi = squeeze(dr, transcript)?;
        let z = squeeze(dr, transcript)?;
        let rounds = (0..rounds)
            .map(|_| {
                runs.absorb(dr, transcript)?; // the round's L and R
                squeeze(dr, transcript)
            })
            .collect::<Result<Vec<_>>>()?;
        messages.c.absorb(dr, transcript)?;

        Ok(Challenges {
            sampled,
            weights: Weights {
                mu,
                nu,
                mu_prime,
                nu_prime,
            },
            rho,
            r,
            alpha,
            u,
            beta,
            xi,
            z,
            rounds,
        })
    }

    /// The nested curve's reduction, batch and IPA on the transcript: its
    /// scalars come as runs, one before each challenge scalars precede; its
    /// IPA's $c$ precedes none.
    fn nested_side<'dr, D, P, C>(
        dr: &mut D,
        transcript: &mut Transcript<'dr, D, P>,
        sampled: Sampled<Challenge<'dr, D>>,
        messages: &NestedMessages<'dr, D, C>,
        runs: &mut Runs<'_, 'dr, D, C>,
    ) -> Result<Challenges<'dr, D>>
    where
        D: Driver<'dr>,
        P: PoseidonPermutation<D::F>,
        C: Affine<Base = D::F>,
    {
        let squeeze = Challenge::squeeze;

        messages.inner.absorb(dr, transcript)?;
        let mu = squeeze(dr, transcript)?;
        let nu = squeeze(dr, transcript)?;
        messages.outer.absorb(dr, transcript)?;
        let mu_prime = squeeze(dr, transcript)?;
        let nu_prime = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // the two epsilons
        let rho = squeeze(dr, transcript)?;
        messages.p.absorb(dr, transcript)?;
        messages.q.absorb(dr, transcript)?;
        let r = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // the openings, p(1/r) and q(r)

        let alpha = squeeze(dr, transcript)?;
        messages.f.absorb(dr, transcript)?;
        let u = squeeze(dr, transcript)?;
        runs.absorb(dr, transcript)?; // the batch's values
        let beta = squeeze(dr, transcript)?;

        messages.s_commitment.absorb(dr, transcript)?;
        let xi = squeeze(dr, transcript)?;
        let z = squeeze(dr, transcript)?;
        let mut rounds = Vec::with_capacity(messages.rounds.len());
        for (l, r) in &messages.rounds {
            l.absorb(dr, transcript)?;
            r.absorb(dr, transcript)?;
            rounds.push(squeeze(dr, transcript)?);
        }

        Ok(Challenges {
            sampled,
            weights: Weights {
                mu,
                nu,
                mu_prime,
                nu_prime,
            },
            rho,
            r,
            alpha,
            u,
            beta,
            xi,
            z,
            rounds,
        })
    }

    mod tests {
        //! The transcript gadget against the native transcript on a real
        //! compressed proof: over the allocated instance, header and messages,
        //! with the commitments of the scalar field's runs the native transcript
        //! absorbs allocated as points, it squeezes every challenge the native
        //! verifier squeezes on both curves, each as the lift of the endoscalar
        //! the native squeeze yields, and follows a tampered message as the native
        //! transcript does.

        use alloc::vec::Vec;

        use ragu_core::{
            Cycle, Result,
            drivers::Driver,
            maybe::Maybe,
            pasta::{Fp, Fq, Pasta},
        };
        use ragu_primitives::{Point, Simulator, extract_endoscalar, lift_endoscalar};
        use udon::field::Field;

        use super::{Challenges, Child, Instance, NativeMessages, NestedMessages, replay};
        use crate::{
            compress::{self, Sampled},
            decompress::{
                stages::num_runs,
                support::{
                    EpAffine, EqAffine, Setup, TestR, alloc, alloc_all, replay_batch, replay_ipa,
                    replay_reduction,
                },
            },
        };

        type Dr = Simulator<Fp>;

        fn point(dr: &mut Dr, point: EpAffine) -> Result<Point<'static, Dr, EpAffine>> {
            Point::alloc(dr, <Dr as Driver>::just(|| point))
        }

        fn points(
            dr: &mut Dr,
            points: impl IntoIterator<Item = EpAffine>,
        ) -> Result<Vec<Point<'static, Dr, EpAffine>>> {
            points.into_iter().map(|p| point(dr, p)).collect()
        }

        /// The instance allocated as the transcript gadget takes it: its circuit
        /// field's values and nested commitments.
        fn instance(
            dr: &mut Dr,
            instance: &compress::instance::Instance<Pasta>,
        ) -> Result<Instance<'static, Dr, EpAffine>> {
            let child = |dr: &mut Dr, child: compress::instance::Child<Fp>| {
                Ok::<_, ragu_core::Error>(Child {
                    x: alloc(dr, child.x)?,
                    y: alloc(dr, child.y)?,
                })
            };
            Ok(Instance {
                circuit_id: alloc(dr, instance.circuit_id.omega_j())?,
                nested: points(dr, instance.nested.iter().copied())?,
                nested_registry_xy: point(dr, instance.nested_registry_xy)?,
                nested_p: point(dr, instance.nested_p)?,
                nested_challenges_partial: point(dr, instance.nested_challenges_partial)?,
                c: alloc(dr, instance.c)?,
                v: alloc(dr, instance.v)?,
                left: child(dr, instance.left)?,
                right: child(dr, instance.right)?,
                a_at_u: alloc(dr, instance.a_at_u)?,
                b_at_u: alloc(dr, instance.b_at_u)?,
            })
        }

        /// The host curve's messages allocated: its scalars as elements.
        fn native_messages(
            dr: &mut Dr,
            messages: &compress::Messages<EqAffine>,
        ) -> Result<NativeMessages<'static, Dr>> {
            let reduction = &messages.reduction;
            Ok(NativeMessages {
                inner_epsilon: alloc(dr, reduction.fold.inner_epsilon)?,
                outer_epsilon: alloc(dr, reduction.fold.outer_epsilon)?,
                openings: alloc_all(dr, reduction.openings.iter().copied())?,
                p_at_inverse_r: alloc(dr, reduction.p_at_inverse_r)?,
                q_at_r: alloc(dr, reduction.q_at_r)?,
                evaluations: alloc_all(dr, messages.batch.evaluations.iter().copied())?,
                c: alloc(dr, messages.opening.c)?,
            })
        }

        /// The nested curve's messages allocated: its points.
        fn nested_messages(
            dr: &mut Dr,
            messages: &compress::Messages<EpAffine>,
        ) -> Result<NestedMessages<'static, Dr, EpAffine>> {
            let reduction = &messages.reduction;
            let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
            for &(l, r) in &messages.opening.rounds {
                rounds.push((point(dr, l)?, point(dr, r)?));
            }
            Ok(NestedMessages {
                inner: point(dr, reduction.fold.inner)?,
                outer: point(dr, reduction.fold.outer)?,
                p: point(dr, reduction.p)?,
                q: point(dr, reduction.q)?,
                f: point(dr, messages.batch.f)?,
                s_commitment: point(dr, messages.opening.s_commitment)?,
                rounds,
            })
        }

        /// One curve's native challenges in the gadget's order.
        struct Native<F> {
            sampled: Sampled<F>,
            rest: Vec<F>,
        }

        impl<F: Field> Native<F> {
            fn new(
                sampled: Sampled<F>,
                (weights, rho, r): (compress::revdot::fold::Weights<F>, F, F),
                (alpha, u, beta): (F, F, F),
                (xi, z, rounds): (F, F, Vec<F>),
            ) -> Self {
                let mut rest = alloc::vec![
                    weights.mu,
                    weights.nu,
                    weights.mu_prime,
                    weights.nu_prime,
                    rho,
                    r,
                    alpha,
                    u,
                    beta,
                    xi,
                    z,
                ];
                rest.extend(rounds);
                Native { sampled, rest }
            }
        }

        /// The lift into the circuit field of the endoscalar a raw squeeze yields,
        /// on either curve: what the gadget's `lift` must be.
        fn lifted<F: Field>(raw: F) -> Fp {
            lift_endoscalar(extract_endoscalar(raw).expect("a squeeze is in range"))
        }

        /// The gadget's challenges' lifts in the same order, by value.
        fn flatten(challenges: &Challenges<'static, Dr>) -> (Vec<Fp>, Vec<Fp>) {
            let value = |challenge: &super::Challenge<'static, Dr>| *challenge.lift.value().take();
            let sampled = [
                &challenges.sampled.w,
                &challenges.sampled.y,
                &challenges.sampled.z,
                &challenges.sampled.sigma,
            ]
            .map(value)
            .to_vec();
            let mut rest = [
                &challenges.weights.mu,
                &challenges.weights.nu,
                &challenges.weights.mu_prime,
                &challenges.weights.nu_prime,
                &challenges.rho,
                &challenges.r,
                &challenges.alpha,
                &challenges.u,
                &challenges.beta,
                &challenges.xi,
                &challenges.z,
            ]
            .map(value)
            .to_vec();
            rest.extend(challenges.rounds.iter().map(value));
            (sampled, rest)
        }

        /// Replays `proof`'s transcript natively, as raw squeezes, and in the
        /// gadget, and compares every challenge's lift.
        fn check(setup: &Setup, proof: &crate::CompressedProof<Pasta>) {
            let mut t = setup.absorbed();
            let native_sampled = Sampled::squeeze(&mut t.host()).unwrap();
            let nested_sampled = Sampled::squeeze(&mut t.nested()).unwrap();
            let native = Native::new(
                native_sampled,
                replay_reduction(&proof.native.reduction, &mut t.host()),
                replay_batch(&proof.native.batch, &mut t.host()),
                replay_ipa(&proof.native.opening, &mut t.host()),
            );
            let nested = Native::new(
                nested_sampled,
                replay_reduction(&proof.nested.reduction, &mut t.nested()),
                replay_batch(&proof.nested.batch, &mut t.nested()),
                replay_ipa(&proof.nested.opening, &mut t.nested()),
            );

            // The commitments the native transcript absorbed, one per run, as the
            // points the gadget absorbs.
            let runs: Vec<EpAffine> = t.runs().to_vec();
            assert_eq!(runs.len(), num_runs::<TestR>(), "one commitment per run");
            let dr = Simulator::simulate((), |dr, _| {
                let instance = instance(dr, &proof.instance)?;
                let header = alloc_all(dr, setup.header.iter().copied())?;
                let native_messages = native_messages(dr, &proof.native)?;
                let nested_messages = nested_messages(dr, &proof.nested)?;
                let runs = points(dr, runs.iter().copied())?;
                let (host, scalar) = replay(
                    dr,
                    Pasta::circuit_poseidon(crate::pasta::baked()),
                    &instance,
                    &header,
                    &native_messages,
                    &nested_messages,
                    &runs,
                )?;

                let (sampled, rest) = flatten(&host);
                let Sampled { w, y, z, sigma } = native.sampled;
                assert_eq!(sampled, [w, y, z, sigma].map(lifted).to_vec());
                assert_eq!(
                    rest,
                    native
                        .rest
                        .iter()
                        .map(|&raw| lifted(raw))
                        .collect::<Vec<_>>()
                );

                let (sampled, rest) = flatten(&scalar);
                let Sampled { w, y, z, sigma } = nested.sampled;
                assert_eq!(sampled, [w, y, z, sigma].map(lifted).to_vec());
                assert_eq!(
                    rest,
                    nested
                        .rest
                        .iter()
                        .map(|&raw| lifted(raw))
                        .collect::<Vec<_>>()
                );
                Ok(())
            })
            .unwrap();
            std::println!(
                "transcript: {} gates, {} constraints",
                dr.num_gates(),
                dr.num_constraints()
            );
        }

        #[test]
        fn squeezes_the_native_challenges() {
            let setup = Setup::new();
            check(&setup, &setup.proof);
        }

        #[test]
        fn follows_a_tampered_message() {
            let setup = Setup::new();
            let mut tampered = setup.proof.clone();
            tampered.native.reduction.fold.inner_epsilon += Fp::ONE;
            tampered.nested.batch.evaluations[1] += Fq::ONE;
            check(&setup, &tampered);
        }
    }
}

fn elements<'dr, D: Driver<'dr>>(
    dr: &mut D,
    values: impl IntoIterator<Item = D::F>,
) -> Result<Vec<Element<'dr, D>>> {
    values
        .into_iter()
        .map(|value| Element::alloc(dr, &mut (), D::just(|| value)))
        .collect()
}

fn element<'dr, D: Driver<'dr>>(dr: &mut D, value: D::F) -> Result<Element<'dr, D>> {
    Element::alloc(dr, &mut (), D::just(|| value))
}

fn points<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    values: impl IntoIterator<Item = P>,
) -> Result<Vec<Point<'dr, D, P>>> {
    values
        .into_iter()
        .map(|value| Point::alloc(dr, D::just(|| value)))
        .collect()
}

fn point<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    value: P,
) -> Result<Point<'dr, D, P>> {
    Point::alloc(dr, D::just(|| value))
}

/// The endoscalar of a raw challenge, allocated from its bits on the side
/// that did not squeeze it.
fn endoscalar<'dr, D: Driver<'dr>, F: Field>(dr: &mut D, raw: F) -> Result<Endoscalar<'dr, D>> {
    let endo = ragu_primitives::extract_endoscalar(raw)?;
    Endoscalar::alloc(dr, D::just(|| endo))
}

/// A point's coordinates as elements.
fn coordinates<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    point: &Point<'dr, D, P>,
) -> Result<[Element<'dr, D>; 2]> {
    let mut written = Vec::with_capacity(2);
    GadgetExt::write(point, dr, &mut written)?;
    let [x, y]: [Element<'dr, D>; 2] = written
        .try_into()
        .map_err(|_| Error::InvalidWitness("a point has two coordinates".into()))?;
    Ok([x, y])
}

/// The wire bindings as the revdot gadget takes them, from the side
/// witness's masked lists.
fn bindings<'dr, D: Driver<'dr>>(
    dr: &mut D,
    masked: &[(usize, Vec<usize>, Vec<D::F>)],
) -> Result<Vec<revdot::Binding<'dr, D>>> {
    masked
        .iter()
        .map(|(_, degrees, expected)| {
            Ok(revdot::Binding {
                degrees: degrees.clone(),
                expected: elements(dr, expected.iter().copied())?,
            })
        })
        .collect()
}

/// Binds the elements at `positions` of `binding`'s expected values to
/// `gadgets`: the values the instance supplies rather than the registry.
fn bind_expected<'dr, D: Driver<'dr>>(
    dr: &mut D,
    binding: &revdot::Binding<'dr, D>,
    positions: impl IntoIterator<Item = usize>,
    gadgets: &[Element<'dr, D>],
) -> Result<()> {
    for (position, gadget) in positions.into_iter().zip(gadgets) {
        binding.expected[position].enforce_equal(dr, gadget)?;
    }
    Ok(())
}

/// The opening claims of one side after the reduction's: the registry
/// restriction at the compression's $w$, the batch polynomial at the
/// fuse's $u$ and the accumulator's $a$ and $b$ there, with the values the
/// side holds.
fn instance_claims<'dr, D: Driver<'dr>>(
    base: usize,
    w: &Element<'dr, D>,
    restriction_at_w: Element<'dr, D>,
    u: &Element<'dr, D>,
    v: &Element<'dr, D>,
    a_at_u: &Element<'dr, D>,
    b_at_u: &Element<'dr, D>,
) -> Vec<OpeningClaim<Element<'dr, D>>> {
    let claim = |poly, point: &Element<'dr, D>, value: &Element<'dr, D>| OpeningClaim {
        poly,
        point: point.clone(),
        value: value.clone(),
    };
    vec![
        claim(base, w, &restriction_at_w),
        claim(base + 1, u, v),
        claim(base + 2, u, a_at_u),
        claim(base + 3, u, b_at_u),
    ]
}

/// What one side's scalar checks leave: the batched claim's value, the
/// prover's $c$ and the IPA's $c b z$, the full-width scalars the other
/// side scales by.
struct ScalarChecks<'dr, D: Driver<'dr>> {
    v: Element<'dr, D>,
    c: Element<'dr, D>,
    cbz: Element<'dr, D>,
}

/// One side's scalar checks: the reduction, the instance's openings, the
/// batch and the IPA's scalars, over the challenges' lifts.
fn scalar_checks<'dr, D: Driver<'dr>, K: Rank>(
    dr: &mut D,
    public: &revdot::Public<'dr, D>,
    challenges: &transcript::Challenges<'dr, D>,
    reduction: &revdot::Messages<'dr, D>,
    extra: Vec<OpeningClaim<Element<'dr, D>>>,
    evaluations: &[Element<'dr, D>],
    c: &Element<'dr, D>,
) -> Result<ScalarChecks<'dr, D>> {
    let lifts = revdot::Challenges {
        z: challenges.sampled.z.lift.clone(),
        weights: Weights {
            mu: challenges.weights.mu.lift.clone(),
            nu: challenges.weights.nu.lift.clone(),
            mu_prime: challenges.weights.mu_prime.lift.clone(),
            nu_prime: challenges.weights.nu_prime.lift.clone(),
        },
        rho: challenges.rho.lift.clone(),
        r: challenges.r.lift.clone(),
    };
    let mut claims = revdot::verify::<_, K>(dr, public, &lifts, reduction)?;
    claims.extend(extra);
    let polys = Derived::ALL.len() + 2 + crate::compress::instance::OPENED;
    let batched = batch::verify(
        dr,
        &claims,
        polys,
        &batch::Challenges {
            alpha: challenges.alpha.lift.clone(),
            u: challenges.u.lift.clone(),
            beta: challenges.beta.lift.clone(),
        },
        &batch::Messages {
            evaluations: evaluations.to_vec(),
        },
    )?;
    let scalars = ipa::verify(
        dr,
        &batched.point,
        &batched.value,
        &ipa::Challenges {
            xi: challenges.xi.lift.clone(),
            z: challenges.z.lift.clone(),
            rounds: challenges
                .rounds
                .iter()
                .map(|round| round.lift.clone())
                .collect(),
        },
        &ipa::Messages { c: c.clone() },
    )?;
    Ok(ScalarChecks {
        v: batched.value,
        c: c.clone(),
        cbz: scalars.u.negate(dr),
    })
}

/// One side's point checks for the other curve: the derived commitments,
/// the batched commitment and the IPA's final check, over the challenges'
/// endoscalars, with `reduction` the fold's two error commitments and $p$
/// and $q$, and `extra` the instance's four opened commitments.
#[allow(clippy::too_many_arguments)]
fn point_checks<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    claims: Vec<derive::Claim<'dr, D, P>>,
    weights: &Weights<Endoscalar<'dr, D>>,
    reduction: [&Point<'dr, D, P>; 4],
    extra: [&Point<'dr, D, P>; 4],
    f: &Point<'dr, D, P>,
    beta: &Endoscalar<'dr, D>,
    opening: &derive::Opening<'dr, D, P>,
    xi: &Endoscalar<'dr, D>,
    rounds: &[Endoscalar<'dr, D>],
    scalars: &derive::Scalars<'dr, D>,
    fixed: Fixed<P>,
    bank: &mut NonzeroBank<'dr, D>,
) -> Result<()> {
    let [a, dilated, raw] = derive::fold(dr, &claims, weights, bank)?;
    let [inner, outer, p, q] = reduction;
    let commitments: Vec<Point<'dr, D, P>> = [&a, &dilated, &raw, inner, outer, p, q]
        .into_iter()
        .chain(extra)
        .cloned()
        .collect();
    let h = derive::batched(dr, f, &commitments, beta, bank)?;
    derive::enforce_opening(dr, &h, opening, xi, rounds, scalars, fixed, bank)
}

/// The circuit-field side of the decompressed verifier.
pub(crate) fn circuit_field_side<'dr, D, C, K, const HEADER_SIZE: usize>(
    dr: &mut D,
    params: &'dr C::Params,
    witness: &Witness<C>,
) -> Result<()>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let poseidon = C::circuit_poseidon(params);
    let instance = &witness.proof.instance;
    let nested_generators = C::nested_generators(params);

    // The instance, allocated as the transcript absorbs it: the circuit
    // field's values as elements and the nested commitments as points. The
    // scalar field's values are in the transcript's run commitments.
    let nested_points = points(dr, instance.nested.iter().copied())?;
    let allocated = transcript::Instance {
        circuit_id: element(dr, instance.circuit_id.omega_j())?,
        nested: nested_points,
        nested_registry_xy: point(dr, instance.nested_registry_xy)?,
        nested_p: point(dr, instance.nested_p)?,
        nested_challenges_partial: point(dr, instance.nested_challenges_partial)?,
        c: element(dr, instance.c)?,
        v: element(dr, instance.v)?,
        left: transcript::Child {
            x: element(dr, instance.left.x)?,
            y: element(dr, instance.left.y)?,
        },
        right: transcript::Child {
            x: element(dr, instance.right.x)?,
            y: element(dr, instance.right.y)?,
        },
        a_at_u: element(dr, instance.a_at_u)?,
        b_at_u: element(dr, instance.b_at_u)?,
    };
    let header = elements(dr, witness.header.iter().copied())?;
    let nested_at = |component| &allocated.nested[nested_position::<Standard>(component)];
    let bridge_at = |index| nested_at(nested::RxComponent::Rx(index));

    // The fuse's challenges, replayed from the bridge commitments under the
    // fuse's tag, each read as an endoscalar as the fuse's circuits read
    // them.
    let fuse = {
        use nested::RxIndex::*;
        let mut t = Transcript::new(dr, poseidon, RAGU_TAG)?;
        let squeeze = RawChallenge::squeeze;
        bridge_at(BridgePreamble).absorb(dr, &mut t)?;
        let w = squeeze(dr, &mut t)?;
        bridge_at(BridgeSPrime).absorb(dr, &mut t)?;
        let y = squeeze(dr, &mut t)?;
        let z = squeeze(dr, &mut t)?;
        bridge_at(BridgeInnerError).absorb(dr, &mut t)?;
        let mu = squeeze(dr, &mut t)?;
        bridge_at(BridgeOuterError).absorb(dr, &mut t)?;
        let mu_prime = squeeze(dr, &mut t)?;
        bridge_at(BridgeAB).absorb(dr, &mut t)?;
        let x = squeeze(dr, &mut t)?;
        bridge_at(BridgeQuery).absorb(dr, &mut t)?;
        let alpha = squeeze(dr, &mut t)?;
        bridge_at(BridgeF).absorb(dr, &mut t)?;
        let u = squeeze(dr, &mut t)?;
        bridge_at(BridgeEval).absorb(dr, &mut t)?;
        let pre_beta = squeeze(dr, &mut t)?;
        [w, y, z, mu, mu_prime, x, alpha, u, pre_beta]
    };

    // The targets, through the proof inputs the fuse derives them with,
    // bound to the instance and the replayed challenges.
    let unified = instance.unified(&witness.fuse);
    let proof_inputs = ProofInputs::<D, C, HEADER_SIZE>::alloc_from_parts(
        dr,
        D::just(|| witness.header.as_slice()),
        D::just(|| instance.circuit_id.omega_j()),
        // The standard profile has no statement circuit, so no step
        // binding.
        D::just(|| -> &[C::CircuitField] { &[] }),
        D::just(|| &unified),
        // Nor an online batch.
        D::just(|| -> &[C::NestedCurve] { &[] }),
        D::just(|| -> &[C::CircuitField] { &[] }),
        D::just(|| -> &[C::CircuitField] { &[] }),
    )?;
    {
        use nested::RxIndex::*;
        let out = &proof_inputs.unified;
        bridge_at(BridgeHash).enforce_equal(dr, &out.bridge_hash_commitment)?;
        bridge_at(BridgePreamble).enforce_equal(dr, &out.bridge_preamble_commitment)?;
        bridge_at(BridgeSPrime).enforce_equal(dr, &out.bridge_s_prime_commitment)?;
        bridge_at(BridgeInnerError).enforce_equal(dr, &out.bridge_inner_error_commitment)?;
        bridge_at(BridgeOuterError).enforce_equal(dr, &out.bridge_outer_error_commitment)?;
        bridge_at(BridgeAB).enforce_equal(dr, &out.bridge_ab_commitment)?;
        bridge_at(BridgeQuery).enforce_equal(dr, &out.bridge_query_commitment)?;
        bridge_at(BridgeF).enforce_equal(dr, &out.bridge_f_commitment)?;
        bridge_at(BridgeEval).enforce_equal(dr, &out.bridge_eval_commitment)?;
        allocated
            .nested_challenges_partial
            .enforce_equal(dr, &out.nested_challenges_partial)?;
        allocated
            .nested_p
            .enforce_equal(dr, &out.nested_p_commitment)?;
        nested_at(nested::RxComponent::AbA).enforce_equal(dr, &out.nested_a_commitment)?;
        nested_at(nested::RxComponent::AbB).enforce_equal(dr, &out.nested_b_commitment)?;
        allocated
            .nested_registry_xy
            .enforce_equal(dr, &out.nested_registry_xy_commitment)?;
        fuse[0].raw.enforce_equal(dr, &out.w)?;
        fuse[1].raw.enforce_equal(dr, &out.y)?;
        fuse[2].raw.enforce_equal(dr, &out.z)?;
        fuse[3].raw.enforce_equal(dr, &out.mu)?;
        fuse[4].raw.enforce_equal(dr, &out.mu_prime)?;
        fuse[5].raw.enforce_equal(dr, &out.x)?;
        fuse[6].raw.enforce_equal(dr, &out.alpha)?;
        fuse[7].raw.enforce_equal(dr, &out.u)?;
        fuse[8].raw.enforce_equal(dr, &out.pre_beta)?;
        allocated.c.enforce_equal(dr, &out.c)?;
        allocated.v.enforce_equal(dr, &out.v)?;
        allocated
            .circuit_id
            .enforce_equal(dr, &proof_inputs.circuit_id)?;
        // Indexed by the constant rather than zipped over the allocated
        // header, so that the loop's bound is visibly fixed.
        #[allow(clippy::needless_range_loop)]
        for i in 0..HEADER_SIZE {
            header[i].enforce_equal(dr, &proof_inputs.output_header[i])?;
        }
    }

    // The compression's transcript over the statement and both curves'
    // messages: the host curve's scalars and the nested curve's points,
    // the rest through the runs' commitments, witness points here.
    let native_messages = {
        let m = &witness.proof.native;
        transcript::NativeMessages {
            inner_epsilon: element(dr, m.reduction.fold.inner_epsilon)?,
            outer_epsilon: element(dr, m.reduction.fold.outer_epsilon)?,
            openings: elements(dr, m.reduction.openings.iter().copied())?,
            p_at_inverse_r: element(dr, m.reduction.p_at_inverse_r)?,
            q_at_r: element(dr, m.reduction.q_at_r)?,
            evaluations: elements(dr, m.batch.evaluations.iter().copied())?,
            c: element(dr, m.opening.c)?,
        }
    };
    let nested_messages = {
        let m = &witness.proof.nested;
        let mut rounds = Vec::with_capacity(m.opening.rounds.len());
        for &(l, r) in &m.opening.rounds {
            rounds.push((point(dr, l)?, point(dr, r)?));
        }
        transcript::NestedMessages {
            inner: point(dr, m.reduction.fold.inner)?,
            outer: point(dr, m.reduction.fold.outer)?,
            p: point(dr, m.reduction.p)?,
            q: point(dr, m.reduction.q)?,
            f: point(dr, m.batch.f)?,
            s_commitment: point(dr, m.opening.s_commitment)?,
            rounds,
        }
    };
    let runs = points(dr, witness.runs.iter().copied())?;
    let (native_challenges, nested_challenges) = transcript::replay(
        dr,
        poseidon,
        &allocated,
        &header,
        &native_messages,
        &nested_messages,
        &runs,
    )?;

    // The host curve's field checks.
    {
        let side = &witness.native;
        let y = &native_challenges.sampled.y.lift;
        let (unified_target, unified_bridge) = proof_inputs.unified_ky_values(dr, y)?;
        let targets = NativeTargets {
            c: allocated.c.clone(),
            unified_bridge,
            unified: unified_target,
            one: Element::one(),
            zero: Element::zero(dr),
        };
        let targets: Vec<_> = native::claims::ky_values::<Standard, _>(&targets)
            .take(side.kinds.len())
            .collect();
        let restrictions = side
            .restrictions
            .iter()
            .map(|&(circuit, value)| Ok((circuit, element(dr, value)?)))
            .collect::<Result<Vec<_>>>()?;
        let bindings = bindings(dr, &side.masked)?;
        // The bindings' values the instance supplies: the preamble's
        // children, the eval stage's a(u) and b(u), and the points
        // stages' coordinates of the nested commitments.
        let (l, r) = (&allocated.left, &allocated.right);
        bind_expected(
            dr,
            &bindings[0],
            0..4,
            &[l.x.clone(), l.y.clone(), r.x.clone(), r.y.clone()],
        )?;
        bind_expected(
            dr,
            &bindings[2],
            [3, 4],
            &[allocated.a_at_u.clone(), allocated.b_at_u.clone()],
        )?;
        let [ax, ay] = coordinates(dr, nested_at(nested::RxComponent::AbA))?;
        let [bx, by] = coordinates(dr, nested_at(nested::RxComponent::AbB))?;
        bind_expected(dr, &bindings[3], 0..4, &[ax, ay, bx, by])?;
        let [gx, gy] = coordinates(dr, &allocated.nested_registry_xy)?;
        bind_expected(dr, &bindings[4], 0..2, &[gx, gy])?;

        let public = revdot::Public {
            kinds: side.kinds.clone(),
            targets,
            restrictions,
            bindings,
            sigma: native_challenges.sampled.sigma.lift.clone(),
        };
        let reduction = revdot::Messages {
            inner_epsilon: native_messages.inner_epsilon.clone(),
            outer_epsilon: native_messages.outer_epsilon.clone(),
            openings: native_messages.openings.clone(),
            p_at_inverse_r: native_messages.p_at_inverse_r.clone(),
            q_at_r: native_messages.q_at_r.clone(),
        };
        let restriction_at_w = element(dr, side.restriction_at_w)?;
        let extra = instance_claims(
            Derived::ALL.len() + 2,
            &native_challenges.sampled.w.lift,
            restriction_at_w,
            &fuse[7].raw,
            &allocated.v,
            &allocated.a_at_u,
            &allocated.b_at_u,
        );
        let checks = scalar_checks::<_, K>(
            dr,
            &public,
            &native_challenges,
            &reduction,
            extra,
            &native_messages.evaluations,
            &native_messages.c,
        )?;
        // The digits the scalar-field side scales by, bound here to the
        // values this side computed, which are held to the witness's, the
        // native verifier's: the circuit's v and c b z reach no other
        // check, so this is what tests them.
        Digits::bind(dr, &checks.v)?;
        Digits::bind(dr, &checks.c)?;
        Digits::bind(dr, &checks.cbz)?;
        let expected_v = element(dr, side.v)?;
        checks.v.enforce_equal(dr, &expected_v)?;
        let expected_cbz = element(dr, side.cbz)?;
        checks.cbz.enforce_equal(dr, &expected_cbz)?;
    }

    // The nested curve's point checks, under its challenges' endoscalars.
    NonzeroBank::scope(dr, |dr, bank| {
        let side = &witness.nested;
        let claims = derive::nested_claims(
            dr,
            &allocated.nested,
            &nested_challenges.sampled.z.endoscalar,
            side.masked.iter().map(|&(position, _, _)| {
                nested_components::<Standard>()
                    .nth(position)
                    .expect("a nested component")
            }),
            bank,
        )?;
        let weights = Weights {
            mu: nested_challenges.weights.mu.endoscalar.clone(),
            nu: nested_challenges.weights.nu.endoscalar.clone(),
            mu_prime: nested_challenges.weights.mu_prime.endoscalar.clone(),
            nu_prime: nested_challenges.weights.nu_prime.endoscalar.clone(),
        };
        let opening = derive::Opening {
            s_commitment: nested_messages.s_commitment.clone(),
            rounds: nested_messages.rounds.clone(),
            inverse_scaled: points(dr, side.inverse_scaled.iter().copied())?,
            g_prime: point(dr, side.g_prime)?,
        };
        let scalars = derive::Scalars {
            v: Digits::alloc(dr, D::just(|| side.v))?,
            c: Digits::alloc(dr, D::just(|| witness.proof.nested.opening.c))?,
            cbz: Digits::alloc(dr, D::just(|| side.cbz))?,
        };
        point_checks(
            dr,
            claims,
            &weights,
            [
                &nested_messages.inner,
                &nested_messages.outer,
                &nested_messages.p,
                &nested_messages.q,
            ],
            [
                &allocated.nested_registry_xy,
                &allocated.nested_p,
                nested_at(nested::RxComponent::AbA),
                nested_at(nested::RxComponent::AbB),
            ],
            &nested_messages.f,
            &nested_challenges.beta.endoscalar,
            &opening,
            &nested_challenges.xi.endoscalar,
            &nested_challenges
                .rounds
                .iter()
                .map(|round| round.endoscalar.clone())
                .collect::<Vec<_>>(),
            &scalars,
            side.fixed,
            bank,
        )
    })?;

    // The nested stages the native verifier recomputes: the challenge
    // stage from the challenges' endoscalars and the base-case sign, and
    // the ab bridge from its coordinates' digits.
    NonzeroBank::scope(dr, |dr, bank| {
        let g = nested_generators.g();
        let generator = |dr: &mut D, i: usize| Point::constant(dr, g[generator_index::<C, K>(i)]);
        let mut acc: Option<Point<'dr, D, C::NestedCurve>> = None;
        for (i, challenge) in fuse.iter().take(challenge_stage::NUM).enumerate() {
            let base = generator(dr, i)?;
            let term = challenge.endoscalar.group_scale(dr, &base)?;
            acc = Some(match acc {
                None => term,
                Some(acc) => acc.add_incomplete(dr, &term, bank)?,
            });
        }
        // The base case, read off the circuit id: a proof that took it
        // is one of the bootstrap step.
        let bootstrap = crate::step::InternalStepIndex::Bootstrap.circuit_index::<Standard>()?;
        let bootstrap = Element::constant(dr, bootstrap.omega_j());
        let base_case = allocated.circuit_id.is_equal(dr, &mut (), &bootstrap)?;
        let sign = generator(dr, challenge_stage::SIGN_INDEX)?;
        let negate = base_case.not(dr);
        let sign = sign.conditional_negate(dr, &negate)?;
        let acc = acc.expect("the stage has challenges");
        let acc = acc.add_incomplete(dr, &sign, bank)?;
        let beta = generator(dr, challenge_stage::BETA_INDEX)?;
        let beta = fuse[8].endoscalar.group_scale(dr, &beta)?;
        let acc = acc.add_incomplete(dr, &beta, bank)?;
        acc.enforce_equal(dr, bridge_at(nested::RxIndex::ChallengeStage))?;

        let ab = {
            let a = instance.native_commitment(native::RxComponent::AbA);
            let b = instance.native_commitment(native::RxComponent::AbB);
            let points_ab =
                instance.native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb));
            let coordinates = |point: C::HostCurve| -> Result<[C::ScalarField; 2]> {
                let (x, y) = point
                    .coordinates()
                    .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
                Ok([x, y])
            };
            let value = |which: AbValue| -> Result<C::ScalarField> {
                Ok(match which {
                    AbValue::A(i) => coordinates(a)?[i],
                    AbValue::B(i) => coordinates(b)?[i],
                    AbValue::PointsAb(i) => coordinates(points_ab)?[i],
                    AbValue::Alpha => {
                        bridge_alpha_power(instance.bridge_alpha, nested::RxIndex::BridgeAB)
                    }
                })
            };
            let mut acc: Option<Point<'dr, D, C::NestedCurve>> = None;
            for &(index, which) in &witness.ab_terms {
                let base = Point::constant(dr, g[index])?;
                let digits = Digits::alloc(dr, D::try_just(|| value(which))?)?;
                let term = if which == AbValue::Alpha {
                    derive::scale_chain(dr, &base, &digits, None, *C::nested_u(params), bank)?
                } else {
                    derive::scale(dr, &base, &digits, *C::nested_u(params), bank)?
                };
                acc = Some(match acc {
                    None => term,
                    Some(acc) => acc.add_incomplete(dr, &term, bank)?,
                });
            }
            let acc = acc.expect("the ab bridge has coefficients");
            let correction = derive::scale_offset(
                *C::nested_u(params),
                Digits::<'dr, D>::width::<C::ScalarField>(),
            );
            let correction = Point::constant(dr, correction)?.negate(dr);
            acc.add_incomplete(dr, &correction, bank)?
        };
        ab.enforce_equal(dr, bridge_at(nested::RxIndex::BridgeAB))
    })?;

    Ok(())
}

/// The scalar-field side of the decompressed verifier.
pub(crate) fn scalar_field_side<'dr, D, C, K>(dr: &mut D, witness: &Witness<C>) -> Result<()>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let instance = &witness.proof.instance;
    let side = &witness.nested;

    // The fuse's challenges' lifts, from their endoscalars.
    let fuse_lift = |dr: &mut D, raw: C::CircuitField| -> Result<Element<'dr, D>> {
        endoscalar(dr, raw)?.lift(dr)
    };
    let fuse_x = fuse_lift(dr, witness.fuse.x)?;
    let fuse_y = fuse_lift(dr, witness.fuse.y)?;
    let fuse_u = fuse_lift(dr, witness.fuse.u)?;

    // The nested unified output, bound to the lifts, and the host curve's
    // commitments it exports.
    let nested_unified = instance.nested_unified(&witness.fuse)?;
    let output =
        nested_unified::Output::<D, C::HostCurve>::alloc(dr, &mut (), D::just(|| &nested_unified))?;
    output.x.enforce_equal(dr, &fuse_x)?;
    output.y.enforce_equal(dr, &fuse_y)?;
    output.u.enforce_equal(dr, &fuse_u)?;
    let exported_components = {
        use native::{RxComponent::*, RxIndex::*};
        [
            Rx(Preamble),
            Rx(InnerError),
            Rx(OuterError),
            Rx(Query),
            Rx(Eval),
            AbA,
            AbB,
        ]
    };
    let mut native_points: Vec<Option<Point<'dr, D, C::HostCurve>>> =
        vec![None; instance.native.len()];
    for (component, exported) in exported_components.iter().zip(output.exported.iter()) {
        native_points[native_position::<Standard>(*component)] = Some(exported.clone());
    }
    let native_registry_xy = output.exported[7].clone();
    let native_p = output.exported[8].clone();
    {
        use native::{RxComponent::Rx, RxIndex::*};
        for (i, index) in [
            PointsBinding,
            PointsPreamble,
            PointsRegistryWx,
            PointsAb,
            PointsF,
        ]
        .into_iter()
        .enumerate()
        {
            native_points[native_position::<Standard>(Rx(index))] =
                Some(output.exported[9 + i].clone());
        }
    }
    for (commitment, exported) in instance
        .online_commitments
        .iter()
        .zip(&output.exported[14..16])
    {
        point(dr, *commitment)?.enforce_equal(dr, exported)?;
    }
    let mut commitments = Vec::with_capacity(native_points.len());
    for (position, allocated) in native_points.into_iter().enumerate() {
        commitments.push(match allocated {
            Some(point) => point,
            None => point(dr, instance.native[position])?,
        });
    }

    // The compression's challenges for this curve, lifted from their
    // endoscalars, as the transcript gadget on the other side yields them.
    let challenge = |dr: &mut D, raw: C::ScalarField| -> Result<Challenge<'dr, D>> {
        let endoscalar = endoscalar(dr, raw)?;
        let lift = endoscalar.lift(dr)?;
        Ok(Challenge { endoscalar, lift })
    };
    let challenges = {
        let raw = &side.raw;
        let mut rounds = Vec::with_capacity(raw.rounds.len());
        for &u_j in &raw.rounds {
            rounds.push(challenge(dr, u_j)?);
        }
        transcript::Challenges {
            sampled: Sampled {
                w: challenge(dr, raw.sampled.w)?,
                y: challenge(dr, raw.sampled.y)?,
                z: challenge(dr, raw.sampled.z)?,
                sigma: challenge(dr, raw.sampled.sigma)?,
            },
            weights: Weights {
                mu: challenge(dr, raw.weights.mu)?,
                nu: challenge(dr, raw.weights.nu)?,
                mu_prime: challenge(dr, raw.weights.mu_prime)?,
                nu_prime: challenge(dr, raw.weights.nu_prime)?,
            },
            rho: challenge(dr, raw.rho)?,
            r: challenge(dr, raw.r)?,
            alpha: challenge(dr, raw.alpha)?,
            u: challenge(dr, raw.u)?,
            beta: challenge(dr, raw.beta)?,
            xi: challenge(dr, raw.xi)?,
            z: challenge(dr, raw.ipa_z)?,
            rounds,
        }
    };

    // The nested curve's field checks.
    {
        let targets = NestedTargets {
            c: output.c.clone(),
            unified: output.ky(dr, &challenges.sampled.y.lift)?,
            one: Element::one(),
            zero: Element::zero(dr),
        };
        let targets: Vec<_> = nested::claims::ky_values::<Standard, _>(&targets)
            .take(side.kinds.len())
            .collect();
        let restrictions = side
            .restrictions
            .iter()
            .map(|&(circuit, value)| Ok((circuit, element(dr, value)?)))
            .collect::<Result<Vec<_>>>()?;
        let bindings = bindings(dr, &side.masked)?;
        let (l, r) = (instance.nested_left, instance.nested_right);
        let children = elements(dr, [l.x, l.y, r.x, r.y])?;
        bind_expected(dr, &bindings[0], 0..4, &children)?;
        let at_u = elements(dr, [instance.nested_a_at_u, instance.nested_b_at_u])?;
        bind_expected(dr, &bindings[2], [3, 4], &at_u)?;

        let m = &witness.proof.nested;
        let public = revdot::Public {
            kinds: side.kinds.clone(),
            targets,
            restrictions,
            bindings,
            sigma: challenges.sampled.sigma.lift.clone(),
        };
        let reduction = revdot::Messages {
            inner_epsilon: element(dr, m.reduction.fold.inner_epsilon)?,
            outer_epsilon: element(dr, m.reduction.fold.outer_epsilon)?,
            openings: elements(dr, m.reduction.openings.iter().copied())?,
            p_at_inverse_r: element(dr, m.reduction.p_at_inverse_r)?,
            q_at_r: element(dr, m.reduction.q_at_r)?,
        };
        let restriction_at_w = element(dr, side.restriction_at_w)?;
        let extra = instance_claims(
            Derived::ALL.len() + 2,
            &challenges.sampled.w.lift,
            restriction_at_w,
            &fuse_u,
            &output.v,
            &at_u[0],
            &at_u[1],
        );
        let evaluations = elements(dr, m.batch.evaluations.iter().copied())?;
        let c = element(dr, m.opening.c)?;
        let checks = scalar_checks::<_, K>(
            dr,
            &public,
            &challenges,
            &reduction,
            extra,
            &evaluations,
            &c,
        )?;
        Digits::bind(dr, &checks.v)?;
        Digits::bind(dr, &checks.c)?;
        Digits::bind(dr, &checks.cbz)?;
        let expected_v = element(dr, side.v)?;
        checks.v.enforce_equal(dr, &expected_v)?;
        let expected_cbz = element(dr, side.cbz)?;
        checks.cbz.enforce_equal(dr, &expected_cbz)?;

        // The ab bridge's coordinates and alpha, whose digits the other
        // side scales generators by, bound here to the exported points and
        // the instance's bridge_alpha.
        let [ax, ay] = coordinates(
            dr,
            &commitments[native_position::<Standard>(native::RxComponent::AbA)],
        )?;
        let [bx, by] = coordinates(
            dr,
            &commitments[native_position::<Standard>(native::RxComponent::AbB)],
        )?;
        let [px, py] = coordinates(
            dr,
            &commitments
                [native_position::<Standard>(native::RxComponent::Rx(native::RxIndex::PointsAb))],
        )?;
        let bridge_alpha = element(dr, instance.bridge_alpha)?;
        let alpha = bridge_alpha.square(dr)?;
        for (_, which) in &witness.ab_terms {
            let value = match which {
                AbValue::A(0) => &ax,
                AbValue::A(_) => &ay,
                AbValue::B(0) => &bx,
                AbValue::B(_) => &by,
                AbValue::PointsAb(0) => &px,
                AbValue::PointsAb(_) => &py,
                AbValue::Alpha => &alpha,
            };
            Digits::bind(dr, value)?;
        }
    }

    // The host curve's point checks, under the native challenges'
    // endoscalars.
    let native = &witness.native;
    let (z, weights, beta, xi, rounds) = {
        let raw = &native.raw;
        let mut rounds = Vec::with_capacity(raw.rounds.len());
        for &u_j in &raw.rounds {
            rounds.push(endoscalar(dr, u_j)?);
        }
        (
            endoscalar(dr, raw.sampled.z)?,
            Weights {
                mu: endoscalar(dr, raw.weights.mu)?,
                nu: endoscalar(dr, raw.weights.nu)?,
                mu_prime: endoscalar(dr, raw.weights.mu_prime)?,
                nu_prime: endoscalar(dr, raw.weights.nu_prime)?,
            },
            endoscalar(dr, raw.beta)?,
            endoscalar(dr, raw.xi)?,
            rounds,
        )
    };
    NonzeroBank::scope(dr, |dr, bank| {
        let m = &witness.proof.native;
        let claims = derive::native_claims(
            dr,
            &commitments,
            &z,
            native.masked.iter().map(|&(position, _, _)| {
                native_components::<Standard>()
                    .nth(position)
                    .expect("a native component")
            }),
            bank,
        )?;
        let mut round_points = Vec::with_capacity(m.opening.rounds.len());
        for &(l, r) in &m.opening.rounds {
            round_points.push((point(dr, l)?, point(dr, r)?));
        }
        let opening = derive::Opening {
            s_commitment: point(dr, m.opening.s_commitment)?,
            rounds: round_points,
            inverse_scaled: points(dr, native.inverse_scaled.iter().copied())?,
            g_prime: point(dr, native.g_prime)?,
        };
        let scalars = derive::Scalars {
            v: Digits::alloc(dr, D::just(|| native.v))?,
            c: Digits::alloc(dr, D::just(|| m.opening.c))?,
            cbz: Digits::alloc(dr, D::just(|| native.cbz))?,
        };
        let inner = point(dr, m.reduction.fold.inner)?;
        let outer = point(dr, m.reduction.fold.outer)?;
        let p = point(dr, m.reduction.p)?;
        let q = point(dr, m.reduction.q)?;
        let f = point(dr, m.batch.f)?;
        point_checks(
            dr,
            claims,
            &weights,
            [&inner, &outer, &p, &q],
            [
                &native_registry_xy,
                &native_p,
                &commitments[native_position::<Standard>(native::RxComponent::AbA)],
                &commitments[native_position::<Standard>(native::RxComponent::AbB)],
            ],
            &f,
            &beta,
            &opening,
            &xi,
            &rounds,
            &scalars,
            native.fixed,
            bank,
        )
    })?;

    Ok(())
}

mod tests {
    //! The decompressed verifier end to end on a real compressed proof: both
    //! sides' circuits accept the honest proof, and a message or statement
    //! tampered with after the witness is prepared fails one of them. The
    //! tamperings leave the witness's $G'$ honest: these whole-side circuits
    //! take $G'$ as a witness point they do not bind, which the chunk circuits
    //! do through the step binding, so a prover who recomputes $G'$ to fit is
    //! not covered here.

    use ragu_core::pasta::{Fp, Fq, Pasta};
    use ragu_primitives::Simulator;
    use udon::field::Field;

    use super::{circuit_field_side, scalar_field_side};
    use crate::{
        CompressedProof,
        decompress::{
            prover::Witness,
            support::{HEADER_SIZE, Setup, TestR},
        },
    };

    fn witness(setup: &Setup) -> Witness<Pasta> {
        let pcd = setup.proof.clone().carry(());
        Witness::prepare::<TestR, HEADER_SIZE, _, ()>(&setup.app, &pcd).expect("the proof verifies")
    }

    /// Runs both sides on `witness`; `Ok` with the two sides' gate counts if
    /// both accept.
    fn run(witness: &Witness<Pasta>) -> ragu_core::Result<(usize, usize)> {
        let circuit = Simulator::simulate((), |dr, _| {
            circuit_field_side::<_, Pasta, TestR, HEADER_SIZE>(
                dr,
                crate::pasta::baked_aggregator(),
                witness,
            )
        })?;
        let scalar = Simulator::simulate((), |dr, _| {
            scalar_field_side::<_, Pasta, TestR>(dr, witness)
        })?;
        Ok((circuit.num_gates(), scalar.num_gates()))
    }

    #[test]
    fn accepts_the_honest_proof() {
        let setup = Setup::new();
        let witness = witness(&setup);
        let (circuit, scalar) = run(&witness).expect("both sides accept");
        std::println!("circuit-field side: {circuit} gates; scalar-field side: {scalar} gates");
    }

    #[test]
    fn rejects_tampering() {
        let setup = Setup::new();
        let honest = witness(&setup);
        let tamperings: [fn(&mut CompressedProof<Pasta>); 6] = [
            |proof| proof.native.reduction.openings[0] += Fp::ONE,
            |proof| proof.native.opening.c += Fp::ONE,
            |proof| proof.nested.reduction.fold.inner_epsilon += Fq::ONE,
            |proof| proof.nested.batch.evaluations[3] += Fq::ONE,
            |proof| proof.instance.c += Fp::ONE,
            |proof| proof.instance.left.x += Fp::ONE,
        ];
        for tamper in tamperings {
            let mut tampered = Witness {
                proof: honest.proof.clone(),
                header: honest.header.clone(),
                fuse: honest.fuse,
                native: honest.native.clone(),
                nested: honest.nested.clone(),
                ab_terms: honest.ab_terms.clone(),
                runs: honest.runs.clone(),
            };
            tamper(&mut tampered.proof);
            assert!(run(&tampered).is_err(), "a tampered proof fails a side");
        }

        let mut tampered = Witness {
            proof: honest.proof.clone(),
            header: honest.header.clone(),
            fuse: honest.fuse,
            native: honest.native.clone(),
            nested: honest.nested.clone(),
            ab_terms: honest.ab_terms.clone(),
            runs: honest.runs.clone(),
        };
        tampered.header[0] += Fp::ONE;
        assert!(run(&tampered).is_err(), "a tampered statement fails a side");
    }
}
