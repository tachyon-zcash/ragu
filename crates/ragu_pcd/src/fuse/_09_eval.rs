//! Commit to the evaluations of every queried polynomial at $u$.
//!
//! This sets the native `eval` stage containing the claimed evaluations at $u$
//! of every element that was also queried in the `query` stage. The evaluation
//! $f(u)$ is derived from the aforementioned evaluations.
//!
//! The nested evaluations at $u_n$ of every polynomial the nested batch folds
//! into $p_n$ are computed here as well; they ride inside the `eval` bridge
//! stage, whose commitment is what `pre_beta` is squeezed from.
//!
//! The native `eval` stage also carries the running partial sums of the
//! nested challenge binding (see `bind_challenges`), computed here from the
//! same witness that will be committed in the nested challenge stage: the
//! ten lifts and the base-case sign derived from the child headers. Their
//! binding sum goes to the unified instance.

use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::Result;
use rand::CryptoRng;
use udon::field::Field;

use super::{
    _03_s_prime::{NativeSPrime, NestedSPrime},
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    device::Devices,
};
use crate::{
    Application, Proof,
    internal::{native, nested, online},
    multicore::par_join,
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_eval(
        &self,
        bound_challenges: &[C::CircuitField; native::circuits::bind_challenges::NUM_BOUND],
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        s_prime: &NativeSPrime<C, R>,
        registry_wy: &RegistryWy<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        builder: &ProofBuilder<'_, C, R, B>,
        devices: &mut Devices<'_, C, R>,
    ) -> Result<(
        native::stages::eval::Witness<C>,
        nested::stages::eval::Evaluations<C::ScalarField, C::Profile>,
        nested::stages::challenges::Witness<C::ScalarField>,
    )> {
        // The binding partials over the lifts of the challenges squeezed so
        // far, in challenge-stage order; `u` is the last of them.
        let mut lifts = [C::ScalarField::ZERO; native::circuits::bind_challenges::NUM_BOUND];
        for (lift, challenge) in lifts.iter_mut().zip(bound_challenges) {
            *lift = nested::challenge::<C>(*challenge)?;
        }
        // The binding partials use only the ten lifts and the sign. Beta
        // is filled after `pre_beta` is squeezed, before this witness is committed.
        let nested_challenges = nested::stages::challenges::Witness::new::<_, HEADER_SIZE>(
            lifts,
            builder.left_header(),
            builder.right_header(),
            C::ScalarField::ZERO,
        );
        let u = bound_challenges[native::circuits::bind_challenges::NUM_BOUND - 1];
        let u_nested = nested::challenge::<C>(u)?;

        // ProofBuilder contains OnceCell fields and is therefore !Sync.
        // Extract shared references to the already-set polynomials so the
        // closures below capture &Polynomial (which is Sync) rather than
        // &ProofBuilder.
        let native_a_poly = builder.native_a_poly();
        let native_b_poly = builder.native_b_poly();
        let native_registry_xy_poly = builder.native_registry_xy_poly();
        let online_polynomials = online::polys(left, right, builder.online_polynomials());
        let nested_a_poly = builder.nested_a_poly();
        let nested_b_poly = builder.nested_b_poly();
        let nested_registry_xy_poly = builder.nested_registry_xy_poly();

        // A side with a device evaluates there, from the polynomials it
        // holds: every polynomial of the batch at once, in the order the
        // witnesses below take the values. The two sides and the binding
        // partials read nothing of one another, so the three run together.
        let native_batch = devices.native.is_some().then(|| {
            let (polys, _) = self.native_p_terms(left, right, s_prime, registry_wy, builder);
            (
                polys,
                self.native_current_polys(s_prime, registry_wy, builder),
            )
        });
        let nested_batch = devices.nested.is_some().then(|| {
            let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
            (batch.evaluated().collect::<Vec<_>>(), batch.current())
        });
        let (native_device, nested_device) =
            (devices.native.as_deref_mut(), devices.nested.as_deref_mut());
        let (native_held, nested_held) = (&mut devices.native_held, &mut devices.nested_held);
        let params = self.params;
        let (partials, native_values, nested_values) = par_join!(
            || native::stages::eval::BindingPartials::compute::<C, R, B>(
                params,
                &nested_challenges
            ),
            || native_device
                .zip(native_batch)
                .map(|(device, (polys, current))| {
                    let slots = native_held.slots(device, &current, &polys);
                    let powers = device.powers(u);
                    let pairs: Vec<_> = slots.into_iter().map(|slot| (slot, powers)).collect();
                    device.dot(&pairs)
                }),
            || nested_device
                .zip(nested_batch)
                .map(|(device, (polys, current))| {
                    let slots = nested_held.slots(device, &current, &polys);
                    let powers = device.powers(u_nested);
                    let pairs: Vec<_> = slots.into_iter().map(|slot| (slot, powers)).collect();
                    device.dot(&pairs)
                }),
        );

        // Evaluate left/right child witnesses concurrently with the
        // current-step polynomial evaluations at u.
        let (left_witness, right_witness, current) = if let Some(values) = native_values {
            let mut values = values.into_iter();
            let left = native::stages::eval::ChildEvaluationsWitness::from_values(&mut values);
            let right = native::stages::eval::ChildEvaluationsWitness::from_values(&mut values);
            let mut next = || values.next().expect("one value per polynomial");
            let current = native::stages::eval::CurrentStepWitness {
                registry_wx0: next(),
                registry_wx1: next(),
                registry_wy: next(),
                a_poly: next(),
                b_poly: next(),
                registry_xy: next(),
                online: core::array::from_fn(|_| next()),
            };
            (left, right, current)
        } else {
            par_join!(
                || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(left, u),
                || native::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(right, u),
                || native::stages::eval::CurrentStepWitness {
                    registry_wx0: B::sparse_eval(&s_prime.registry_wx0_poly, u),
                    registry_wx1: B::sparse_eval(&s_prime.registry_wx1_poly, u),
                    registry_wy: B::sparse_eval(&registry_wy.poly, u),
                    a_poly: B::sparse_eval(native_a_poly, u),
                    b_poly: B::sparse_eval(native_b_poly, u),
                    registry_xy: B::sparse_eval(native_registry_xy_poly, u),
                    online: online_polynomials.map(|poly| B::sparse_eval(poly, u)),
                },
            )
        };

        let native = native::stages::eval::Witness {
            left: left_witness,
            right: right_witness,
            current,
            partials,
        };

        let (left_nested, right_nested, current_nested) = if let Some(values) = nested_values {
            let mut values = values.into_iter();
            let left = nested::stages::eval::ChildEvaluationsWitness::from_values(&mut values);
            let right = nested::stages::eval::ChildEvaluationsWitness::from_values(&mut values);
            let mut next = || values.next().expect("one value per polynomial");
            let current = nested::stages::eval::CurrentStepWitness {
                registry_wx0: next(),
                registry_wx1: next(),
                registry_wy: next(),
                a_poly: next(),
                b_poly: next(),
                registry_xy: next(),
            };
            (left, right, current)
        } else {
            par_join!(
                || nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    left, u_nested
                ),
                || nested::stages::eval::ChildEvaluationsWitness::from_proof::<C, R, B>(
                    right, u_nested
                ),
                || nested::stages::eval::CurrentStepWitness {
                    registry_wx0: B::sparse_eval(&nested_s_prime.registry_wx0_poly, u_nested),
                    registry_wx1: B::sparse_eval(&nested_s_prime.registry_wx1_poly, u_nested),
                    registry_wy: B::sparse_eval(&nested_registry_wy.poly, u_nested),
                    a_poly: B::sparse_eval(nested_a_poly, u_nested),
                    b_poly: B::sparse_eval(nested_b_poly, u_nested),
                    registry_xy: B::sparse_eval(nested_registry_xy_poly, u_nested),
                },
            )
        };

        let nested = nested::stages::eval::Evaluations {
            left: left_nested,
            right: right_nested,
            current: current_nested,
        };

        Ok((native, nested, nested_challenges))
    }

    /// Samples fresh eval-stage blindings and returns the native eval rx
    /// together with the `eval` bridge stage's rx and commitment.
    ///
    /// The `pre_beta` rejection loop calls this once per attempt, re-deriving
    /// the challenge from a fresh commitment until it lands in range. Only the
    /// accepted rxs are committed to the builder, so this computes the
    /// commitments without populating any builder cell.
    pub(super) fn sample_eval_commitment<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        eval_witness: &native::stages::eval::Witness<C>,
        nested_eval: &nested::stages::eval::Evaluations<C::ScalarField, C::Profile>,
    ) -> Result<(
        sparse::Polynomial<C::CircuitField, R>,
        sparse::Polynomial<C::ScalarField, R>,
        C::NestedCurve,
    )> {
        let eval_rx = native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            eval_witness,
        )?;
        let native_eval_commitment =
            B::sparse_commit_to_affine(&eval_rx, C::host_generators(self.params));

        let bridge_rx = nested::stages::eval::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested::stages::eval::Witness {
                native_eval: native_eval_commitment,
                nested: nested_eval.clone(),
            },
        )?;
        let bridge_eval_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));

        Ok((eval_rx, bridge_rx, bridge_eval_commitment))
    }

    /// Commits the nested challenge stage: the lifts of this step's
    /// challenges, the base-case sign and the lift of `pre_beta`, unblinded,
    /// so that its nested-curve commitment is the fixed linear combination
    /// of generators the binding circuits recompute. Completes the witness
    /// used for the eval stage's binding partials with beta's lift and returns
    /// it for the nested circuits that load the stage.
    pub(super) fn commit_nested_challenges(
        &self,
        mut challenges: nested::stages::challenges::Witness<C::ScalarField>,
        pre_beta: C::CircuitField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<nested::stages::challenges::Witness<C::ScalarField>> {
        challenges.beta = nested::challenge::<C>(pre_beta)?;
        builder.set_nested_challenges_rx(nested::stages::challenges::Stage::<
            C::HostCurve,
            R,
            C::Profile,
        >::rx(C::ScalarField::ZERO, &challenges)?);
        Ok(challenges)
    }
}
