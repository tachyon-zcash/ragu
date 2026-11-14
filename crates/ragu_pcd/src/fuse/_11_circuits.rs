//! Trace the internal circuits.
//!
//! This traces the native and nested internal circuits over the stage
//! witnesses the earlier phases saved, assembles their rx polynomials, and
//! sets them on the [`ProofBuilder`] together with the profile's extension.

use alloc::vec::Vec;

use ragu_circuits::{CircuitExt, Trace, polynomials::Rank, staging::MultiStage};
use ragu_core::{Cycle, Error, Result};
use ragu_primitives::Uendo;
use rand::CryptoRng;
use udon::field::Field;

use super::_10_p::{NativeInputs, NativeWalk};
use crate::{
    Application,
    header::NUM_ONLINE_POLYNOMIALS,
    internal::{native, native::total_circuit_counts, nested},
    multicore::par_join,
    profile::{Profile, ProfiledCycle},
    proof::{ProofBuilder, commit_all, commit_all_beside},
};

/// The native circuits traced for a step: four that hash and fold, the
/// challenge binders, and the two that bind beta and the endoscalar.
const NATIVE_CHAIN: usize = 6 + native::NUM_BINDERS;

/// The registered circuit that is the `index`-th of the native chain.
fn native_chain_circuit(index: usize) -> native::InternalCircuitIndex {
    use native::InternalCircuitIndex::*;
    match index {
        0 => Hashes1Circuit,
        1 => Hashes2Circuit,
        2 => CollapseCircuit,
        3 => ComputeVCircuit,
        index if index < 4 + native::NUM_BINDERS => BindChallengesCircuit((index - 4) as u32),
        index if index == 4 + native::NUM_BINDERS => BindBetaCircuit,
        _ => BindEndoscalarCircuit,
    }
}

/// What a chain of circuits produced, each of which reads the instance the
/// one before it completed: one `T` a circuit, in order, up to the first
/// that failed, with its error.
struct Chain<T> {
    done: Vec<T>,
    error: Option<Error>,
}

impl<T> Chain<T> {
    /// Runs `steps`, which pushes what each circuit produces as it
    /// completes.
    fn run(steps: impl FnOnce(&mut Vec<T>) -> Result<()>) -> Self {
        let mut done = Vec::new();
        let error = steps(&mut done).err();
        Self { done, error }
    }

    /// The chain of circuits that were each traced with a
    /// [`fork`](native::unified::Instance::fork) of `unified`: what they
    /// produced, in order up to the first that failed, each one's coverage
    /// added to `unified` as the circuit would have added it to the
    /// instance handed along, and the instance checked for completeness if
    /// none failed.
    fn gather<C: Cycle>(
        traced: impl Iterator<Item = Result<(T, native::unified::Instance<C>)>>,
        mut unified: native::unified::Instance<C>,
    ) -> Self {
        let mut done = Vec::new();
        for result in traced {
            match result {
                Ok((produced, fork)) => {
                    unified.absorb(fork);
                    done.push(produced);
                }
                Err(error) => {
                    return Self {
                        done,
                        error: Some(error),
                    };
                }
            }
        }
        unified.assert_complete();
        Self { done, error: None }
    }

    /// What each circuit produced, in order, then the error of the circuit
    /// that failed, if one did: what running them one at a time would
    /// yield.
    fn into_results(self) -> impl Iterator<Item = Result<T>> {
        self.done.into_iter().map(Ok).chain(self.error.map(Err))
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Traces this step's native and nested internal circuits, assembles
    /// their Rx polynomials, and stores them in the proof builder with the
    /// profile's extensions.
    ///
    /// Builds the shared native instance from the accumulated proof data and
    /// supplies the saved stage witnesses to the circuits for the transcript,
    /// folding, batch evaluation, and nested challenge and commitment binding;
    /// the nested circuits read the nested instance, which exports the native
    /// stage commitments.
    ///
    /// Neither side's circuits read the other's, and tracing reads no
    /// randomness, so the two chains of traces run together. Each circuit is
    /// then assembled in the order it would be traced one at a time, native
    /// before nested, which draws its blinding in that order. The
    /// commitments still pending on the builder are computed alongside the
    /// tracing, in one backend call per curve.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_internal_circuits<RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        preamble_witness: &native::stages::preamble::Witness<'_, C, R, HEADER_SIZE>,
        native_outer_error_witness: &native::stages::outer_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        native_inner_error_witness: &native::stages::inner_error::Witness<
            C,
            native::RevdotParameters<C::Profile>,
        >,
        query_witness: &native::stages::query::Witness<C>,
        eval_witness: &native::stages::eval::Witness<C>,
        native_points: &NativeInputs<C>,
        native_walk: &NativeWalk<C>,
        nested_endoscalar: Uendo,
        nested_points: &nested::PointsWitness<C::HostCurve, C::Profile>,
        nested_preamble_witness: &nested::stages::preamble::Witness<C::HostCurve, C::Profile>,
        nested_s_prime_witness: &nested::stages::s_prime::Witness<C::HostCurve>,
        nested_inner_error_witness: &nested::stages::inner_error::Witness<C::HostCurve, C::Profile>,
        nested_outer_error_witness: &nested::stages::outer_error::Witness<C::HostCurve, C::Profile>,
        nested_ab_witness: &nested::stages::ab::Witness<C::HostCurve>,
        nested_query_witness: &nested::stages::query::Witness<C::HostCurve, C::Profile>,
        nested_f_witness: &nested::stages::f::Witness<C::HostCurve>,
        nested_eval_witness: &nested::stages::eval::Witness<C::HostCurve, C::Profile>,
        nested_challenges_witness: &nested::stages::challenges::Witness<C::ScalarField>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        // The accumulators' revdot products and the batches' evaluations
        // read polynomials that are set and nothing of one another, so the
        // four are computed together.
        let u = builder.u();
        let nested_u = nested::challenge::<C>(u);
        let (native_c, v, nested_c, nested_v) = {
            let (native_a, native_b, native_p) = (
                builder.native_a_poly(),
                builder.native_b_poly(),
                builder.native_p_poly(),
            );
            let (nested_a, nested_b, nested_p) = (
                builder.nested_a_poly(),
                builder.nested_b_poly(),
                builder.nested_p_poly(),
            );
            let nested_at = nested_u.as_ref().ok().copied();
            par_join!(
                || B::sparse_revdot(native_a, native_b),
                || B::sparse_eval(native_p, u),
                || B::sparse_revdot(nested_a, nested_b),
                || nested_at.map(|u| B::sparse_eval(nested_p, u)),
            )
        };
        // A challenge with no nested counterpart is reported where the
        // nested instance is read.
        let nested_v =
            nested_u.map(|_| nested_v.expect("evaluated where the challenge has a counterpart"));
        let unified = native::unified::Instance {
            bridge_preamble_commitment: builder.bridge_preamble_commitment(),
            bridge_hash_commitment: builder.bridge_hash_commitment(),
            w: builder.w(),
            bridge_s_prime_commitment: builder.bridge_s_prime_commitment(),
            y: builder.y(),
            z: builder.z(),
            bridge_inner_error_commitment: builder.bridge_inner_error_commitment(),
            mu: builder.mu(),
            bridge_outer_error_commitment: builder.bridge_outer_error_commitment(),
            mu_prime: builder.mu_prime(),
            c: native_c,
            bridge_ab_commitment: builder.bridge_ab_commitment()?,
            x: builder.x(),
            bridge_query_commitment: builder.bridge_query_commitment(),
            alpha: builder.alpha(),
            bridge_f_commitment: builder.bridge_f_commitment(),
            u,
            bridge_eval_commitment: builder.bridge_eval_commitment(),
            pre_beta: builder.pre_beta(),
            v,
            nested_challenges_partial: builder.nested_challenges_partial(),
            nested_p_commitment: builder.nested_p_commitment(),
            nested_a_commitment: builder.nested_a_commitment(),
            nested_b_commitment: builder.nested_b_commitment(),
            nested_registry_xy_commitment: builder.nested_registry_xy_commitment(),
            coverage: Default::default(),
        };

        // The nested instance reads only values the earlier phases fixed.
        // What can fail in forming it is reported where the nested circuits
        // are assembled below, after the native ones.
        let nested_instance = (|| -> Result<_> {
            Ok(nested::unified::Instance {
                c: nested_c,
                v: nested_v?,
                x: nested::challenge::<C>(builder.x())?,
                y: nested::challenge::<C>(builder.y())?,
                u: nested::challenge::<C>(builder.u())?,
                exported: [
                    builder.native_preamble_commitment(),
                    builder.native_inner_error_commitment(),
                    builder.native_outer_error_commitment(),
                    builder.native_query_commitment(),
                    builder.native_eval_commitment(),
                    builder.native_a_commitment(),
                    builder.native_b_commitment(),
                    builder.native_registry_xy_commitment(),
                    builder.native_p_commitment(),
                    builder.native_points_binding_commitment(),
                    builder.native_points_children_commitment(),
                    builder.native_points_registry_wx_commitment(),
                    builder.native_points_ab_commitment(),
                    builder.native_points_f_commitment(),
                    builder.online_commitments()[0],
                    builder.online_commitments()[1],
                    builder.native_application_stage_commitment(),
                ],
                coverage: Default::default(),
            })
        })();
        let bridge_hash = builder.online_commitments()[NUM_ONLINE_POLYNOMIALS - 1];

        let params = self.params;
        let internal_circuits = total_circuit_counts::<C::Profile>(self.num_application_steps).1;

        // The commitments nothing has asked for yet, most of them the
        // endoscaling steps', computed while the circuits are traced. A
        // failure to list the nested ones is left for `build` to report.
        let pending_native = builder.pending_native();
        let pending_nested = builder.pending_nested().ok();
        let (native_polys, nested_polys) = (
            &pending_native.polys,
            pending_nested.as_ref().map(|pending| &pending.polys),
        );
        let (host_generators, nested_generators) =
            (C::host_generators(params), C::nested_generators(params));

        // The inverses the binding circuits' scalings divide by, which their
        // witness generation would otherwise compute one at a time.
        let scalings: Vec<_> = native::circuits::bind_challenges::scalings::<C, R>(
            params,
            [
                unified.w,
                unified.y,
                unified.z,
                unified.mu,
                unified.mu_prime,
                unified.x,
                unified.alpha,
                unified.u,
            ],
        )
        .into_iter()
        .chain(native::circuits::bind_beta::scalings(
            params,
            preamble_witness,
        ))
        .collect();
        let advice: Vec<_> = B::map(&scalings, |(challenge, generator)| {
            crate::internal::endoscalar::challenge_advice(*challenge, generator)
        })
        .collect();
        let (challenge_advice, beta_advice) =
            advice.split_at(native::circuits::bind_challenges::NUM_BOUND);

        // The native circuits' blindings, drawn here in the order assembling
        // the circuits one after another draws them, so that each circuit
        // is assembled where it is traced.
        let native_alphas: Vec<C::CircuitField> = (0..NATIVE_CHAIN)
            .map(|_| C::CircuitField::random(|bytes| rng.fill_bytes(bytes)))
            .collect();
        let native_registry = &self.native_registry;

        // The commitments are the longest of the four and wait on the
        // device, so they are started first; the traces then have the
        // workers, those that wait for the commitments included.
        let (native_commitments, nested_commitments, native_chain, nested_chain) = par_join!(
            || crate::timing::span("c.native.commit", || {
                commit_all_beside::<B, <C as Cycle>::HostCurve, R, _>(native_polys, host_generators)
            }),
            || crate::timing::span("c.nested.commit", || {
                nested_polys.map(|polys| {
                    commit_all_beside::<B, <C as Cycle>::NestedCurve, R, _>(
                        polys,
                        nested_generators,
                    )
                })
            }),
            || {
                // A circuit reads the unified instance's values and adds what
                // it covers, nothing else, so the circuits are traced apart,
                // each with a copy that covers nothing, and their coverage is
                // gathered in circuit order. Each is assembled as soon as it
                // is traced.
                let traced = B::map(0..NATIVE_CHAIN, |index| {
                    let unified = unified.fork();
                    let (trace, fork) = match index {
                        0 => native::circuits::hashes_1::Circuit::<
                            C,
                            R,
                            HEADER_SIZE,
                            native::RevdotParameters<C::Profile>,
                        >::new(params, internal_circuits)
                        .trace(native::circuits::hashes_1::Witness {
                            unified,
                            preamble_witness,
                            outer_error_witness: native_outer_error_witness,
                        })?
                        .into_parts(),
                        1 => native::circuits::hashes_2::Circuit::<
                            C,
                            R,
                            HEADER_SIZE,
                            native::RevdotParameters<C::Profile>,
                        >::new(params)
                        .trace(native::circuits::hashes_2::Witness {
                            unified,
                            outer_error_witness: native_outer_error_witness,
                        })?
                        .into_parts(),
                        2 => native::circuits::collapse::Circuit::<
                            C,
                            R,
                            HEADER_SIZE,
                            native::RevdotParameters<C::Profile>,
                        >::new()
                        .trace(native::circuits::collapse::Witness {
                            binding: &native_points.binding,
                            preamble_witness,
                            unified,
                            outer_error_witness: native_outer_error_witness,
                            inner_error_witness: native_inner_error_witness,
                        })?
                        .into_parts(),
                        3 => native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new()
                            .trace(native::circuits::compute_v::Witness {
                                unified,
                                preamble_witness,
                                query_witness,
                                eval_witness,
                            })?
                            .into_parts(),
                        index if index < 4 + native::NUM_BINDERS => {
                            let k = index - 4;
                            crate::with_binder!(k, C, R, HEADER_SIZE, params, |circuit| {
                                circuit
                                    .trace(native::circuits::bind_challenges::Witness {
                                        unified,
                                        preamble_witness,
                                        query_witness,
                                        eval_witness,
                                        advice: challenge_advice,
                                    })?
                                    .into_parts()
                            })
                        }
                        index if index == 4 + native::NUM_BINDERS => {
                            native::circuits::bind_beta::Circuit::<C, R, HEADER_SIZE>::new(params)
                                .trace(native::circuits::bind_beta::Witness {
                                    unified,
                                    binding: &native_points.binding,
                                    preamble_witness,
                                    advice: beta_advice,
                                })?
                                .into_parts()
                        }
                        _ => native::circuits::bind_endoscalar::Circuit::<C, R>::new()
                            .trace(native::circuits::bind_endoscalar::Witness {
                                unified,
                                inputs: native_points,
                                walk: native_walk,
                            })?
                            .into_parts(),
                    };
                    let rx = native_registry.assemble_with_alpha(
                        &trace,
                        native_chain_circuit(index).circuit_index::<C::Profile>(),
                        native_alphas[index],
                    )?;
                    Ok((rx, fork))
                });
                // Nothing is covered before the first circuit.
                Chain::gather(traced, unified.fork())
            },
            || Chain::<Trace<C::ScalarField>>::run(|traces| {
                let witness = |instance| nested::circuits::common::Witness {
                    instance,
                    endoscalar: nested_endoscalar,
                    bridge_hash,
                    points: nested_points,
                    preamble: nested_preamble_witness,
                    s_prime: nested_s_prime_witness,
                    inner_error: nested_inner_error_witness,
                    outer_error: nested_outer_error_witness,
                    ab: nested_ab_witness,
                    query: nested_query_witness,
                    f: nested_f_witness,
                    eval: nested_eval_witness,
                    challenges: nested_challenges_witness,
                };

                let (trace, instance) = MultiStage::new(nested::circuits::collapse::Circuit::<
                    C::HostCurve,
                    R,
                    C::Profile,
                >::new())
                .trace(witness(nested_instance?))?
                .into_parts();
                traces.push(trace);

                let (trace, instance) = MultiStage::new(nested::circuits::compute_v::Circuit::<
                    C::HostCurve,
                    R,
                    C::Profile,
                >::new())
                .trace(witness(instance))?
                .into_parts();
                traces.push(trace);

                instance.assert_complete();
                Ok(())
            }),
        );
        pending_native.fill(native_commitments);
        if let (Some(pending), Some(commitments)) = (pending_nested, nested_commitments) {
            pending.fill(commitments);
        }

        // The native circuits' polynomials, in the order of the chain.
        let mut rxs = native_chain.into_results();
        let mut assembled = || rxs.next().expect("a polynomial or the chain's error");
        let hashes_1_rx = assembled()?;
        let hashes_2_rx = assembled()?;
        let collapse_rx = assembled()?;
        let compute_v_rx = assembled()?;
        let mut bind_challenges_rxs = Vec::with_capacity(native::NUM_BINDERS);
        for _ in 0..native::NUM_BINDERS {
            bind_challenges_rxs.push(assembled()?);
        }
        let bind_beta_rx = assembled()?;
        let bind_endoscalar_rx = assembled()?;

        builder.set_native_hashes_1_rx(hashes_1_rx);
        builder.set_native_hashes_2_rx(hashes_2_rx);
        builder.set_native_collapse_rx(collapse_rx);
        builder.set_native_compute_v_rx(compute_v_rx);
        builder.set_native_bind_challenges_rxs(bind_challenges_rxs);
        builder.set_native_bind_beta_rx(bind_beta_rx);
        builder.set_native_bind_endoscalar_rx(bind_endoscalar_rx);

        let extension = C::Profile::native_extension();
        let rxs = C::Profile::native_extension_rxs::<C::Base, R, HEADER_SIZE, B, RNG>(
            &self.context,
            &self.native_registry,
            rng,
        )?;
        if rxs.circuits.len() != extension.circuits.len() || rxs.stages.len() != extension.stages {
            return Err(Error::Initialization(
                "the profile's prover did not fill its native extension".into(),
            ));
        }
        builder.set_native_extension_circuit_rxs(rxs.circuits);
        builder.set_native_extension_stage_rxs(rxs.stages);

        // The nested circuits.
        let mut traces = nested_chain.into_results();
        let mut assemble = |id: nested::InternalCircuitIndex, rng: &mut RNG| {
            let trace = traces.next().expect("a trace or the chain's error")?;
            self.nested_registry
                .assemble(&trace, id.circuit_index::<C::Profile>(), rng)
        };
        let collapse_rx = assemble(nested::InternalCircuitIndex::Collapse, &mut *rng)?;
        let compute_v_rx = assemble(nested::InternalCircuitIndex::ComputeV, &mut *rng)?;

        builder.set_nested_collapse_rx(collapse_rx);
        builder.set_nested_compute_v_rx(compute_v_rx);

        let extension = C::Profile::nested_extension();
        let rxs = C::Profile::nested_extension_rxs::<C::Base, R, HEADER_SIZE, B, RNG>(
            &self.context,
            &self.nested_registry,
            rng,
        )?;
        if rxs.circuits.len() != extension.circuits.len() || rxs.stages.len() != extension.stages {
            return Err(Error::Initialization(
                "the profile's prover did not fill its nested extension".into(),
            ));
        }
        builder.set_nested_extension_circuit_rxs(rxs.circuits);
        builder.set_nested_extension_stage_rxs(rxs.stages);

        // The commitments of what was just assembled, one backend call per
        // curve, issued together: `build` then finds none missing. A failure
        // to list the nested ones is again left for it to report.
        let pending_native = builder.pending_native();
        let pending_nested = builder.pending_nested().ok();
        let (native_polys, nested_polys) = (
            &pending_native.polys,
            pending_nested.as_ref().map(|pending| &pending.polys),
        );
        let (native_commitments, nested_commitments) = par_join!(
            || commit_all::<B, <C as Cycle>::HostCurve, R, _>(native_polys, host_generators),
            || nested_polys.map(|polys| {
                commit_all::<B, <C as Cycle>::NestedCurve, R, _>(polys, nested_generators)
            }),
        );
        pending_native.fill(native_commitments);
        if let (Some(pending), Some(commitments)) = (pending_nested, nested_commitments) {
            pending.fill(commitments);
        }

        Ok(())
    }
}
