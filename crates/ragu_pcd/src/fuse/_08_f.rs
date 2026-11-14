//! Construct and commit to $f(X)$.
//!
//! This computes the multi-quotient polynomial $f(X)$ that acts as a witness
//! for the claimed evaluations in the `query` stage. This also constructs the
//! bridge for committing to the polynomial.
//!
//! Each query below contributes the quotient $(p\_i(X) - v\_i) / (X - x\_i)$,
//! as `udon::polynomial::divide_linear_rev` computes it. The static query
//! prefix is defined by
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

use ragu_backend::{PolyDevice, Slot};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Cycle, FixedGenerators, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::{
    _03_s_prime::{NativeSPrime, NestedSPrime},
    _04_inner_error::{NestedRegistryWy, RegistryWy},
    device::{Devices, Held},
};
use crate::{
    Application, Proof,
    internal::{
        native,
        native::{RxComponent, RxIndex, STATIC_F_QUERIES, StaticFQuery},
        nested::{self, pcs},
        online,
    },
    multicore::par_join,
    profile::ProfiledCycle,
    proof::ProofBuilder,
    timing::span,
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
        devices: &mut Devices<'_, C, R>,
    ) -> Result<(NativeF<C, R>, NestedF<C, R>)>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let native_alpha = *alpha.value().take();
        let native_queries =
            self.native_f_queries(w, y, z, x, s_prime, registry_wy, builder, left, right);
        let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);
        let challenges = self.nested_challenges(w, x, y, z, left, right)?;
        let nested_alpha = nested::challenge::<C>(native_alpha)?;
        let nested_queries: Vec<_> = batch.queries(challenges).collect();

        // The two batches read only polynomials that are already fixed, so
        // they run together; their commitments follow in order. A side with
        // a device has it divide, from the polynomials it holds.
        let native_current = self.native_current_polys(s_prime, registry_wy, builder);
        let nested_current = batch.current();
        let (native_device, nested_device) =
            (devices.native.as_deref_mut(), devices.nested.as_deref_mut());
        let (native_held, nested_held) = (&mut devices.native_held, &mut devices.nested_held);
        let (host_generators, nested_generators) = (
            C::host_generators(self.params),
            C::nested_generators(self.params),
        );
        let ((native_poly, native_commitment), (nested_poly, nested_commitment)) =
            span("f.quotients", || {
                par_join!(
                    || {
                        let jobs = quotient_jobs(native_queries, native_alpha);
                        match native_device {
                            Some(device) => device_quotients::<B, C::HostCurve, R, _>(
                                device,
                                native_held,
                                &native_current,
                                &jobs,
                                host_generators,
                            ),
                            None => (host_quotients::<B, _, R>(&jobs), None),
                        }
                    },
                    || {
                        let jobs = quotient_jobs(nested_queries, nested_alpha);
                        match nested_device {
                            Some(device) => device_quotients::<B, C::NestedCurve, R, _>(
                                device,
                                nested_held,
                                &nested_current,
                                &jobs,
                                nested_generators,
                            ),
                            None => (host_quotients::<B, _, R>(&jobs), None),
                        }
                    },
                )
            });
        // The two commitments are independent, and on different curves. A
        // device that divided has committed to its quotient already.
        let (commitment, nested_commitment) = span("f.commit", || {
            par_join!(
                || native_commitment
                    .unwrap_or_else(|| B::sparse_commit_to_affine(&native_poly, host_generators)),
                || nested_commitment
                    .unwrap_or_else(|| B::sparse_commit_to_affine(&nested_poly, nested_generators)),
            )
        });
        let native = NativeF {
            commitment,
            poly: native_poly,
        };
        let nested = NestedF {
            commitment: nested_commitment,
            poly: nested_poly,
        };
        span("f.points", || {
            self.commit_native_points_f(
                rng,
                builder.nested_registry_xy_commitment(),
                nested.commitment,
                builder,
            )
        })?;
        span("f.bridge", || self.compute_bridge_f(rng, &native, builder))?;
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
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let bridge_rx = nested::stages::f::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::random(|bytes| rng.fill_bytes(bytes)),
            &nested::stages::f::Witness {
                native_f: native.commitment,
                native_points_f: builder.native_points_f_commitment(),
            },
        )?;
        let bridge_commitment =
            B::sparse_commit_to_affine(&bridge_rx, C::nested_generators(self.params));
        builder.set_bridge_f_rx(bridge_rx, bridge_commitment);
        Ok(())
    }

    /// Every opening in the native batch, as `(polynomial, point)` pairs, in
    /// the order $f(X)$ batches their quotients with $\alpha$.
    fn native_f_queries<'a, 'dr, D>(
        &self,
        w: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        x: &Element<'dr, D>,
        s_prime: &'a NativeSPrime<C, R>,
        registry_wy: &'a RegistryWy<C, R>,
        builder: &'a ProofBuilder<'_, C, R, B>,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
    ) -> Vec<(&'a sparse::Polynomial<C::CircuitField, R>, C::CircuitField)>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let w = *w.value().take();
        let y = *y.value().take();
        let z = *z.value().take();
        let x = *x.value().take();
        let xz = x * z;

        let omega_j = |idx: native::InternalCircuitIndex| -> C::CircuitField {
            idx.circuit_index::<C::Profile>().omega_j()
        };

        let mut iters: Vec<_> = STATIC_F_QUERIES
            .into_iter()
            .map(|query| match query {
                StaticFQuery::LeftP => (left.native_p_poly(), left.u()),
                StaticFQuery::RightP => (right.native_p_poly(), right.u()),
                StaticFQuery::LeftRegistryXyAtW => (left.native_registry_xy_poly(), w),
                StaticFQuery::RightRegistryXyAtW => (right.native_registry_xy_poly(), w),
                StaticFQuery::RegistryWx0AtLeftY => (&s_prime.registry_wx0_poly, left.y()),
                StaticFQuery::RegistryWx1AtRightY => (&s_prime.registry_wx1_poly, right.y()),
                StaticFQuery::RegistryWx0AtY => (&s_prime.registry_wx0_poly, y),
                StaticFQuery::RegistryWx1AtY => (&s_prime.registry_wx1_poly, y),
                StaticFQuery::RegistryWyAtLeftX => (&registry_wy.poly, left.x()),
                StaticFQuery::RegistryWyAtRightX => (&registry_wy.poly, right.x()),
                StaticFQuery::RegistryWyAtX => (&registry_wy.poly, x),
                StaticFQuery::RegistryXyAtW => (builder.native_registry_xy_poly(), w),
                StaticFQuery::RegistryXyAtLeftCircuitId => (
                    builder.native_registry_xy_poly(),
                    left.circuit_id().omega_j(),
                ),
                StaticFQuery::RegistryXyAtRightCircuitId => (
                    builder.native_registry_xy_poly(),
                    right.circuit_id().omega_j(),
                ),
                StaticFQuery::LeftAbAAtXz => (&left[RxComponent::AbA], xz),
                StaticFQuery::LeftAbBAtX => (&left[RxComponent::AbB], x),
                StaticFQuery::RightAbAAtXz => (&right[RxComponent::AbA], xz),
                StaticFQuery::RightAbBAtX => (&right[RxComponent::AbB], x),
                StaticFQuery::CurrentAAtXz => (builder.native_a_poly(), xz),
                StaticFQuery::CurrentBAtX => (builder.native_b_poly(), x),
            })
            .collect();
        // Per-rx evaluations at xz only. The same r_i(xz) values feed
        // into both A(xz) (undilated) and B(x) (Z-dilated).
        for proof in [left, right] {
            for id in RxIndex::all::<C::Profile>() {
                iters.push((&proof[id], xz));
            }
        }

        // m(\omega^j, x, y) evaluations for each internal index j
        for id in native::InternalCircuitIndex::all::<C::Profile>() {
            iters.push((builder.native_registry_xy_poly(), omega_j(id)));
        }

        // The online openings, in slot order, each at its own point.
        let polys = online::polys(left, right, builder.online_polynomials());
        for (poly, query) in polys.into_iter().zip(builder.online_openings()) {
            iters.push((poly, query.x));
        }

        iters
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
}

/// The weighted polynomials opened at one point.
type QuotientJob<'a, F, R> = (F, Vec<(F, &'a sparse::Polynomial<F, R>)>);

/// Batches the queries with $\alpha$ by point: of $K$ queries, the quotient
/// of query $k$ has weight $\alpha^{K-1-k}$, so the first receives the
/// highest power, and each point, in order of its first query, has the
/// weighted polynomials opened there.
///
/// Dividing by $X - x$ is linear in the dividend, so queries at the same
/// point are combined with their weights first and divided once: the
/// quotient of the combination is the combination of the quotients. The
/// batch is then the plain sum of one quotient per point, and its
/// coefficients are the same field elements as the weighted sum of one
/// quotient per query.
fn quotient_jobs<F: Field, R: Rank>(
    queries: Vec<(&sparse::Polynomial<F, R>, F)>,
    alpha: F,
) -> Vec<QuotientJob<'_, F, R>> {
    let mut weights = alloc::vec![F::ONE; queries.len()];
    for k in (1..queries.len()).rev() {
        weights[k - 1] = weights[k] * alpha;
    }
    let mut by_point: Vec<QuotientJob<'_, F, R>> = Vec::new();
    for ((poly, point), weight) in queries.into_iter().zip(weights) {
        match by_point.iter_mut().find(|(known, _)| *known == point) {
            Some((_, members)) => members.push((weight, poly)),
            None => by_point.push((point, alloc::vec![(weight, poly)])),
        }
    }
    by_point
}

/// The sum of the jobs' quotients on `device`, which keeps it as the batch's
/// quotient polynomial, read back, with its commitment over `generators` if
/// the backend commits to it where it is.
fn device_quotients<B: ragu_backend::Backend, P: Affine, R: Rank, G: FixedGenerators<P>>(
    device: &mut dyn PolyDevice<P::Scalar, R>,
    held: &mut Held<'_, P::Scalar, R>,
    current: &[&sparse::Polynomial<P::Scalar, R>],
    jobs: &[QuotientJob<'_, P::Scalar, R>],
    generators: &G,
) -> (sparse::Polynomial<P::Scalar, R>, Option<P>) {
    let polys: Vec<_> = jobs
        .iter()
        .flat_map(|(_, members)| members.iter().map(|(_, poly)| *poly))
        .collect();
    let mut slots = held.slots(device, current, &polys).into_iter();
    let jobs: Vec<(P::Scalar, Vec<(P::Scalar, Slot)>)> = jobs
        .iter()
        .map(|(point, members)| {
            let terms = members
                .iter()
                .map(|(weight, _)| (*weight, slots.next().expect("one slot per member")))
                .collect();
            (*point, terms)
        })
        .collect();
    let quotient = device.quotients(&jobs);
    held.f = Some(quotient);
    // The quotient is committed to where it is, in the request that reads
    // it back, if the backend can.
    if let Some((mut polys, commitments)) =
        B::device_commit::<P, R, G>(device, &[quotient], generators)
        && let (Some(poly), [commitment]) = (polys.pop(), commitments.as_slice())
    {
        return (poly, Some((*commitment).into()));
    }
    let poly = device
        .download(&[quotient])
        .pop()
        .expect("one polynomial per slot");
    (poly, None)
}

/// The sum of the jobs' quotients on the host. A job is divided in groups of
/// a few polynomials, which are independent and go through
/// [`Backend::map`](ragu_backend::Backend::map).
fn host_quotients<B: ragu_backend::Backend, F: Field, R: Rank>(
    by_point: &[QuotientJob<'_, F, R>],
) -> sparse::Polynomial<F, R> {
    /// The most polynomials combined before a division, which bounds the
    /// longest piece of independent work.
    const MAX_GROUP: usize = 8;
    let n = R::num_coeffs();

    let groups: Vec<_> = by_point
        .iter()
        .flat_map(|(point, members)| members.chunks(MAX_GROUP).map(move |chunk| (*point, chunk)))
        .collect();

    // The groups are dealt out to one share per worker. A share sums its
    // groups' quotients, reusing one buffer for the dividends.
    let shares = crate::multicore::current_num_threads().max(1);
    let mut dealt: Vec<Vec<_>> = (0..shares).map(|_| Vec::new()).collect();
    for (index, group) in groups.into_iter().enumerate() {
        dealt[index % shares].push(group);
    }
    let mut sums = B::map(dealt, |share| {
        let mut total = alloc::vec![F::ZERO; n - 1];
        let mut coeffs = alloc::vec![F::ZERO; n];
        for (point, members) in share {
            coeffs.fill(F::ZERO);
            for (weight, poly) in members {
                for (start, run) in poly.blocks() {
                    for (sum, coeff) in coeffs[start..].iter_mut().zip(run) {
                        *sum = coeff.mul_add(weight, sum);
                    }
                }
            }
            // Synthetic division from the top: the quotient's coefficient
            // of degree `i` is the running value when the dividend's is
            // read, and the constant coefficient only affects the
            // discarded remainder.
            let mut carry = coeffs[n - 1];
            for i in (0..n - 1).rev() {
                total[i] += carry;
                if i > 0 {
                    carry = carry.mul_add(&point, &coeffs[i]);
                }
            }
        }
        total
    });

    let mut total = sums.next().unwrap_or_default();
    for share in sums {
        for (sum, coeff) in total.iter_mut().zip(share) {
            *sum += coeff;
        }
    }
    sparse::Polynomial::from_coeffs(total)
}
