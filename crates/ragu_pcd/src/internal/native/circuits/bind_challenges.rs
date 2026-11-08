//! Native circuits checking the nested challenge stage's partial commitment.
//!
//! ## Operations
//!
//! The nested side reads its challenges from the nested challenge stage,
//! whose commitment is the unblinded linear combination
//! $C_s = \sum_i \mathrm{lift}(\mathrm{ch}_i) \cdot G_{\mathrm{idx}(i)}$ of
//! the nested-curve generators (see [`challenges`]). These native circuits
//! recompute that point: each takes two challenges from the
//! unified instance, decomposes them into bits ([`EndoscalarChallenge`]) and
//! endoscales the matching constant generators by those bits
//! ([`Endoscalar::group_scale`]), which yields exactly the lifted scalar
//! times the generator. The sum so far is checked against the running
//! partial the [`eval`] stage witnessed; circuit $k$ continues from partial
//! $k - 1$. The first limb binder (below) adds the base-case sign's term to
//! the last partial, reading the base case off the [`preamble`] as the
//! native circuits do, and enforces the sum equal to the instance's
//! [`nested_challenges_partial`] slot: the
//! challenge stage's commitment without its $\beta$ term, which the nested
//! side reads the base case from and which a parent's
//! [`bind_beta`](super::bind_beta) completes with $\beta$'s term and holds
//! against the stage as walked. $\beta$ is squeezed after the eval stage is
//! committed, so its term cannot be bound here.
//!
//! These checks fix the claimed partial to the expected generator sum. A
//! parent carries that point to the stage polynomial the nested claims
//! consume, through its [`bind_beta`](super::bind_beta), its endoscaling walk
//! and its nested batch (see [`challenges`]).
//!
//! ## Limb binding
//!
//! The last [`NUM_LIMB_BINDERS`] circuits recompute the stage's terms for
//! the [limbs](crate::internal::limbs) of the step's own last online
//! commitment $O_1$, one coordinate each: the step's bridge hash
//! $H(O_1) = \sum_{i < 4} \ell_i \cdot G_{\mathrm{idx}(i)}$. Each reads its
//! coordinate's two limbs off the [`eval`] stage, decomposes the low limb into 128 bits and the
//! high limb into the rest of the coordinate field's capacity, which makes
//! the split unique, and adds each limb's multiple of its generator with
//! [`Point::add_fixed_base_mul`], starting from the independent blinding
//! generator $H$ so that no addition meets an exceptional case. The first
//! enforces the $x$ limbs' terms equal to the [`eval`] stage's limb partial;
//! the second adds the $y$ limbs' terms to it and enforces the sum equal to
//! the instance's [`bridge_hash`] slot, which the application circuit
//! reads and a parent's [`bind_beta`](super::bind_beta) adds into the stage
//! as walked. That walk ties the native limbs to the stage's, which the
//! nested `collapse` circuit holds to $O_1$.
//!
//! ## Staging
//!
//! Chained through [`eval`] for its partials. The first limb-binding
//! circuit reads [`preamble`] for base-case detection; the binding stage at
//! the root and [`query`] are reserved but unused.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] via [`unified::InternalOutputKind`]. The
//! challenge-binding circuits read challenges; the first limb-binding
//! circuit covers [`nested_challenges_partial`] and the last
//! [`bridge_hash`].
//!
//! [`bridge_hash`]: unified::Output::bridge_hash
//! [`nested_challenges_partial`]: unified::Output::nested_challenges_partial
//!
//! [`challenges`]: crate::internal::nested::stages::challenges
//! [`eval`]: super::super::stages::eval
//! [`preamble`]: super::super::stages::preamble
//! [`query`]: super::super::stages::query

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, FixedGenerators, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point,
    allocator::{Allocator, Standard},
    decompose_bits,
};

use super::super::{
    stages::{
        eval as native_eval, points::BindingStage, preamble as native_preamble,
        query as native_query,
    },
    unified::{self, OutputBuilder},
};
use crate::{
    internal::{limbs, nested},
    profile::ProfiledCycle,
};

/// The number of challenge-binding circuits, with two challenges per
/// circuit.
pub const NUM_CHALLENGE_BINDERS: usize = nested::stages::challenges::NUM / 2;

/// The number of limb-binding circuits, one per coordinate of $O_1$.
pub const NUM_LIMB_BINDERS: usize = limbs::NUM / 2;

/// The number of binding circuits: the challenge binders, then the limb
/// binders.
pub const NUM_BINDERS: usize = NUM_CHALLENGE_BINDERS + NUM_LIMB_BINDERS;

const _: () = assert!(nested::stages::challenges::NUM.is_multiple_of(2));

/// The challenges the binders cover, two per circuit, in challenge-stage
/// order.
pub const NUM_BOUND: usize = nested::stages::challenges::NUM;

/// Reads the `i`-th challenge, in challenge-stage order, from the unified
/// instance.
///
/// Only the first [`NUM_BOUND`] challenges are bound here; a larger `i`
/// panics.
fn read_challenge<'dr, D: Driver<'dr>, A: Allocator<'dr, D>, C: Cycle<CircuitField = D::F>>(
    unified: &mut OutputBuilder<'dr, D, A, C>,
    dr: &mut D,
    allocator: &mut A,
    i: usize,
) -> Result<Element<'dr, D>> {
    let slots: [_; NUM_BOUND] = [
        &mut unified.w,
        &mut unified.y,
        &mut unified.z,
        &mut unified.mu,
        &mut unified.mu_prime,
        &mut unified.x,
        &mut unified.alpha,
        &mut unified.u,
    ];
    slots[i].read(dr, allocator)
}

/// Circuit `K` of the nested challenge binding.
///
/// See the [module-level documentation] for details.
///
/// [module-level documentation]: self
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, const K: usize> {
    params: &'params C::Params,
    _marker: PhantomData<R>,
}

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, const K: usize>
    Circuit<'params, C, R, HEADER_SIZE, K>
{
    /// Creates a new multi-stage circuit.
    ///
    /// `params` provides the nested-curve generators the challenge stage is
    /// committed with.
    pub fn new(params: &'params C::Params) -> MultiStage<C::CircuitField, R, Self> {
        const { assert!(K < NUM_BINDERS) };
        MultiStage::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

/// Witness for a binding circuit.
pub struct Witness<'a, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance containing the challenges and accumulated
    /// coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the preamble stage, used by the first limb binder to
    /// derive the base-case condition from the child headers.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// Witness for the query stage (reserved, unused).
    pub query_witness: &'a native_query::Witness<C>,
    /// Witness for the eval stage (provides the binding partials, and the
    /// limbs the limb binders decompose).
    pub eval_witness: &'a native_eval::Witness<C>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, const K: usize>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, K>
{
    type Last = native_eval::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let builder = builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let _ = query.unenforced(dr, witness.as_ref().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.as_ref().map(|w| w.eval_witness))?;

        let allocator = &mut Standard::new();
        // A limb binder's coordinate, and its two limbs from the eval stage:
        // the low one in 128 bits, the high one in the rest of the capacity,
        // so the split is unique.
        let coordinate = K.checked_sub(NUM_CHALLENGE_BINDERS);
        let limb_bits = coordinate
            .map(|coordinate| {
                Ok::<_, ragu_core::Error>((
                    decompose_bits(dr, allocator, &eval.limbs[2 * coordinate], limbs::LO_BITS)?,
                    decompose_bits(
                        dr,
                        allocator,
                        &eval.limbs[2 * coordinate + 1],
                        limbs::hi_bits::<<C::HostCurve as udon::curve::Affine>::Base>(),
                    )?,
                ))
            })
            .transpose()?;
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let generators = C::nested_generators(self.params);

        if let (Some(coordinate), Some((lo_bits, hi_bits))) = (coordinate, limb_bits) {
            let (lo, hi) = (2 * coordinate, 2 * coordinate + 1);
            let g = |i| generators.g()[limbs::limb_generator_index::<C, R>(i)];
            if coordinate == 0 {
                // The challenge binders' last sum, closed with the base-case
                // sign's term, plus or minus the generator of the stage's
                // sign value, and pinned to the instance. It is here rather
                // than in the last challenge binder, which the preamble,
                // query and eval stages leave no room for.
                let is_base_case = preamble.is_base_case(dr, allocator)?;
                let generator = generators.g()
                    [native_eval::generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)];
                let generator = Point::constant(dr, generator)?;
                let negate = is_base_case.not(dr);
                let term = generator.conditional_negate(dr, &negate)?;
                let closed = NonzeroBank::scope(dr, |dr, bank| {
                    eval.partials[NUM_CHALLENGE_BINDERS - 1].add_incomplete(dr, &term, bank)
                })?;
                let binding = unified_output
                    .nested_challenges_partial
                    .receive(dr, allocator)?;
                closed.enforce_equal(dr, &binding)?;
            }
            let bridge_hash = (coordinate + 1 == NUM_LIMB_BINDERS)
                .then(|| unified_output.bridge_hash.receive(dr, allocator))
                .transpose()?;
            NonzeroBank::scope(dr, |dr, bank| {
                // Start from H, which no limb term can cancel, and take it
                // off at the end, so that the checked point is computed
                // forward from the bits and the stage.
                let start = Point::constant(dr, *generators.h())?;
                let unstart = Point::constant(dr, -*generators.h())?;
                let mut sum = start
                    .add_fixed_base_mul(dr, g(lo), &lo_bits, bank)?
                    .add_fixed_base_mul(dr, g(hi), &hi_bits, bank)?;
                if bridge_hash.is_some() {
                    // The y terms join the x terms the limb partial holds.
                    sum = sum.add_incomplete(dr, &eval.limb_partial, bank)?;
                }
                let sum = sum.add_incomplete(dr, &unstart, bank)?;
                match &bridge_hash {
                    // The x terms are the limb partial.
                    None => sum.enforce_equal(dr, &eval.limb_partial),
                    // All four are the bridge hash.
                    Some(bridge_hash) => sum.enforce_equal(dr, bridge_hash),
                }
            })?;
            let (output, aux) = unified_output.finish(dr, allocator)?;
            return Ok(WithAux::new(output, aux));
        }

        // Continue the running sum from the previous circuit's partial, or
        // start it.
        let mut acc: Option<Point<'dr, D, C::NestedCurve>> =
            (K > 0).then(|| eval.partials[K - 1].clone());

        for i in 2 * K..2 * (K + 1) {
            let challenge = read_challenge(&mut unified_output, dr, allocator, i)?;
            let challenge = EndoscalarChallenge::from_element(dr, allocator, challenge)?;
            let bits = Endoscalar::extract(challenge);

            let generator = generators.g()[native_eval::generator_index::<C, R>(i)];
            let generator = Point::constant(dr, generator)?;
            let term = bits.group_scale(dr, &generator)?;

            acc = Some(match acc {
                None => term,
                Some(sum) => {
                    NonzeroBank::scope(dr, |dr, bank| sum.add_incomplete(dr, &term, bank))?
                }
            });
        }

        // Every challenge binder checks its running sum against the eval
        // stage's next partial; the first limb binder closes the last one.
        acc.expect("two terms were added")
            .enforce_equal(dr, &eval.partials[K])?;

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}

/// Invokes `$body` with `$circuit` bound to the binding circuit numbered by
/// the runtime index `$k`.
#[macro_export]
macro_rules! with_binder {
    ($k:expr, $C:ty, $R:ty, $H:expr, $params:expr, |$circuit:ident| $body:expr) => {{
        use $crate::internal::native::circuits::bind_challenges::Circuit;
        match $k {
            0 => {
                let $circuit = Circuit::<$C, $R, $H, 0>::new($params);
                $body
            }
            1 => {
                let $circuit = Circuit::<$C, $R, $H, 1>::new($params);
                $body
            }
            2 => {
                let $circuit = Circuit::<$C, $R, $H, 2>::new($params);
                $body
            }
            3 => {
                let $circuit = Circuit::<$C, $R, $H, 3>::new($params);
                $body
            }
            4 => {
                let $circuit = Circuit::<$C, $R, $H, 4>::new($params);
                $body
            }
            5 => {
                let $circuit = Circuit::<$C, $R, $H, 5>::new($params);
                $body
            }
            _ => panic!("no binding circuit {}", $k),
        }
    }};
}
