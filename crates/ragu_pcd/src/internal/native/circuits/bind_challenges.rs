//! Circuits binding the nested challenge stage to the transcript.
//!
//! ## Operations
//!
//! The nested side reads its challenges from the nested challenge stage,
//! whose commitment is the unblinded linear combination
//! $C_s = \sum_i \mathrm{lift}(\mathrm{ch}_i) \cdot G_{\mathrm{idx}(i)}$ of
//! the nested-curve generators (see [`challenges`]). Nothing on the nested
//! side can relate a lift to the native challenge it came from, so these
//! circuits do it on the native side: each takes two challenges from the
//! unified instance, decomposes them into bits ([`EndoscalarChallenge`]) and
//! endoscales the matching constant generators by those bits
//! ([`Endoscalar::group_scale`]), which yields exactly the lifted scalar
//! times the generator. The sum so far is checked against the running
//! partial the [`eval`] stage witnessed; circuit $k$ continues from partial
//! $k - 1$. The last circuit also adds the base-case sign's term, reading the
//! base case off the [`preamble`] as the native circuits do, and enforces
//! the sum equal to the instance's [`nested_challenges_partial`] slot: the
//! challenge stage's commitment without its $\beta$ term, which the nested
//! side reads the base case from and which a parent's
//! [`bind_beta`](super::bind_beta) completes with $\beta$'s term and holds
//! against the stage as walked. $\beta$ is squeezed after the eval stage is
//! committed, so its term cannot be bound here.
//!
//! ## Staging
//!
//! Chained through [`eval`] for its partials: the binding stage at the
//! root, [`preamble`] and [`query`] are reserved but unused.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] via [`unified::InternalOutputKind`]. The circuits
//! read challenges; the last covers [`nested_challenges_partial`].
//!
//! [`nested_challenges_partial`]: unified::Output::nested_challenges_partial
//!
//! [`challenges`]: crate::internal::nested::stages::challenges
//! [`eval`]: super::super::stages::eval
//! [`preamble`]: super::super::stages::preamble
//! [`query`]: super::super::stages::query

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, FixedGenerators};
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point,
    allocator::{Allocator, Standard},
};

use super::super::{
    stages::{
        eval as native_eval, points::BindingStage, preamble as native_preamble,
        query as native_query,
    },
    unified::{self, OutputBuilder},
};
use crate::internal::nested;

/// The number of binding circuits: two challenges each over the ten the
/// challenge stage holds.
pub const NUM_BINDERS: usize = 5;

/// The challenges the binders cover, two per circuit, in challenge-stage
/// order.
pub const NUM_BOUND: usize = 2 * NUM_BINDERS;

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
        &mut unified.nu,
        &mut unified.mu_prime,
        &mut unified.nu_prime,
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

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, const K: usize>
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
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance containing the challenges and accumulated
    /// coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the preamble stage (reserved, unused).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// Witness for the query stage (reserved, unused).
    pub query_witness: &'a native_query::Witness<C>,
    /// Witness for the eval stage (provides the binding partials).
    pub eval_witness: &'a native_eval::Witness<C>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, const K: usize>
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
        let builder = builder.skip_stage::<BindingStage<C::NestedCurve>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let _ = query.unenforced(dr, witness.as_ref().map(|w| w.query_witness))?;
        let eval = eval.unenforced(dr, witness.as_ref().map(|w| w.eval_witness))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let generators = C::nested_generators(self.params);

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

        let mut acc = acc.expect("two terms were added");

        // The last circuit adds the base-case sign's term, plus or minus the
        // generator of the challenge stage's sign value, and pins the sum to
        // the instance; the others check it against the eval stage's next
        // partial.
        if K + 1 == NUM_BINDERS {
            let is_base_case = preamble.is_base_case(dr, allocator)?;
            let generator = generators.g()
                [native_eval::generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)];
            let generator = Point::constant(dr, generator)?;
            let negate = is_base_case.not(dr);
            let term = generator.conditional_negate(dr, &negate)?;
            acc = NonzeroBank::scope(dr, |dr, bank| acc.add_incomplete(dr, &term, bank))?;
            let binding = unified_output
                .nested_challenges_partial
                .receive(dr, allocator)?;
            acc.enforce_equal(dr, &binding)?;
        } else {
            acc.enforce_equal(dr, &eval.partials[K])?;
        }

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
            _ => panic!("no binding circuit {}", $k),
        }
    }};
}
