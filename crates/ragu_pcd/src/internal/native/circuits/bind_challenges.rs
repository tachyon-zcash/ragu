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
//! $k - 1$, and the last partial is $C_s$ itself. $\beta$, squeezed after
//! the eval stage is committed, is bound by [`bind_beta`](super::bind_beta).
//!
//! ## Staging
//!
//! Chained through [`eval`] for its partials: [`preamble`] and [`query`]
//! are reserved but unused.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] via [`unified::InternalOutputKind`]. The circuits
//! read challenges and cover no slot.
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
    stages::{eval as native_eval, preamble as native_preamble, query as native_query},
    unified::{self, OutputBuilder},
};

/// The number of binding circuits: two challenges each over the ten the
/// challenge stage holds.
pub const NUM_BINDERS: usize = 5;

/// The challenges the binders cover, two per circuit, in challenge-stage
/// order.
pub const NUM_BOUND: usize = 2 * NUM_BINDERS;

/// Reads the `i`-th challenge, in challenge-stage order, from the unified
/// instance.
fn read_challenge<'dr, D: Driver<'dr>, A: Allocator<'dr, D>, C: Cycle<CircuitField = D::F>>(
    unified: &mut OutputBuilder<'dr, D, A, C>,
    dr: &mut D,
    allocator: &mut A,
    i: usize,
) -> Result<Element<'dr, D>> {
    match i {
        0 => unified.w.read(dr, allocator),
        1 => unified.y.read(dr, allocator),
        2 => unified.z.read(dr, allocator),
        3 => unified.mu.read(dr, allocator),
        4 => unified.nu.read(dr, allocator),
        5 => unified.mu_prime.read(dr, allocator),
        6 => unified.nu_prime.read(dr, allocator),
        7 => unified.x.read(dr, allocator),
        8 => unified.alpha.read(dr, allocator),
        9 => unified.u.read(dr, allocator),
        _ => unreachable!("only the first {NUM_BOUND} challenges are bound here"),
    }
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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (query, builder) = builder.add_stage::<native_query::Stage<C, R, HEADER_SIZE>>()?;
        let (eval, builder) = builder.add_stage::<native_eval::Stage<C, R, HEADER_SIZE>>()?;
        let dr = builder.finish();

        let _ = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
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
            _ => panic!("no binding circuit {}", $k),
        }
    }};
}
