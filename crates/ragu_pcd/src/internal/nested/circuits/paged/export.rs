//! The circuit that exposes the online values beside the nested unified
//! instance, in the [`compute_v`](super::super::compute_v) circuit's place.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{allocator::Standard, vec::FixedVec};
use udon::curve::EndomorphismAffine as Affine;

use super::{Loads, OnPreamble, Witness, cells};
use crate::{
    internal::{
        nested::{
            circuits::compute_v::Output,
            stages::{self, challenges},
            unified,
        },
        program::Memory,
    },
    profile::Profile,
};

/// Circuit exposing the compute-v circuit's public output for a profile
/// whose stages are laid side by side.
///
/// The output is the nested unified instance and then the online values
/// ([`Output`]). The circuit holds no slot of the unified instance: its
/// claim's $k(y_n)$ and the [instance circuit](super::instance)'s are
/// computed from one copy of the instance, which the parent holds, and the
/// instance circuit holds every slot.
///
/// Each online value is a stage's wire or a memory cell:
///
/// - the lifted $w$, $\alpha$ and $\beta$, from the challenge stage;
/// - the online helper's two sums, the cells the prover supplied to the
///   last [`Quotients`](super::Step::Quotients) and
///   [`Evaluations`](super::Step::Evaluations) pages;
/// - the native online stage commitments and points, from the `preamble`,
///   `s_prime` and `ab` stages, and from the cells the steps that load the
///   `query` and `eval` stages stored;
/// - the children's nested $x$ and $y$, from the `preamble` stage.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::preamble::Stage<C, R, P>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, P>;
    type Output = Kind![C::Base; Output<'_, _, C, P>];
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages, memory) = <OnPreamble as Loads<C, R, P>>::load(dr, &witness, None)?;
        let memory = Memory::loaded(&memory);
        let cells = cells::<P>();
        let preamble = stages.preamble()?;

        let mut load_points = |cells: &[_]| {
            cells
                .iter()
                .map(|&cell| memory.load_point(dr, cell))
                .collect::<Result<Vec<_>>>()
        };
        let query_online_points = load_points(&cells.query_online_points)?;
        let query_online_stage = load_points(&cells.query_online_stage)?;
        let eval_online_stage = load_points(&cells.eval_online_stage)?;
        let online_fold = cells
            .online_fold
            .iter()
            .map(|&cell| memory.load_element(dr, cell))
            .collect::<Result<Vec<_>>>()?;

        // The unified instance, no slot of which this circuit holds.
        let allocator = &mut Standard::new();
        let unified =
            unified::OutputBuilder::new(witness.as_ref().map(|w| w.stages.instance.clone()));
        let (output, instance) = unified.finish(dr, allocator)?;

        let online_values = FixedVec::from_fn(|i| match i {
            0 => stages.lift(challenges::W).clone(),
            1 => stages.lift(challenges::ALPHA).clone(),
            2 => stages.challenges.beta.lift.clone(),
            _ => online_fold[i - 3].clone(),
        });
        Ok(WithAux::new(
            Output {
                inherited_coordinates: FixedVec::from_fn(|i| {
                    [
                        &preamble.left.nested.x,
                        &preamble.left.nested.y,
                        &preamble.right.nested.x,
                        &preamble.right.nested.y,
                    ][i]
                        .clone()
                }),
                unified: output,
                online_values,
                online_points: preamble
                    .online_points
                    .iter()
                    .chain(stages.s_prime.online_points.iter())
                    .chain(stages.ab.online_points.iter())
                    .chain(query_online_points.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .try_into()?,
                online_stages: FixedVec::from_fn(|i| match i {
                    0 => preamble.online_stage[0].clone(),
                    1 => query_online_stage[0].clone(),
                    _ => eval_online_stage[0].clone(),
                }),
            },
            instance,
        ))
    }
}
