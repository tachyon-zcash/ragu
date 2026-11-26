//! The circuit that exposes the nested unified instance, in the
//! [`collapse`](super::super::collapse) circuit's place.

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Standard, consistent::Consistent};
use udon::curve::EndomorphismAffine as Affine;

use super::{Loads, OnPreamble, Witness, cells};
use crate::{
    header::NUM_ONLINE_FP_POLYS,
    internal::{
        nested::{circuits::collapse::Exported, stages, unified},
        program::Memory,
    },
    profile::Profile,
};

/// Circuit binding the nested unified instance to the stages and to the
/// memory of the [program](super).
///
/// It is the only circuit of the layout that holds a slot of the instance,
/// and it holds every slot:
///
/// - $x$, $y$ and $u$ to the challenge stage's lifts.
/// - The exported commitments to their stage copies, in the collapse
///   circuit's order ([`Exported`]). It loads the trunk and the `preamble`
///   stage. The copies of the `inner_error`, `outer_error`, `query` and
///   `eval` stages are memory cells that a step loading the stage stored.
/// - $c_n$ to the cell the last [`Errors`](super::Step::Errors) page
///   stored, outside the base case, with the challenge stage's sign as the
///   collapse circuit takes it.
/// - $v_n$ is the cell the last [`Evaluations`](super::Step::Evaluations)
///   page stored.
///
/// The circuit also holds what the collapse and compute-v circuits hold of
/// the trunk: the endoscalar stage's contract, that endoscalar's lift to
/// the challenge stage's $\beta_n$, the bridge-hash stage's point to the
/// step's own last online commitment, and the two ends of the walk. The
/// first link is the commitment of $f$, and the last link, which the
/// instance exports, is the walk's result. The
/// [`Walk`](super::Step::Walk) steps hold each group between its links.
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
    type Output = unified::OutputKind<C>;
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

        // The endoscalar stage's contract, and the endoscalar the
        // endoscaling steps walked P with lifts to the challenge stage's
        // beta wire.
        stages.endoscalar.enforce_consistent(dr)?;
        stages
            .endoscalar
            .lift(dr)?
            .enforce_equal(dr, &stages.challenges.beta.lift)?;

        // The walk starts from the commitment of f and ends at the last
        // link.
        let links = &stages.links.states;
        links
            .first()
            .expect("a grouped walk has links")
            .enforce_equal(dr, &stages.f.native_f)?;
        let walked = links.last().expect("a grouped walk has links");

        let allocator = &mut Standard::new();
        let mut unified =
            unified::OutputBuilder::new(witness.as_ref().map(|w| w.stages.instance.clone()));

        // The lifted challenges a parent opens this step at.
        unified
            .x
            .receive(dr, allocator)?
            .enforce_equal(dr, stages.lift(stages::challenges::X))?;
        unified
            .y
            .receive(dr, allocator)?
            .enforce_equal(dr, stages.lift(stages::challenges::Y))?;
        unified
            .u
            .receive(dr, allocator)?
            .enforce_equal(dr, stages.lift(stages::challenges::U))?;

        // The commitments a parent endoscales, in `unified` order.
        let native_inner_error = memory.load_point(dr, cells.native_inner_error)?;
        let native_outer_error = memory.load_point(dr, cells.native_outer_error)?;
        let native_query = memory.load_point(dr, cells.native_query)?;
        let native_eval = memory.load_point(dr, cells.native_eval)?;
        let registry_xy = memory.load_point(dr, cells.registry_xy)?;
        let held = Exported {
            preamble,
            s_prime: &stages.s_prime,
            ab: &stages.ab,
            f: &stages.f,
            native_inner_error: &native_inner_error,
            native_outer_error: &native_outer_error,
            native_query: &native_query,
            native_eval: &native_eval,
            registry_xy: &registry_xy,
            walked,
        }
        .copies();
        // The bridge-hash stage holds the step's own last online commitment,
        // the one the preamble holds and w absorbed.
        stages
            .bridge_hash
            .o1
            .enforce_equal(dr, &preamble.online_commitments[NUM_ONLINE_FP_POLYS - 1])?;

        let exported = unified.exported.receive(dr, allocator)?;
        for (instance, stage) in exported.iter().zip(held) {
            instance.enforce_equal(dr, stage)?;
        }

        // The fold of the children's claims is c_n, outside the base case.
        let computed_c = memory.load_element(dr, cells.c)?;
        let witnessed_c = unified.c.receive(dr, allocator)?;
        let is_base_case =
            stages
                .challenges
                .base_case
                .lift
                .is_equal(dr, allocator, &Element::one())?;
        is_base_case
            .not(dr)
            .conditional_enforce_equal(dr, allocator, &witnessed_c, &computed_c)?;

        // v_n, as the last page of the evaluations stored it.
        let v = memory.load_element(
            dr,
            *cells
                .evaluations
                .last()
                .expect("the evaluations have a page"),
        )?;
        unified.v.provide(v);

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}
