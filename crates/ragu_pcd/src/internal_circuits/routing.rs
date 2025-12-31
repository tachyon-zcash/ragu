//! Routing for `HostCurve` commitments to endoscaling slots.

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

pub use super::stages::native::aggregate::{Stage, Witness as AggregateWitness};

/// Number of endoscaling slots for routing the HostCurve commitments.
///
/// 1.  application.commitment
/// 2.  preamble.stage_commitment
/// 3.  s_prime.mesh_wx0_commitment
/// 4.  s_prime.mesh_wx1_commitment
/// 5.  error_m.mesh_wy_commitment
/// 6.  error_m.stage_commitment
/// 7.  error_n.stage_commitment
/// 8.  ab.a_commitment
/// 9.  ab.b_commitment
/// 10. query.mesh_xy_commitment
/// 11. query.stage_commitment
/// 12. f.commitment
/// 13. eval.stage_commitment
/// 14. circuits.hashes_1_commitment
/// 15. circuits.hashes_2_commitment
/// 16. circuits.partial_collapse_commitment
/// 17. circuits.full_collapse_commitment
/// 18. circuits.compute_v_commitment
pub const NUM_SLOTS: usize = 18;

/// Witness for the routing circuit.
///
/// Contains all HostCurve commitments from the current proof that need to be
/// routed to aggregate slots for Fq-side endoscaling.
pub struct Witness<C: Cycle> {
    pub aggregate: AggregateWitness<C::HostCurve, NUM_SLOTS>,
}

impl<C: Cycle> Witness<C> {
    /// Creates a new routing witness from individual proof commitments.
    pub fn new(
        application: C::HostCurve,
        preamble_stage: C::HostCurve,
        s_prime_mesh_wx0: C::HostCurve,
        s_prime_mesh_wx1: C::HostCurve,
        error_m_mesh_wy: C::HostCurve,
        error_m_stage: C::HostCurve,
        error_n_stage: C::HostCurve,
        ab_a: C::HostCurve,
        ab_b: C::HostCurve,
        query_mesh_xy: C::HostCurve,
        query_stage: C::HostCurve,
        f: C::HostCurve,
        eval_stage: C::HostCurve,
        hashes_1: C::HostCurve,
        hashes_2: C::HostCurve,
        partial_collapse: C::HostCurve,
        full_collapse: C::HostCurve,
        compute_v: C::HostCurve,
    ) -> Self {
        Self {
            aggregate: AggregateWitness {
                commitments: FixedVec::from_fn(|i| match i {
                    0 => application,
                    1 => preamble_stage,
                    2 => s_prime_mesh_wx0,
                    3 => s_prime_mesh_wx1,
                    4 => error_m_mesh_wy,
                    5 => error_m_stage,
                    6 => error_n_stage,
                    7 => ab_a,
                    8 => ab_b,
                    9 => query_mesh_xy,
                    10 => query_stage,
                    11 => f,
                    12 => eval_stage,
                    13 => hashes_1,
                    14 => hashes_2,
                    15 => partial_collapse,
                    16 => full_collapse,
                    17 => compute_v,
                    _ => unreachable!("NUM_SLOTS is 18"),
                }),
            },
        }
    }

    /// Returns the commitment at the given slot index.
    pub fn slot(&self, i: usize) -> C::HostCurve {
        self.aggregate.commitments[i]
    }
}

/// Routing circuit for HostCurve (Vesta) commitments.
///
/// This circuit witnesses source commitments from individual nested stages,
/// witnesses them in an aggregate stage, and enforces equality constraints.
pub struct Circuit<C: Cycle, R: Rank> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> Circuit<C, R> {
    /// Creates a new routing circuit wrapped in the [`Staged`] adapter.
    pub fn new() -> Staged<C::ScalarField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Output of the routing circuit - the aggregate stage output.
#[derive(Gadget, Write)]
pub struct CircuitOutput<'dr, D: Driver<'dr>, C: Cycle> {
    /// The routed commitments in slot order.
    #[ragu(gadget)]
    pub slots: FixedVec<Point<'dr, D, C::HostCurve>, ConstLen<NUM_SLOTS>>,
    #[ragu(phantom)]
    _marker: PhantomData<C>,
}

impl<C: Cycle, R: Rank> StagedCircuit<C::ScalarField, R> for Circuit<C, R> {
    type Final = Stage<C::HostCurve, NUM_SLOTS>;

    type Instance<'source> = ();
    type Witness<'source> = &'source Witness<C>;
    type Output = ragu_core::gadgets::Kind![C::ScalarField; CircuitOutput<'_, _, C>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::ScalarField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("routing circuit instance is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::ScalarField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (guard, builder) = builder.add_stage::<Stage<C::HostCurve, NUM_SLOTS>>()?;
        let dr = builder.finish();

        let sources: FixedVec<Point<'dr, D, C::HostCurve>, ConstLen<NUM_SLOTS>> =
            FixedVec::try_from_fn(|i| Point::alloc(dr, witness.view().map(|w| w.slot(i))))?;

        let aggregate_output = guard.enforced(dr, witness.view().map(|w| &w.aggregate))?;

        for i in 0..NUM_SLOTS {
            sources[i].enforce_equal(dr, &aggregate_output.slots[i])?;
        }

        Ok((
            CircuitOutput {
                slots: aggregate_output.slots,
                _marker: PhantomData,
            },
            D::just(|| ()),
        ))
    }
}
