//! First real nested circuit - uses all nested stages with actual witness data.
//!
//! This circuit operates on ScalarField (= HostCurve::Base) and builds
//! through the full nested stage hierarchy, witnessing HostCurve commitments.

use arithmetic::{CurveAffine, Cycle};
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::io::Write;

use core::marker::PhantomData;

use super::stages::{ab, error_m, error_n, eval, f, preamble, query, s_prime};

/// Witness data for the child proofs circuit.
///
/// Contains all the witness data needed for each nested stage.
pub struct Witness<'a, C: CurveAffine> {
    pub preamble: &'a preamble::Witness<C>,
    pub s_prime: &'a s_prime::Witness<C>,
    pub error_m: &'a error_m::Witness<C>,
    pub error_n: &'a error_n::Witness<C>,
    pub ab: &'a ab::Witness<C>,
    pub query: &'a query::Witness<C>,
    pub f: &'a f::Witness<C>,
    pub eval: &'a eval::Witness<C>,
}

/// Circuit output - all stage outputs combined.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine> {
    #[ragu(gadget)]
    pub preamble: preamble::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub s_prime: s_prime::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub error_m: error_m::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub error_n: error_n::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub ab: ab::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub query: query::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub f: f::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub eval: eval::Output<'dr, D, C>,
}

/// Staged circuit that uses all nested stages.
pub struct Circuit<C: Cycle, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> Circuit<C, R> {
    /// Create a new staged circuit.
    pub fn new() -> Staged<C::ScalarField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, R: Rank> StagedCircuit<C::ScalarField, R> for Circuit<C, R> {
    type Final = eval::Stage<C::HostCurve, R>;

    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C::HostCurve>;
    type Output = Kind![C::ScalarField; Output<'_, _, C::HostCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::ScalarField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance path not used for internal circuits")
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
        // Build through all stages with actual witness data
        let (preamble_guard, builder) = builder.add_stage::<preamble::Stage<C::HostCurve, R>>()?;
        let (s_prime_guard, builder) = builder.add_stage::<s_prime::Stage<C::HostCurve, R>>()?;
        let (error_m_guard, builder) = builder.add_stage::<error_m::Stage<C::HostCurve, R>>()?;
        let (error_n_guard, builder) = builder.add_stage::<error_n::Stage<C::HostCurve, R>>()?;
        let (ab_guard, builder) = builder.add_stage::<ab::Stage<C::HostCurve, R>>()?;
        let (query_guard, builder) = builder.add_stage::<query::Stage<C::HostCurve, R>>()?;
        let (f_guard, builder) = builder.add_stage::<f::Stage<C::HostCurve, R>>()?;
        let (eval_guard, builder) = builder.add_stage::<eval::Stage<C::HostCurve, R>>()?;
        let dr = builder.finish();

        // Execute each stage with its witness data
        let preamble_out = preamble_guard.enforced(dr, witness.view().map(|w| w.preamble))?;
        let s_prime_out = s_prime_guard.enforced(dr, witness.view().map(|w| w.s_prime))?;
        let error_m_out = error_m_guard.enforced(dr, witness.view().map(|w| w.error_m))?;
        let error_n_out = error_n_guard.enforced(dr, witness.view().map(|w| w.error_n))?;
        let ab_out = ab_guard.enforced(dr, witness.view().map(|w| w.ab))?;
        let query_out = query_guard.enforced(dr, witness.view().map(|w| w.query))?;
        let f_out = f_guard.enforced(dr, witness.view().map(|w| w.f))?;
        let eval_out = eval_guard.enforced(dr, witness.view().map(|w| w.eval))?;

        let output = Output {
            preamble: preamble_out,
            s_prime: s_prime_out,
            error_m: error_m_out,
            error_n: error_n_out,
            ab: ab_out,
            query: query_out,
            f: f_out,
            eval: eval_out,
        };

        Ok((output, D::just(|| ())))
    }
}
