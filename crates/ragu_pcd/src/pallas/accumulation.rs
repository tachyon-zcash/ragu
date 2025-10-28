use crate::accumulator::CycleAccumulator;
use crate::engine::CycleEngine;
use arithmetic::Cycle;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;

impl<'a, C: Cycle + Default, R: Rank> CycleEngine<'a, C, R> {
    /// Executes the Pallas-side accumulation step.
    ///
    /// This is the Fq round — computations are done over Fq, and commitments
    /// are made on the Pallas host curve.
    pub fn accumulation_pallas(
        mesh: &Mesh<'_, C::ScalarField, R>,
        witnesses: &[C::ScalarField],
        acc1: &mut CycleAccumulator<C::NestedCurve, C::HostCurve, R>,
        acc2: &CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        cycle: &C,
    ) -> Result<()> {
        todo!()
    }
}
