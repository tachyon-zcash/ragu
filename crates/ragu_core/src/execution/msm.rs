//! Udon MSM execution with caller-owned scratch and Ragu's worker pool.

use alloc::{vec, vec::Vec};
use core::any::Any;

use udon::{
    curve::{
        Affine, AffineAdapter, AffinePoint, Pallas, PastaCurve, Point, ProjectiveAdapter,
        ProjectivePoint, Vesta,
    },
    exec::{ExecutionOptions, Executor},
    field::{FieldAdapter, PastaField},
    msm::{
        Bases, Input, ScalarStorage, Scratch,
        execution::{BatchPlan, JobStorage, WorkerStorage},
    },
};

use super::executor::{self, PoolExecutor};

/// Computes $\sum_i \mathrm{scalars}_i \cdot \mathrm{bases}_i$.
///
/// Pasta MSMs use Udon's planner with scratch sized for the input and the
/// current Rayon pool when `multicore` is enabled. Other curves retain their
/// [`Affine::msm`] implementation. Empty inputs return the identity.
///
/// Inputs are collected into owned vectors; passing vectors reuses their
/// allocations. This lets the Pasta adapters borrow native buffers without
/// converting point or scalar encodings.
///
/// # Panics
///
/// Panics if the input lengths differ or the scratch size overflows.
pub fn msm<C: Affine>(
    scalars: impl IntoIterator<Item = C::Scalar>,
    bases: impl IntoIterator<Item = C>,
) -> C::Projective {
    let scalars: Vec<_> = scalars.into_iter().collect();
    let bases: Vec<_> = bases.into_iter().collect();
    assert_eq!(
        scalars.len(),
        bases.len(),
        "msm operands must have equal length"
    );

    if bases.is_empty() {
        return C::identity().to_projective();
    }

    // The generic curve trait has no executor or native-buffer interface.
    // Checked downcasts of the owned vectors select Pasta's safe borrowed
    // views without unsafe casts or per-element conversions.
    pasta::<C, Pallas>(&scalars, &bases)
        .or_else(|| pasta::<C, Vesta>(&scalars, &bases))
        .unwrap_or_else(|| C::msm(&scalars, &bases))
}

/// Computes independent MSMs, returning their results in input order.
///
/// Each input is a `(scalars, bases)` pair. Pasta inputs share a Udon
/// [`BatchPlan`] and the current worker pool's task budget. The plan can
/// schedule work between MSMs as well as within each MSM; it does not combine
/// their equations. Other curves use [`Affine::msm`] separately for each input.
///
/// # Panics
///
/// Panics if any input's scalar and base lengths differ or scratch sizing
/// overflows. All input lengths are checked before executing any MSM.
pub fn msm_batch<C: Affine, const N: usize>(
    inputs: [(
        impl IntoIterator<Item = C::Scalar>,
        impl IntoIterator<Item = C>,
    ); N],
) -> [C::Projective; N] {
    let inputs = inputs.map(|(scalars, bases)| {
        let scalars: Vec<_> = scalars.into_iter().collect();
        let bases: Vec<_> = bases.into_iter().collect();
        assert_eq!(
            scalars.len(),
            bases.len(),
            "msm operands must have equal length"
        );
        (scalars, bases)
    });
    pasta_batch::<C, Pallas, N>(&inputs)
        .or_else(|| pasta_batch::<C, Vesta, N>(&inputs))
        .unwrap_or_else(|| inputs.map(|(scalars, bases)| C::msm(&scalars, &bases)))
}

fn pasta_batch<C: Affine, P: PastaCurve, const N: usize>(
    inputs: &dyn Any,
) -> Option<[C::Projective; N]> {
    let inputs =
        inputs.downcast_ref::<[(Vec<FieldAdapter<P::Scalar>>, Vec<AffineAdapter<P>>); N]>()?;
    let inputs = inputs.each_ref().map(|(scalars, bases)| {
        Input::new(
            Bases::Points(AffineAdapter::as_slice(bases)),
            FieldAdapter::as_slice(scalars),
        )
    });
    let output = execute_batch(&inputs, executor::options(), &PoolExecutor);
    #[cfg(test)]
    tests::record_dispatch();
    Some(output.map(|point| {
        let result = ProjectiveAdapter::new(point);
        *(&result as &dyn Any)
            .downcast_ref::<C::Projective>()
            .expect("the selected Pasta curve's projective type")
    }))
}

fn execute_batch<C: PastaCurve, X: Executor, const N: usize>(
    inputs: &[Input<'_, C>; N],
    options: ExecutionOptions,
    executor: &X,
) -> [ProjectivePoint<C>; N] {
    let (jobs, workers) = BatchPlan::<C>::storage_len(N, options).expect("MSM metadata size fits");
    let mut jobs = vec![JobStorage::EMPTY; jobs];
    let mut workers = vec![WorkerStorage::EMPTY; workers];
    let plan = BatchPlan::new(inputs, options, &mut jobs, &mut workers)
        .expect("MSM batch scratch size fits");
    let required = plan.requirements();
    let mut records = vec![ScalarStorage::ZERO; required.scalars()];
    let mut digits = vec![0; required.digits()];
    let mut affine = vec![AffinePoint::GENERATOR; required.affine()];
    let mut projective = vec![ProjectivePoint::IDENTITY; required.projective()];
    let mut field = vec![PastaField::ZERO; required.field()];
    let mut indices = vec![0; required.indices()];
    let scratch = Scratch::new(
        &mut records,
        &mut digits,
        &mut affine,
        &mut projective,
        &mut field,
        &mut indices,
    );
    let mut output = [ProjectivePoint::IDENTITY; N];
    plan.execute(&mut output, executor, scratch);
    output
}

fn pasta<C: Affine, P: PastaCurve>(scalars: &dyn Any, bases: &dyn Any) -> Option<C::Projective> {
    let bases = bases.downcast_ref::<Vec<AffineAdapter<P>>>()?;
    let scalars = scalars
        .downcast_ref::<Vec<FieldAdapter<P::Scalar>>>()
        .expect("the selected Pasta curve's scalar type");
    let result = ProjectiveAdapter::new(execute(
        FieldAdapter::as_slice(scalars),
        AffineAdapter::as_slice(bases),
        executor::options(),
        &PoolExecutor,
    ));
    #[cfg(test)]
    tests::record_dispatch();
    Some(
        *(&result as &dyn Any)
            .downcast_ref::<C::Projective>()
            .expect("the selected Pasta curve's projective type"),
    )
}

fn execute<C: PastaCurve, X: Executor>(
    scalars: &[PastaField<C::Scalar>],
    bases: &[Point<C>],
    options: ExecutionOptions,
    executor: &X,
) -> ProjectivePoint<C> {
    let input = Input::new(Bases::Points(bases), scalars);
    let required = input.requirements(options).expect("MSM scratch size fits");
    let mut records = vec![ScalarStorage::ZERO; required.scalars()];
    let mut digits = vec![0; required.digits()];
    let mut affine = vec![AffinePoint::GENERATOR; required.affine()];
    let mut projective = vec![ProjectivePoint::IDENTITY; required.projective()];
    let mut field = vec![PastaField::ZERO; required.field()];
    let mut indices = vec![0; required.indices()];
    let scratch = Scratch::new(
        &mut records,
        &mut digits,
        &mut affine,
        &mut projective,
        &mut field,
        &mut indices,
    );
    input
        .execute(options, executor, scratch)
        .expect("scratch was sized for these inputs and execution options")
}

#[cfg(test)]
#[path = "tests/msm.rs"]
mod tests;
