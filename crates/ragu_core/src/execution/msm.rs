//! Udon MSM execution with caller-owned scratch and Ragu's worker pool.

#[cfg(feature = "std")]
extern crate std;

use alloc::{vec, vec::Vec};
use core::any::Any;

use udon::{
    curve::{
        Affine, AffineAdapter, AffinePoint, Pallas, PastaCurve, Point, PreparedAffinePoint,
        ProjectiveAdapter, ProjectivePoint, Vesta,
    },
    exec::{ExecutionOptions, Executor},
    field::{FieldAdapter, PastaField},
    msm::{
        Bases, Input, Requirements, ScalarStorage, Scratch,
        execution::{BatchPlan, JobStorage, WorkerStorage},
    },
};

use super::executor::{self, PoolExecutor};

/// Reusable storage for prepared Pasta MSMs.
///
/// Buffers grow on demand and retain their capacity until this value is
/// dropped. Ragu's compressed verifier scopes one to each check; a workspace
/// uses no global or thread-local storage. MSMs without a workspace retain
/// scratch of their own (see [`msm`]).
#[derive(Default)]
pub struct MsmWorkspace {
    pub(super) pallas: MsmBuffers<Pallas>,
    pub(super) vesta: MsmBuffers<Vesta>,
}

pub(super) struct MsmBuffers<C: PastaCurve> {
    records: Vec<ScalarStorage<C>>,
    digits: Vec<u8>,
    affine: Vec<AffinePoint<C>>,
    projective: Vec<ProjectivePoint<C>>,
    field: Vec<PastaField<C::Base>>,
    indices: Vec<usize>,
}

impl<C: PastaCurve> MsmBuffers<C> {
    const EMPTY: Self = Self {
        records: Vec::new(),
        digits: Vec::new(),
        affine: Vec::new(),
        projective: Vec::new(),
        field: Vec::new(),
        indices: Vec::new(),
    };
}

impl<C: PastaCurve> Default for MsmBuffers<C> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<C: PastaCurve> MsmBuffers<C> {
    fn scratch(&mut self, required: Requirements) -> Scratch<'_, C> {
        // Udon overwrites scratch before reading it, so a buffer's elements
        // are initialized only when it first grows to hold them. A smaller
        // requirement borrows a prefix and leaves the rest as it was.
        fn prefix<T: Clone>(buffer: &mut Vec<T>, len: usize, initial: T) -> &mut [T] {
            if buffer.len() < len {
                buffer.resize(len, initial);
            }
            &mut buffer[..len]
        }
        Scratch::new(
            prefix(&mut self.records, required.scalars(), ScalarStorage::ZERO),
            prefix(&mut self.digits, required.digits(), 0),
            prefix(&mut self.affine, required.affine(), AffinePoint::GENERATOR),
            prefix(
                &mut self.projective,
                required.projective(),
                ProjectivePoint::IDENTITY,
            ),
            prefix(&mut self.field, required.field(), PastaField::ZERO),
            prefix(&mut self.indices, required.indices(), 0),
        )
    }

    /// The bytes these buffers hold.
    #[cfg(feature = "std")]
    fn bytes(&self) -> usize {
        size_of_val(self.records.as_slice())
            + size_of_val(self.digits.as_slice())
            + size_of_val(self.affine.as_slice())
            + size_of_val(self.projective.as_slice())
            + size_of_val(self.field.as_slice())
            + size_of_val(self.indices.as_slice())
    }
}

/// A Pasta curve whose MSMs without a workspace retain their scratch.
pub(super) trait Retained: PastaCurve {
    /// The curve's retained buffers, empty while an MSM has taken them.
    #[cfg(feature = "std")]
    fn retained() -> &'static std::sync::Mutex<MsmBuffers<Self>>;
}

macro_rules! impl_retained {
    ($($curve:ty),*) => {$(
        impl Retained for $curve {
            #[cfg(feature = "std")]
            fn retained() -> &'static std::sync::Mutex<MsmBuffers<Self>> {
                static RETAINED: std::sync::Mutex<MsmBuffers<$curve>> =
                    std::sync::Mutex::new(MsmBuffers::EMPTY);
                &RETAINED
            }
        }
    )*};
}

impl_retained!(Pallas, Vesta);

/// Runs `work` with scratch buffers for an MSM on `C`.
///
/// With `std`, the MSM takes the curve's retained buffers, grows them to its
/// own requirement, and hands them back, so that successive MSMs neither
/// reallocate nor reinitialize their scratch. An MSM that finds the buffers
/// taken starts from empty ones; whichever set is larger is kept. Without
/// `std`, every MSM allocates and frees its own.
fn with_buffers<C: Retained, T>(work: impl FnOnce(&mut MsmBuffers<C>) -> T) -> T {
    #[cfg(feature = "std")]
    {
        // The lock is never held while an MSM runs, and a poisoned one still
        // guards usable buffers: their contents are never read before they
        // are overwritten.
        let lock = || {
            C::retained()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let mut buffers = core::mem::take(&mut *lock());
        let output = work(&mut buffers);
        let mut retained = lock();
        if buffers.bytes() > retained.bytes() {
            *retained = buffers;
        }
        output
    }
    #[cfg(not(feature = "std"))]
    work(&mut MsmBuffers::default())
}

/// Computes $\sum_i \mathrm{scalars}_i \cdot \mathrm{bases}_i$.
///
/// Pasta MSMs use Udon's planner with scratch sized for the input and the
/// current Rayon pool when `multicore` is enabled. Other curves retain their
/// [`Affine::msm`] implementation. Empty inputs return the identity.
///
/// With `std`, each Pasta curve keeps the scratch of its largest MSM so far
/// for the life of the process, and this function, [`msm_batch`] and
/// [`msm_many`] reuse it. Without `std`, each call allocates and frees its
/// scratch.
///
/// Proving holds witnesses and witness-derived polynomials in ordinary
/// process memory. Uncompressed proofs retain such polynomials for recursion,
/// and ordinary deallocation provides no erasure guarantee. With `std`, the
/// MSM cache can also keep scalar-derived data after the proof and
/// application are dropped. Later MSMs overwrite only the scratch they use.
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

/// Computes any number of independent MSMs, returning their results in input
/// order.
///
/// This is [`msm_batch`] for a count known only at run time: Pasta inputs
/// share one Udon [`BatchPlan`] and the current worker pool's task budget,
/// and other curves use [`Affine::msm`] separately for each input.
///
/// # Panics
///
/// Panics if any input's scalar and base lengths differ or scratch sizing
/// overflows. All input lengths are checked before executing any MSM.
pub fn msm_many<C: Affine>(inputs: Vec<(Vec<C::Scalar>, Vec<C>)>) -> Vec<C::Projective> {
    for (scalars, bases) in &inputs {
        assert_eq!(
            scalars.len(),
            bases.len(),
            "msm operands must have equal length"
        );
    }
    pasta_many::<C, Pallas>(&inputs)
        .or_else(|| pasta_many::<C, Vesta>(&inputs))
        .unwrap_or_else(|| {
            inputs
                .iter()
                .map(|(scalars, bases)| C::msm(scalars, bases))
                .collect()
        })
}

fn pasta_many<C: Affine, P: Retained>(inputs: &dyn Any) -> Option<Vec<C::Projective>> {
    let inputs =
        inputs.downcast_ref::<Vec<(Vec<FieldAdapter<P::Scalar>>, Vec<AffineAdapter<P>>)>>()?;
    let inputs: Vec<_> = inputs
        .iter()
        .map(|(scalars, bases)| {
            Input::new(
                Bases::Points(AffineAdapter::as_slice(bases)),
                FieldAdapter::as_slice(scalars),
            )
        })
        .collect();
    let mut output = vec![ProjectivePoint::IDENTITY; inputs.len()];
    execute_plan(&inputs, &mut output, executor::options(), &PoolExecutor);
    #[cfg(test)]
    tests::record_dispatch();
    Some(
        output
            .into_iter()
            .map(|point| {
                let result = ProjectiveAdapter::new(point);
                *(&result as &dyn Any)
                    .downcast_ref::<C::Projective>()
                    .expect("the selected Pasta curve's projective type")
            })
            .collect(),
    )
}

/// Executes indexed rows against one shared Pasta base bank.
pub(super) fn execute_indexed<C: Affine, P: Retained>(
    bases: Bases<'_, P>,
    rows: &dyn Any,
) -> Vec<C::Projective> {
    let rows = rows
        .downcast_ref::<Vec<(Vec<FieldAdapter<P::Scalar>>, Vec<u32>)>>()
        .expect("the selected Pasta curve's scalar type");
    let inputs: Vec<_> = rows
        .iter()
        .map(|(scalars, positions)| {
            assert_eq!(
                scalars.len(),
                positions.len(),
                "msm operands must have equal length"
            );
            Input::indexed(bases, positions, FieldAdapter::as_slice(scalars))
                .expect("every position lies within the base bank")
        })
        .collect();
    let mut output = vec![ProjectivePoint::IDENTITY; inputs.len()];
    execute_plan(&inputs, &mut output, executor::options(), &PoolExecutor);
    output
        .into_iter()
        .map(|point| {
            let result = ProjectiveAdapter::new(point);
            *(&result as &dyn Any)
                .downcast_ref::<C::Projective>()
                .expect("the selected Pasta curve's projective type")
        })
        .collect()
}

fn pasta_batch<C: Affine, P: Retained, const N: usize>(
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

fn execute_batch<C: Retained, X: Executor, const N: usize>(
    inputs: &[Input<'_, C>; N],
    options: ExecutionOptions,
    executor: &X,
) -> [ProjectivePoint<C>; N] {
    let mut output = [ProjectivePoint::IDENTITY; N];
    execute_plan(inputs, &mut output, options, executor);
    output
}

/// Executes `inputs` under one batch plan, writing each sum to its slot of
/// `output`.
pub(super) fn execute_plan<C: Retained, X: Executor>(
    inputs: &[Input<'_, C>],
    output: &mut [ProjectivePoint<C>],
    options: ExecutionOptions,
    executor: &X,
) {
    let (jobs, workers) =
        BatchPlan::<C>::storage_len(inputs.len(), options).expect("MSM metadata size fits");
    let mut jobs = vec![JobStorage::EMPTY; jobs];
    let mut workers = vec![WorkerStorage::EMPTY; workers];
    let plan = BatchPlan::new(inputs, options, &mut jobs, &mut workers)
        .expect("MSM batch scratch size fits");
    let required = plan.requirements();
    with_buffers(|buffers| plan.execute(output, executor, buffers.scratch(required)));
}

fn pasta<C: Affine, P: Retained>(scalars: &dyn Any, bases: &dyn Any) -> Option<C::Projective> {
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

fn execute<C: Retained, X: Executor>(
    scalars: &[PastaField<C::Scalar>],
    bases: &[Point<C>],
    options: ExecutionOptions,
    executor: &X,
) -> ProjectivePoint<C> {
    with_buffers(|buffers| {
        execute_input(
            Input::new(Bases::Points(bases), scalars),
            options,
            executor,
            buffers,
        )
    })
}

pub(super) fn execute_prepared<C: PastaCurve, X: Executor>(
    scalars: &[PastaField<C::Scalar>],
    bases: &[PreparedAffinePoint<C>],
    options: ExecutionOptions,
    executor: &X,
    buffers: &mut MsmBuffers<C>,
) -> ProjectivePoint<C> {
    execute_input(
        Input::new(Bases::Prepared(bases), scalars),
        options,
        executor,
        buffers,
    )
}

fn execute_input<C: PastaCurve, X: Executor>(
    input: Input<'_, C>,
    options: ExecutionOptions,
    executor: &X,
    buffers: &mut MsmBuffers<C>,
) -> ProjectivePoint<C> {
    let required = input.requirements(options).expect("MSM scratch size fits");
    input
        .execute(options, executor, buffers.scratch(required))
        .expect("scratch was sized for these inputs and execution options")
}

#[cfg(test)]
#[path = "tests/msm.rs"]
mod tests;
