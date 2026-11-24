//! Udon FFT execution with caller-owned scratch and Ragu's worker pool.

use alloc::{vec, vec::Vec};
use core::any::Any;

use udon::{
    exec::{ExecutionOptions, Executor},
    fft::{Direction, Domain, StorageLayout, Transform, TransformRequest, execution::FftPlan},
    field::{Field, FieldAdapter, PallasBase, PallasScalar, PastaField, PrimeModulus},
};

use super::executor::{self, PoolExecutor};

/// Transforms natural-order coefficients into natural-order domain evaluations.
///
/// Pasta FFTs use Udon's planner with scratch sized for the domain and the
/// current Rayon pool when `multicore` is enabled. Other fields retain their
/// [`Field::fft`] implementation.
///
/// The vector is transformed in place. Borrowing its owned storage permits
/// checked dispatch to Pasta's native buffer views without copying values or
/// converting field encodings.
///
/// # Panics
///
/// Panics before mutation if the input length differs from the domain size
/// or the scratch size overflows.
pub fn fft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
    assert_eq!(values.len(), domain.size(), "transform input length");
    transform(domain, values, false);
}

/// Transforms natural-order domain evaluations into normalized coefficients.
///
/// Uses the same execution and storage policy as [`fft`]. The inverse
/// includes division by the domain size.
///
/// # Panics
///
/// Panics before mutation if the input length differs from the domain size
/// or the scratch size overflows.
pub fn ifft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
    assert_eq!(values.len(), domain.size(), "transform input length");
    transform(domain, values, true);
}

/// Transforms consecutive domain-sized coefficient slices in place.
///
/// # Panics
///
/// Panics before mutation if the buffer does not contain complete slices.
pub fn fft_batch<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
    transform(domain, values, false);
}

/// Inverts [`fft_batch`] with one normalized inverse per slice.
///
/// # Panics
///
/// Panics before mutation if the buffer does not contain complete slices.
pub fn ifft_batch<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
    transform(domain, values, true);
}

#[allow(
    clippy::ptr_arg,
    reason = "checked Any dispatch requires the vector's concrete type"
)]
fn transform<F: Field>(domain: Domain<F>, values: &mut Vec<F>, inverse: bool) {
    assert!(
        values.len().is_multiple_of(domain.size()),
        "batch must contain complete transform inputs"
    );
    if values.is_empty()
        || pasta::<PallasBase>(domain.log_size(), values, inverse)
        || pasta::<PallasScalar>(domain.log_size(), values, inverse)
    {
        return;
    }

    for values in values.chunks_exact_mut(domain.size()) {
        if inverse {
            domain.inverse_transform(values);
        } else {
            domain.transform(values);
        }
    }
}

fn pasta<M: PrimeModulus>(log_size: u32, values: &mut dyn Any, inverse: bool) -> bool {
    let Some(values) = values.downcast_mut::<Vec<FieldAdapter<M>>>() else {
        return false;
    };
    // Pasta domains use canonical roots, fixed by their size. Reconstruct
    // the native descriptor after the checked field-type match.
    let domain = Domain::<PastaField<M>>::new(log_size).expect("valid Pasta domain");
    let values = FieldAdapter::as_slice_mut(values);
    let options = executor::options();
    if values.len() == domain.size() {
        execute(domain, values, inverse, options, &PoolExecutor);
    } else {
        execute_batch(domain, values, inverse, options, &PoolExecutor);
    }
    #[cfg(test)]
    tests::record_dispatch(inverse);
    true
}

fn execute<M: PrimeModulus, E: Executor>(
    domain: Domain<PastaField<M>>,
    values: &mut [PastaField<M>],
    inverse: bool,
    options: ExecutionOptions,
    executor: &E,
) {
    let transform = Transform::new(domain.subgroup());
    let required = transform
        .scratch_requirements(options)
        .expect("FFT scratch size fits");
    let mut scratch = vec![PastaField::ZERO; required];
    if inverse {
        transform.inverse(values, options, executor, &mut scratch)
    } else {
        transform.forward(values, options, executor, &mut scratch)
    }
    .expect("scratch was sized for this domain and execution options");
}

fn execute_batch<M: PrimeModulus, E: Executor>(
    domain: Domain<PastaField<M>>,
    values: &mut [PastaField<M>],
    inverse: bool,
    options: ExecutionOptions,
    executor: &E,
) {
    let direction = if inverse {
        Direction::Inverse
    } else {
        Direction::Forward
    };
    let plan = FftPlan::new(
        Transform::new(domain.subgroup()),
        TransformRequest::new(direction),
        StorageLayout::Contiguous,
        options,
    )
    .expect("valid Pasta FFT batch plan");
    let required = plan
        .batch_fields(values.len() / domain.size())
        .expect("FFT batch scratch size fits");
    let mut scratch = vec![PastaField::ZERO; required];
    plan.execute_batch(values, &mut scratch, executor);
}

#[cfg(test)]
#[path = "tests/fft.rs"]
mod tests;
