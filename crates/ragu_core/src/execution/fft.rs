//! Udon FFT execution with caller-owned scratch and Ragu's worker pool.

use alloc::{vec, vec::Vec};
use core::any::Any;

use udon::{
    exec::{ExecutionOptions, Executor},
    fft::{Domain, Transform},
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
    transform(domain, values, true);
}

#[allow(
    clippy::ptr_arg,
    reason = "checked Any dispatch requires the vector's concrete type"
)]
fn transform<F: Field>(domain: Domain<F>, values: &mut Vec<F>, inverse: bool) {
    assert_eq!(values.len(), domain.size(), "transform input length");
    if pasta::<PallasBase>(domain.log_size(), values, inverse)
        || pasta::<PallasScalar>(domain.log_size(), values, inverse)
    {
        return;
    }

    if inverse {
        domain.inverse_transform(values);
    } else {
        domain.transform(values);
    }
}

fn pasta<M: PrimeModulus>(log_size: u32, values: &mut dyn Any, inverse: bool) -> bool {
    let Some(values) = values.downcast_mut::<Vec<FieldAdapter<M>>>() else {
        return false;
    };
    // Pasta domains use canonical roots, fixed by their size. Reconstruct
    // the native descriptor after the checked field-type match.
    let domain = Domain::<PastaField<M>>::new(log_size).expect("valid Pasta domain");
    execute(
        domain,
        FieldAdapter::as_slice_mut(values),
        inverse,
        executor::options(),
        &PoolExecutor,
    );
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

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{
        cell::Cell,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rand::{Rng, SeedableRng, rngs::StdRng};
    use udon::exec::{SerialExecutor, TaskBudget};

    use super::*;
    use crate::pasta::{Fp, Fq};

    std::thread_local! {
        static PASTA_DISPATCHES: Cell<[usize; 2]> = const { Cell::new([0; 2]) };
    }

    pub(super) fn record_dispatch(inverse: bool) {
        let mut dispatches = PASTA_DISPATCHES.get();
        dispatches[usize::from(inverse)] += 1;
        PASTA_DISPATCHES.set(dispatches);
    }

    fn assert_pasta_dispatch(inverse: bool, f: impl FnOnce()) {
        let mut expected = PASTA_DISPATCHES.get();
        expected[usize::from(inverse)] += 1;
        f();
        assert_eq!(
            PASTA_DISPATCHES.get(),
            expected,
            "{} must dispatch to Udon's Pasta planner",
            if inverse { "IFFT" } else { "FFT" }
        );
    }

    fn check_field<F: Field>() {
        let check = || {
            let mut rng = StdRng::seed_from_u64(890);
            for log_size in [0, 1, 2, 3, 5, 8, 9, 10, 13, 14] {
                let domain = F::domain(log_size).unwrap();
                let input: Vec<_> = (0..domain.size())
                    .map(|i| match i % 5 {
                        0 => F::ONE,
                        1 => F::ZERO,
                        2 => -F::ONE,
                        _ => F::random(|bytes| rng.fill_bytes(bytes)),
                    })
                    .collect();
                let mut expected = input.clone();
                domain.transform(&mut expected);
                let mut actual = input.clone();
                assert_pasta_dispatch(false, || crate::fft(domain, &mut actual));
                assert_eq!(actual, expected);

                // Direct Horner evaluation is independent of both FFT paths
                // and checks natural output order on the smaller domains.
                if log_size <= 5 {
                    let mut point = F::ONE;
                    for value in &actual {
                        let evaluated = input
                            .iter()
                            .rev()
                            .fold(F::ZERO, |acc, coefficient| acc * point + *coefficient);
                        assert_eq!(*value, evaluated);
                        point *= domain.root();
                    }
                }

                assert_pasta_dispatch(true, || crate::ifft(domain, &mut actual));
                assert_eq!(actual, input);

                // Compare inverses on arbitrary evaluations as well, so
                // forward/inverse mistakes cannot cancel in a round trip.
                expected.clone_from(&input);
                domain.inverse_transform(&mut expected);
                actual.clone_from(&input);
                assert_pasta_dispatch(true, || crate::ifft(domain, &mut actual));
                assert_eq!(actual, expected);
            }
        };

        #[cfg(all(
            feature = "multicore",
            not(all(target_arch = "wasm32", not(target_feature = "atomics")))
        ))]
        for threads in [1, 3, 7] {
            maybe_rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(check);
        }
        #[cfg(not(all(
            feature = "multicore",
            not(all(target_arch = "wasm32", not(target_feature = "atomics")))
        )))]
        check();
    }

    #[test]
    fn fp_matches_serial_and_horner() {
        check_field::<Fp>();
    }

    #[test]
    fn fq_matches_serial_and_horner() {
        check_field::<Fq>();
    }

    struct CountingExecutor(AtomicUsize);

    impl Executor for CountingExecutor {
        fn join<L, R, A, B>(&self, left: L, right: R) -> (A, B)
        where
            L: FnOnce() -> A + Send,
            R: FnOnce() -> B + Send,
            A: Send,
            B: Send,
        {
            self.0.fetch_add(1, Ordering::Relaxed);
            SerialExecutor.join(left, right)
        }
    }

    fn planned_fft<M: PrimeModulus>() {
        let domain = Domain::<PastaField<M>>::new(14).unwrap();
        let input: Vec<_> = (0..domain.size())
            .map(|i| PastaField::<M>::from_u64(i as u64))
            .collect();
        let mut actual = input.clone();
        let options = ExecutionOptions::default().with_task_budget(TaskBudget::new(4).unwrap());
        let executor = CountingExecutor(AtomicUsize::new(0));
        execute(domain, &mut actual, false, options, &executor);
        let joins = executor.0.load(Ordering::Relaxed);
        assert!(joins > 0, "Udon must use the supplied executor");
        execute(domain, &mut actual, true, options, &executor);
        assert!(executor.0.load(Ordering::Relaxed) > joins);
        for (actual, expected) in actual.iter().zip(&input) {
            assert_eq!(actual.reduce(), expected.reduce());
        }
    }

    #[test]
    fn fp_plan_uses_executor() {
        planned_fft::<PallasBase>();
    }

    #[test]
    fn fq_plan_uses_executor() {
        planned_fft::<PallasScalar>();
    }

    #[test]
    fn invalid_lengths_leave_inputs_unchanged() {
        fn check<F: Field>() {
            let domain = F::domain(3).unwrap();
            for len in [0, 7, 9] {
                for inverse in [false, true] {
                    let mut values = vec![F::ONE; len];
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        transform(domain, &mut values, inverse);
                    }));
                    assert!(result.is_err());
                    assert_eq!(values, vec![F::ONE; len]);
                }
            }
        }
        check::<Fp>();
        check::<Fq>();
    }
}
