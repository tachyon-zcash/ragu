//! FFT parity, ordering, dispatch and input validation.

extern crate std;

use core::{
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};

use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::exec::TaskBudget;

use super::*;
use crate::{
    execution::tests::CountingExecutor,
    pasta::{Fp, Fq},
};

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
fn pasta_transforms_match_serial_and_horner() {
    check_field::<Fp>();
    check_field::<Fq>();
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
fn pasta_transform_plans_use_executor() {
    planned_fft::<PallasBase>();
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
