//! Single and batched MSM parity, planner dispatch and input validation.

extern crate std;

use core::{
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};

use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{exec::TaskBudget, field::Field};

use super::*;
use crate::execution::tests::CountingExecutor;

std::thread_local! {
    static PASTA_DISPATCHES: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record_dispatch() {
    PASTA_DISPATCHES.set(PASTA_DISPATCHES.get() + 1);
}

fn planned_msms<C: PastaCurve>() {
    let mut rng = StdRng::seed_from_u64(892);
    let sizes = [0, 1, 17, 257, 2049];
    let inputs = sizes.map(|n| {
        let scalars: Vec<_> = (0..n)
            .map(|i| {
                if n < 2049 && i % 7 == 0 {
                    FieldAdapter::<C::Scalar>::ZERO
                } else {
                    FieldAdapter::random(|bytes| rng.fill_bytes(bytes))
                }
            })
            .collect();
        let generator = AffineAdapter::<C>::generator();
        let bases: Vec<_> = (0..n)
            .map(|i| match i % 3 {
                0 => generator,
                1 => -generator,
                _ => AffineAdapter::identity(),
            })
            .collect();
        (scalars, bases)
    });
    let expected = inputs
        .each_ref()
        .map(|(scalars, bases)| AffineAdapter::<C>::msm(scalars, bases));
    let native = inputs.each_ref().map(|(scalars, bases)| {
        Input::new(
            Bases::Points(AffineAdapter::as_slice(bases)),
            FieldAdapter::as_slice(scalars),
        )
    });
    // Fixed task budgets exercise serial and split plans on every host.
    for task_budget in [1, 4] {
        let options =
            ExecutionOptions::default().with_task_budget(TaskBudget::new(task_budget).unwrap());
        let executor = CountingExecutor(AtomicUsize::new(0));
        let (scalars, bases) = &inputs[4];
        let actual = execute(
            FieldAdapter::as_slice(scalars),
            AffineAdapter::as_slice(bases),
            options,
            &executor,
        );
        assert_eq!(ProjectiveAdapter::new(actual), expected[4]);
        let joins = executor.0.load(Ordering::Relaxed);
        if task_budget > 1 {
            assert!(joins > 0, "the single MSM must use its executor");
        }
        let actual = execute_batch(&native, options, &executor).map(ProjectiveAdapter::new);
        assert_eq!(actual, expected);
        if task_budget > 1 {
            assert!(
                executor.0.load(Ordering::Relaxed) > joins,
                "the batch must use its executor"
            );
        }
    }

    // Equality alone cannot distinguish native planner dispatch from fallback.
    let dispatches = PASTA_DISPATCHES.get();
    assert_eq!(
        crate::msm(inputs[4].0.iter().copied(), inputs[4].1.iter().copied()),
        expected[4]
    );
    assert_eq!(
        PASTA_DISPATCHES.get(),
        dispatches + 1,
        "the single MSM must use Udon's Pasta planner"
    );
    let dispatches = PASTA_DISPATCHES.get();
    assert_eq!(crate::msm_batch(inputs), expected);
    assert_eq!(
        PASTA_DISPATCHES.get(),
        dispatches + 1,
        "the batch must use Udon's Pasta planner"
    );

    let empty: [(Vec<FieldAdapter<C::Scalar>>, Vec<AffineAdapter<C>>); 0] = [];
    assert_eq!(crate::msm_batch(empty), []);
    let zeros = vec![FieldAdapter::<C::Scalar>::ZERO; 33];
    let bases = vec![AffineAdapter::<C>::generator(); 33];
    assert_eq!(
        crate::msm_batch([(zeros, bases)]),
        [AffineAdapter::<C>::identity().to_projective()]
    );
}

#[test]
fn pasta_msm_plans_match_separate_sums() {
    planned_msms::<Pallas>();
    planned_msms::<Vesta>();
}

#[test]
#[should_panic(expected = "msm operands must have equal length")]
fn batch_rejects_mismatched_operands() {
    crate::msm_batch::<AffineAdapter<Pallas>, 2>([
        (vec![], vec![]),
        (vec![FieldAdapter::ONE], vec![]),
    ]);
}
