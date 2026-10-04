//! Shared Udon execution on Ragu's worker pool.

use udon::exec::{ExecutionOptions, Executor, TaskBudget};

pub(crate) fn options() -> ExecutionOptions {
    ExecutionOptions::default()
        .with_task_budget(TaskBudget::new(worker_count()).expect("at least one worker"))
}

// Match maybe-rayon's serial fallback on WebAssembly without atomics.
#[cfg(all(
    feature = "multicore",
    not(all(target_arch = "wasm32", not(target_feature = "atomics")))
))]
fn worker_count() -> usize {
    maybe_rayon::current_num_threads()
}

#[cfg(not(all(
    feature = "multicore",
    not(all(target_arch = "wasm32", not(target_feature = "atomics")))
)))]
fn worker_count() -> usize {
    1
}

pub(crate) struct PoolExecutor;

impl Executor for PoolExecutor {
    fn join<L, R, A, B>(&self, left: L, right: R) -> (A, B)
    where
        L: FnOnce() -> A + Send,
        R: FnOnce() -> B + Send,
        A: Send,
        B: Send,
    {
        #[cfg(all(
            feature = "multicore",
            not(all(target_arch = "wasm32", not(target_feature = "atomics")))
        ))]
        {
            maybe_rayon::join(left, right)
        }
        #[cfg(not(all(
            feature = "multicore",
            not(all(target_arch = "wasm32", not(target_feature = "atomics")))
        )))]
        {
            // Also completes the right job if the left one panics, as the
            // Executor contract requires.
            udon::exec::SerialExecutor.join(left, right)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn executor_completes_right_job_after_left_panic() {
        let completed = AtomicBool::new(false);
        let result = std::panic::catch_unwind(|| {
            PoolExecutor.join(
                || panic!("left job"),
                || completed.store(true, Ordering::Relaxed),
            )
        });
        assert!(result.is_err());
        assert!(completed.load(Ordering::Relaxed));
    }
}
