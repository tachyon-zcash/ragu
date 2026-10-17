//! Shared Udon execution on Ragu's worker pool.

use udon::exec::{ExecutionOptions, Executor, TaskBudget};

pub(crate) fn options() -> ExecutionOptions {
    ExecutionOptions::default()
        .with_task_budget(TaskBudget::new(worker_count()).expect("at least one worker"))
}

/// Applies `work` to independent items using Udon's scoped scheduler.
///
/// Each callback receives the item's original index and the task allowance
/// for nested Udon work. The current pool's worker count bounds concurrent
/// jobs; builds without `multicore` execute serially. This does not allocate
/// or create a new thread pool.
///
/// Callbacks may run in any order, but each item is visited exactly once on
/// success. If a callback panics, all scheduled jobs finish or unwind before
/// the panic propagates; some items may remain unvisited.
pub fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T, TaskBudget) + Sync) {
    udon::exec::for_each_mut(values, options().task_budget(), &PoolExecutor, work);
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
