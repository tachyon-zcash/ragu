//! Shared Udon execution on Ragu's worker pool.

use udon::exec::{ExecutionOptions, Executor, TaskBudget};

pub(crate) fn options() -> ExecutionOptions {
    ExecutionOptions::default()
        .with_task_budget(TaskBudget::new(worker_count()).expect("at least one worker"))
}

/// Applies `work` to independent items using Udon's scoped scheduler.
///
/// Each callback receives the item's original index. The current pool's
/// worker count bounds concurrent jobs; builds without `multicore` execute
/// serially. This does not allocate or create a new thread pool.
///
/// Callbacks may run in any order, but each item is visited exactly once on
/// success. If a callback panics, all scheduled jobs finish or unwind before
/// the panic propagates; some items may remain unvisited.
pub fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
    // No Ragu kernel accepts a nested task budget, so the scheduler's
    // per-job budget stays internal.
    udon::exec::for_each_mut(
        values,
        options().task_budget(),
        &PoolExecutor,
        |index, value, _| work(index, value),
    );
}

/// Applies `work` to each consecutive chunk of `chunk_len` items using Udon's
/// scoped scheduler.
///
/// Chunks have `chunk_len` items, except the last, which may be shorter. The
/// callback's index `i` identifies the chunk starting at `i * chunk_len`. The
/// current pool's worker count bounds concurrent jobs, and each job visits a
/// run of consecutive chunks in order; builds without `multicore` execute
/// serially. This does not allocate or create a new thread pool.
///
/// Callbacks may run in any order, but each chunk is visited exactly once on
/// success. If a callback panics, all scheduled jobs finish or unwind before
/// the panic propagates; some chunks may remain unvisited.
///
/// # Panics
///
/// Panics if `chunk_len` is zero.
pub fn for_each_chunk_mut<T: Send>(
    values: &mut [T],
    chunk_len: usize,
    work: impl Fn(usize, &mut [T]) + Sync,
) {
    // As in `for_each_mut`, the scheduler's per-job budget stays internal.
    udon::exec::for_each_chunk_mut(
        values,
        chunk_len,
        options().task_budget(),
        &PoolExecutor,
        |index, chunk, _| work(index, chunk),
    );
}

/// Runs two independent jobs and returns both results.
///
/// The jobs may run concurrently on the current pool; builds without
/// `multicore` run `left` and then `right`. Neither job may depend on the
/// other having run. This does not allocate or create a new thread pool.
///
/// If either job panics, the panic propagates once both have finished or
/// unwound.
pub fn join<A: Send, B: Send>(
    left: impl FnOnce() -> A + Send,
    right: impl FnOnce() -> B + Send,
) -> (A, B) {
    PoolExecutor.join(left, right)
}

/// Returns the current worker pool's size, or one for serial execution.
pub fn worker_count() -> usize {
    // Match maybe-rayon's serial fallback on WebAssembly without atomics.
    #[cfg(all(
        feature = "multicore",
        not(all(target_arch = "wasm32", not(target_feature = "atomics")))
    ))]
    {
        maybe_rayon::current_num_threads()
    }
    #[cfg(not(all(
        feature = "multicore",
        not(all(target_arch = "wasm32", not(target_feature = "atomics")))
    )))]
    {
        1
    }
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
