//! Execution-adapter tests and shared helpers.

extern crate std;

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use udon::exec::{Executor, SerialExecutor};

use super::executor::PoolExecutor;

// Observe planner scheduling independently of the test host's worker count.
pub(super) struct CountingExecutor(pub(super) AtomicUsize);

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
