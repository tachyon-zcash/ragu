//! Wall-clock marks between the stages of [`Application::fuse`].
//!
//! With the `stage-timing` feature the fuse records how long each stage took
//! on the calling thread, for the experiment harness to read back with
//! [`take`]. Without it every call here compiles to nothing.
//!
//! [`Application::fuse`]: crate::Application::fuse

#[cfg(feature = "stage-timing")]
mod imp {
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use std::time::{Duration, Instant};

    struct State {
        last: Option<Instant>,
        marks: Vec<(&'static str, Duration)>,
    }

    std::thread_local! {
        static STATE: RefCell<State> = const {
            RefCell::new(State { last: None, marks: Vec::new() })
        };
    }

    pub(crate) fn start() {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.marks.clear();
            state.last = Some(Instant::now());
        });
    }

    pub(crate) fn mark(name: &'static str) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let now = Instant::now();
            if let Some(last) = state.last.replace(now) {
                state.marks.push((name, now - last));
            }
        });
    }

    /// Returns the marks of the last fuse on this thread, in pipeline order.
    /// A stage that is entered more than once appears once per entry.
    pub fn take() -> Vec<(&'static str, Duration)> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.last = None;
            core::mem::take(&mut state.marks)
        })
    }
}

#[cfg(feature = "stage-timing")]
mod spans {
    use alloc::vec::Vec;
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };

    static SPANS: Mutex<Vec<(&'static str, Duration)>> = Mutex::new(Vec::new());

    /// Runs `work` and records how long it took under `name`. Unlike the
    /// stage marks, spans may be recorded from any thread and may overlap.
    pub(crate) fn span<T>(name: &'static str, work: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let output = work();
        let elapsed = start.elapsed();
        SPANS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((name, elapsed));
        output
    }

    /// Returns every span recorded since the last call, in completion order.
    pub fn take_spans() -> Vec<(&'static str, Duration)> {
        core::mem::take(
            &mut *SPANS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

#[cfg(feature = "stage-timing")]
pub use imp::take;
#[cfg(feature = "stage-timing")]
pub(crate) use imp::{mark, start};
#[cfg(feature = "stage-timing")]
pub(crate) use spans::span;
#[cfg(feature = "stage-timing")]
pub use spans::take_spans;

#[cfg(not(feature = "stage-timing"))]
#[inline(always)]
pub(crate) fn span<T>(_name: &'static str, work: impl FnOnce() -> T) -> T {
    work()
}

#[cfg(not(feature = "stage-timing"))]
#[inline(always)]
pub(crate) fn start() {}

#[cfg(not(feature = "stage-timing"))]
#[inline(always)]
pub(crate) fn mark(_name: &'static str) {}
