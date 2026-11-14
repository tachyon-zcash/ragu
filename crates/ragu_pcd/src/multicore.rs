/// N-way parallel join for coarse-grained task parallelism.
///
/// Like [`maybe_rayon::join`] for more than two closures: nests internally and flattens
/// the result into a single tuple. Each closure may return a different type.
/// Supports 2..=4 closures — for higher arities prefer a data-parallel
/// iterator.
macro_rules! par_join {
    ($a:expr, $b:expr $(,)?) => {
        maybe_rayon::join($a, $b)
    };
    ($a:expr, $b:expr, $c:expr $(,)?) => {{
        let (a, (b, c)) = maybe_rayon::join($a, || maybe_rayon::join($b, $c));
        (a, b, c)
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr $(,)?) => {{
        let ((a, b), (c, d)) =
            maybe_rayon::join(|| maybe_rayon::join($a, $b), || maybe_rayon::join($c, $d));
        (a, b, c, d)
    }};
}

#[cfg(feature = "multicore")]
pub(crate) use maybe_rayon::current_num_threads;
pub(crate) use par_join;

/// One thread, as a build without `multicore` runs.
#[cfg(not(feature = "multicore"))]
pub(crate) fn current_num_threads() -> usize {
    1
}

/// Runs `foreground` on the calling thread while `background` runs on a
/// worker, and returns once both have finished. Unlike [`par_join!`], the
/// foreground need not be [`Send`], so it can hold the caller's random
/// number generator. Without the `multicore` feature the background runs
/// first.
#[cfg(feature = "multicore")]
pub(crate) fn overlap<T>(background: impl FnOnce() + Send, foreground: impl FnOnce() -> T) -> T {
    maybe_rayon::in_place_scope(|scope| {
        scope.spawn(|_| background());
        foreground()
    })
}

/// Runs `background` and then `foreground`, as a build with one thread does.
#[cfg(not(feature = "multicore"))]
pub(crate) fn overlap<T>(background: impl FnOnce() + Send, foreground: impl FnOnce() -> T) -> T {
    background();
    foreground()
}

/// Returns once `ready` holds, and until then does other work of the pool
/// on the calling thread, if there is any: a worker that only waited, on a
/// device say, would be a worker the pool does without. Without the
/// `multicore` feature this returns at once, and the caller waits in what
/// it does next.
#[cfg(feature = "multicore")]
pub(crate) fn wait_until(mut ready: impl FnMut() -> bool) {
    while !ready() {
        if !matches!(maybe_rayon::yield_now(), Some(maybe_rayon::Yield::Executed)) {
            core::hint::spin_loop();
        }
    }
}

/// Returns at once: a build with one thread has no other work to do.
#[cfg(not(feature = "multicore"))]
pub(crate) fn wait_until(_ready: impl FnMut() -> bool) {}

/// Where [`scope`] lets work be started that the caller does not wait for.
#[cfg(feature = "multicore")]
pub(crate) struct Background<'a, 'scope>(&'a maybe_rayon::Scope<'scope>);

/// Where [`scope`] lets work be started that the caller does not wait for.
#[cfg(not(feature = "multicore"))]
pub(crate) struct Background<'a, 'scope>(core::marker::PhantomData<&'a &'scope ()>);

impl<'scope> Background<'_, 'scope> {
    /// Starts `task` on a worker and returns at once. The [`scope`] this
    /// came from returns only once the task has finished.
    #[cfg(feature = "multicore")]
    pub(crate) fn spawn(&self, task: impl FnOnce() + Send + 'scope) {
        self.0.spawn(move |_| task());
    }

    /// Runs `task` before returning, as a build with one thread does.
    #[cfg(not(feature = "multicore"))]
    pub(crate) fn spawn(&self, task: impl FnOnce() + Send + 'scope) {
        task();
    }
}

/// How [`Batches`] handles a batch of items: either as work it begins and
/// waits for later, or, where the work cannot be begun that way, from
/// beginning to end on the thread that asks.
#[cfg_attr(not(feature = "multicore"), allow(dead_code))]
pub(crate) trait Handle<T, U>: Copy + Send {
    /// Work begun on a batch and not yet waited for.
    type Started: Send;

    /// Begins handling `items` and returns without waiting for the results,
    /// or returns `None` if handling them takes the calling thread.
    fn start(self, items: &[T]) -> Option<Self::Started>;

    /// Whether [`wait`](Self::wait) would return without waiting.
    fn ready(self, started: &mut Self::Started) -> bool;

    /// Waits for the work begun on `items` and returns their results, in
    /// their order.
    fn wait(self, started: Self::Started, items: &[T]) -> alloc::vec::Vec<U>;

    /// Handles `items` from beginning to end: their results, in their
    /// order.
    fn run(self, items: &[T]) -> alloc::vec::Vec<U>;
}

/// Items handed over one at a time, from any thread, and handled in batches
/// behind the threads that hand them over: one batch at a time, each made of
/// whatever arrived while the batch before it was computed.
///
/// This suits work that a device does faster in bulk, a few requests at a
/// time, on items that become ready one by one. The first item begins a
/// batch at once. No thread waits for a batch: each later
/// [`push`](Self::push) looks in on those begun, and begins another with
/// the items that arrived meanwhile once one is done, or once enough have
/// arrived to make one worth beginning beside it: a batch takes time to
/// begin, and the device is idle for that time unless it is computing
/// another. [`close`](Self::close) then hands what is left to a task that
/// does wait.
///
/// Which items share a batch depends on timing, so a [`Handle`] must give
/// each item the result it would have alone. Where the handle cannot begin
/// work without waiting, the items are all left to `close`. Without the
/// `multicore` feature nothing is handled until [`finish`](Self::finish),
/// which handles every item as one batch.
pub(crate) struct Batches<T, U, S> {
    #[cfg(feature = "multicore")]
    state: std::sync::Mutex<BatchState<T, U, S>>,
    #[cfg(not(feature = "multicore"))]
    _marker: core::marker::PhantomData<fn(T, S) -> U>,
}

#[cfg(feature = "multicore")]
struct BatchState<T, U, S> {
    /// The items no batch has taken yet, with their indices.
    waiting: alloc::vec::Vec<(usize, T)>,
    /// The batches that work was begun on and has not been waited for,
    /// oldest first: each one's indices, its items and the work.
    started: alloc::vec::Vec<(alloc::vec::Vec<usize>, alloc::vec::Vec<T>, S)>,
    /// Whether a thread is tending the batches: looking in on those begun,
    /// or beginning the next. Only that thread takes `started` or
    /// `waiting`.
    tended: bool,
    /// Whether work could not be begun without waiting. Nothing is begun
    /// from then on.
    blocking: bool,
    /// The results so far, with their items' indices.
    done: alloc::vec::Vec<(usize, U)>,
}

impl<T: Send, U: Send, S: Send> Batches<T, U, S> {
    /// No items yet.
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(feature = "multicore")]
            state: std::sync::Mutex::new(BatchState {
                waiting: alloc::vec::Vec::new(),
                started: alloc::vec::Vec::new(),
                tended: false,
                blocking: false,
                done: alloc::vec::Vec::new(),
            }),
            #[cfg(not(feature = "multicore"))]
            _marker: core::marker::PhantomData,
        }
    }

    #[cfg(feature = "multicore")]
    fn state(&self) -> std::sync::MutexGuard<'_, BatchState<T, U, S>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hands over `item`, the `index`-th of those [`finish`](Self::finish)
    /// is later given, and moves the batches on as far as that takes no
    /// waiting: if the batch begun is done, or none was, the items waiting
    /// begin the next.
    #[cfg(feature = "multicore")]
    pub(crate) fn push<H: Handle<T, U, Started = S>>(&self, index: usize, item: T, handle: H) {
        let mut state = self.state();
        state.waiting.push((index, item));
        if state.tended || state.blocking {
            return;
        }
        state.tended = true;
        drop(state);
        self.tend(handle, false);
    }

    /// Leaves `item` to [`finish`](Self::finish), as a build with one
    /// thread does.
    #[cfg(not(feature = "multicore"))]
    pub(crate) fn push<H: Handle<T, U, Started = S>>(&self, _index: usize, _item: T, _handle: H) {}

    /// Moves the batches on as [`push`](Self::push) does, with no item to
    /// hand over. A thread that will be some time before its next item
    /// calls this, so that a batch that is done does not hold up the next.
    #[cfg(feature = "multicore")]
    pub(crate) fn look_in<H: Handle<T, U, Started = S>>(&self, handle: H) {
        let mut state = self.state();
        if state.tended || state.blocking || (state.started.is_empty() && state.waiting.is_empty())
        {
            return;
        }
        state.tended = true;
        drop(state);
        self.tend(handle, false);
    }

    /// Nothing, as a build with one thread does.
    #[cfg(not(feature = "multicore"))]
    pub(crate) fn look_in<H: Handle<T, U, Started = S>>(&self, _handle: H) {}

    /// Moves the batches on, as the one thread that set `tended`, and
    /// clears it. A `patient` thread begins one batch of every item
    /// waiting, if that takes no waiting, waits for the batches begun, and
    /// handles the items that could not be begun; another only collects the
    /// batches that are done and begins what there is room and reason to
    /// begin.
    #[cfg(feature = "multicore")]
    fn tend<H: Handle<T, U, Started = S>>(&self, handle: H, patient: bool) {
        /// The batches begun and not waited for at one time: one being
        /// computed and two behind it, begun while it was. A device takes
        /// only so many requests begun this way, and the last of its places
        /// is left to whoever else has one to begin.
        const BEGUN: usize = 3;
        /// The fewest items worth beginning a batch for beside another: a
        /// batch of fewer costs the device more for each than a batch does.
        const WORTH: usize = 4;
        /// The most items in a batch begun without waiting, which bounds
        /// the time the thread that begins it is away from its own work.
        const MOST: usize = 8;

        let mut state = self.state();
        loop {
            // A patient thread has no later item to gather a batch from:
            // what is left is begun now, for the device to have while the
            // batches before it are waited for.
            if patient && !state.blocking && !state.waiting.is_empty() {
                let (indices, items): (alloc::vec::Vec<usize>, alloc::vec::Vec<T>) =
                    core::mem::take(&mut state.waiting).into_iter().unzip();
                drop(state);
                let started = handle.start(&items);
                state = self.state();
                match started {
                    Some(started) => state.started.push((indices, items, started)),
                    None => {
                        state.blocking = true;
                        let later = core::mem::replace(
                            &mut state.waiting,
                            indices.into_iter().zip(items).collect(),
                        );
                        state.waiting.extend(later);
                    }
                }
            }
            // The batches that are done, oldest first; the rest stay begun.
            let begun = core::mem::take(&mut state.started);
            drop(state);
            let mut still = alloc::vec::Vec::with_capacity(begun.len());
            let mut finished = alloc::vec::Vec::new();
            for (indices, items, mut started) in begun {
                if !patient && !handle.ready(&mut started) {
                    still.push((indices, items, started));
                    continue;
                }
                let results = handle.wait(started, &items);
                debug_assert_eq!(results.len(), items.len(), "one result per item");
                finished.extend(indices.into_iter().zip(results));
            }
            state = self.state();
            state.done.extend(finished);
            state.started = still;

            if state.waiting.is_empty() {
                break;
            }
            if patient {
                let (indices, items): (alloc::vec::Vec<usize>, alloc::vec::Vec<T>) =
                    core::mem::take(&mut state.waiting).into_iter().unzip();
                drop(state);
                let results = handle.run(&items);
                debug_assert_eq!(results.len(), items.len(), "one result per item");
                drop(items);
                state = self.state();
                state.done.extend(indices.into_iter().zip(results));
                continue;
            }
            let room = state.started.len() < BEGUN;
            let reason = state.started.is_empty() || state.waiting.len() >= WORTH;
            if state.blocking || !room || !reason {
                break;
            }
            let take = state.waiting.len().min(MOST);
            let (indices, items): (alloc::vec::Vec<usize>, alloc::vec::Vec<T>) =
                state.waiting.drain(..take).unzip();
            drop(state);
            match handle.start(&items) {
                // Begun; there may be room and reason for another.
                Some(started) => {
                    state = self.state();
                    state.started.push((indices, items, started));
                }
                // The items go back ahead of those that arrived meanwhile.
                None => {
                    state = self.state();
                    state.blocking = true;
                    let later = core::mem::replace(
                        &mut state.waiting,
                        indices.into_iter().zip(items).collect(),
                    );
                    state.waiting.extend(later);
                    break;
                }
            }
        }
        state.tended = false;
    }

    /// Handles what is left on `background`: waits there for the batch
    /// begun, and handles the items no batch took. To be called once every
    /// [`push`](Self::push) has returned.
    #[cfg(feature = "multicore")]
    pub(crate) fn close<'scope, H>(&'scope self, background: &Background<'_, 'scope>, handle: H)
    where
        H: Handle<T, U, Started = S> + 'scope,
        T: 'scope,
        U: 'scope,
        S: 'scope,
    {
        let mut state = self.state();
        if state.tended || (state.waiting.is_empty() && state.started.is_empty()) {
            return;
        }
        state.tended = true;
        drop(state);
        background.spawn(move || self.tend(handle, true));
    }

    /// Leaves the items to [`finish`](Self::finish), as a build with one
    /// thread does.
    #[cfg(not(feature = "multicore"))]
    pub(crate) fn close<'scope, H>(&'scope self, _background: &Background<'_, 'scope>, _handle: H)
    where
        H: Handle<T, U, Started = S> + 'scope,
        T: 'scope,
        U: 'scope,
        S: 'scope,
    {
    }

    /// The results of `items`, in their order: `items[index]` is the item
    /// handed over with `index`. To be called once the scope
    /// [`close`](Self::close) was given has ended. If the batches did not
    /// handle exactly these items, `handle` handles all of them here.
    pub(crate) fn finish(
        self,
        items: &[T],
        handle: impl FnOnce(&[T]) -> alloc::vec::Vec<U>,
    ) -> alloc::vec::Vec<U> {
        #[cfg(feature = "multicore")]
        {
            let state = self
                .state
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut done = state.done;
            done.sort_unstable_by_key(|(index, _)| *index);
            if state.waiting.is_empty()
                && state.started.is_empty()
                && done.iter().map(|(index, _)| *index).eq(0..items.len())
            {
                return done.into_iter().map(|(_, result)| result).collect();
            }
        }
        handle(items)
    }
}

/// Runs `work` on the calling thread, handing it a place to start tasks that
/// run behind the rest of `work`, and returns once `work` and every task it
/// started have finished. Like [`overlap`]'s foreground, `work` need not be
/// [`Send`], and a task may be started from any thread.
#[cfg(feature = "multicore")]
pub(crate) fn scope<'scope, T>(work: impl FnOnce(&Background<'_, 'scope>) -> T) -> T {
    maybe_rayon::in_place_scope(|scope| work(&Background(scope)))
}

/// Runs `work`, each task it starts running where it is started.
#[cfg(not(feature = "multicore"))]
pub(crate) fn scope<'scope, T>(work: impl FnOnce(&Background<'_, 'scope>) -> T) -> T {
    work(&Background(core::marker::PhantomData))
}

/// Applies `f` to disjoint chunks of `v`, in parallel when the `multicore`
/// feature is enabled. Each call receives one chunk and the index in `v` at
/// which that chunk starts.
///
/// This is the data-parallel counterpart of [`par_join!`]: one operation
/// over a slice, split into as many chunks as there are threads.
pub(crate) fn parallelize<T: Send, F: Fn(&mut [T], usize) + Send + Sync + Clone>(
    v: &mut [T],
    f: F,
) {
    let n = v.len();
    if n == 0 {
        return;
    }
    let num_threads = current_num_threads();
    let mut chunk = n / num_threads;
    if chunk < num_threads {
        chunk = n;
    }

    maybe_rayon::scope(|scope| {
        for (chunk_num, v) in v.chunks_mut(chunk).enumerate() {
            let f = f.clone();
            scope.spawn(move |_| {
                let start = chunk_num * chunk;
                f(v, start);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    /// Doubles each item, counting the items it has handled; begins work
    /// without waiting only if `starts`, and that work is ready from the
    /// second time it is asked.
    #[derive(Clone, Copy)]
    struct Double<'a> {
        handled: &'a core::sync::atomic::AtomicUsize,
        starts: bool,
    }

    impl super::Handle<u64, u64> for Double<'_> {
        type Started = (alloc::vec::Vec<u64>, bool);

        fn start(self, items: &[u64]) -> Option<Self::Started> {
            self.starts
                .then(|| (super::Handle::run(self, items), false))
        }

        fn ready(self, started: &mut Self::Started) -> bool {
            core::mem::replace(&mut started.1, true)
        }

        fn wait(self, started: Self::Started, _items: &[u64]) -> alloc::vec::Vec<u64> {
            started.0
        }

        fn run(self, items: &[u64]) -> alloc::vec::Vec<u64> {
            self.handled
                .fetch_add(items.len(), core::sync::atomic::Ordering::Relaxed);
            items.iter().map(|item| 2 * item).collect()
        }
    }

    #[test]
    fn batches_give_each_item_its_result() {
        use alloc::vec::Vec;
        use core::sync::atomic::{AtomicUsize, Ordering};

        use super::Handle as _;

        let items: Vec<u64> = (0..100).map(|i| 3 * i + 1).collect();
        let doubled: Vec<u64> = items.iter().map(|item| 2 * item).collect();
        for starts in [true, false] {
            // Every item handed over inside the scope, from two tasks.
            let handled = AtomicUsize::new(0);
            let double = Double {
                handled: &handled,
                starts,
            };
            let batches = super::Batches::<u64, u64, (Vec<u64>, bool)>::new();
            super::scope(|background| {
                super::par_join!(
                    || (0..50).for_each(|index| batches.push(index, items[index], double)),
                    || (50..100).for_each(|index| batches.push(index, items[index], double)),
                );
                batches.close(background, double);
            });
            assert_eq!(batches.finish(&items, |items| double.run(items)), doubled);
            // Each item was handled once, behind the scope or at the end.
            assert_eq!(handled.load(Ordering::Relaxed), 100);
        }

        // Items the batches did not all see are handled at the end, all of
        // them.
        let handled = AtomicUsize::new(0);
        let double = Double {
            handled: &handled,
            starts: true,
        };
        let batches = super::Batches::<u64, u64, (Vec<u64>, bool)>::new();
        super::scope(|background| {
            batches.push(1, items[1], double);
            batches.close(background, double);
        });
        assert_eq!(
            batches.finish(&items[..3], |items| double.run(items)),
            doubled[..3]
        );
    }

    #[test]
    fn flattens_to_tuple() {
        let (a, b) = par_join!(|| 1u32, || "two");
        assert_eq!((a, b), (1, "two"));

        let (a, b, c) = par_join!(|| 1u32, || "two", || 3.0_f64);
        assert_eq!((a, b, c), (1, "two", 3.0));

        let (a, b, c, d) = par_join!(|| 1u32, || "two", || 3.0_f64, || 4i64);
        assert_eq!((a, b, c, d), (1, "two", 3.0, 4));
    }
}
