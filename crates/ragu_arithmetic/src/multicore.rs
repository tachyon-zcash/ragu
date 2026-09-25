//! Parallel-execution utilities backed by [`maybe_rayon`].

#[cfg(feature = "multicore")]
pub use maybe_rayon::{current_num_threads, iter::ParallelIterator};
pub use maybe_rayon::{iter::IntoParallelIterator, join, scope};

/// Returns 1 when the `multicore` feature is disabled.
#[cfg(not(feature = "multicore"))]
pub fn current_num_threads() -> usize {
    1
}

/// Applies `f` to disjoint chunks of `v`, in parallel when the `multicore`
/// feature is enabled. Each call receives one chunk and the index in `v` at
/// which that chunk starts.
///
/// This is the data-parallel counterpart of [`par_join!`](crate::par_join): one operation
/// over a slice, split into as many chunks as there are threads.
pub fn parallelize<T: Send, F: Fn(&mut [T], usize) + Send + Sync + Clone>(v: &mut [T], f: F) {
    let n = v.len();
    if n == 0 {
        return;
    }
    let num_threads = current_num_threads();
    let mut chunk = n / num_threads;
    if chunk < num_threads {
        chunk = n;
    }

    scope(|scope| {
        for (chunk_num, v) in v.chunks_mut(chunk).enumerate() {
            let f = f.clone();
            scope.spawn(move |_| {
                let start = chunk_num * chunk;
                f(v, start);
            });
        }
    });
}

/// N-way parallel join for coarse-grained task parallelism.
///
/// Like [`join`] for more than two closures: nests internally and flattens
/// the result into a single tuple. Each closure may return a different type.
/// Supports 2..=4 closures — for higher arities prefer a data-parallel
/// iterator.
#[macro_export]
macro_rules! par_join {
    ($a:expr, $b:expr $(,)?) => {
        $crate::join($a, $b)
    };
    ($a:expr, $b:expr, $c:expr $(,)?) => {{
        let (a, (b, c)) = $crate::join($a, || $crate::join($b, $c));
        (a, b, c)
    }};
    ($a:expr, $b:expr, $c:expr, $d:expr $(,)?) => {{
        let ((a, b), (c, d)) = $crate::join(|| $crate::join($a, $b), || $crate::join($c, $d));
        (a, b, c, d)
    }};
}

#[cfg(test)]
mod tests {
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
