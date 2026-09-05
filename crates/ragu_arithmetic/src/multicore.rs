//! Parallel-execution utilities backed by [`maybe_rayon`].

#[cfg(feature = "multicore")]
pub use maybe_rayon::{current_num_threads, iter::ParallelIterator};
pub use maybe_rayon::{iter::IntoParallelIterator, join};

/// Returns 1 when the `multicore` feature is disabled.
#[cfg(not(feature = "multicore"))]
pub fn current_num_threads() -> usize {
    1
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
