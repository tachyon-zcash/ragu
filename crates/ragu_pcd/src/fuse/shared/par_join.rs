//! The fork-join the query and eval phases run their independent work under.

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

pub(crate) use par_join;

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
