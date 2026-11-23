//! The fork-join the query and eval phases run their independent work under.

/// N-way join for coarse-grained task parallelism, through the backend
/// named first.
///
/// Like [`Backend::join`](ragu_backend::Backend::join) for more than two
/// closures: nests internally and flattens the result into a single tuple, so
/// the jobs run concurrently exactly when the backend runs joined jobs
/// concurrently. Each closure may return a different type. Supports 2..=4
/// closures — for higher arities prefer a data-parallel iterator.
macro_rules! par_join {
    ($backend:ty; $a:expr, $b:expr $(,)?) => {
        <$backend as ragu_backend::Backend>::join($a, $b)
    };
    ($backend:ty; $a:expr, $b:expr, $c:expr $(,)?) => {{
        let (a, (b, c)) = <$backend as ragu_backend::Backend>::join($a, || {
            <$backend as ragu_backend::Backend>::join($b, $c)
        });
        (a, b, c)
    }};
    ($backend:ty; $a:expr, $b:expr, $c:expr, $d:expr $(,)?) => {{
        let ((a, b), (c, d)) = <$backend as ragu_backend::Backend>::join(
            || <$backend as ragu_backend::Backend>::join($a, $b),
            || <$backend as ragu_backend::Backend>::join($c, $d),
        );
        (a, b, c, d)
    }};
}

pub(crate) use par_join;

#[cfg(test)]
mod tests {
    #[test]
    fn flattens_to_tuple() {
        let (a, b) = par_join!(ragu_backend::ReferenceBackend; || 1u32, || "two");
        assert_eq!((a, b), (1, "two"));

        let (a, b, c) = par_join!(ragu_backend::ReferenceBackend; || 1u32, || "two", || 3.0_f64);
        assert_eq!((a, b, c), (1, "two", 3.0));

        let (a, b, c, d) =
            par_join!(ragu_backend::ReferenceBackend; || 1u32, || "two", || 3.0_f64, || 4i64);
        assert_eq!((a, b, c, d), (1, "two", 3.0, 4));
    }
}
