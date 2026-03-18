pub use maybe_rayon::{iter::IntoParallelIterator, join};

#[cfg(feature = "multicore")]
pub use maybe_rayon::{current_num_threads, iter::ParallelIterator};

#[cfg(not(feature = "multicore"))]
pub fn current_num_threads() -> usize {
    1
}
