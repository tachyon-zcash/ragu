#[cfg(feature = "multicore")]
pub use ragu_rayon::{current_num_threads, iter::ParallelIterator};
pub use ragu_rayon::{iter::IntoParallelIterator, join};

#[cfg(not(feature = "multicore"))]
pub fn current_num_threads() -> usize {
    1
}
