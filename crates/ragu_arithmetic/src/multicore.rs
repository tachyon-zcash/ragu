pub use maybe_rayon::iter::IntoParallelIterator;

#[cfg(feature = "multicore")]
pub use maybe_rayon::iter::ParallelIterator;
