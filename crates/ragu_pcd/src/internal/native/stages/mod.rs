//! Native field stages for fuse operations.

pub mod eval;
pub mod inner_error;
pub mod outer_error;
pub mod preamble;
pub mod query;

#[cfg(test)]
pub mod tests {
    pub use crate::internal::native::RevdotParameters;
    pub use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};
}
