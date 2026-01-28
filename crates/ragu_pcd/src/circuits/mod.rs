//! Internal circuits for recursive proof verification.
//!
//! Contains native and nested curve circuits that implement the recursive
//! verification logic, including proof components and internal circuit registration.

pub(crate) mod native;
pub(crate) mod nested;

pub(crate) use crate::components::fold_revdot::NativeParameters;

#[cfg(test)]
pub(crate) mod tests;
