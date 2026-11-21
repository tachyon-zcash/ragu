//! The recursive verifier: the fuse's internal circuits over both fields of
//! the cycle, and their registration. These hold the constraints; the stages
//! they read are defined in [`crate::protocol`].

pub(crate) mod native;
pub(crate) mod nested;
