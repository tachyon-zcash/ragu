//! Shared protocol representations, canonical orders, and arithmetic.

pub(crate) mod claims;
pub(crate) mod compress;
pub(crate) mod const_fns;
pub(crate) mod fold_revdot;
pub(crate) mod ipa;
pub(crate) mod ky;
pub(crate) mod native;
pub(crate) mod nested;
pub(crate) mod transcript;

/// Identifies which child supplies a component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}
