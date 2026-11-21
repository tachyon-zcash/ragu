//! The definitions the fuse's prover, its circuits and the compression share:
//! the canonical sizes and orders of each side, the stages a proof commits
//! to, the revdot claims and their folding, the gadgets the stages and
//! circuits are built from, and the transcript. These modules do not depend
//! on the fuse or the compression.

pub(crate) mod const_fns;
pub(crate) mod gadgets;
pub(crate) mod ky;
pub(crate) mod native;
pub(crate) mod nested;
pub(crate) mod revdot;
pub(crate) mod transcript;

/// Identifies which child supplies a component.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}
