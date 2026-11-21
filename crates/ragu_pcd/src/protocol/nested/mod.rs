//! The nested side's shared definitions: its layout, claim order, unified
//! instance, online slots, batched evaluation and stages.

pub(crate) mod claims;
pub(crate) mod layout;
pub(crate) mod online;
pub(crate) mod pcs;
pub(crate) mod stages;
pub(crate) mod unified;
pub use layout::*;
