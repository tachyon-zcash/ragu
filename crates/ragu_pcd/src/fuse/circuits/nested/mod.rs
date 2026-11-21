//! The nested recursive verification circuits, over the scalar field, and
//! their registration.
//!
//! Contains these circuits:
//!
//! - **Endoscaling**: verifies that the commitment accumulation
//!   in `compute_p` was computed correctly via Horner's rule.
//! - **Loading**: enforces consistency between [`PointsStage`]
//!   inputs and the bridge stage commitments for the current step.
//! - **Collapse**: pins the nested [`unified`](crate::protocol::nested::unified)
//!   instance to its stages and verifies both layers of the children's nested
//!   fold.
//! - **Compute v**: recomputes the nested batch evaluation $v_n$, the mirror
//!   of the native `compute_v`.
//!
//! The collapse and compute-v circuits share the
//! [`unified`](crate::protocol::nested::unified) instance as their public
//! input, each constraining the slots it owns.
//!
//! [`PointsStage`]: crate::protocol::gadgets::endoscalar::PointsStage

pub(crate) mod collapse;
pub(crate) mod common;
pub(crate) mod compute_v;
pub(crate) mod loading;
pub(crate) mod register;
