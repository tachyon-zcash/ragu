//! The native recursive verification circuits, and their registration.
//!
//! Besides the circuits that verify the native fold and batch, the native
//! side walks the nested batch's commitments: the endoscaling steps of
//! [`endoscaling_step`] fold the [`NUM_ENDOSCALING_POINTS`] nested-curve
//! points of [`stages::points`] into $P_n$ by Horner's rule under $\beta$'s
//! endoscalar, which [`bind_endoscalar`] ties to `pre_beta`. The points are
//! committed in stages the transcript absorbs before the challenges the
//! nested openings are at (see [`stages::points`]). This mirrors the nested
//! side's walk over the native batch.
//!
//! [`bind_endoscalar`] emits the bit and curve contracts the steps share, and
//! pins the walk's endpoint and this step's persistent points to the unified
//! instance. [`bind_beta`] holds the children's walked points against the
//! children's unified instances.
//!
//! [`NUM_ENDOSCALING_POINTS`]: crate::protocol::native::NUM_ENDOSCALING_POINTS
//! [`stages::points`]: crate::protocol::native::stages::points

pub(crate) mod bind_beta;
pub(crate) mod bind_challenges;
pub(crate) mod bind_endoscalar;
pub(crate) mod collapse;
pub(crate) mod compute_v;
pub(crate) mod endoscaling_step;
pub(crate) mod hashes_1;
pub(crate) mod hashes_2;
pub(crate) mod register;
