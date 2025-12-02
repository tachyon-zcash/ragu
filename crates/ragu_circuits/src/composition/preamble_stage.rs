//! Preamble staging polynomial.

use crate::Rank;
use crate::staging::Stage;
use crate::{ephemeral_stage, indirection_stage};
use alloc::vec::Vec;
use arithmetic::CurveAffine;
use ragu_core::Result;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

///////////////////////////////////////////////////////////////////////////////////////
// PREAMBLE STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStagePreamble);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStagePreamble);
