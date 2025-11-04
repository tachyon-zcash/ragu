//! B staging polynomial.

use crate::{ephemeral_stage, indirection_stage};
use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::Stage};
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
// B STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral inner stages used to create nested commitments.
ephemeral_stage!(EphemeralStageB);

// Indirection stage (the "outer layer problem")
indirection_stage!(IndirectionStageB);
