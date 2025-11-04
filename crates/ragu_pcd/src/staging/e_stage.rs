//! E staging polynomial.

use crate::{ephemeral_stage, indirection_stage};
use arithmetic::CurveAffine;
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

///////////////////////////////////////////////////////////////////////////////////////
// E STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral Stage: used to creating nested commitments.
ephemeral_stage!(EphemeralStageE);

// Indirection Stage: for resolving the "outer layer problem".
indirection_stage!(IndirectionStageE);
