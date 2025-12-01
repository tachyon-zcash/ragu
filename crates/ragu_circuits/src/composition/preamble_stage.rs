//! Preamble staging polynomial.
//!
//! The preamble stage is over `C::CircuitField` (Fp) and contains the raw k(Y)
//! polynomial coefficients `(output_header, left_header, right_header)` for each
//! proof being checked. This binds the prover to the public inputs before
//! challenges are derived.
//!
//! The preamble stage commitment (a `C::HostCurve` point) is then included in
//! the nested preamble stage along with the A polynomial commitments.

use crate::staging::Stage;
use crate::{Rank, nested_stage, stage};
use alloc::vec::Vec;
use arithmetic::CurveAffine;
use ragu_core::Result;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};

///////////////////////////////////////////////////////////////////////////////////////
// PREAMBLE STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Native stage (over C::CircuitField) with raw k(Y) polynomial coefficients.
stage!(field PreambleStage);

// Nested stage (over C::ScalarField) containing the preamble commitment + A commitments.
nested_stage!(NestedPreambleStage);
