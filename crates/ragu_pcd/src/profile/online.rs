//! Setup-fixed declarations for a profile's private polynomial openings.
//!
//! Polynomial order determines the commitment fold; opening order determines
//! the quotient fold. Repeated openings refer to the same polynomial index and
//! never add another commitment or evaluation at the batch point.

use ragu_core::{Error, Result};

pub mod batch;
pub mod circuit;
pub(crate) mod extension;
pub mod prepared;
pub(crate) mod prover;
pub mod stages;

#[cfg(test)]
mod tests;

/// The last transcript boundary before a polynomial must be committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Private online polynomials, fixed before the step's first challenge.
    BeforeW,
    /// Auxiliary polynomials prepared from `w`, before `y`.
    BeforeY,
    /// Auxiliary polynomials prepared from `w` and `y`, before `x`.
    BeforeX,
    /// Auxiliary polynomials prepared from `w`, `y` and `x`, before `alpha`.
    BeforeAlpha,
}

/// An enclosing-step challenge that can be an opening point.
///
/// On the nested side these mean the prescribed nested lifts. The batch point
/// `u` is deliberately absent: queries must be committed before `alpha`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// The challenge testing the private polynomials.
    W,
    /// The second registry coordinate challenge.
    Y,
    /// The first registry coordinate challenge.
    X,
}

/// The source of an opening point, fixed by setup rather than by the prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// An authenticated challenge of the enclosing step.
    Challenge(Challenge),
    /// A small integer embedded in the polynomial's field.
    Constant(u64),
    /// The registry domain point for this circuit index.
    Circuit(u32),
    /// A value from the input stage committed before `w`.
    Input(usize),
    /// A wire of `OnlineQuery`, constrained by the consuming circuit.
    ///
    /// This supports arbitrary field elements. The consumer must bind any
    /// relation to earlier input stages explicitly; the opening proves only
    /// evaluation at the point in this wire.
    Witness(usize),
}

/// One opening in quotient-fold order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Index in [`Layout::polynomials`].
    pub polynomial: usize,
    /// Source of the point at which the polynomial is opened.
    pub point: Point,
    /// Index of the claimed value in `OnlineQuery`.
    ///
    /// Several openings can share this index to enforce an intersection
    /// equality without witnessing independent copies of its value.
    pub value: usize,
}

/// The private and auxiliary batch on one field, fixed for a profile type.
///
/// The empty layout adds no stages or circuits. Nonempty layouts have one
/// evaluation at `u` per polynomial, independent of the number of openings.
/// No entry creates an application or header slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Commitment deadlines, in commitment-fold order and phase order.
    pub polynomials: &'static [Phase],
    /// Opening claims, in quotient-fold order.
    pub openings: &'static [Opening],
    /// Number of input values committed before `w` and shared by consumers.
    pub inputs: usize,
    /// Number of separately witnessed point wires in `OnlineQuery`.
    pub points: usize,
    /// Number of claimed value wires in `OnlineQuery`.
    pub values: usize,
}

impl Layout {
    /// No private or auxiliary batch.
    pub const EMPTY: Self = Self {
        polynomials: &[],
        openings: &[],
        inputs: 0,
        points: 0,
        values: 0,
    };

    /// Whether this declaration adds nothing.
    pub const fn is_empty(&self) -> bool {
        self.polynomials.is_empty()
            && self.openings.is_empty()
            && self.inputs == 0
            && self.points == 0
            && self.values == 0
    }

    /// Checks indices, phase order and coverage of all declared entries.
    ///
    /// # Errors
    ///
    /// Rejects out-of-range indices, unused polynomial/point/value slots and
    /// decreasing commitment phases. Repeated polynomial and value indices
    /// are allowed: they are how multi-point openings and mesh edges work.
    pub fn check(&self) -> Result<()> {
        let valid = self.polynomials.windows(2).all(|p| p[0] <= p[1])
            && self.openings.iter().all(|opening| {
                opening.polynomial < self.polynomials.len()
                    && opening.value < self.values
                    && match opening.point {
                        Point::Input(input) => input < self.inputs,
                        Point::Witness(point) => point < self.points,
                        _ => true,
                    }
            })
            && (0..self.polynomials.len()).all(|i| self.openings.iter().any(|o| o.polynomial == i))
            && (0..self.points).all(|i| self.openings.iter().any(|o| o.point == Point::Witness(i)))
            && (0..self.values).all(|i| self.openings.iter().any(|o| o.value == i));
        if valid {
            Ok(())
        } else {
            Err(Error::Initialization(
                "the profile's private opening layout is not well formed".into(),
            ))
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    const LAYOUT: Layout = Layout {
        polynomials: &[Phase::BeforeW, Phase::BeforeY],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 0,
                point: Point::Circuit(3),
                value: 1,
            },
            Opening {
                polynomial: 1,
                point: Point::Witness(0),
                value: 0,
            },
        ],
        inputs: 0,
        points: 1,
        values: 2,
    };

    #[test]
    fn repeated_polynomials_and_shared_values_are_valid() -> Result<()> {
        Layout::EMPTY.check()?;
        LAYOUT.check()
    }

    #[test]
    fn malformed_layouts_reject() {
        for layout in [
            Layout {
                points: 0,
                ..LAYOUT
            },
            Layout {
                points: 2,
                ..LAYOUT
            },
            Layout {
                values: 1,
                ..LAYOUT
            },
            Layout {
                values: 3,
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW, Phase::BeforeY, Phase::BeforeX],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeY, Phase::BeforeW],
                ..LAYOUT
            },
            Layout {
                polynomials: &[Phase::BeforeW],
                ..Layout::EMPTY
            },
        ] {
            assert!(layout.check().is_err(), "accepted {layout:?}");
        }
    }
}
