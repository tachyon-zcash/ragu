//! Setup-fixed declarations for a profile's online polynomial openings.
//!
//! Polynomial order determines the commitment fold; opening order determines
//! the quotient fold. Repeated openings refer to the same polynomial index and
//! never add another commitment or evaluation at the batch point.

use ragu_core::{Error, Result};

pub mod batch;
pub mod circuit;
pub(crate) mod extension;
pub mod mesh;
pub(crate) mod mesh_preparation;
pub(crate) mod mesh_terminal;
pub mod prepared;
pub(crate) mod prover;
pub mod source;
pub mod stages;

#[cfg(test)]
mod tests;

/// The last transcript boundary before a polynomial must be committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Online polynomials, fixed before the step's first challenge.
    BeforeW,
    /// Auxiliary polynomials prepared from `w`, before `y`.
    BeforeY,
    /// Auxiliary polynomials prepared from `w` and `y`, before `x`.
    BeforeX,
    /// Auxiliary polynomials prepared from `w`, `y` and `x`, before `alpha`.
    BeforeAlpha,
}

impl Phase {
    /// The commitment deadlines in polynomial order.
    pub const ALL: [Self; 4] = [
        Self::BeforeW,
        Self::BeforeY,
        Self::BeforeX,
        Self::BeforeAlpha,
    ];
}

/// An enclosing-step challenge that can be an opening point.
///
/// On the nested side these mean the prescribed nested lifts. The batch point
/// `u` is deliberately absent: queries must be committed before `alpha`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// The challenge testing the online polynomials.
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

/// The online and auxiliary batch on one field, fixed for a profile type.
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
    /// No online polynomials.
    pub const EMPTY: Self = Self {
        polynomials: &[],
        openings: &[],
        inputs: 0,
        points: 0,
        values: 0,
    };

    /// The distinct-polynomial indices committed at one deadline.
    ///
    /// Layout validation requires the polynomial list to follow phase order.
    pub fn phase_range(&self, phase: Phase) -> core::ops::Range<usize> {
        let start = self.polynomials.partition_point(|&p| p < phase);
        let end = self.polynomials.partition_point(|&p| p <= phase);
        start..end
    }

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
                "the profile's online opening layout is not well formed".into(),
            ))
        }
    }
}

/// The default bodies of the per-side preparation hooks on
/// [`Profile`](crate::profile::Profile), shared by the native and nested hooks
/// so that the two sides cannot drift apart.
pub(crate) mod defaults {
    use alloc::vec::Vec;

    use ragu_core::{Error, Result};
    use udon::field::Field;

    use super::{Phase, stages::Side};
    use crate::profile::Profile;

    fn side<S: Side>(native: &'static str, nested: &'static str) -> Error {
        Error::Initialization(if S::NATIVE { native } else { nested }.into())
    }

    /// Supplies only inherited mesh coordinates, which the protocol fills in.
    pub(crate) fn inputs<P: Profile, S: Side, F: Field>() -> Result<Vec<F>> {
        let layout = S::layout::<P>();
        let inherited_only = S::mesh::<P>().is_some_and(|mesh| {
            (0..layout.inputs).all(|i| mesh.inherited_coordinates().contains(&i))
        });
        if layout.inputs == 0 || inherited_only {
            Ok(alloc::vec![F::ZERO; layout.inputs])
        } else {
            Err(side::<S>(
                "the profile has no native online input prover",
                "the profile has no nested online input prover",
            ))
        }
    }

    /// Supplies nothing, which suffices when the mesh owns every slot of
    /// the phase.
    pub(crate) fn polynomials<P: Profile, S: Side, T>(phase: Phase) -> Result<Vec<T>> {
        let mesh = S::mesh::<P>();
        if S::layout::<P>()
            .phase_range(phase)
            .any(|i| !mesh.is_some_and(|mesh| mesh.owns(i)))
        {
            Err(side::<S>(
                "the profile has no native online polynomial prover",
                "the profile has no nested online polynomial prover",
            ))
        } else {
            Ok(Vec::new())
        }
    }

    /// Supplies no witness points, which suffices when none are declared.
    pub(crate) fn points<P: Profile, S: Side, F>() -> Result<Vec<F>> {
        if S::layout::<P>().points == 0 {
            Ok(Vec::new())
        } else {
            Err(side::<S>(
                "the profile has no native online query prover",
                "the profile has no nested online query prover",
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
