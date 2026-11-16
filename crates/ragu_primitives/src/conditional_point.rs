//! Point encoding selected by a type-level identity policy.

use core::marker::PhantomData;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
};
use udon::curve::EndomorphismAffine as Affine;

use crate::{CompletePoint, GadgetExt, Nonzero, Point, consistent::Consistent, io::Write};

/// A type-level choice of finite or complete affine encoding.
pub trait PointEncoding: Copy + Send + Sync + 'static {
    /// Whether `(0, 0)` represents the identity. The finite encoding preserves
    /// exactly the allocation and consistency constraints of [`Point`].
    const ALLOW_IDENTITY: bool;
}

/// A point with a type-level choice of whether to admit the identity.
///
/// Both encodings occupy two wires. The finite policy uses [`Point`]'s
/// constraints and arithmetic boundary unchanged; the complete policy uses
/// [`CompletePoint`] and requires a checked conversion to finite arithmetic.
#[derive(Gadget, Write)]
pub struct ConditionalPoint<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, E: PointEncoding> {
    #[ragu(gadget)]
    point: CompletePoint<'dr, D, C>,
    #[ragu(phantom)]
    marker: PhantomData<E>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, E: PointEncoding> ConditionalPoint<'dr, D, C, E> {
    /// Allocates a point under the fixed encoding's curve-membership contract.
    pub fn alloc(dr: &mut D, value: DriverValue<D, C>) -> Result<Self> {
        let point = if !E::ALLOW_IDENTITY {
            CompletePoint::from_affine(Point::alloc(dr, value)?)
        } else {
            CompletePoint::alloc(dr, value)?
        };
        Ok(Self {
            point,
            marker: PhantomData,
        })
    }

    /// Converts an already constrained finite point without adding gates.
    pub fn from_affine(point: Point<'dr, D, C>) -> Self {
        Self {
            point: CompletePoint::from_affine(point),
            marker: PhantomData,
        }
    }

    /// Views the coordinates in the complete encoding without adding gates.
    pub fn complete(&self) -> &CompletePoint<'dr, D, C> {
        &self.point
    }

    /// Returns the finite representation without adding gates.
    ///
    /// # Panics
    ///
    /// Panics if the encoding permits the identity; use [`Self::endpoint`]
    /// for a checked conversion from that encoding.
    pub fn finite(&self) -> Point<'dr, D, C> {
        assert!(!E::ALLOW_IDENTITY);
        self.finite_unchecked()
    }

    /// Converts the final aggregate to the existing protocol's finite encoding.
    pub fn endpoint(&self, dr: &mut D) -> Result<Point<'dr, D, C>> {
        if !E::ALLOW_IDENTITY {
            Ok(self.finite_unchecked())
        } else {
            self.point.to_affine(dr)
        }
    }

    fn finite_unchecked(&self) -> Point<'dr, D, C> {
        let (x, y) = self.point.coordinates();
        Point::new_unchecked(
            Nonzero::new_unchecked(x.clone()),
            Nonzero::new_unchecked(y.clone()),
        )
    }

    /// Binds the last interstitial to the protocol's finite aggregate endpoint.
    pub fn enforce_equal_affine(&self, dr: &mut D, other: &Point<'dr, D, C>) -> Result<()> {
        self.point
            .enforce_equal(dr, &CompletePoint::from_affine(other.clone()))
    }
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, E: PointEncoding> Consistent<'dr, D>
    for ConditionalPoint<'dr, D, C, E>
{
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        if !E::ALLOW_IDENTITY {
            self.finite_unchecked().enforce_consistent(dr)
        } else {
            self.point.enforce_consistent(dr)
        }
    }
}
