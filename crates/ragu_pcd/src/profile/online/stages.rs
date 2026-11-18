//! Independent input, query and evaluation stages for online batches.

use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    consistent::Consistent,
    io::Write,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use super::Layout;
use crate::profile::Profile;

mod sealed {
    pub trait Sealed {}
}

/// Which field's declaration a stage uses.
pub trait Side: sealed::Sealed + Copy + Default + Send + Sync + 'static {
    /// Selects the profile's fixed layout.
    fn layout<P: Profile>() -> Layout;
    /// Selects the other field's fixed layout.
    fn other_layout<P: Profile>() -> Layout;
    /// Selects the source identity accumulator on this field.
    fn mesh<P: Profile>() -> Option<super::mesh::Mesh>;
    /// Selects the inputs held to the source registry's domain.
    fn domain_inputs<P: Profile>() -> &'static [usize];
    /// Whether the helper must lift the native `pre_beta` endoscalar.
    const NATIVE: bool;
}

/// The native polynomial field.
#[derive(Clone, Copy, Debug, Default)]
pub struct Native;
/// The nested polynomial field.
#[derive(Clone, Copy, Debug, Default)]
pub struct Nested;
impl sealed::Sealed for Native {}
impl sealed::Sealed for Nested {}
impl Side for Native {
    fn layout<P: Profile>() -> Layout {
        P::NATIVE_ONLINE
    }
    fn other_layout<P: Profile>() -> Layout {
        P::NESTED_ONLINE
    }
    fn mesh<P: Profile>() -> Option<super::mesh::Mesh> {
        P::NATIVE_MESH
    }
    fn domain_inputs<P: Profile>() -> &'static [usize] {
        P::NATIVE_DOMAIN_INPUTS
    }
    const NATIVE: bool = true;
}
impl Side for Nested {
    fn layout<P: Profile>() -> Layout {
        P::NESTED_ONLINE
    }
    fn other_layout<P: Profile>() -> Layout {
        P::NATIVE_ONLINE
    }
    fn mesh<P: Profile>() -> Option<super::mesh::Mesh> {
        P::NESTED_MESH
    }
    fn domain_inputs<P: Profile>() -> &'static [usize] {
        P::NESTED_DOMAIN_INPUTS
    }
    const NATIVE: bool = false;
}

macro_rules! count {
    ($name:ident, $field:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name<P: Profile, S: Side>(PhantomData<(P, S)>);
        impl<P: Profile, S: Side> Len for $name<P, S> {
            fn len() -> usize {
                S::layout::<P>().$field
            }
        }
    };
}
count!(InputsLen, inputs, "The number of pre-w input values.");
count!(
    PointsLen,
    points,
    "The number of separately witnessed query points."
);
count!(
    ValuesLen,
    values,
    "The number of shared claimed query values."
);

/// A fixed number of values when this side has an online batch, otherwise none.
pub struct Present<P: Profile, S: Side, const N: usize>(PhantomData<(P, S)>);
impl<P: Profile, S: Side, const N: usize> Len for Present<P, S, N> {
    fn len() -> usize {
        if S::layout::<P>().is_empty() { 0 } else { N }
    }
}

/// The number of distinct polynomials, including auxiliary polynomials.
pub struct PolynomialsLen<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> Len for PolynomialsLen<P, S> {
    fn len() -> usize {
        S::layout::<P>().polynomials.len()
    }
}

/// A fixed number of wires when this side has a source-registry mesh.
pub struct MeshPresent<P: Profile, S: Side, const N: usize>(PhantomData<(P, S)>);
impl<P: Profile, S: Side, const N: usize> Len for MeshPresent<P, S, N> {
    fn len() -> usize {
        if S::mesh::<P>().is_some() { N } else { 0 }
    }
}

/// Number of common source-mesh coordinates and intersection values.
pub struct MeshClaimsLen<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> Len for MeshClaimsLen<P, S> {
    fn len() -> usize {
        S::mesh::<P>().map_or(0, |mesh| mesh.claims_len())
    }
}

/// Number of polynomials at one commitment deadline.
///
/// PHASE indexes Phase::ALL, from BeforeW (0) through BeforeAlpha (3).
pub struct PhaseLen<P: Profile, S: Side, const PHASE: usize>(PhantomData<(P, S)>);
impl<P: Profile, S: Side, const PHASE: usize> Len for PhaseLen<P, S, PHASE> {
    fn len() -> usize {
        S::layout::<P>().phase_range(super::Phase::ALL[PHASE]).len()
    }
}

/// Scalar coordinate count for the commitments fixed at one deadline.
pub struct PhaseCoordinatesLen<P: Profile, S: Side, const PHASE: usize>(PhantomData<(P, S)>);
impl<P: Profile, S: Side, const PHASE: usize> Len for PhaseCoordinatesLen<P, S, PHASE> {
    fn len() -> usize {
        2 * PhaseLen::<P, S, PHASE>::len()
    }
}

/// Selects a fixed phase's commitments from commitment-fold order.
pub(crate) fn phase_points<P: Profile, S: Side, const PHASE: usize, T: Clone>(
    points: &[T],
) -> FixedVec<T, PhaseLen<P, S, PHASE>> {
    let start = S::layout::<P>().phase_range(super::Phase::ALL[PHASE]).start;
    FixedVec::from_fn(|i| points[start + i].clone())
}

/// Coordinates of the other field's online commitments fixed before w.
/// Each point occupies two wires.
pub struct ForeignLen<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> Len for ForeignLen<P, S> {
    fn len() -> usize {
        2 * S::other_layout::<P>()
            .polynomials
            .iter()
            .filter(|&&p| p == super::Phase::BeforeW)
            .count()
    }
}

/// User inputs and the opposite field's online commitment coordinates.
#[derive(Clone)]
pub struct InputWitness<F, P: Profile, S: Side> {
    /// The source tag, constrained to the registry captured by setup.
    pub source_tag: FixedVec<F, MeshPresent<P, S, 1>>,
    /// User data fixed before w.
    pub values: FixedVec<F, InputsLen<P, S>>,
    /// Opposite-field pre-w commitments in polynomial order, x then y.
    pub foreign: FixedVec<F, ForeignLen<P, S>>,
}

/// Early wires shared by all declared online consumers.
#[derive(Gadget, Write, Consistent)]
pub struct InputOutput<'dr, D: Driver<'dr>, P: Profile, S: Side> {
    /// The source tag, authenticated by the batch helper's circuit constant.
    #[ragu(gadget)]
    pub source_tag: FixedVec<Element<'dr, D>, MeshPresent<P, S, 1>>,
    /// User data fixed before w.
    #[ragu(gadget)]
    pub values: FixedVec<Element<'dr, D>, InputsLen<P, S>>,
    /// Coordinates authenticated against the commitment walk through the
    /// helper's public target. [`Self::foreign_point`] reads a point off them.
    #[ragu(gadget)]
    pub foreign: FixedVec<Element<'dr, D>, ForeignLen<P, S>>,
}

impl<'dr, D: Driver<'dr>, P: Profile, S: Side> InputOutput<'dr, D, P, S> {
    /// Reads an authenticated opposite-field commitment from its staged
    /// wires: a point on the curve whose coordinates are constrained equal to
    /// them.
    ///
    /// The index follows the other layout's BeforeW polynomial order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`] if the staged coordinates are not
    /// those of a finite point.
    ///
    /// # Panics
    ///
    /// Panics if the index is outside the fixed foreign commitment layout.
    pub fn foreign_point<C: udon::curve::EndomorphismAffine<Base = D::F>>(
        &self,
        dr: &mut D,
        index: usize,
    ) -> Result<Point<'dr, D, C>> {
        assert!(
            index < self.foreign.len() / 2,
            "foreign commitment index outside layout"
        );
        let (x, y) = (&self.foreign[2 * index], &self.foreign[2 * index + 1]);
        let value = D::try_just(|| {
            C::from_xy(*x.value().take(), *y.value().take()).ok_or_else(|| {
                Error::InvalidWitness("a foreign commitment is not a finite point".into())
            })
        })?;
        let point = Point::alloc(dr, value)?;
        let mut coordinates = alloc::vec::Vec::new();
        point.write(dr, &mut coordinates)?;
        coordinates[0].enforce_equal(dr, x)?;
        coordinates[1].enforce_equal(dr, y)?;
        Ok(point)
    }
}

/// Witnessed query points and claimed values in the profile's fixed order.
#[derive(Clone)]
pub struct QueryWitness<F, P: Profile, S: Side> {
    /// Authenticated enclosing-step w, y and x, in that order.
    pub challenges: FixedVec<F, Present<P, S, 3>>,
    /// The separately witnessed points, fixed before `alpha`.
    pub points: FixedVec<F, PointsLen<P, S>>,
    /// Shared value wires, fixed before `alpha`.
    pub values: FixedVec<F, ValuesLen<P, S>>,
}

/// The query wires shared by consumers and the batch helper.
#[derive(Gadget, Write, Consistent)]
pub struct QueryOutput<'dr, D: Driver<'dr>, P: Profile, S: Side> {
    /// Enclosing-step w, y and x, bound by the helper public target.
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, Present<P, S, 3>>,
    /// Separately witnessed query points.
    #[ragu(gadget)]
    pub points: FixedVec<Element<'dr, D>, PointsLen<P, S>>,
    /// Shared claimed query values.
    #[ragu(gadget)]
    pub values: FixedVec<Element<'dr, D>, ValuesLen<P, S>>,
}

/// Input values committed before the enclosing step's `w`.
///
/// This is independent of the fuse preamble. Consumers that reserve its query
/// child share the same early wires, rather than witnessing fresh copies.
pub struct InputStage<P: Profile, S: Side>(PhantomData<(P, S)>);
/// Opening claims committed before `alpha`.
pub struct QueryStage<P: Profile, S: Side>(PhantomData<(P, S)>);
/// One evaluation at `u` per polynomial, committed before `pre_beta`.
pub struct EvalStage<P: Profile, S: Side>(PhantomData<(P, S)>);

macro_rules! default_stage {
    ($stage:ident) => {
        impl<P: Profile, S: Side> Default for $stage<P, S> {
            fn default() -> Self {
                Self(PhantomData)
            }
        }
    };
}
default_stage!(InputStage);
default_stage!(QueryStage);
default_stage!(EvalStage);

impl<F: Field, R: Rank, P: Profile, S: Side> Stage<F, R> for InputStage<P, S> {
    type Parent = ();
    type Witness<'source> = &'source InputWitness<F, P, S>;
    type OutputKind = Kind![F; InputOutput<'_, _, P, S>];
    fn values() -> usize {
        MeshPresent::<P, S, 1>::len() + InputsLen::<P, S>::len() + ForeignLen::<P, S>::len()
    }
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(InputOutput {
            source_tag: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.source_tag[i]))
            })?,
            values: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.values[i]))
            })?,
            foreign: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.foreign[i]))
            })?,
        })
    }
}

impl<F: Field, R: Rank, P: Profile, S: Side> Stage<F, R> for QueryStage<P, S> {
    type Parent = InputStage<P, S>;
    type Witness<'source> = &'source QueryWitness<F, P, S>;
    type OutputKind = Kind![F; QueryOutput<'_, _, P, S>];
    fn values() -> usize {
        Present::<P, S, 3>::len() + PointsLen::<P, S>::len() + ValuesLen::<P, S>::len()
    }
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(QueryOutput {
            challenges: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.challenges[i]))
            })?,
            points: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.points[i]))
            })?,
            values: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|v| v.values[i]))
            })?,
        })
    }
}

impl<F: Field, R: Rank, P: Profile, S: Side> Stage<F, R> for EvalStage<P, S> {
    type Parent = QueryStage<P, S>;
    type Witness<'source> = &'source FixedVec<F, PolynomialsLen<P, S>>;
    type OutputKind = Kind![F; FixedVec<Element<'_, _>, PolynomialsLen<P, S>>];
    fn values() -> usize {
        PolynomialsLen::<P, S>::len()
    }
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| Element::alloc(dr, &mut (), witness.as_ref().map(|v| v[i])))
    }
}
