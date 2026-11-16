//! Independent input, query and evaluation stages for private batches.

use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
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
    const NATIVE: bool = true;
}
impl Side for Nested {
    fn layout<P: Profile>() -> Layout {
        P::NESTED_ONLINE
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

/// The number of distinct polynomials, including auxiliary polynomials.
pub struct PolynomialsLen<P: Profile, S: Side>(PhantomData<(P, S)>);
impl<P: Profile, S: Side> Len for PolynomialsLen<P, S> {
    fn len() -> usize {
        S::layout::<P>().polynomials.len()
    }
}

/// Witnessed query points and claimed values in the profile's fixed order.
#[derive(Clone)]
pub struct QueryWitness<F, P: Profile, S: Side> {
    /// The separately witnessed points, fixed before `alpha`.
    pub points: FixedVec<F, PointsLen<P, S>>,
    /// Shared value wires, fixed before `alpha`.
    pub values: FixedVec<F, ValuesLen<P, S>>,
}

/// The query wires shared by consumers and the batch helper.
#[derive(Gadget, Write, Consistent)]
pub struct QueryOutput<'dr, D: Driver<'dr>, P: Profile, S: Side> {
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
    type Witness<'source> = &'source FixedVec<F, InputsLen<P, S>>;
    type OutputKind = Kind![F; FixedVec<Element<'_, _>, InputsLen<P, S>>];
    fn values() -> usize {
        InputsLen::<P, S>::len()
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

impl<F: Field, R: Rank, P: Profile, S: Side> Stage<F, R> for QueryStage<P, S> {
    type Parent = InputStage<P, S>;
    type Witness<'source> = &'source QueryWitness<F, P, S>;
    type OutputKind = Kind![F; QueryOutput<'_, _, P, S>];
    fn values() -> usize {
        PointsLen::<P, S>::len() + ValuesLen::<P, S>::len()
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
