//! Trivial test fixtures for ragu_pcd tests and benchmarks.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

use crate::{
    Application, ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};

/// A trivial header with no data.
pub struct NoopHeader;

impl<F: Field> Header<F> for NoopHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data<'source> = ();
    type Output = ();

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _dr: &mut D,
        _witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}

/// A trivial leaf step: () -> NoopHeader
pub struct NoopLeafStep;

impl<C: Cycle> Step<C> for NoopLeafStep {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = NoopHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());
        Ok(((left, right, output), D::just(|| ())))
    }
}

/// A trivial merge step: (NoopHeader, NoopHeader) -> NoopHeader
pub struct NoopMergeStep;

impl<C: Cycle> Step<C> for NoopMergeStep {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = NoopHeader;
    type Right = NoopHeader;
    type Output = NoopHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let left = Encoded::new(dr, left)?;
        let right = Encoded::new(dr, right)?;
        let output = Encoded::from_gadget(());
        Ok(((left, right, output), D::just(|| ())))
    }
}

pub fn build_app<C: Cycle>(params: &C::Params) -> Application<'_, C, R<13>, 4> {
    ApplicationBuilder::<C, R<13>, 4>::new()
        .register(NoopLeafStep)
        .unwrap()
        .register(NoopMergeStep)
        .unwrap()
        .finalize(params)
        .unwrap()
}
