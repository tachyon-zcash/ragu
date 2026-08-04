//! The context object threaded through [`Step::witness`](super::Step::witness).

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_core::drivers::Driver;

/// Framework-side state threaded through
/// [`Step::witness`](super::Step::witness): so far only the [`Driver`], so a
/// sub-component called from a step body takes a single `&mut StepCtx`.
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    /// The underlying driver, for allocation and constraint emission.
    pub dr: &'a mut D,
    _marker: PhantomData<(&'dr (), C)>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(dr: &'a mut D) -> Self {
        Self {
            dr,
            _marker: PhantomData,
        }
    }
}
