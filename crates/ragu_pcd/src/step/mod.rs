//! Merging operations defined for the proof-carrying data computational graph.

mod encoder;
pub(crate) mod internal;

use ragu_arithmetic::Cycle;
use ragu_circuits::registry::CircuitIndex;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use super::header::Header;
use crate::circuits::native::NUM_INTERNAL_CIRCUITS;

pub use encoder::Encoded;

#[derive(Copy, Clone)]
#[repr(usize)]
pub(crate) enum InternalStepIndex {
    /// Internal step for [`internal::rerandomize`].
    Rerandomize = 0,
    /// Internal step that produces a valid trivial proof for rerandomization.
    Trivial = 1,
}

/// The number of internal steps used by Ragu for things like rerandomization or
/// proof decompression.  Derived from the last variant so that adding a new
/// variant forces an update here.
pub(crate) const NUM_INTERNAL_STEPS: usize = InternalStepIndex::Trivial as usize + 1;

/// A handle to a registered [`Step`] that carries the auto-assigned circuit
/// index.
///
/// Returned by [`ApplicationBuilder::register`](crate::ApplicationBuilder::register)
/// and required by [`Application::seed`](crate::Application::seed) and
/// [`Application::fuse`](crate::Application::fuse) to identify which circuit to
/// use during proving.
#[derive(Copy, Clone)]
pub struct StepHandle<S> {
    circuit_index: CircuitIndex,
    _marker: core::marker::PhantomData<fn() -> S>,
}

impl<S> StepHandle<S> {
    pub(crate) fn new(circuit_index: CircuitIndex) -> Self {
        StepHandle {
            circuit_index,
            _marker: core::marker::PhantomData,
        }
    }

    pub(crate) fn circuit_index(&self) -> CircuitIndex {
        self.circuit_index
    }
}

impl InternalStepIndex {
    /// Returns the circuit index for this internal step.
    ///
    /// Internal steps come after internal circuits in the registry.
    pub(crate) fn circuit_index(self) -> CircuitIndex {
        CircuitIndex::from_u32(NUM_INTERNAL_CIRCUITS as u32 + self as u32)
    }
}

#[test]
fn test_index_map() {
    use crate::circuits::native::NUM_INTERNAL_CIRCUITS;

    assert_eq!(
        InternalStepIndex::Rerandomize.circuit_index(),
        CircuitIndex::new(NUM_INTERNAL_CIRCUITS)
    );
    assert_eq!(
        InternalStepIndex::Trivial.circuit_index(),
        CircuitIndex::new(NUM_INTERNAL_CIRCUITS + 1)
    );
}

/// Represents a node in the computational graph (or the proof-carrying data
/// tree) that represents the merging of two pieces of proof-carrying data.
///
/// Steps are registered with an [`ApplicationBuilder`](crate::ApplicationBuilder)
/// via [`register`](crate::ApplicationBuilder::register), which returns a
/// [`StepHandle`] that carries the auto-assigned circuit index. The handle is
/// then passed to [`Application::seed`](crate::Application::seed) or
/// [`Application::fuse`](crate::Application::fuse) alongside the step instance.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// The witness data needed to construct a proof for this step.
    type Witness<'source>: Send;

    /// Auxiliary information produced during circuit synthesis. This may be
    /// necessary to construct the [`Header::Data`] for the resulting proof.
    type Aux<'source>: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// The main synthesis method that checks the validity of this merging step.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data<'source>>,
        right: DriverValue<D, <Self::Right as Header<C::CircuitField>>::Data<'source>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}
