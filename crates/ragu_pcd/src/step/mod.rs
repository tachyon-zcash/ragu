//! Merging operations defined for the proof-carrying data computational graph.

mod encoder;
pub(crate) mod internal;

pub use encoder::Encoded;
use ragu_circuits::registry::CircuitIndex;
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
};

use super::header::Header;
use crate::{internal::native::InternalCircuitIndex, profile::Profile};

#[derive(Copy, Clone)]
#[repr(usize)]
pub(crate) enum InternalStepIndex {
    /// Internal step for [`internal::rerandomize`].
    Rerandomize = 0,
    /// Internal step that bootstraps the recursion; see [`internal::bootstrap`].
    Bootstrap = 1,
    /// Internal step that decompresses a compressed proof; see
    /// [`internal::decompress`]. Registered only by a profile whose native
    /// extension has a statement circuit.
    Decompress = 2,
}

/// Internal representation of a [`Step`] index distinguishing internal vs.
/// application steps.
enum StepIndex {
    Internal(InternalStepIndex),
    Application(usize),
}

/// The internal steps every profile registers: rerandomization and the
/// bootstrap.
pub(crate) const NUM_INTERNAL_STEPS: usize = 2;

/// The internal steps profile `P` registers: every profile's, and the
/// decompression step for a profile whose native extension has a statement
/// circuit.
pub(crate) fn num_internal_steps<P: Profile>() -> usize {
    NUM_INTERNAL_STEPS + usize::from(P::native_extension().statement.is_some())
}

impl InternalStepIndex {
    /// The circuit index of this internal step in profile `P`: after the
    /// internal circuits, in declaration order.
    ///
    /// # Errors
    ///
    /// Fails for a step the profile does not register, the decompression
    /// step of a profile without a statement circuit, whose index would
    /// otherwise be an application step's.
    pub(crate) fn circuit_index<P: Profile>(self) -> Result<CircuitIndex> {
        let step = self as usize;
        if step >= num_internal_steps::<P>() {
            return Err(ragu_core::Error::Initialization(
                "attempted to use an internal step the profile does not register".into(),
            ));
        }
        Ok(CircuitIndex::new(InternalCircuitIndex::num::<P>() + step))
    }
}

/// The index of a [`Step`] in an application.
///
/// All steps added to an application have a unique index and must be inserted
/// sequentially so that their location (and other metadata) can be identified
/// during proof generation and at other times.
pub struct Index {
    index: StepIndex,
}

impl Index {
    /// Creates a new application-defined [`Step`] index.
    pub const fn new(value: usize) -> Self {
        Index {
            index: StepIndex::Application(value),
        }
    }

    /// Returns the circuit index for this step.
    ///
    /// Circuits are registered in the following order: internal circuits,
    /// internal masks, internal steps, then application steps.
    ///
    /// Pass the known number of application steps to validate and compute the
    /// final index of this step. Returns an error if an application step index
    /// exceeds the number of registered steps, or if an internal step is one
    /// the profile does not register.
    pub(crate) fn circuit_index<P: Profile>(
        &self,
        num_application_steps: usize,
    ) -> Result<CircuitIndex> {
        match self.index {
            StepIndex::Internal(i) => i.circuit_index::<P>(),
            StepIndex::Application(i) => {
                if i >= num_application_steps {
                    return Err(ragu_core::Error::Initialization(
                            "attempted to use application Step index that exceeds Application registered steps".into(),
                        ));
                }

                Ok(CircuitIndex::new(
                    num_internal_steps::<P>() + InternalCircuitIndex::num::<P>() + i,
                ))
            }
        }
    }

    /// Creates a new internal-defined [`Step`] index. Only called internally by
    /// Ragu.
    pub(crate) const fn internal(value: InternalStepIndex) -> Self {
        Index {
            index: StepIndex::Internal(value),
        }
    }

    /// Called during application step registration to assert the appropriate
    /// next sequential index.
    ///
    /// ## Panics
    ///
    /// Panics if called on an internal step.
    pub(crate) fn assert_index(&self, expect_id: usize) -> Result<()> {
        match self.index {
            StepIndex::Application(i) => {
                if i != expect_id {
                    return Err(ragu_core::Error::Initialization(
                        "steps must be registered in sequential order".into(),
                    ));
                }

                Ok(())
            }
            StepIndex::Internal(_) => panic!("step should be application-defined"),
        }
    }
}

/// Represents a node in the computational graph (or the proof-carrying data
/// tree) that represents the merging of two pieces of proof-carrying data.
///
/// See the [Writing Circuits](https://tachyon.z.cash/ragu/guide/writing_circuits.html)
/// guide for usage patterns and examples.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// Each unique [`Step`] implementation within a provided context must have
    /// a unique index.
    const INDEX: Index;

    /// The witness input needed to construct a proof for this step.
    type Witness<'source>: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// Auxiliary information produced during witness generation that may be
    /// used to pipeline witness input to later steps.
    type Aux<'source>: Send;

    /// Emits the constraints that check the validity of this merging step.
    ///
    /// Returns the encoded headers (left, right, output), the data to be
    /// carried in the resulting PCD, and any auxiliary witness data.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<C::CircuitField>>::Data>,
        right: DriverValue<D, <Self::Right as Header<C::CircuitField>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_map() -> Result<()> {
        use crate::profile::Standard;
        let num_application_steps = 10;
        let app_offset = NUM_INTERNAL_STEPS + InternalCircuitIndex::NUM;

        // Internal steps come after internal circuits
        assert_eq!(
            Index::internal(InternalStepIndex::Rerandomize)
                .circuit_index::<Standard>(num_application_steps)?,
            CircuitIndex::new(InternalCircuitIndex::NUM)
        );
        assert_eq!(
            Index::internal(InternalStepIndex::Bootstrap)
                .circuit_index::<Standard>(num_application_steps)?,
            CircuitIndex::new(InternalCircuitIndex::NUM + 1)
        );

        // Application steps occupy indices (InternalCircuitIndex::NUM + NUM_INTERNAL_STEPS)..
        assert_eq!(
            Index::new(0).circuit_index::<Standard>(num_application_steps)?,
            CircuitIndex::new(app_offset)
        );
        assert_eq!(
            Index::new(1).circuit_index::<Standard>(num_application_steps)?,
            CircuitIndex::new(app_offset + 1)
        );
        Index::new(999).assert_index(999)?;
        assert!(
            Index::new(10)
                .circuit_index::<Standard>(num_application_steps)
                .is_err()
        );

        Ok(())
    }

    /// A profile with a statement circuit registers the statement step
    /// after the two every profile has, and its application steps after
    /// it.
    #[test]
    fn test_a_statement_registers_its_step() -> Result<()> {
        use crate::profile::{Standard, testing::Stated};
        assert_eq!(num_internal_steps::<Standard>(), NUM_INTERNAL_STEPS);
        assert_eq!(num_internal_steps::<Stated>(), NUM_INTERNAL_STEPS + 1);
        let internal = InternalCircuitIndex::num::<Stated>();
        assert_eq!(
            Index::internal(InternalStepIndex::Decompress).circuit_index::<Stated>(1)?,
            CircuitIndex::new(internal + 2)
        );
        assert_eq!(
            Index::new(0).circuit_index::<Stated>(1)?,
            CircuitIndex::new(internal + 3)
        );
        Ok(())
    }

    /// An internal step a profile does not register has no circuit index
    /// in it: resolving the decompression step for the standard profile
    /// fails rather than naming its first application step.
    #[test]
    fn test_an_unregistered_internal_step_is_refused() -> Result<()> {
        use crate::profile::{Standard, testing::Stated};
        assert!(
            InternalStepIndex::Decompress
                .circuit_index::<Standard>()
                .is_err()
        );
        assert!(
            Index::internal(InternalStepIndex::Decompress)
                .circuit_index::<Standard>(1)
                .is_err()
        );
        assert_eq!(
            InternalStepIndex::Decompress.circuit_index::<Stated>()?,
            CircuitIndex::new(InternalCircuitIndex::num::<Stated>() + 2)
        );
        Ok(())
    }
}
