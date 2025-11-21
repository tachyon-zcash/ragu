use super::header::Header;

mod encoder;
mod padded;

/// Internal representation of a [`Step`] index distinguishing internal vs.
/// application steps.
enum StepIndex {
    Internal(usize),
    Application(usize),
}

/// The number of internal steps used by Ragu for things like rerandomization or
/// proof decompression.
///
/// * `0` is used for the rerandomization step (see [`rerandomize`]).
pub(crate) const NUM_INTERNAL_STEPS: usize = 1;

/// The index of a [`Step`] in an [`Application`].
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

    /// Obtain the circuit index of a [`Step`] based on whether this represents
    /// an internal or application [`Step`]'s index.
    ///
    /// Requires the number of application steps that were registered in order
    /// to index properly. Do not call this and then later register more
    /// application steps.
    pub(crate) fn circuit_index(&self, num_application_steps: usize) -> usize {
        match self.index {
            StepIndex::Internal(i) => num_application_steps + i,
            StepIndex::Application(i) => i,
        }
    }

    /// Creates a new internal-defined [`Step`] index. Only called internally by
    /// Ragu.
    pub(crate) const fn internal(value: usize) -> Self {
        if value >= NUM_INTERNAL_STEPS {
            panic!("invalid internal step index");
        }

        Index {
            index: StepIndex::Internal(value),
        }
    }
}

#[test]
fn test_index_map() {
    let num_application_steps = 10;

    assert_eq!(Index::internal(0).circuit_index(num_application_steps), 10);
    assert_eq!(Index::new(0).circuit_index(num_application_steps), 0);
    assert_eq!(Index::new(1).circuit_index(num_application_steps), 1);
}
