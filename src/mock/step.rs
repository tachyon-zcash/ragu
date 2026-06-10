//! Mock PCD step — mirrors `ragu_pcd::Step`.

use crate::{
    ctx::StepCtx,
    error::{Error, Result},
    header::Header,
};

/// Number of internal step indexes reserved by mock_ragu.
///
/// Mirrors real ragu's `InternalStepIndex` layout:
/// - Slot 0: `Rerandomize` (reserved; mock rerandomize is a transformation, not
///   a Step, but the slot stays reserved for migration parity).
/// - Slot 1: trivial step (used to seed [`crate::proof::Proof::trivial`]).
pub(crate) const NUM_INTERNAL_STEPS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum StepIndex {
    Internal(usize),
    Application(usize),
}

/// Mirrors `ragu_pcd::step::Index`.
///
/// Variants are crate-private. Construct via [`Index::new`] for application
/// steps; only mock_ragu itself constructs internal-step indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Index {
    index: StepIndex,
}

impl Index {
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self {
            index: StepIndex::Application(value),
        }
    }

    pub(crate) const fn internal(value: usize) -> Self {
        assert!(value < NUM_INTERNAL_STEPS, "invalid internal step index");
        Self {
            index: StepIndex::Internal(value),
        }
    }

    /// Returns the encoded value mapping internal vs application into a
    /// single `u64` namespace. Internal values occupy `0..NUM_INTERNAL_STEPS`
    /// and application values follow.
    #[expect(
        clippy::expect_used,
        reason = "usize fits in u64 on all supported targets"
    )]
    pub(crate) fn get(self) -> u64 {
        let value_usize = match self.index {
            StepIndex::Internal(value) => value,
            StepIndex::Application(value) => value + NUM_INTERNAL_STEPS,
        };
        u64::try_from(value_usize).expect("step index fits in u64")
    }

    /// Returns the application offset (0-based) if this is an application
    /// step, or `None` if it is internal.
    pub(crate) fn application(self) -> Option<usize> {
        match self.index {
            StepIndex::Application(value) => Some(value),
            StepIndex::Internal(_) => None,
        }
    }

    /// Parses an [`Index`] from its `get()` value.
    pub(crate) fn from_value(value: u64) -> Result<Self> {
        let value_usize =
            usize::try_from(value).map_err(|_err| Error("step index value exceeds usize"))?;
        if value_usize < NUM_INTERNAL_STEPS {
            return Ok(Self {
                index: StepIndex::Internal(value_usize),
            });
        }
        let application = value_usize
            .checked_sub(NUM_INTERNAL_STEPS)
            .ok_or(Error("step index value underflow"))?;
        Ok(Self {
            index: StepIndex::Application(application),
        })
    }

    /// Mirrors `ragu_pcd::step::Index::assert_index`. Used during
    /// registration to require sequential application indexes.
    pub(crate) fn assert_sequential(self, expected: usize) -> Result<()> {
        match self.index {
            StepIndex::Application(value) if value == expected => Ok(()),
            StepIndex::Application(_) => Err(Error("steps must be registered in sequential order")),
            StepIndex::Internal(_) => Err(Error("step INDEX must be application-defined")),
        }
    }
}

/// Mirrors `ragu_pcd::Step`.
pub trait Step: Sized + Send + Sync {
    const INDEX: Index;
    type Witness<'source>: Send;
    type Aux<'source>: Send;
    type Left: Header;
    type Right: Header;
    type Output: Header;

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)>;
}
