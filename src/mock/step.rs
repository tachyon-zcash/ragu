//! Mock PCD step — mirrors `ragu_pcd::Step`.

use alloc::vec::Vec;

use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    pasta::Fp,
};
use ragu_primitives::{Element, GadgetExt, allocator::Allocator, io::Buffer, shared::Shared};

pub use super::ctx::StepCtx;
use super::header::Header;

/// Encoded header gadget returned by a step, preserving its computed wires.
///
/// `HEADER_SIZE` is the application's configured width, including the suffix
/// slot, as in real ragu. Serialization pads with zeros and rejects overflow.
/// No recursive uniform-encoding variant is needed here.
pub struct Encoded<'dr, D: Driver<'dr, F = Fp>, H: Header, const HEADER_SIZE: usize>(
    Bound<'dr, D, H::Output>,
);

impl<'dr, D: Driver<'dr, F = Fp>, H: Header, const HEADER_SIZE: usize> Clone
    for Encoded<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'dr, D: Driver<'dr, F = Fp>, H: Header, const HEADER_SIZE: usize>
    Encoded<'dr, D, H, HEADER_SIZE>
{
    /// Wraps the actual gadget computed by the step without reallocation.
    pub fn from_gadget(gadget: Bound<'dr, D, H::Output>) -> Self {
        Self(gadget)
    }

    /// Borrows the underlying header gadget.
    pub fn as_gadget(&self) -> &Bound<'dr, D, H::Output> {
        &self.0
    }

    /// Encodes witness data using the supplied driver and allocator.
    pub fn new<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, H::Data>,
    ) -> Result<Self> {
        Ok(Self::from_gadget(H::encode(dr, allocator, witness)?))
    }

    pub(crate) fn write(self, dr: &mut D, buf: &mut Vec<Element<'dr, D>>) -> Result<()> {
        if HEADER_SIZE == 0 {
            return Err(Error::MalformedEncoding(
                "HEADER_SIZE must include a suffix slot".into(),
            ));
        }
        let mut counting = CountingBuffer::<_, HEADER_SIZE> {
            written: 0,
            inner: buf,
        };
        self.0.write(dr, &mut counting)?;
        while counting.written < HEADER_SIZE - 1 {
            Element::zero(dr).write(dr, &mut counting)?;
        }
        Element::constant(dr, Fp::from(H::SUFFIX.get())).write(dr, counting.inner)?;
        Ok(())
    }
}

struct CountingBuffer<'a, B, const HEADER_SIZE: usize> {
    written: usize,
    inner: &'a mut B,
}

impl<'dr, D: Driver<'dr>, B: Buffer<'dr, D>, const HEADER_SIZE: usize> Buffer<'dr, D>
    for CountingBuffer<'_, B, HEADER_SIZE>
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        let capacity = HEADER_SIZE.saturating_sub(1);
        if self.written >= capacity {
            return Err(Error::MalformedEncoding(
                alloc::format!("Header encoding size exceeded HEADER_SIZE - 1 ({capacity})").into(),
            ));
        }
        self.inner.write(dr, value)?;
        self.written += 1;
        Ok(())
    }
}

/// Number of internal step indexes reserved by mock_ragu.
///
/// Mirrors real ragu's `InternalStepIndex` layout:
/// - Slot 0: `Rerandomize` (reserved; mock rerandomize is a transformation, not
///   a Step, but the slot stays reserved for migration parity).
/// - Slot 1: bootstrap step (produces [`crate::Proof::bootstrap`]).
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
    pub(crate) fn get(self) -> u64 {
        match self.index {
            StepIndex::Internal(value) => value as u64,
            StepIndex::Application(value) => (value + NUM_INTERNAL_STEPS) as u64,
        }
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
        let value_usize = usize::try_from(value)
            .map_err(|_err| Error::MalformedEncoding("step index value exceeds usize".into()))?;
        if value_usize < NUM_INTERNAL_STEPS {
            return Ok(Self {
                index: StepIndex::Internal(value_usize),
            });
        }
        let application = value_usize
            .checked_sub(NUM_INTERNAL_STEPS)
            .ok_or_else(|| Error::MalformedEncoding("step index value underflow".into()))?;
        Ok(Self {
            index: StepIndex::Application(application),
        })
    }

    /// Mirrors `ragu_pcd::step::Index::assert_index`. Used during
    /// registration to require sequential application indexes.
    pub(crate) fn assert_sequential(self, expected: usize) -> Result<()> {
        match self.index {
            StepIndex::Application(value) if value == expected => Ok(()),
            StepIndex::Application(_) => Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            )),
            StepIndex::Internal(_) => Err(Error::Initialization(
                "step INDEX must be application-defined".into(),
            )),
        }
    }
}

/// Mirrors `ragu_pcd::Step`.
pub trait Step: Sized + Send + Sync {
    const INDEX: Index;
    /// The shared application-stage gadget. The mock executes its constraints
    /// locally but does not commit a separate recursive stage polynomial.
    type Shared: Shared<Fp>;
    type Witness<'source>: Send;
    type Aux<'source>: Send;
    type Left: Header;
    type Right: Header;
    type Output: Header;

    /// Emits this step's constraints using real ragu drivers and gadgets.
    ///
    /// Returns encoded left, right, and output headers, carried output data,
    /// and auxiliary witness data. Use `Encoded::from_gadget` for computed
    /// outputs so the proof binds the same wires used by the step's constraints.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}
