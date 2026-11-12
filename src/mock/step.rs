//! Mock PCD step — mirrors `ragu_pcd::Step`.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
use ragu_primitives::allocator::Allocator;
use udon::field::Field;

use super::header::{HEADER_POLYNOMIALS, Has, Header};

pub mod oracles;
pub use oracles::{Oracle, Oracles};

/// Mirrors `ragu_pcd::step::Prepared`.
pub struct Prepared<F, O> {
    polynomials: [Vec<F>; HEADER_POLYNOMIALS],
    staged: Vec<F>,
    _marker: PhantomData<fn() -> O>,
}

impl<F: Field, O: Header<F>> Default for Prepared<F, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, O: Header<F>> Prepared<F, O> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            polynomials: core::array::from_fn(|_| vec![F::ONE]),
            staged: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Mirrors `ragu_pcd::step::Prepared::poly`.
    #[must_use]
    pub fn poly<P, I>(mut self, _kind: P, coefficients: impl Into<Vec<F>>) -> Self
    where
        O::OnlinePolyCommit: Has<P, I>,
    {
        self.polynomials[<O::OnlinePolyCommit as Has<P, I>>::INDEX] = coefficients.into();
        self
    }

    /// Mirrors `ragu_pcd::step::Prepared::stage`.
    #[must_use]
    pub fn stage(mut self, values: impl Into<Vec<F>>) -> Self {
        self.staged.extend(values.into());
        self
    }

    pub fn polynomial<P, I>(&self, _kind: P) -> &[F]
    where
        O::OnlinePolyCommit: Has<P, I>,
    {
        &self.polynomials[<O::OnlinePolyCommit as Has<P, I>>::INDEX]
    }

    pub fn polynomials(&self) -> &[Vec<F>; HEADER_POLYNOMIALS] {
        &self.polynomials
    }

    pub fn staged(&self) -> &[F] {
        &self.staged
    }
}

pub struct Encoded<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>(
    Bound<'dr, D, H::Output>,
);

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize> Clone
    for Encoded<'dr, D, H, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'dr, D: Driver<'dr>, H: Header<D::F>, const HEADER_SIZE: usize>
    Encoded<'dr, D, H, HEADER_SIZE>
{
    pub fn from_gadget(gadget: Bound<'dr, D, H::Output>) -> Self {
        Self(gadget)
    }

    pub fn as_gadget(&self) -> &Bound<'dr, D, H::Output> {
        &self.0
    }

    pub fn new<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, H::Data>,
    ) -> Result<Self> {
        Ok(Self::from_gadget(H::encode(dr, allocator, witness)?))
    }
}

/// Number of internal step indexes reserved by mock_ragu.
///
/// Mirrors real ragu's `InternalStepIndex` layout:
/// - Slot 0: `Rerandomize` (reserved; mock rerandomize is a transformation, not
///   a Step, but the slot stays reserved for migration parity).
/// - Slot 1: bootstrap step (produces [`crate::Application::bootstrap_proof`]).
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
    pub(crate) fn get(&self) -> u64 {
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

/// Mirrors `ragu_pcd::step::HeaderInput`.
pub struct HeaderInput<'a, F: Field, H: Header<F>> {
    pub data: &'a H::Data,
    polynomials: &'a [Vec<F>; HEADER_POLYNOMIALS],
}

impl<'a, F: Field, H: Header<F>> HeaderInput<'a, F, H> {
    pub(crate) fn new(data: &'a H::Data, polynomials: &'a [Vec<F>; HEADER_POLYNOMIALS]) -> Self {
        Self { data, polynomials }
    }

    /// Mirrors `ragu_pcd::step::HeaderInput::polynomial`.
    pub fn polynomial<P, I>(&self, _kind: P) -> &'a [F]
    where
        H::OnlinePolyCommit: Has<P, I>,
    {
        &self.polynomials[<H::OnlinePolyCommit as Has<P, I>>::INDEX]
    }
}

/// Mirrors `ragu_pcd::Step`.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    const INDEX: Index;
    type Witness<'source>: Send;
    type Aux<'source>: Send;
    type Left: Header<C::CircuitField>;
    type Right: Header<C::CircuitField>;
    type Output: Header<C::CircuitField>;

    const NUM_STAGED: usize = 0;

    /// Mirrors `ragu_pcd::Step::prepare`.
    fn prepare<'source>(
        &self,
        witness: &Self::Witness<'source>,
        left: HeaderInput<'_, C::CircuitField, Self::Left>,
        right: HeaderInput<'_, C::CircuitField, Self::Right>,
    ) -> Result<Prepared<C::CircuitField, Self::Output>> {
        let _ = (witness, left, right);
        Ok(Prepared::new())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
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
